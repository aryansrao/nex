use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{stdin, stdout};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;
use zip::write::FileOptions;

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: String,
    created_at: DateTime<Utc>,
    recorder_version: String,
    duration_seconds: Option<f64>,
}

#[derive(Serialize, Deserialize)]
struct Event {
    t: f64,
    data: String, // base64
}

static RECORDING_PATH: &str = ".nex_recording.tmp";

fn default_recording_path() -> PathBuf {
    let now = Utc::now();
    // RFC3339 includes fractional seconds and timezone, replace ':' with '-' for filenames
    let s = now.to_rfc3339();
    let safe = s.replace(':', "-");
    PathBuf::from(format!("recording-{}.nex", safe))
}

pub fn start(out: Option<PathBuf>) -> Result<()> {
    let out = out.unwrap_or_else(|| default_recording_path());
    println!("Starting recording. Output: {}", out.display());

    let pty_system = NativePtySystem::default();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("Failed to open pty")?;

    // Choose a sensible default shell depending on the platform.
    // On Unix prefer $SHELL or /bin/sh; on Windows prefer %COMSPEC% (cmd.exe) or powershell.exe.
    let shell_path = if cfg!(windows) {
        std::env::var("COMSPEC").unwrap_or_else(|_| "powershell.exe".into())
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
    };

    // If zsh on Unix, create a temporary ZDOTDIR with hooks to emit command markers
    // (Windows shells are not compatible with these zsh hooks and are skipped).
    let mut envs = std::env::vars().collect::<Vec<(String, String)>>();
    if cfg!(unix) && shell_path.contains("zsh") {
        let tmpdir = std::env::temp_dir().join(format!("nex_zsh_{}", std::process::id()));
        std::fs::create_dir_all(&tmpdir)?;
        let zshrc = tmpdir.join(".zshrc");
        let marker_start = "\x1f__NEX_CMD_START__";
        let marker_end = "\x1f__NEX_CMD_END__";
        let zshrc_contents = format!(
            r#"{preexec}
{precmd}
"#,
            preexec = format!(
                r#"preexec() {{
  local t=$(date +%s.%N)
  local cwd=$(pwd | sed 's/"/\\\"/g')
  local cmd_b64=$(printf '%s' "$1" | base64)
  printf '{ms}%s|%s|%s\n' "$t" "$cwd" "$cmd_b64"
}}"#,
                ms = marker_start
            ),
            precmd = format!(
                r#"precmd() {{
  local t=$(date +%s.%N)
  local rc=$?
  printf '{me}%s|%s\n' "$t" "$rc"
}}"#,
                me = marker_end
            )
        );
        std::fs::write(&zshrc, zshrc_contents)?;
        // set ZDOTDIR to tmpdir so zsh reads this .zshrc
        envs.push(("ZDOTDIR".into(), tmpdir.to_string_lossy().into()));
    }

    let mut cmd_builder = CommandBuilder::new(shell_path.clone());
    for (k, v) in &envs {
        cmd_builder.env(k, v);
    }

    let mut child = pair
        .slave
        .spawn_command(cmd_builder)
        .context("Failed to spawn shell")?;

    let mut reader = pair.master.try_clone_reader().context("clone reader")?;
    let mut writer = pair.master.try_clone_writer().context("clone writer")?;

    let recording_file = File::create(RECORDING_PATH).context("create tmp recording")?;
    let recording = Arc::new(Mutex::new(recording_file));

    let start_instant = Instant::now();

    // buffer to accumulate partial marker data across reads
    let marker_buf = Arc::new(Mutex::new(String::new()));

    // Reader thread: copy from pty to recording (record JSON-line events)
    let rec_clone = recording.clone();
    let marker_clone = marker_buf.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    // Append incoming chunk to marker buffer and process markers without printing them
                    let s = String::from_utf8_lossy(&buf[..n]).to_string();
                    let mut mb = marker_clone.lock().unwrap();
                    mb.push_str(&s);

                    // collect bytes that are NOT markers into this buffer so we record cleaned output
                    let mut written_bytes: Vec<u8> = Vec::new();

                    // process markers and write non-marker text to stdout
                    loop {
                        if let Some(start_idx) = mb.find("\x1f__NEX_CMD_") {
                            // write text before marker
                            if start_idx > 0 {
                                let before = mb.drain(..start_idx).collect::<String>();
                                let before_bytes = before.as_bytes();
                                let _ = stdout().write_all(before_bytes);
                                let _ = stdout().flush();
                                written_bytes.extend_from_slice(before_bytes);
                            }
                            // now mb starts with marker; check for newline to have full marker line
                            if let Some(nl_pos) = mb.find('\n') {
                                let marker_line: String = mb.drain(..=nl_pos).collect();
                                // process marker_line content but DO NOT print it
                                if marker_line.contains("__NEX_CMD_START__") {
                                    if let Some(idx) = marker_line.find("__NEX_CMD_START__") {
                                        let payload =
                                            &marker_line[idx + "__NEX_CMD_START__".len()..].trim();
                                        let parts: Vec<&str> = payload.splitn(3, '|').collect();
                                        if parts.len() == 3 {
                                            let ct: f64 = parts[0].parse().unwrap_or(0.0);
                                            let cwd = parts[1].to_string();
                                            let cmd_b64 = parts[2].trim().to_string();
                                            let cmd_ev = serde_json::json!({
                                                "type": "command",
                                                "phase": "start",
                                                "t": ct,
                                                "cwd": cwd,
                                                "cmd_b64": cmd_b64,
                                            });
                                            let mut f = rec_clone.lock().unwrap();
                                            let _ = f.write_all(cmd_ev.to_string().as_bytes());
                                            let _ = f.write_all(b"\n");
                                        }
                                    }
                                } else if marker_line.contains("__NEX_CMD_END__") {
                                    if let Some(idx) = marker_line.find("__NEX_CMD_END__") {
                                        let payload =
                                            &marker_line[idx + "__NEX_CMD_END__".len()..].trim();
                                        let parts: Vec<&str> = payload.splitn(2, '|').collect();
                                        if parts.len() == 2 {
                                            let ct: f64 = parts[0].parse().unwrap_or(0.0);
                                            let rc: i32 = parts[1].trim().parse().unwrap_or(0);
                                            let cmd_ev = serde_json::json!({
                                                "type": "command",
                                                "phase": "end",
                                                "t": ct,
                                                "rc": rc,
                                            });
                                            let mut f = rec_clone.lock().unwrap();
                                            let _ = f.write_all(cmd_ev.to_string().as_bytes());
                                            let _ = f.write_all(b"\n");
                                        }
                                    }
                                }
                                // continue looping to find more markers
                                continue;
                            } else {
                                // incomplete marker, wait for more bytes
                                break;
                            }
                        } else {
                            // no marker; write entire buffer and clear
                            if !mb.is_empty() {
                                let before = mb.drain(..).collect::<String>();
                                let before_bytes = before.as_bytes();
                                let _ = stdout().write_all(before_bytes);
                                let _ = stdout().flush();
                                written_bytes.extend_from_slice(before_bytes);
                            }
                            break;
                        }
                    }

                    // record JSON-line event with timestamp for cleaned bytes (excluding markers)
                    if !written_bytes.is_empty() {
                        let t = start_instant.elapsed().as_secs_f64();
                        let data_b64 = general_purpose::STANDARD.encode(&written_bytes);
                        let ev = Event { t, data: data_b64 };
                        if let Ok(line) = serde_json::to_string(&ev) {
                            let mut f = rec_clone.lock().unwrap();
                            let _ = f.write_all(line.as_bytes());
                            let _ = f.write_all(b"\n");
                            let _ = f.flush();
                        }
                    }
                }
                Err(e) => {
                    eprintln!("pty read error: {}", e);
                    break;
                }
            }
        }
    });

    // Forward stdin to PTY writer in another thread
    thread::spawn(move || {
        let mut stdin = stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = writer.write_all(&buf[..n]);
                    let _ = writer.flush();
                }
                Err(_) => break,
            }
        }
    });

    // enable raw mode so user's terminal behaves as expected
    let _ = enable_raw_mode();

    // Wait for child to exit
    let status = child.wait().context("wait child")?;
    let _ = disable_raw_mode();
    println!("Shell exited with {:?}. Finalizing...", status);

    // Create .nex zip with manifest + recording
    // finalize: read temp JSON-lines events and write to zip as session.json
    let mut events_json = String::new();
    let mut tmp = File::open(RECORDING_PATH).context("open tmp recording")?;
    tmp.read_to_string(&mut events_json)
        .context("read tmp events")?;

    // compute duration from last event
    let mut duration = None;
    if let Some(last_line) = events_json.lines().last() {
        if let Ok(ev) = serde_json::from_str::<Event>(last_line) {
            duration = Some(ev.t);
        }
    }

    let manifest = Manifest {
        version: "1.0".into(),
        created_at: Utc::now(),
        recorder_version: "0.2".into(),
        duration_seconds: duration,
    };

    let out_file = File::create(&out).context("create output file")?;
    let mut zip = zip::ZipWriter::new(out_file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("manifest.json", options).unwrap();
    let m = serde_json::to_vec(&manifest).unwrap();
    zip.write_all(&m).unwrap();

    zip.start_file("session.json", options).unwrap();
    zip.write_all(events_json.as_bytes()).unwrap();

    zip.finish().unwrap();

    // Clean up
    let _ = fs::remove_file(RECORDING_PATH);
    println!("Recorded to {}", out.display());
    Ok(())
}

pub fn stop() -> Result<()> {
    // In this simple MVP start runs shell and exits when shell ends. stop is a no-op placeholder.
    println!(
        "Use Ctrl-D or exit in the spawned shell to stop recording (start handles finalize). "
    );
    Ok(())
}

pub fn inspect(file: PathBuf) -> Result<()> {
    let f = File::open(&file).context("open .nex")?;
    let mut zip = zip::ZipArchive::new(f).context("open zip")?;
    let mut manifest = String::new();
    zip.by_name("manifest.json")?
        .read_to_string(&mut manifest)?;
    println!("manifest:\n{}", manifest);
    Ok(())
}

pub fn play(file: PathBuf, show_commands: bool) -> Result<()> {
    let f = File::open(&file).context("open .nex")?;
    let mut zip = zip::ZipArchive::new(f).context("open zip")?;
    let mut session = String::new();
    zip.by_name("session.json")?.read_to_string(&mut session)?;
    // replay: handle both raw Event lines and command event objects
    let mut last_t = 0.0f64;
    for line in session.lines() {
        if line.trim().is_empty() {
            continue;
        }

        // try parse as Event with data
        if let Ok(ev) = serde_json::from_str::<Event>(line) {
            let wait = ev.t - last_t;
            if wait > 0.0 {
                std::thread::sleep(std::time::Duration::from_secs_f64(wait));
            }
            let bytes = general_purpose::STANDARD
                .decode(ev.data)
                .unwrap_or_default();
            stdout().write_all(&bytes)?;
            stdout().flush()?;
            last_t = ev.t;
            continue;
        }

        // otherwise try to parse as a generic JSON object (command events)
        if show_commands {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                if val.get("type").and_then(|t| t.as_str()) == Some("command") {
                    if let Some(phase) = val.get("phase").and_then(|p| p.as_str()) {
                        if phase == "start" {
                            let cwd = val.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
                            let cmd_b64 = val.get("cmd_b64").and_then(|v| v.as_str()).unwrap_or("");
                            let cmd = general_purpose::STANDARD
                                .decode(cmd_b64)
                                .ok()
                                .and_then(|b| Some(String::from_utf8_lossy(&b).to_string()))
                                .unwrap_or_default();
                            println!("[command start] {} -- {}", cwd, cmd);
                        } else if phase == "end" {
                            let rc = val.get("rc").and_then(|v| v.as_i64()).unwrap_or(0);
                            println!("[command end] rc={}", rc);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn export_csv(file: PathBuf, out: Option<PathBuf>) -> Result<()> {
    let out = out.unwrap_or_else(|| PathBuf::from("recording.csv"));
    let f = File::open(&file).context("open .nex")?;
    let mut zip = zip::ZipArchive::new(f).context("open zip")?;
    let mut session = String::new();
    zip.by_name("session.json")?.read_to_string(&mut session)?;

    // lightweight command record used during aggregation
    #[derive(Default)]
    struct CmdInfo {
        start_t: Option<f64>,
        end_t: Option<f64>,
        cwd: Option<String>,
        cmd_b64: Option<String>,
        rc: Option<i64>,
        output_bytes: usize,
        output_snippet: String,
    }

    // We'll parse events line-by-line and attribute raw Event bytes to the currently open command
    let mut cmds: Vec<CmdInfo> = Vec::new();
    let mut open_stack: Vec<usize> = Vec::new();
    let mut last_raw_t = 0.0f64;

    for line in session.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<Event>(line) {
            last_raw_t = ev.t;
            // attribute to most-recent open command if present
            if let Some(&idx) = open_stack.last() {
                if let Ok(bytes) = general_purpose::STANDARD.decode(&ev.data) {
                    cmds[idx].output_bytes += bytes.len();
                    if cmds[idx].output_snippet.len() < 200 {
                        let take = std::cmp::min(200 - cmds[idx].output_snippet.len(), bytes.len());
                        cmds[idx]
                            .output_snippet
                            .push_str(&String::from_utf8_lossy(&bytes[..take]));
                    }
                }
            }
            continue;
        }

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if val.get("type").and_then(|t| t.as_str()) == Some("command") {
                if let Some(phase) = val.get("phase").and_then(|p| p.as_str()) {
                    if phase == "start" {
                        let mut info = CmdInfo::default();
                        info.start_t = val.get("t").and_then(|v| v.as_f64());
                        info.cwd = val
                            .get("cwd")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        info.cmd_b64 = val
                            .get("cmd_b64")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        cmds.push(info);
                        open_stack.push(cmds.len() - 1);
                    } else if phase == "end" {
                        let end_t = val.get("t").and_then(|v| v.as_f64());
                        let rc = val.get("rc").and_then(|v| v.as_i64());
                        if let Some(idx) = open_stack.pop() {
                            cmds[idx].end_t = end_t;
                            cmds[idx].rc = rc;
                        } else {
                            // stray end: synthesize a short command record
                            let mut info = CmdInfo::default();
                            info.start_t = end_t.map(|t| t - 0.001);
                            info.end_t = end_t;
                            info.rc = rc;
                            cmds.push(info);
                        }
                    }
                }
            }
        }
    }

    // close remaining open commands at last_raw_t or start+epsilon
    while let Some(idx) = open_stack.pop() {
        if cmds[idx].end_t.is_none() {
            let inferred = if last_raw_t > cmds[idx].start_t.unwrap_or(0.0) {
                last_raw_t
            } else {
                cmds[idx].start_t.unwrap_or(0.0) + 0.001
            };
            cmds[idx].end_t = Some(inferred);
        }
    }

    // Build CSV rows with enhanced columns
    let mut wtr = csv::Writer::from_path(&out).context("create csv")?;
    wtr.write_record(&[
        "start_iso",
        "start_t",
        "end_t",
        "duration_s",
        "duration_human",
        "cwd",
        "cmd",
        "rc",
        "output_bytes",
        "output_snippet",
    ])?;

    for c in cmds {
        let start_t = c.start_t.unwrap_or(0.0);
        let end_t = c.end_t.unwrap_or(start_t);
        // ISO8601
        let secs = start_t.trunc() as i64;
        let nanos = ((start_t.fract()) * 1_000_000_000.0).round() as u32;
        // Use timestamp_opt to construct DateTime<Utc> without deprecated APIs
        let start_dt = Utc
            .timestamp_opt(secs, nanos)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap());
        let start_iso = start_dt.to_rfc3339();
        let duration_s = if end_t >= start_t {
            end_t - start_t
        } else {
            0.0
        };
        let duration_human = if duration_s >= 1.0 {
            format!("{:.3}s", duration_s)
        } else if duration_s >= 0.001 {
            format!("{:.0}ms", duration_s * 1000.0)
        } else {
            format!("{:.0}µs", duration_s * 1_000_000.0)
        };
        let cwd = c.cwd.unwrap_or_default();
        let cmd = c
            .cmd_b64
            .map(|b| {
                general_purpose::STANDARD
                    .decode(b)
                    .ok()
                    .map(|bb| String::from_utf8_lossy(&bb).to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let rc = c.rc.map(|v| v.to_string()).unwrap_or_default();
        let bytes = c.output_bytes.to_string();
        let snippet = c.output_snippet.replace('\n', "\\n");

        wtr.write_record(&[
            &start_iso,
            &format!("{:.6}", start_t),
            &format!("{:.6}", end_t),
            &format!("{:.6}", duration_s),
            &duration_human,
            &cwd,
            &cmd,
            &rc,
            &bytes,
            &snippet,
        ])?;
    }
    wtr.flush()?;
    println!("CSV exported to {}", out.display());
    Ok(())
}

pub fn export_json(file: PathBuf, out: Option<PathBuf>) -> Result<()> {
    let out = out.unwrap_or_else(|| PathBuf::from("recording.json"));
    let f = File::open(&file).context("open .nex")?;
    let mut zip = zip::ZipArchive::new(f).context("open zip")?;
    let mut session = String::new();
    zip.by_name("session.json")?.read_to_string(&mut session)?;

    #[derive(Serialize)]
    struct CmdSummary {
        start_iso: String,
        start_t: f64,
        end_t: Option<f64>,
        duration_s: Option<f64>,
        duration_human: Option<String>,
        cwd: Option<String>,
        cmd: Option<String>,
        rc: Option<i64>,
        output_bytes: usize,
        output_snippet: String,
    }

    // reuse logic from export_csv: parse sequentially and attribute raw bytes to current command
    #[derive(Default)]
    struct CmdInfo2 {
        start_t: Option<f64>,
        end_t: Option<f64>,
        cwd: Option<String>,
        cmd_b64: Option<String>,
        rc: Option<i64>,
        output_bytes: usize,
        output_snippet: String,
    }

    let mut cmds: Vec<CmdInfo2> = Vec::new();
    let mut open_stack: Vec<usize> = Vec::new();
    let mut last_raw_t = 0.0f64;

    for line in session.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<Event>(line) {
            last_raw_t = ev.t;
            if let Some(&idx) = open_stack.last() {
                if let Ok(bytes) = general_purpose::STANDARD.decode(&ev.data) {
                    cmds[idx].output_bytes += bytes.len();
                    if cmds[idx].output_snippet.len() < 200 {
                        let take = std::cmp::min(200 - cmds[idx].output_snippet.len(), bytes.len());
                        cmds[idx]
                            .output_snippet
                            .push_str(&String::from_utf8_lossy(&bytes[..take]));
                    }
                }
            }
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if val.get("type").and_then(|t| t.as_str()) == Some("command") {
                if let Some(phase) = val.get("phase").and_then(|p| p.as_str()) {
                    if phase == "start" {
                        let mut info = CmdInfo2::default();
                        info.start_t = val.get("t").and_then(|v| v.as_f64());
                        info.cwd = val
                            .get("cwd")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        info.cmd_b64 = val
                            .get("cmd_b64")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        cmds.push(info);
                        open_stack.push(cmds.len() - 1);
                    } else if phase == "end" {
                        let end_t = val.get("t").and_then(|v| v.as_f64());
                        let rc = val.get("rc").and_then(|v| v.as_i64());
                        if let Some(idx) = open_stack.pop() {
                            cmds[idx].end_t = end_t;
                            cmds[idx].rc = rc;
                        } else {
                            let mut info = CmdInfo2::default();
                            info.start_t = end_t.map(|t| t - 0.001);
                            info.end_t = end_t;
                            info.rc = rc;
                            cmds.push(info);
                        }
                    }
                }
            }
        }
    }

    // close remaining open commands
    while let Some(idx) = open_stack.pop() {
        if cmds[idx].end_t.is_none() {
            let inferred = if last_raw_t > cmds[idx].start_t.unwrap_or(0.0) {
                last_raw_t
            } else {
                cmds[idx].start_t.unwrap_or(0.0) + 0.001
            };
            cmds[idx].end_t = Some(inferred);
        }
    }

    // build summaries
    let mut summaries: Vec<CmdSummary> = Vec::new();
    for c in cmds {
        let start_t = c.start_t.unwrap_or(0.0);
        let end_t = c.end_t;
        let duration = end_t.map(|e| if e >= start_t { e - start_t } else { 0.0 });
        let duration_human = duration.map(|d| {
            if d >= 1.0 {
                format!("{:.3}s", d)
            } else if d >= 0.001 {
                format!("{:.0}ms", d * 1000.0)
            } else {
                format!("{:.0}µs", d * 1_000_000.0)
            }
        });
        let secs = start_t.trunc() as i64;
        let nanos = ((start_t.fract()) * 1_000_000_000.0).round() as u32;
        let start_dt = Utc
            .timestamp_opt(secs, nanos)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap());
        let start_iso = start_dt.to_rfc3339();
        let cmd = c.cmd_b64.map(|b| {
            general_purpose::STANDARD
                .decode(b)
                .ok()
                .map(|bb| String::from_utf8_lossy(&bb).to_string())
                .unwrap_or_default()
        });
        summaries.push(CmdSummary {
            start_iso,
            start_t,
            end_t,
            duration_s: duration,
            duration_human,
            cwd: c.cwd,
            cmd,
            rc: c.rc,
            output_bytes: c.output_bytes,
            output_snippet: c.output_snippet.replace('\n', "\\n"),
        });
    }

    // write JSON array
    let out_file = File::create(&out).context("create json output")?;
    serde_json::to_writer_pretty(out_file, &summaries)?;
    println!("JSON exported to {}", out.display());
    Ok(())
}

/// Start a TCP server that spawns a shell and shares its PTY with connected clients.
pub fn serve(port: u16, verbose: bool) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    if verbose {
        println!("Starting nex serve on {}", addr);
    }
    let listener = TcpListener::bind(&addr).context("bind")?;
    listener.set_nonblocking(true).ok();

    // spawn a pty-backed shell similar to start(), but we won't record.
    let pty_system = NativePtySystem::default();
    let pair = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;
    let shell_path = std::env::var("SHELL").unwrap_or("/bin/sh".into());
    let cmd_builder = CommandBuilder::new(shell_path.clone());
    let mut child = pair.slave.spawn_command(cmd_builder)?;

    let mut reader = pair.master.try_clone_reader()?;
    let mut writer = pair.master.try_clone_writer()?;

    // track connected clients (declare before threads that use it)
    let clients = Arc::new(Mutex::new(Vec::<TcpStream>::new()));

    // enable raw mode on server host so we can forward per-keystroke input
    let _ = enable_raw_mode();

    // forward local stdin to PTY (so server host keystrokes go into the shared PTY)
    // NOTE: we intentionally do NOT broadcast local keystrokes to connected clients.
    // The PTY will echo characters and the PTY-read -> broadcast thread will
    // deliver the canonical output to all clients, preventing duplicate characters
    // and making the PTY the single source of truth for the shared input buffer.
    let mut writer_clone = pair.master.try_clone_writer()?;
    thread::spawn(move || {
        let mut stdin = stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = writer_clone.write_all(&buf[..n]) {
                        eprintln!("failed writing to pty: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("stdin read error: {}", e);
                    break;
                }
            }
        }
    });

    // accept loop
    let clients_accept = clients.clone();
    thread::spawn(move || loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                if verbose {
                    println!("client connected: {}", addr);
                }
                stream.set_nonblocking(true).ok();
                clients_accept.lock().unwrap().push(stream);
            }
            Err(_) => {
                // no incoming connection right now
                thread::sleep(Duration::from_millis(100));
            }
        }
    });

    // read PTY and broadcast to clients
    let clients_bcast = clients.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let slice = &buf[..n];
                    // write to stdout locally
                    let _ = stdout().write_all(slice);
                    let _ = stdout().flush();
                    // broadcast to each client, removing any that fail
                    let mut guard = clients_bcast.lock().unwrap();
                    let mut i = 0;
                    while i < guard.len() {
                        match guard[i].write_all(slice) {
                            Ok(()) => {
                                let _ = guard[i].flush();
                                i += 1;
                            }
                            Err(_) => {
                                // remove failing client
                                guard.remove(i);
                            }
                        }
                    }
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });

    // read from clients and forward to PTY
    let clients_read = clients.clone();
    thread::spawn(move || {
        loop {
            let mut remove_idx: Option<usize> = None;
            {
                let mut guard = clients_read.lock().unwrap();
                // iterate in reverse so removal doesn't shift remaining indices
                for i in (0..guard.len()).rev() {
                    let mut buf = [0u8; 1024];
                    match guard[i].read(&mut buf) {
                        Ok(0) => {
                            remove_idx = Some(i);
                            break;
                        }
                        Ok(n) => {
                            // Forward this client's bytes into the shared PTY only.
                            // The PTY will echo and that canonical output will be
                            // broadcast to all participants by the PTY-read thread.
                            if let Err(e) = writer.write_all(&buf[..n]) {
                                eprintln!("failed writing client input to pty: {}", e);
                                remove_idx = Some(i);
                                break;
                            }
                            let _ = writer.flush();
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                // no data right now
                                continue;
                            } else {
                                remove_idx = Some(i);
                                break;
                            }
                        }
                    }
                }
            }
            if let Some(i) = remove_idx {
                clients_read.lock().unwrap().remove(i);
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    // wait for shell to exit
    let status = child.wait()?;
    let _ = disable_raw_mode();
    if verbose {
        println!("shared shell exited: {:?}", status);
    }
    Ok(())
}

/// Connect to a serve() instance and proxy local stdin/stdout
pub fn catch(host: String, port: u16, out: Option<PathBuf>) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    println!("Connecting to {}...", addr);
    let stream = TcpStream::connect(&addr).context("connect")?;
    stream.set_nonblocking(true).ok();
    // create a temporary JSON-lines recording for session events
    let recording_file = File::create(RECORDING_PATH).context("create tmp recording")?;
    let recording = Arc::new(Mutex::new(recording_file));

    // spawn thread to read from stream and write to stdout AND record events
    let mut s_read = stream.try_clone()?;
    let rec_clone = recording.clone();
    let marker_buf = Arc::new(Mutex::new(String::new()));
    let marker_clone = marker_buf.clone();
    // enable raw mode on client so local keystrokes aren't echoed locally
    let _ = enable_raw_mode();
    let start_instant = Instant::now();
    thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match s_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    // process incoming bytes: detect markers and write non-marker bytes to stdout
                    let s = String::from_utf8_lossy(&buf[..n]).to_string();
                    let mut mb = marker_clone.lock().unwrap();
                    mb.push_str(&s);

                    let mut written_bytes: Vec<u8> = Vec::new();

                    loop {
                        if let Some(start_idx) = mb.find("\x1f__NEX_CMD_") {
                            // write text before marker
                            if start_idx > 0 {
                                let before = mb.drain(..start_idx).collect::<String>();
                                let before_bytes = before.as_bytes();
                                let _ = stdout().write_all(before_bytes);
                                let _ = stdout().flush();
                                written_bytes.extend_from_slice(before_bytes);
                            }
                            if let Some(nl_pos) = mb.find('\n') {
                                let marker_line: String = mb.drain(..=nl_pos).collect();
                                // process marker line and write corresponding command event into recording
                                if marker_line.contains("__NEX_CMD_START__") {
                                    if let Some(idx) = marker_line.find("__NEX_CMD_START__") {
                                        let payload =
                                            &marker_line[idx + "__NEX_CMD_START__".len()..].trim();
                                        let parts: Vec<&str> = payload.splitn(3, '|').collect();
                                        if parts.len() == 3 {
                                            let ct: f64 = parts[0].parse().unwrap_or(0.0);
                                            let cwd = parts[1].to_string();
                                            let cmd_b64 = parts[2].trim().to_string();
                                            let cmd_ev = serde_json::json!({
                                                "type": "command",
                                                "phase": "start",
                                                "t": ct,
                                                "cwd": cwd,
                                                "cmd_b64": cmd_b64,
                                            });
                                            let mut f = rec_clone.lock().unwrap();
                                            let _ = f.write_all(cmd_ev.to_string().as_bytes());
                                            let _ = f.write_all(b"\n");
                                            let _ = f.flush();
                                        }
                                    }
                                } else if marker_line.contains("__NEX_CMD_END__") {
                                    if let Some(idx) = marker_line.find("__NEX_CMD_END__") {
                                        let payload =
                                            &marker_line[idx + "__NEX_CMD_END__".len()..].trim();
                                        let parts: Vec<&str> = payload.splitn(2, '|').collect();
                                        if parts.len() == 2 {
                                            let ct: f64 = parts[0].parse().unwrap_or(0.0);
                                            let rc: i32 = parts[1].trim().parse().unwrap_or(0);
                                            let cmd_ev = serde_json::json!({
                                                "type": "command",
                                                "phase": "end",
                                                "t": ct,
                                                "rc": rc,
                                            });
                                            let mut f = rec_clone.lock().unwrap();
                                            let _ = f.write_all(cmd_ev.to_string().as_bytes());
                                            let _ = f.write_all(b"\n");
                                            let _ = f.flush();
                                        }
                                    }
                                }
                                continue;
                            } else {
                                break;
                            }
                        } else {
                            if !mb.is_empty() {
                                let before = mb.drain(..).collect::<String>();
                                let before_bytes = before.as_bytes();
                                let _ = stdout().write_all(before_bytes);
                                let _ = stdout().flush();
                                written_bytes.extend_from_slice(before_bytes);
                            }
                            break;
                        }
                    }

                    // record JSON-line event with timestamp for cleaned bytes (excluding markers)
                    if !written_bytes.is_empty() {
                        let t = start_instant.elapsed().as_secs_f64();
                        let data_b64 = general_purpose::STANDARD.encode(&written_bytes);
                        let ev = Event { t, data: data_b64 };
                        if let Ok(line) = serde_json::to_string(&ev) {
                            let mut f = rec_clone.lock().unwrap();
                            let _ = f.write_all(line.as_bytes());
                            let _ = f.write_all(b"\n");
                            let _ = f.flush();
                        }
                    }
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });

    // forward stdin to stream
    let mut s_write = stream;
    let mut stdin = stdin();
    let mut buf = [0u8; 1024];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(_) = s_write.write_all(&buf[..n]) {
                    // connection likely closed; break to finalize recording
                    break;
                }
                let _ = s_write.flush();
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    // finalize recording: read temp JSON-lines events and write to recording.nex
    let _ = disable_raw_mode();
    println!("Connection closed; finalizing recording...");

    let mut events_json = String::new();
    let mut tmp = File::open(RECORDING_PATH).context("open tmp recording")?;
    tmp.read_to_string(&mut events_json)
        .context("read tmp events")?;

    // compute duration from last event
    let mut duration = None;
    if let Some(last_line) = events_json.lines().last() {
        if let Ok(ev) = serde_json::from_str::<Event>(last_line) {
            duration = Some(ev.t);
        }
    }

    let manifest = Manifest {
        version: "1.0".into(),
        created_at: Utc::now(),
        recorder_version: "0.2".into(),
        duration_seconds: duration,
    };

    let out = out.unwrap_or_else(|| PathBuf::from("recording.nex"));
    let out_file = File::create(&out).context("create output file")?;
    let mut zip = zip::ZipWriter::new(out_file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("manifest.json", options).unwrap();
    let m = serde_json::to_vec(&manifest).unwrap();
    zip.write_all(&m).unwrap();

    zip.start_file("session.json", options).unwrap();
    zip.write_all(events_json.as_bytes()).unwrap();

    zip.finish().unwrap();

    let _ = fs::remove_file(RECORDING_PATH);
    println!("Recorded to {}", out.display());
    Ok(())
}
