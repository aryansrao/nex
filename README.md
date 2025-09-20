# nex - terminal recorder & sharing

This project contains a Rust CLI `nex` that records terminal sessions into `.nex` files.

Commands (MVP):
- `nex start` — start recording the current shell session
- `nex stop` — stop recording and finalize the `.nex` file
- `nex inspect <file.nex>` — view metadata
- `nex play <file.nex>` — replay recorded session (TBD)

This scaffold implements a minimal MVP for start/stop using a PTY-based approach in Rust.

Build:

```bash
cargo build --release
# nex — terminal session recorder

nex records interactive terminal sessions into a portable `.nex` archive. It can:

- Record a local interactive shell to a `.nex` file (`nex start` / `nex stop`).
- Replay a `.nex` (`nex play <file>`).
- Export recorded sessions to CSV or JSON (`nex csv <file>`, `nex json <file>`).
- Serve a shared shell over TCP for collaborative sessions (`nex serve <port>`).
- Join a shared session as a client and auto-save the session (`nex catch <host> <port>`).

This project is a small Rust prototype. It uses a PTY-backed shell and records raw terminal bytes plus command lifecycle markers (injected via zsh hooks) into a newline-delimited JSON stream inside the `.nex` archive.

## Quickstart

Build:

```bash
cargo build --release
```

Record locally (default timestamped filename):

```bash
./target/release/nex start
# exit the spawned shell to finalize and save recording-<timestamp>.nex
```

Replay:

```bash
./target/release/nex play recording-<timestamp>.nex
```

CSV / JSON export:

```bash
./target/release/nex csv recording-<timestamp>.nex --out out.csv
./target/release/nex json recording-<timestamp>.nex --out out.json
```

Collaborative session (host):

```bash
./target/release/nex serve 3000           # silent by default
./target/release/nex serve 3000 --verbose # show connect/exits
```

Collaborative session (client):

```bash
./target/release/nex catch <host-ip> 3000 --out mysession.nex
```


## Recording format

A `.nex` file is a ZIP archive containing:

- `manifest.json` — metadata and duration
- `session.json` — newline-delimited JSON events (raw terminal bytes and command start/end objects)

Raw event example:

```json
{"t": 0.123, "data": "<base64>"}
```

Command event example:

```json
{"type":"command","phase":"start","t": 1234567890.123,"cwd":"/home/user","cmd_b64":"..."}
```

