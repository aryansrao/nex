use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod recorder;

#[derive(Parser)]
#[command(name = "nex")]
#[command(about = "Terminal recorder (.nex)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start {
        /// Output file (defaults to recording.nex)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    Stop,
    Inspect {
        file: PathBuf,
    },
    Play {
        file: PathBuf,
        /// Show command start/end events during playback
        #[arg(long)]
        show_commands: bool,
    },
    Csv {
        file: PathBuf,
        /// Output CSV file path (defaults to recording.csv)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    Json {
        file: PathBuf,
        /// Output JSON file path (defaults to recording.json)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Start a collaborative session server on the given port
    Serve {
        /// TCP port to listen on
        port: u16,
        /// Show startup and client connection messages (disabled by default)
        #[arg(short, long)]
        verbose: bool,
        /// Serve a simple web UI (HTTP + WebSocket) on the same port
        #[arg(long)]
        web: bool,
    },
    /// Connect to a collaborative session server
    Catch {
        /// Host to connect to
        host: String,
        /// TCP port
        port: u16,
        /// Output .nex file path (defaults to recording.nex in the current directory)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start { out } => recorder::start(out),
        Commands::Stop => recorder::stop(),
        Commands::Inspect { file } => recorder::inspect(file),
        Commands::Play {
            file,
            show_commands,
        } => recorder::play(file, show_commands),
        Commands::Csv { file, out } => recorder::export_csv(file, out),
        Commands::Json { file, out } => recorder::export_json(file, out),
    Commands::Serve { port, verbose, web } => recorder::serve(port, verbose, web),
        Commands::Catch { host, port, out } => recorder::catch(host, port, out),
    }
}
