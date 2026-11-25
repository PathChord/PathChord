use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use pathchord_cli::{
    DiagnosticLevel, DiagnosticRole, IngressArgs, log_service_event, run_ingress_service,
};

#[derive(Debug, Parser)]
#[command(
    name = "pathchord-ingressd",
    version,
    about = "PathChord Ingress service"
)]
struct Cli {
    /// Local Unix socket or platform control endpoint.
    #[arg(long)]
    socket: Option<PathBuf>,
    #[command(flatten)]
    args: IngressArgs,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Cli { socket, args } = Cli::parse();
    let result = run_ingress_service(socket, args).await;
    match result {
        Ok(()) => {
            log_service_event(
                DiagnosticRole::Ingress,
                DiagnosticLevel::Info,
                "service_stopped",
                None,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            log_service_event(
                DiagnosticRole::Ingress,
                DiagnosticLevel::Fatal,
                "service_failed",
                Some(error.service_failure_reason()),
            );
            ExitCode::FAILURE
        }
    }
}
