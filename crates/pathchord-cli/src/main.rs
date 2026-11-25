use std::process::ExitCode;

use clap::Parser;
use pathchord_cli::{Cli, Command, DiagnosticLevel, DiagnosticRole, log_service_event, run};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let role = match &cli.command {
        Command::Ingress(_) => Some(DiagnosticRole::Ingress),
        Command::Egress(_) => Some(DiagnosticRole::Egress),
        _ => None,
    };
    match run(cli).await {
        Ok(()) => {
            if let Some(role) = role {
                log_service_event(role, DiagnosticLevel::Info, "service_stopped", None);
            }
            ExitCode::SUCCESS
        },
        Err(error) => {
            if let Some(role) = role {
                log_service_event(role, DiagnosticLevel::Fatal, "service_failed", Some(error.service_failure_reason()));
            } else {
                eprintln!("pathchord: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
