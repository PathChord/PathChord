//! Bootstrap command surface for the future local management client.

use clap::{Parser, Subcommand};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(name = "pathchord", version, about = "PathChord management client")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Run the Ingress service.
    Ingress,
    /// Run the Egress service.
    Egress,
    /// Query local runtime status.
    Status,
    /// Manage explicit endpoint enrollment.
    Enroll,
}

impl Command {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
            Self::Status => "status",
            Self::Enroll => "enroll",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapError {
    #[error("command `{command}` is defined but not implemented in the Phase 0 bootstrap")]
    NotImplemented { command: &'static str },
}

pub fn run(cli: Cli) -> Result<(), BootstrapError> {
    Err(BootstrapError::NotImplemented {
        command: cli.command.name(),
    })
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;

    use super::*;

    #[test]
    fn exposes_all_planned_commands() {
        for (name, command) in [
            ("ingress", Command::Ingress),
            ("egress", Command::Egress),
            ("status", Command::Status),
            ("enroll", Command::Enroll),
        ] {
            let parsed = Cli::try_parse_from(["pathchord", name]).expect("known command");
            assert_eq!(parsed.command, command);
        }
    }

    #[test]
    fn commands_fail_explicitly_until_the_management_api_exists() {
        let error = run(Cli {
            command: Command::Status,
        })
        .expect_err("bootstrap command must not pretend to operate");

        assert_eq!(error, BootstrapError::NotImplemented { command: "status" });
    }

    #[test]
    fn help_is_rendered_by_clap() {
        let error = Cli::try_parse_from(["pathchord", "--help"]).expect_err("help exits early");
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
    }
}
