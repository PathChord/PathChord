//! Local management client for the PathChord control plane.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use getrandom::fill;
use pathchord_ingress::{
    Actor, ErrorCode, LOCAL_API_VERSION, LocalProtocolError, RequestEnvelope, ResponseEnvelope,
    read_object, write_object,
};
use serde_json::Value;
use thiserror::Error;

/// Default local control endpoint on Unix hosts.
pub const DEFAULT_SOCKET_PATH: &str = "/run/pathchord/ingress.sock";

#[derive(Debug, Parser)]
#[command(name = "pathchord", version, about = "PathChord management client")]
pub struct Cli {
    /// Local Unix socket or platform control endpoint.
    #[arg(long, global = true, default_value = DEFAULT_SOCKET_PATH)]
    pub socket: PathBuf,
    /// Actor identity attached to local control requests.
    #[arg(long, global = true, default_value = "local-admin")]
    pub actor: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Run the Ingress service.
    Ingress,
    /// Run the Egress service.
    Egress,
    /// Query local runtime status.
    Status,
    /// Manage the Windows system-proxy control-plane switch.
    #[command(subcommand)]
    SystemProxy(SystemProxyCommand),
    /// Manage explicit endpoint enrollment.
    Enroll,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum SystemProxyCommand {
    /// Enable system proxy using an existing HTTP or SOCKS listener.
    Enable(SystemProxyEnableArgs),
    /// Restore the previous system-proxy state.
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct SystemProxyEnableArgs {
    /// Listener ID to use as the system-proxy endpoint.
    #[arg(long)]
    pub listener_id: String,
}

impl Command {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
            Self::Status => "status",
            Self::SystemProxy(SystemProxyCommand::Enable(_)) => "system-proxy enable",
            Self::SystemProxy(SystemProxyCommand::Disable) => "system-proxy disable",
            Self::Enroll => "enroll",
        }
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("command `{command}` is not implemented yet")]
    NotImplemented { command: &'static str },
    #[error("local control protocol failed: {0}")]
    LocalProtocol(#[from] LocalProtocolError),
    #[error("local control transport is unsupported on {platform}")]
    UnsupportedTransport { platform: &'static str },
    #[error("local control request failed: {code:?}: {message}")]
    Remote { code: ErrorCode, message: String },
    #[error("request ID generation failed: {0}")]
    RequestId(String),
    #[error("JSON output failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn status_request(actor: impl Into<String>) -> RequestEnvelope {
    request(
        "status.get",
        actor,
        serde_json::json!({}),
        vec!["status:read"],
    )
}

pub fn system_proxy_enable_request(
    actor: impl Into<String>,
    listener_id: impl Into<String>,
) -> RequestEnvelope {
    request(
        "system_proxy.enable",
        actor,
        serde_json::json!({"listener_id": listener_id.into()}),
        vec!["system_proxy:write"],
    )
}

pub fn system_proxy_disable_request(actor: impl Into<String>) -> RequestEnvelope {
    request(
        "system_proxy.disable",
        actor,
        serde_json::json!({}),
        vec!["system_proxy:write"],
    )
}

fn request(
    operation: &str,
    actor: impl Into<String>,
    body: Value,
    capabilities: Vec<&str>,
) -> RequestEnvelope {
    RequestEnvelope {
        api_version: LOCAL_API_VERSION.to_owned(),
        operation: operation.to_owned(),
        request_id: request_id().unwrap_or_else(|_| "cli-request-id-unavailable".to_owned()),
        actor: Actor {
            id: actor.into(),
            capabilities: capabilities.into_iter().map(str::to_owned).collect(),
        },
        expected_generation: None,
        body,
    }
}

fn request_id() -> Result<String, CliError> {
    let mut bytes = [0_u8; 16];
    fill(&mut bytes).map_err(|error| CliError::RequestId(error.to_string()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub async fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Ingress | Command::Egress | Command::Enroll => Err(CliError::NotImplemented {
            command: cli.command.name(),
        }),
        Command::Status => {
            let response = call_unix(&cli.socket, status_request(cli.actor)).await?;
            print_response(response)
        }
        Command::SystemProxy(SystemProxyCommand::Enable(args)) => {
            let response = call_unix(
                &cli.socket,
                system_proxy_enable_request(cli.actor, args.listener_id),
            )
            .await?;
            print_response(response)
        }
        Command::SystemProxy(SystemProxyCommand::Disable) => {
            let response = call_unix(&cli.socket, system_proxy_disable_request(cli.actor)).await?;
            print_response(response)
        }
    }
}

fn print_response(response: ResponseEnvelope) -> Result<(), CliError> {
    if !response.ok
        && let Some(error) = response.error
    {
        return Err(CliError::Remote {
            code: error.code,
            message: error.message,
        });
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

#[cfg(unix)]
async fn call_unix(
    socket: &std::path::Path,
    request: RequestEnvelope,
) -> Result<ResponseEnvelope, CliError> {
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(LocalProtocolError::from)?;
    write_object(&mut stream, &request).await?;
    Ok(read_object(&mut stream).await?)
}

#[cfg(not(unix))]
async fn call_unix(
    _socket: &std::path::Path,
    _request: RequestEnvelope,
) -> Result<ResponseEnvelope, CliError> {
    Err(CliError::UnsupportedTransport {
        platform: std::env::consts::OS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_status_with_global_socket_and_actor() {
        let cli = Cli::try_parse_from([
            "pathchord",
            "--socket",
            "/tmp/ingress.sock",
            "--actor",
            "operator",
            "status",
        ])
        .expect("status args");
        assert_eq!(cli.socket, PathBuf::from("/tmp/ingress.sock"));
        assert_eq!(cli.actor, "operator");
        assert_eq!(cli.command, Command::Status);
    }

    #[test]
    fn parses_system_proxy_commands() {
        let enable = Cli::try_parse_from([
            "pathchord",
            "system-proxy",
            "enable",
            "--listener-id",
            "local-http",
        ])
        .expect("enable args");
        assert!(matches!(
            enable.command,
            Command::SystemProxy(SystemProxyCommand::Enable(SystemProxyEnableArgs {
                listener_id
            })) if listener_id == "local-http"
        ));

        let disable =
            Cli::try_parse_from(["pathchord", "system-proxy", "disable"]).expect("disable args");
        assert_eq!(
            disable.command,
            Command::SystemProxy(SystemProxyCommand::Disable)
        );
    }

    #[test]
    fn request_builders_use_registered_operation_names_and_capabilities() {
        let status = status_request("operator");
        assert_eq!(status.operation, "status.get");
        assert_eq!(status.actor.capabilities, vec!["status:read"]);

        let enable = system_proxy_enable_request("operator", "local-http");
        assert_eq!(enable.operation, "system_proxy.enable");
        assert_eq!(enable.body["listener_id"], "local-http");
        assert_eq!(enable.actor.capabilities, vec!["system_proxy:write"]);

        let disable = system_proxy_disable_request("operator");
        assert_eq!(disable.operation, "system_proxy.disable");
    }
}
