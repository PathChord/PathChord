use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand};
use getrandom::fill;
use pathchord_control::{
    Actor, ErrorCode, GenerationExpectation, LocalProtocolError, RequestEnvelope, ResponseEnvelope,
    read_object, write_object,
};
use pathchord_noise::{StaticKeypair, generate_static_keypair};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(not(windows))]
const DEFAULT_INGRESS_SOCKET: &str = "/run/pathchord/ingress.sock";
#[cfg(windows)]
const DEFAULT_INGRESS_SOCKET: &str = r"\\.\pipe\pathchord-ingress";
#[cfg(not(windows))]
const DEFAULT_EGRESS_SOCKET: &str = "/run/pathchord/egress.sock";
#[cfg(windows)]
const DEFAULT_EGRESS_SOCKET: &str = r"\\.\pipe\pathchord-egress";
const IDENTITY_FILE_HEADER: &[u8] = b"PATHCHORD-IDENTITY-V1\n";

#[derive(Debug, Parser)]
#[command(
    name = "pathchordctl",
    version,
    about = "PathChord local management client"
)]
struct Cli {
    /// Local Unix socket or Windows Named Pipe. Defaults by operation.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Requested actor; local control assigns the authenticated OS owner.
    #[arg(long, global = true, default_value = "local-admin")]
    actor: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Query local runtime status.
    Status,
    /// Manage the Windows system-proxy switch.
    #[command(subcommand)]
    SystemProxy(SystemProxyCommand),
    /// Manage Egress authorization records.
    Enroll(EnrollmentArgs),
    /// Generate a local static identity file and print its public key.
    Keygen(KeygenArgs),
}

#[derive(Debug, Subcommand)]
enum SystemProxyCommand {
    Enable(SystemProxyEnableArgs),
    Disable,
}

#[derive(Debug, Args)]
struct SystemProxyEnableArgs {
    #[arg(long)]
    listener_id: String,
}

#[derive(Debug, Args)]
struct EnrollmentArgs {
    #[command(subcommand)]
    command: EnrollmentCommand,
}

#[derive(Debug, Subcommand)]
enum EnrollmentCommand {
    List,
    Get(EnrollmentGetArgs),
    Add(EnrollmentAddArgs),
    Enable(EnrollmentMutationArgs),
    Disable(EnrollmentMutationArgs),
    Revoke(EnrollmentMutationArgs),
    Delete(EnrollmentMutationArgs),
}

#[derive(Debug, Args)]
struct EnrollmentGetArgs {
    #[arg(long)]
    ingress_id: String,
}

#[derive(Debug, Args)]
struct EnrollmentAddArgs {
    #[arg(long)]
    ingress_id: String,
    #[arg(long)]
    egress_id: String,
    #[arg(long, allow_hyphen_values = true)]
    public_key: String,
    #[arg(long)]
    expected_generation: u64,
    #[arg(long = "label", value_name = "KEY=VALUE")]
    labels: Vec<String>,
}

#[derive(Debug, Args)]
struct EnrollmentMutationArgs {
    #[arg(long)]
    ingress_id: String,
    #[arg(long)]
    expected_generation: u64,
}

#[derive(Debug, Args)]
struct KeygenArgs {
    #[arg(long)]
    output: PathBuf,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
enum CliError {
    #[error("local control protocol failed: {0}")]
    LocalProtocol(#[from] LocalProtocolError),
    #[error("local control transport is unsupported on {platform}")]
    UnsupportedTransport { platform: &'static str },
    #[error("local control request failed: {code:?}: {message}")]
    Remote { code: ErrorCode, message: String },
    #[error("request ID generation failed: {0}")]
    RequestId(String),
    #[error("invalid administrator label `{label}`; expected KEY=VALUE with a non-empty key")]
    InvalidLabel { label: String },
    #[error("JSON output failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("identity file I/O failed: {0}")]
    IdentityIo(#[from] std::io::Error),
    #[error("Noise identity operation failed: {0}")]
    Noise(#[from] pathchord_noise::NoiseError),
    #[error("configuration generation is missing from the service status")]
    MissingGeneration,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pathchordctl: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    let Cli {
        socket,
        actor,
        command,
    } = cli;
    let explicit_socket = socket.clone();
    let socket = socket.unwrap_or_else(|| match &command {
        Command::Enroll(_) => default_socket("egress.sock", DEFAULT_EGRESS_SOCKET),
        _ => default_socket("ingress.sock", DEFAULT_INGRESS_SOCKET),
    });
    match command {
        Command::Status => print_response(call_local(&socket, status_request(actor)).await?),
        Command::SystemProxy(SystemProxyCommand::Enable(args)) => {
            let generation = local_configuration_generation(&socket, &actor).await?;
            let mut request = system_proxy_enable_request(actor, args.listener_id);
            request.expected_generation = Some(GenerationExpectation {
                scope: "configuration".to_owned(),
                value: generation,
            });
            print_response(call_local(&socket, request).await?)
        }
        Command::SystemProxy(SystemProxyCommand::Disable) => {
            let generation = local_configuration_generation(&socket, &actor).await?;
            let mut request = system_proxy_disable_request(actor);
            request.expected_generation = Some(GenerationExpectation {
                scope: "configuration".to_owned(),
                value: generation,
            });
            print_response(call_local(&socket, request).await?)
        }
        Command::Enroll(args) => {
            let socket = explicit_socket
                .unwrap_or_else(|| default_socket("egress.sock", DEFAULT_EGRESS_SOCKET));
            run_enrollment(&socket, actor, args.command).await
        }
        Command::Keygen(args) => run_keygen(args),
    }
}

fn default_socket(name: &str, service_default: &str) -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .map(|runtime| PathBuf::from(runtime).join("pathchord").join(name))
        .unwrap_or_else(|| PathBuf::from(service_default))
}

fn status_request(actor: impl Into<String>) -> RequestEnvelope {
    request(
        "status.get",
        actor,
        serde_json::json!({}),
        vec!["status:read"],
    )
}

fn system_proxy_enable_request(actor: impl Into<String>, listener_id: String) -> RequestEnvelope {
    request(
        "system_proxy.enable",
        actor,
        serde_json::json!({"listener_id": listener_id}),
        vec!["system_proxy:write"],
    )
}

fn system_proxy_disable_request(actor: impl Into<String>) -> RequestEnvelope {
    request(
        "system_proxy.disable",
        actor,
        serde_json::json!({}),
        vec!["system_proxy:write"],
    )
}

fn run_enrollment_request(
    actor: String,
    command: EnrollmentCommand,
) -> Result<RequestEnvelope, CliError> {
    Ok(match command {
        EnrollmentCommand::List => request(
            "authorizations.list",
            actor,
            serde_json::json!({}),
            vec!["status:read"],
        ),
        EnrollmentCommand::Get(args) => request(
            "authorizations.get",
            actor,
            serde_json::json!({"ingress_id": args.ingress_id}),
            vec!["status:read"],
        ),
        EnrollmentCommand::Add(args) => request_with_generation(
            "authorizations.enroll",
            actor,
            serde_json::json!({
                "ingress_id": args.ingress_id,
                "egress_id": args.egress_id,
                "public_key": args.public_key,
                "administrator_labels": parse_labels(args.labels)?,
            }),
            vec!["authorization:write"],
            args.expected_generation,
        ),
        EnrollmentCommand::Enable(args) => {
            authorization_mutation("authorizations.enable", actor, args)
        }
        EnrollmentCommand::Disable(args) => {
            authorization_mutation("authorizations.disable", actor, args)
        }
        EnrollmentCommand::Revoke(args) => {
            authorization_mutation("authorizations.revoke", actor, args)
        }
        EnrollmentCommand::Delete(args) => {
            authorization_mutation("authorizations.delete", actor, args)
        }
    })
}

async fn run_enrollment(
    socket: &Path,
    actor: String,
    command: EnrollmentCommand,
) -> Result<(), CliError> {
    let request = run_enrollment_request(actor, command)?;
    print_response(call_local(socket, request).await?)
}

fn authorization_mutation(
    operation: &str,
    actor: String,
    args: EnrollmentMutationArgs,
) -> RequestEnvelope {
    request_with_generation(
        operation,
        actor,
        serde_json::json!({"ingress_id": args.ingress_id}),
        vec!["authorization:write"],
        args.expected_generation,
    )
}

fn request(
    operation: &str,
    actor: impl Into<String>,
    body: Value,
    capabilities: Vec<&str>,
) -> RequestEnvelope {
    RequestEnvelope {
        api_version: pathchord_control::LOCAL_API_VERSION.to_owned(),
        operation: operation.to_owned(),
        request_id: request_id().unwrap_or_else(|_| "request-id-generation-failed".to_owned()),
        actor: Actor {
            id: actor.into(),
            capabilities: capabilities.into_iter().map(str::to_owned).collect(),
        },
        expected_generation: None,
        body,
    }
}

fn request_with_generation(
    operation: &str,
    actor: impl Into<String>,
    body: Value,
    capabilities: Vec<&str>,
    generation: u64,
) -> RequestEnvelope {
    let mut request = request(operation, actor, body, capabilities);
    request.expected_generation = Some(GenerationExpectation {
        scope: "authorization".to_owned(),
        value: generation,
    });
    request
}

fn parse_labels(
    labels: Vec<String>,
) -> Result<std::collections::BTreeMap<String, String>, CliError> {
    let mut parsed = std::collections::BTreeMap::new();
    for label in labels {
        let (key, value) = label
            .split_once('=')
            .ok_or_else(|| CliError::InvalidLabel {
                label: label.clone(),
            })?;
        if key.is_empty() || parsed.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(CliError::InvalidLabel { label });
        }
    }
    Ok(parsed)
}

fn request_id() -> Result<String, CliError> {
    let mut bytes = [0_u8; 16];
    fill(&mut bytes).map_err(|error| CliError::RequestId(error.to_string()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

async fn local_configuration_generation(socket: &Path, actor: &str) -> Result<u64, CliError> {
    let response = call_local(socket, status_request(actor)).await?;
    if let Some(error) = response.error {
        return Err(CliError::Remote {
            code: error.code,
            message: error.message,
        });
    }
    response
        .result
        .and_then(|result| {
            result
                .get("configuration_generation")
                .and_then(Value::as_u64)
        })
        .ok_or(CliError::MissingGeneration)
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

fn run_keygen(args: KeygenArgs) -> Result<(), CliError> {
    let identity = generate_static_keypair()?;
    write_identity(&args.output, &identity)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "public_key": URL_SAFE_NO_PAD.encode(identity.public()),
        }))?
    );
    Ok(())
}

fn write_identity(path: &Path, identity: &StaticKeypair) -> Result<(), CliError> {
    let encoded_private = Zeroizing::new(URL_SAFE_NO_PAD.encode(identity.private()));
    let mut contents = Zeroizing::new(Vec::new());
    contents.extend_from_slice(IDENTITY_FILE_HEADER);
    contents.extend_from_slice(encoded_private.as_bytes());
    contents.push(b'\n');
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
async fn call_local(socket: &Path, request: RequestEnvelope) -> Result<ResponseEnvelope, CliError> {
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(LocalProtocolError::from)?;
    write_object(&mut stream, &request).await?;
    Ok(read_object(&mut stream).await?)
}

#[cfg(windows)]
async fn call_local(socket: &Path, request: RequestEnvelope) -> Result<ResponseEnvelope, CliError> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let mut pipe = ClientOptions::new()
        .open(socket)
        .map_err(LocalProtocolError::from)?;
    write_object(&mut pipe, &request).await?;
    Ok(read_object(&mut pipe).await?)
}

#[cfg(not(any(unix, windows)))]
async fn call_local(
    _socket: &Path,
    _request: RequestEnvelope,
) -> Result<ResponseEnvelope, CliError> {
    Err(CliError::UnsupportedTransport {
        platform: std::env::consts::OS,
    })
}
