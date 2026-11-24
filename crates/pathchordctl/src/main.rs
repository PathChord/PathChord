mod config;

use pathchord_config::{Role, RoleLayout, SelectedSource};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use getrandom::fill;
use pathchord_control::{
    Actor, ErrorCode, GenerationExpectation, LocalProtocolError, RequestEnvelope, ResponseEnvelope,
    read_object, write_object,
};
use pathchord_noise::{StaticKeypair, generate_static_keypair};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

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
    #[arg(short, long, global = true, value_enum, default_value = "human")]
    output: Output,
    #[arg(short, long, global = true, conflicts_with = "config_dir")]
    config: Option<PathBuf>,
    #[arg(short = 'C', long, global = true, conflicts_with = "config")]
    config_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize, validate, or edit local configuration.
    Config(config::ConfigArgs),
    /// List local management resources.
    #[command(subcommand)]
    Get(GetCommand),
    /// Show details for a local management resource.
    #[command(subcommand)]
    Describe(DescribeCommand),
    /// Query local runtime status.
    Status,
    /// Query retained runtime diagnostics.
    Diagnostics,
    /// Export retained runtime diagnostics to a bounded JSON file.
    ExportDiagnostics(ExportDiagnosticsArgs),
    /// Manage the Windows system-proxy switch.
    #[command(subcommand)]
    SystemProxy(SystemProxyCommand),
    /// Manage Egress authorization records.
    Enroll(EnrollmentArgs),
    /// Generate a local static identity file and print its public key.
    Keygen(KeygenArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Output {
    Human,
    Json,
    Yaml,
}

#[derive(Debug, Subcommand)]
enum GetCommand {
    Status,
    Diagnostics,
    Enrollments,
}

#[derive(Debug, Subcommand)]
enum DescribeCommand {
    Status,
    Enrollment { ingress_id: String },
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
    egress_id: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    public_key: String,
    #[arg(long)]
    expected_generation: Option<u64>,
    #[arg(long = "label", value_name = "KEY=VALUE")]
    labels: Vec<String>,
}

#[derive(Debug, Args)]
struct EnrollmentMutationArgs {
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    ingress_id: String,
    #[arg(long)]
    expected_generation: Option<u64>,
}

#[derive(Debug, Args)]
struct ExportDiagnosticsArgs {
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct KeygenArgs {
    #[arg(long)]
    identity_file: PathBuf,
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
    #[error("required metadata is missing from the service status")]
    MissingMetadata,
    #[error("confirmation declined; use --yes for unattended revocation or deletion")]
    Confirmation,
    #[error("could not discover a local {role} endpoint: {details}")]
    Discovery { role: &'static str, details: String },
    #[error("mutation outcome is uncertain at {socket}: {message}")]
    Uncertain { socket: PathBuf, message: String },
    #[error("local control request timed out")]
    Timeout,
    #[error("{0}")]
    Config(String),
    #[error("YAML output failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("local control service returned a malformed response")]
    InvalidResponse,
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
        output,
        config,
        config_dir,
        command,
    } = cli;
    let detailed = matches!(command, Command::Describe(_));
    let command = match command {
        Command::Keygen(args) => return run_keygen(args, output),
        Command::Config(args) => {
            return config::run(
                args,
                output,
                config.as_deref(),
                config_dir.as_deref(),
                socket.as_deref(),
            )
            .await
            .map_err(|error| CliError::Config(error.to_string()));
        }
        Command::Get(GetCommand::Status) => Command::Status,
        Command::Get(GetCommand::Diagnostics) => Command::Diagnostics,
        Command::Get(GetCommand::Enrollments) => Command::Enroll(EnrollmentArgs {
            command: EnrollmentCommand::List,
        }),
        Command::Describe(DescribeCommand::Enrollment { ingress_id }) => {
            Command::Enroll(EnrollmentArgs {
                command: EnrollmentCommand::Get(EnrollmentGetArgs { ingress_id }),
            })
        }
        command => command,
    };
    let role = if matches!(command, Command::Enroll(_)) {
        Role::Egress
    } else {
        Role::Ingress
    };
    let (socket, status) = if let Some(socket) = socket {
        (socket, None)
    } else {
        let (socket, status) =
            discover(role, &actor, config.as_deref(), config_dir.as_deref()).await?;
        (socket, Some(status))
    };
    if let Some(status) = &status
        && !status.ok
    {
        return print_response(status, output, false);
    }
    let response = match command {
        Command::Status | Command::Describe(DescribeCommand::Status) => match status {
            Some(status) => status,
            None => call_local(&socket, status_request(actor)).await?,
        },
        Command::ExportDiagnostics(args) => {
            let response = call_local(
                &socket,
                request(
                    "diagnostics.get",
                    actor,
                    serde_json::json!({"export": true}),
                    vec!["metrics:read"],
                ),
            )
            .await?;
            if !response.ok {
                return print_response(&response, output, false);
            }
            let envelope = serde_json::json!({
                "format_version": 1,
                "collected_at_unix_ms": now_unix_ms(),
                "response": response,
            });
            write_json_file(&args.output, &envelope)?;
            println!("{}", args.output.display());
            return Ok(());
        }
        Command::Diagnostics => {
            call_local(
                &socket,
                request(
                    "diagnostics.get",
                    actor,
                    serde_json::json!({}),
                    vec!["metrics:read"],
                ),
            )
            .await?
        }
        Command::SystemProxy(command) => {
            let status = get_status(&socket, &actor, status).await?;
            if !status.ok {
                return print_response(&status, output, false);
            }
            let generation = field(&status, "configuration_generation")
                .and_then(Value::as_u64)
                .ok_or(CliError::MissingGeneration)?;
            let mut request = match command {
                SystemProxyCommand::Enable(args) => {
                    system_proxy_enable_request(actor, args.listener_id)
                }
                SystemProxyCommand::Disable => system_proxy_disable_request(actor),
            };
            request.expected_generation = Some(GenerationExpectation {
                scope: "configuration".to_owned(),
                value: generation,
            });
            mutate(&socket, request).await?
        }
        Command::Enroll(args) => {
            let mut command = args.command;
            let needed = match &command {
                EnrollmentCommand::Add(args) => {
                    args.egress_id.is_none() || args.expected_generation.is_none()
                }
                EnrollmentCommand::Enable(args)
                | EnrollmentCommand::Disable(args)
                | EnrollmentCommand::Revoke(args)
                | EnrollmentCommand::Delete(args) => args.expected_generation.is_none(),
                EnrollmentCommand::List | EnrollmentCommand::Get(_) => false,
            };
            if needed {
                let status = get_status(&socket, &actor, status).await?;
                if !status.ok {
                    return print_response(&status, output, false);
                }
                let generation = field(&status, "authorization_generation").and_then(Value::as_u64);
                match &mut command {
                    EnrollmentCommand::Add(args) => {
                        args.expected_generation = args.expected_generation.or(generation);
                        if args.egress_id.is_none() {
                            args.egress_id = field(&status, "egress_id")
                                .and_then(Value::as_str)
                                .map(str::to_owned);
                        }
                        if args.egress_id.is_none() {
                            return Err(CliError::MissingMetadata);
                        }
                    }
                    EnrollmentCommand::Enable(args)
                    | EnrollmentCommand::Disable(args)
                    | EnrollmentCommand::Revoke(args)
                    | EnrollmentCommand::Delete(args) => {
                        args.expected_generation = args.expected_generation.or(generation);
                    }
                    _ => {}
                }
            }
            match &command {
                EnrollmentCommand::Revoke(args) => confirm("Revoke", args)?,
                EnrollmentCommand::Delete(args) => confirm("Delete", args)?,
                _ => {}
            }
            let request = run_enrollment_request(actor, command)?;
            if request.expected_generation.is_some() {
                mutate(&socket, request).await?
            } else {
                call_local(&socket, request).await?
            }
        }
        _ => unreachable!("normalized command"),
    };
    print_response(&response, output, detailed)
}

fn confirm(action: &str, args: &EnrollmentMutationArgs) -> Result<(), CliError> {
    if args.yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(CliError::Confirmation);
    }
    eprint!("{action} authorization for {:?}? [y/N] ", args.ingress_id);
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(CliError::Confirmation)
    }
}

async fn get_status(
    socket: &Path,
    actor: &str,
    status: Option<ResponseEnvelope>,
) -> Result<ResponseEnvelope, CliError> {
    match status {
        Some(status) => Ok(status),
        None => call_local(socket, status_request(actor)).await,
    }
}

fn field<'a>(status: &'a ResponseEnvelope, name: &str) -> Option<&'a Value> {
    status.result.as_ref()?.get(name)
}

async fn discover(
    role: Role,
    actor: &str,
    config: Option<&Path>,
    config_dir: Option<&Path>,
) -> Result<(PathBuf, ResponseEnvelope), CliError> {
    let mut failures = Vec::new();
    let mut candidates = Vec::new();
    if let Ok(layout) = RoleLayout::current(role) {
        match configured_socket(role, &layout, config, config_dir).await {
            Ok(Some(socket)) => candidates.push(socket),
            Ok(None) => {}
            Err(error) => failures.push(format!("configuration: {error}")),
        }
        for path in layout.socket_candidates {
            if !candidates.contains(&path) {
                candidates.push(path);
            }
        }
    }
    for socket in candidates {
        match call_local(&socket, status_request(actor)).await {
            Ok(status) if !status.ok => return Ok((socket, status)),
            Ok(status) if (field(&status, "egress_id").is_some()) == (role == Role::Egress) => {
                return Ok((socket, status));
            }
            Ok(_) => failures.push(format!("{}: unexpected service role", socket.display())),
            Err(error) => failures.push(format!("{}: {error}", socket.display())),
        }
    }
    Err(CliError::Discovery {
        role: role.name(),
        details: failures.join("; "),
    })
}

async fn configured_socket(
    role: Role,
    layout: &RoleLayout,
    config: Option<&Path>,
    config_dir: Option<&Path>,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let selected = SelectedSource::resolve(layout, config, config_dir)?;
    if selected.origin == pathchord_config::SourceOrigin::AccountDefault
        && !selected.path.try_exists()?
    {
        return Ok(None);
    }
    let source = selected.bind().await?;
    let loaded = source.load().await?;
    let documents = loaded.documents.iter().map(String::as_str);
    let socket = match role {
        Role::Egress => {
            pathchord_config::parse_egress_service_documents(documents)?
                .spec
                .control_socket
        }
        Role::Ingress => pathchord_policy::KubeConfig::from_documents(documents)?
            .into_policy_config()?
            .ingress_service
            .and_then(|spec| spec.control_socket),
    };
    Ok(socket.map(|path| source.base_directory().join(path)))
}

async fn mutate(socket: &Path, request: RequestEnvelope) -> Result<ResponseEnvelope, CliError> {
    call_local(socket, request)
        .await
        .map_err(|error| CliError::Uncertain {
            socket: socket.to_owned(),
            message: error.to_string(),
        })
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
            args.expected_generation.ok_or(CliError::MissingMetadata)?,
        ),
        EnrollmentCommand::Enable(args) => {
            authorization_mutation("authorizations.enable", actor, args)?
        }
        EnrollmentCommand::Disable(args) => {
            authorization_mutation("authorizations.disable", actor, args)?
        }
        EnrollmentCommand::Revoke(args) => {
            authorization_mutation("authorizations.revoke", actor, args)?
        }
        EnrollmentCommand::Delete(args) => {
            authorization_mutation("authorizations.delete", actor, args)?
        }
    })
}

fn authorization_mutation(
    operation: &str,
    actor: String,
    args: EnrollmentMutationArgs,
) -> Result<RequestEnvelope, CliError> {
    Ok(request_with_generation(
        operation,
        actor,
        serde_json::json!({"ingress_id": args.ingress_id}),
        vec!["authorization:write"],
        args.expected_generation.ok_or(CliError::MissingMetadata)?,
    ))
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

fn now_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn write_json_file(path: &Path, value: &Value) -> Result<(), CliError> {
    let contents = serde_json::to_vec_pretty(value)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&contents)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn print_response(
    response: &ResponseEnvelope,
    output: Output,
    detailed: bool,
) -> Result<(), CliError> {
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(response)?),
        Output::Yaml => print!("{}", serde_yaml::to_string(response)?),
        Output::Human if response.ok => {
            if let Some(result) = &response.result {
                print_human(result, detailed);
            } else {
                println!("OK");
            }
        }
        Output::Human => {}
    }
    if !response.ok {
        let error = response.error.as_ref().ok_or(CliError::InvalidResponse)?;
        let mut message = error.message.clone();
        if error.code == ErrorCode::GenerationConflict {
            use std::fmt::Write as _;
            let _ = write!(
                message,
                " (current generation {})",
                response.observed_generation.value
            );
        }
        return Err(CliError::Remote {
            code: error.code,
            message,
        });
    }
    Ok(())
}

fn display_value(value: Option<&Value>) -> String {
    value.map_or_else(
        || "-".to_owned(),
        |value| match value {
            Value::String(text) => text
                .chars()
                .take(160)
                .flat_map(char::escape_default)
                .collect(),
            Value::Array(items) => format!("{} entries", items.len()),
            Value::Object(_) | Value::Null => "-".to_owned(),
            value => value.to_string(),
        },
    )
}

fn print_human(value: &Value, detailed: bool) {
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        println!("INGRESS ID	EGRESS ID	STATE	GENERATION	LABELS");
        for item in items {
            let fields = ["ingress_id", "egress_id", "state", "generation"]
                .map(|key| display_value(item.get(key)));
            let labels = item
                .get("administrator_labels")
                .and_then(Value::as_object)
                .map(|labels| {
                    labels
                        .iter()
                        .take(8)
                        .map(|(key, value)| format!("{key:?}={}", display_value(Some(value))))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            println!("{}	{labels}", fields.join("	"));
        }
        return;
    }
    let role = if value.get("authorization_generation").is_some() {
        Some("Egress")
    } else if value.get("configuration_generation").is_some() {
        Some("Ingress")
    } else {
        None
    };
    if let Some(role) = role {
        println!("Role: {role}");
        if let Some(state) = value.pointer("/ingress/state") {
            println!("State: {}", display_value(Some(state)));
        }
        if let Some(running) = value.pointer("/runtime/running").and_then(Value::as_bool) {
            println!("State: {}", if running { "running" } else { "stopped" });
        }
        for (field, label) in [
            ("active_paths", "Active Paths"),
            ("active_sessions", "Active Sessions"),
            ("restart_required", "Restart required"),
        ] {
            if let Some(entry) = value.get("runtime").and_then(|runtime| runtime.get(field)) {
                println!("{label}: {}", display_value(Some(entry)));
            }
        }
    }
    if let Some(fields) = value.as_object() {
        for (key, value) in fields {
            if detailed || !value.is_object() {
                println!("{}: {}", key.replace('_', " "), display_value(Some(value)));
            }
        }
    }
}

fn run_keygen(args: KeygenArgs, output: Output) -> Result<(), CliError> {
    let identity = generate_static_keypair()?;
    write_identity(&args.identity_file, &identity)?;
    let key = URL_SAFE_NO_PAD.encode(identity.public());
    let document = serde_json::json!({"public_key": key});
    match output {
        Output::Human => println!("{key}"),
        Output::Json => println!("{}", serde_json::to_string_pretty(&document)?),
        Output::Yaml => print!("{}", serde_yaml::to_string(&document)?),
    }
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

async fn call_local(socket: &Path, request: RequestEnvelope) -> Result<ResponseEnvelope, CliError> {
    let id = request.request_id.clone();
    let response = tokio::time::timeout(Duration::from_secs(5), exchange(socket, request))
        .await
        .map_err(|_| CliError::Timeout)??;
    if response.request_id != id || response.api_version != pathchord_control::LOCAL_API_VERSION {
        return Err(CliError::InvalidResponse);
    }
    Ok(response)
}

#[cfg(unix)]
async fn exchange(socket: &Path, request: RequestEnvelope) -> Result<ResponseEnvelope, CliError> {
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(LocalProtocolError::from)?;
    write_object(&mut stream, &request).await?;
    Ok(read_object(&mut stream).await?)
}

#[cfg(windows)]
async fn exchange(socket: &Path, request: RequestEnvelope) -> Result<ResponseEnvelope, CliError> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let mut pipe = ClientOptions::new()
        .open(socket)
        .map_err(LocalProtocolError::from)?;
    write_object(&mut pipe, &request).await?;
    Ok(read_object(&mut pipe).await?)
}

#[cfg(not(any(unix, windows)))]
async fn exchange(_socket: &Path, _request: RequestEnvelope) -> Result<ResponseEnvelope, CliError> {
    Err(CliError::UnsupportedTransport {
        platform: std::env::consts::OS,
    })
}
