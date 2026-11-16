//! Local management client for the PathChord control plane.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{ArgAction, Args, Parser, Subcommand};
use getrandom::fill;
use pathchord_core::{PathReady, PathState, ProtocolLimits, SessionState};
#[cfg(test)]
use pathchord_egress::TargetRequest;
use pathchord_egress::{
    AuthorizationControlDispatcher, AuthorizationStore, EgressNode, EgressNodeConfig,
    TcpTargetConnector,
};
#[cfg(not(windows))]
use pathchord_ingress::UnsupportedPlatformProxyAdapter;
#[cfg(windows)]
use pathchord_ingress::WindowsSystemProxyAdapter;
use pathchord_ingress::{
    Actor, ConfigHotReloader, ConfigReloadHandle, DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS,
    DnsAdapters, DnsRuntime, DynamicTransitRegistration, EndpointStateObservation, ErrorCode,
    IngressControlService, IngressControlStore, IngressDataPlane, IngressDataPlaneConfig,
    IngressPlatformConfig, IngressPlatformFactories, IngressPlatformRuntime, LOCAL_API_VERSION,
    ListenerCredentialError, ListenerCredentialVerifier, ListenerCredentialVerifierFactory,
    ListenerDescriptor, ListenerKind, LocalControlDispatcher, LocalControlServer, LocalDnsAdapter,
    LocalProtocolError, NodeHealthState, NodeId, NodeObservation, PathObservation,
    PlatformProxyAdapter, ProtectedEndpointSet, RejectListenerCredentials, RequestEnvelope,
    ResponseEnvelope, RuntimeCounts, RuntimeError, SessionObservation,
    StaticListenerCredentialVerifier, StreamObservation,
    SubscriptionCacheSpec as ControlSubscriptionCacheSpec, SubscriptionId as ControlSubscriptionId,
    SubscriptionRefreshSpec as ControlSubscriptionRefreshSpec,
    SubscriptionSpec as ControlSubscriptionSpec, SystemProxyPlatform, TcpFlowOpener,
    TransitProbeConfig, TransitProbeState, UdpFlowOpener, WebBearerToken, WebGateway,
    WebGatewayConfig,
};
#[cfg(test)]
use pathchord_ingress::{
    BoxedLocalConnection, FlowBridgeError, IngressTargetDialer, ListenerRuntime, TargetAddress,
    TargetHost,
};
#[cfg(any(unix, windows, test))]
use pathchord_ingress::{read_object, write_object};
use pathchord_noise::{StaticKeypair, generate_static_keypair};
#[cfg(test)]
use pathchord_policy::FallbackAction;
use pathchord_policy::{
    AuthenticationMode, FlowProtocol, Generation, ListenerConfig,
    ListenerKind as PolicyListenerKind, PolicyConfig, RuntimeNodeState, SubscriptionSourceType,
    TransitProxyRuntimeStatus,
};

mod configuration;
mod egress_configuration;
#[cfg(test)]
mod node_observation_tests;
use pathchord_transit::{
    AdapterRegistry, DynamicNodeState, DynamicTransitSnapshot, FileTransitCredentialProvider,
    HttpSubscriptionFetcher, RefreshOutcome, SubscriptionCredentialProvider, SubscriptionManager,
    TransitCredentialProvider,
};
use serde_json::Value;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Default local control endpoint.
#[cfg(not(windows))]
pub const DEFAULT_SOCKET_PATH: &str = "/run/pathchord/ingress.sock";

#[cfg(windows)]
pub const DEFAULT_SOCKET_PATH: &str = r"\\.\pipe\pathchord-ingress";

#[cfg(not(windows))]
pub const DEFAULT_EGRESS_SOCKET_PATH: &str = "/run/pathchord/egress.sock";

#[cfg(windows)]
pub const DEFAULT_EGRESS_SOCKET_PATH: &str = r"\\.\pipe\pathchord-egress";

const IDENTITY_FILE_HEADER: &[u8] = b"PATHCHORD-IDENTITY-V1\n";
const DEFAULT_EGRESS_BIND: &str = "0.0.0.0:7443";
const DEFAULT_MAX_CONCURRENT_PATHS: usize = 256;

#[derive(Debug, Parser)]
#[command(name = "pathchord", version, about = "PathChord management client")]
pub struct Cli {
    /// Local Unix socket or platform control endpoint.
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,
    /// Requested actor; local control assigns the authenticated OS owner instead.
    #[arg(long, global = true, default_value = "local-admin")]
    pub actor: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Run the Ingress service.
    Ingress(IngressArgs),
    /// Run the Egress service.
    Egress(EgressArgs),
    /// Query local runtime status.
    Status,
    /// Manage the Windows system-proxy control-plane switch.
    #[command(subcommand)]
    SystemProxy(SystemProxyCommand),
    /// Manage explicit endpoint enrollment.
    Enroll(EnrollmentArgs),
    /// Generate a local static identity file and print its public key.
    Keygen(KeygenArgs),
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct IngressArgs {
    /// Resource file or directory; overrides PATHCHORD_CONFIG and the account default.
    #[arg(short = 'c', long, conflicts_with = "config_dir")]
    pub config: Option<PathBuf>,
    /// Configuration directory; overrides PATHCHORD_CONFIG_DIR and the account default.
    #[arg(short = 'C', long, conflicts_with = "config")]
    pub config_dir: Option<PathBuf>,
    /// Canonical Ingress identity used during Session attachment.
    #[arg(long, default_value = "local-ingress")]
    pub ingress_id: String,
    /// Versioned private identity file. Required when Egress topology is configured.
    #[arg(long)]
    pub identity: Option<PathBuf>,
    /// Runtime cache and durable local data directory.
    #[arg(long, default_value = "pathchord-ingress-data")]
    pub data_dir: PathBuf,
    /// Directory containing private JSON credential maps named by credentialsRef.
    #[arg(long, default_value = "pathchord-ingress-secrets")]
    pub credentials_dir: PathBuf,
    /// Optional Web Gateway bind. Omit to keep the browser adapter disabled.
    #[arg(long)]
    pub web_bind: Option<SocketAddr>,
    /// File containing the Web bearer token. Required for non-loopback binds.
    #[arg(long)]
    pub web_token_file: Option<PathBuf>,
    /// Exact allowed Origin. May be repeated.
    #[arg(long = "web-origin")]
    pub web_origins: Vec<String>,
    /// Assert a trusted TLS or equivalent protected transport terminates upstream.
    #[arg(long)]
    pub web_protected_transport: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct EgressArgs {
    /// Resource file or directory; overrides environment and account defaults.
    #[arg(short = 'c', long, conflicts_with = "config_dir")]
    pub config: Option<PathBuf>,
    /// Configuration directory; overrides environment and account defaults.
    #[arg(short = 'C', long, conflicts_with = "config")]
    pub config_dir: Option<PathBuf>,
    /// Public Path listener address; may be repeated.
    #[arg(long = "bind", action = ArgAction::Append)]
    pub binds: Vec<SocketAddr>,
    /// Canonical Egress identity bound into the Noise prologue.
    #[arg(long)]
    pub egress_id: Option<String>,
    /// Versioned private identity file.
    #[arg(long)]
    pub identity: Option<PathBuf>,
    /// Egress-owned SQLite authorization database.
    #[arg(long)]
    pub authorization_db: Option<PathBuf>,
    /// Local authorization control socket or Named Pipe.
    #[arg(long)]
    pub control_socket: Option<PathBuf>,
    #[arg(long)]
    pub max_wire_bandwidth_bps: Option<u64>,
    #[arg(long)]
    pub max_inbound_target_connections: Option<usize>,
    #[arg(long)]
    pub quota_remaining: Option<u64>,
    #[arg(long)]
    pub traffic_multiplier_basis_points: Option<u32>,
    /// Optional authorization Web Gateway bind.
    #[arg(long)]
    pub web_bind: Option<SocketAddr>,
    #[arg(long)]
    pub web_token_file: Option<PathBuf>,
    #[arg(long = "web-origin")]
    pub web_origins: Vec<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub web_protected_transport: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct KeygenArgs {
    /// New private identity file. Existing files are never overwritten.
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct EnrollmentArgs {
    #[command(subcommand)]
    pub command: EnrollmentCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum EnrollmentCommand {
    /// List Egress authorization records.
    List,
    /// Get one Egress authorization record.
    Get(EnrollmentGetArgs),
    /// Enroll and enable one Ingress public key.
    Add(EnrollmentAddArgs),
    /// Permit new Paths for an existing record.
    Enable(EnrollmentMutationArgs),
    /// Disable an existing record and clean up its live resources.
    Disable(EnrollmentMutationArgs),
    /// Permanently revoke an existing record.
    Revoke(EnrollmentMutationArgs),
    /// Delete an existing record after live-resource cleanup.
    Delete(EnrollmentMutationArgs),
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct EnrollmentGetArgs {
    #[arg(long)]
    pub ingress_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct EnrollmentAddArgs {
    #[arg(long)]
    pub ingress_id: String,
    #[arg(long)]
    pub egress_id: String,
    /// Unpadded base64url Curve25519 public key.
    #[arg(long, allow_hyphen_values = true)]
    pub public_key: String,
    #[arg(long)]
    pub expected_generation: u64,
    /// Administrator label in KEY=VALUE form. May be repeated.
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct EnrollmentMutationArgs {
    #[arg(long)]
    pub ingress_id: String,
    #[arg(long)]
    pub expected_generation: u64,
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
            Self::Ingress(_) => "ingress",
            Self::Egress(_) => "egress",
            Self::Status => "status",
            Self::SystemProxy(SystemProxyCommand::Enable(_)) => "system-proxy enable",
            Self::SystemProxy(SystemProxyCommand::Disable) => "system-proxy disable",
            Self::Enroll(_) => "enroll",
            Self::Keygen(_) => "keygen",
        }
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("configuration source selection failed: {0}")]
    ConfigurationSource(#[from] configuration::ConfigurationError),
    #[error("configuration source {path} could not be loaded: {source}")]
    ConfigurationLoad {
        path: PathBuf,
        source: pathchord_ingress::ReloadError,
    },
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
    #[error("cannot read configuration {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Egress configuration is invalid: {0}")]
    EgressConfiguration(&'static str),
    #[error("Egress configuration source is invalid: {0}")]
    EgressConfigurationSource(String),
    #[error("configuration validation failed: {0}")]
    Config(#[from] pathchord_policy::ConfigError),
    #[error("local control server failed: {0}")]
    LocalServer(#[from] pathchord_ingress::LocalServerError),
    #[error("listener runtime failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("runtime observation update failed: {0}")]
    Observation(String),
    #[error("listener {listener_id} of kind {kind} is not supported by the current runtime")]
    UnsupportedListenerKind { listener_id: String, kind: String },
    #[error("listener {listener_id} has invalid bind address {bind}")]
    InvalidListenerBind { listener_id: String, bind: String },
    #[error("an identity file is required when Egress topology is configured")]
    MissingIdentity,
    #[error("identity file is invalid")]
    InvalidIdentity,
    #[error("identity file permissions must deny group and other access")]
    InsecureIdentityPermissions,
    #[error("Web bearer token file is invalid")]
    InvalidWebToken,
    #[error("Web bearer token file permissions must deny group and other access")]
    InsecureWebTokenPermissions,
    #[error("identity file I/O failed: {0}")]
    IdentityIo(#[from] std::io::Error),
    #[error("Noise identity operation failed: {0}")]
    Noise(#[from] pathchord_noise::NoiseError),
    #[error("Ingress data plane failed: {0}")]
    DataPlane(#[from] pathchord_ingress::DataPlaneError),
    #[error("Egress node failed: {0}")]
    EgressNode(#[from] pathchord_egress::EgressNodeError),
    #[error("Egress authorization store failed: {0}")]
    AuthorizationStore(#[from] pathchord_egress::AuthorizationStoreError),
    #[error("shutdown signal failed: {0}")]
    ShutdownSignal(String),
    #[error("Transit adapter failed: {0}")]
    Transit(#[from] pathchord_transit::TransitError),
    #[error("Transit credential provider failed: {0}")]
    TransitCredential(#[from] pathchord_transit::TransitCredentialError),
    #[error("subscription runtime failed: {0}")]
    Subscription(#[from] pathchord_transit::SubscriptionError),
    #[error("DNS runtime failed: {0}")]
    Dns(#[from] pathchord_ingress::DnsError),
    #[error("DNS adapter failed: {0}")]
    DnsAdapter(#[from] pathchord_ingress::DnsAdapterError),
    #[error("Ingress control service failed: {0}")]
    Control(#[from] pathchord_ingress::ControlError),
    #[error("Ingress control store failed: {0}")]
    ControlStore(#[from] pathchord_ingress::IngressControlStoreError),
    #[error("configuration hot reload failed: {0}")]
    Reload(#[from] pathchord_ingress::ReloadError),
    #[error("Web Gateway failed: {0}")]
    WebGateway(#[from] pathchord_ingress::WebGatewayError),
    #[error("Ingress platform runtime failed: {0}")]
    PlatformRuntime(#[from] pathchord_ingress::IngressPlatformError),
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

pub fn authorizations_list_request(actor: impl Into<String>) -> RequestEnvelope {
    request(
        "authorizations.list",
        actor,
        serde_json::json!({}),
        vec!["status:read"],
    )
}

pub fn authorization_get_request(
    actor: impl Into<String>,
    ingress_id: impl Into<String>,
) -> RequestEnvelope {
    request(
        "authorizations.get",
        actor,
        serde_json::json!({"ingress_id": ingress_id.into()}),
        vec!["status:read"],
    )
}

pub fn authorization_enroll_request(
    actor: impl Into<String>,
    ingress_id: impl Into<String>,
    egress_id: impl Into<String>,
    public_key: impl Into<String>,
    expected_generation: u64,
    administrator_labels: BTreeMap<String, String>,
) -> RequestEnvelope {
    request_with_generation(
        "authorizations.enroll",
        actor,
        serde_json::json!({
            "ingress_id": ingress_id.into(),
            "egress_id": egress_id.into(),
            "public_key": public_key.into(),
            "administrator_labels": administrator_labels,
        }),
        vec!["authorization:write"],
        expected_generation,
    )
}

pub fn authorization_enable_request(
    actor: impl Into<String>,
    ingress_id: impl Into<String>,
    expected_generation: u64,
) -> RequestEnvelope {
    authorization_mutation_request(
        "authorizations.enable",
        actor,
        ingress_id,
        expected_generation,
    )
}

pub fn authorization_disable_request(
    actor: impl Into<String>,
    ingress_id: impl Into<String>,
    expected_generation: u64,
) -> RequestEnvelope {
    authorization_mutation_request(
        "authorizations.disable",
        actor,
        ingress_id,
        expected_generation,
    )
}

pub fn authorization_revoke_request(
    actor: impl Into<String>,
    ingress_id: impl Into<String>,
    expected_generation: u64,
) -> RequestEnvelope {
    authorization_mutation_request(
        "authorizations.revoke",
        actor,
        ingress_id,
        expected_generation,
    )
}

pub fn authorization_delete_request(
    actor: impl Into<String>,
    ingress_id: impl Into<String>,
    expected_generation: u64,
) -> RequestEnvelope {
    authorization_mutation_request(
        "authorizations.delete",
        actor,
        ingress_id,
        expected_generation,
    )
}

fn authorization_mutation_request(
    operation: &'static str,
    actor: impl Into<String>,
    ingress_id: impl Into<String>,
    expected_generation: u64,
) -> RequestEnvelope {
    request_with_generation(
        operation,
        actor,
        serde_json::json!({"ingress_id": ingress_id.into()}),
        vec!["authorization:write"],
        expected_generation,
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

fn request_with_generation(
    operation: &str,
    actor: impl Into<String>,
    body: Value,
    capabilities: Vec<&str>,
    expected_generation: u64,
) -> RequestEnvelope {
    let mut request = request(operation, actor, body, capabilities);
    request.expected_generation = Some(pathchord_ingress::GenerationExpectation {
        scope: "authorization".to_owned(),
        value: expected_generation,
    });
    request
}

fn parse_labels(labels: Vec<String>) -> Result<BTreeMap<String, String>, CliError> {
    let mut parsed = BTreeMap::new();
    for label in labels {
        let Some((key, value)) = label.split_once('=') else {
            return Err(CliError::InvalidLabel { label });
        };
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

pub async fn run(cli: Cli) -> Result<(), CliError> {
    let Cli {
        socket,
        actor,
        command,
    } = cli;
    let explicit_socket = socket.clone();
    let socket = socket.unwrap_or_else(|| match &command {
        Command::Enroll(_) => {
            configuration::default_control_socket("egress.sock", DEFAULT_EGRESS_SOCKET_PATH)
        }
        _ => configuration::default_control_socket("ingress.sock", DEFAULT_SOCKET_PATH),
    });
    match command {
        Command::Ingress(args) => run_ingress(&socket, args).await,
        Command::Egress(mut args) => {
            if args.control_socket.is_none() {
                args.control_socket = explicit_socket;
            }
            run_egress(args).await
        }
        Command::Enroll(args) => run_enrollment(&socket, actor, args.command).await,
        Command::Keygen(args) => run_keygen(args),
        Command::Status => {
            let response = call_local(&socket, status_request(actor)).await?;
            print_response(response)
        }
        Command::SystemProxy(SystemProxyCommand::Enable(args)) => {
            let generation = local_configuration_generation(&socket, &actor).await?;
            let mut request = system_proxy_enable_request(actor, args.listener_id);
            request.expected_generation = Some(pathchord_ingress::GenerationExpectation {
                scope: "configuration".to_owned(),
                value: generation,
            });
            let response = call_local(&socket, request).await?;
            print_response(response)
        }
        Command::SystemProxy(SystemProxyCommand::Disable) => {
            let generation = local_configuration_generation(&socket, &actor).await?;
            let mut request = system_proxy_disable_request(actor);
            request.expected_generation = Some(pathchord_ingress::GenerationExpectation {
                scope: "configuration".to_owned(),
                value: generation,
            });
            let response = call_local(&socket, request).await?;
            print_response(response)
        }
    }
}

/// Starts the Ingress service from its dedicated service executable.
pub async fn run_ingress_service(
    socket: Option<PathBuf>,
    args: IngressArgs,
) -> Result<(), CliError> {
    let socket = socket.unwrap_or_else(|| {
        configuration::default_control_socket("ingress.sock", DEFAULT_SOCKET_PATH)
    });
    run_ingress(&socket, args).await
}

async fn local_configuration_generation(
    socket: &std::path::Path,
    actor: &str,
) -> Result<u64, CliError> {
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
        .ok_or_else(|| {
            CliError::Observation("local status lacks configuration generation".to_owned())
        })
}

async fn run_enrollment(
    socket: &std::path::Path,
    actor: String,
    command: EnrollmentCommand,
) -> Result<(), CliError> {
    let request = match command {
        EnrollmentCommand::List => authorizations_list_request(actor),
        EnrollmentCommand::Get(args) => authorization_get_request(actor, args.ingress_id),
        EnrollmentCommand::Add(args) => authorization_enroll_request(
            actor,
            args.ingress_id,
            args.egress_id,
            args.public_key,
            args.expected_generation,
            parse_labels(args.labels)?,
        ),
        EnrollmentCommand::Enable(args) => {
            authorization_enable_request(actor, args.ingress_id, args.expected_generation)
        }
        EnrollmentCommand::Disable(args) => {
            authorization_disable_request(actor, args.ingress_id, args.expected_generation)
        }
        EnrollmentCommand::Revoke(args) => {
            authorization_revoke_request(actor, args.ingress_id, args.expected_generation)
        }
        EnrollmentCommand::Delete(args) => {
            authorization_delete_request(actor, args.ingress_id, args.expected_generation)
        }
    };
    print_response(call_local(socket, request).await?)
}

async fn run_ingress(socket: &std::path::Path, args: IngressArgs) -> Result<(), CliError> {
    let source = configuration::ConfigSelection::resolve_ingress(
        args.config.as_deref(),
        args.config_dir.as_deref(),
    )?;
    source.validate()?;
    let reloader = ConfigHotReloader::bind(source.path.clone(), 1)
        .await
        .map_err(|error| CliError::ConfigurationLoad {
            path: source.path.clone(),
            source: error,
        })?;
    let reload_handle = reloader.handle();
    reload_handle.enable_runtime_commit()?;
    let initial_snapshot = reload_handle.snapshot()?;
    let policy_config = (*initial_snapshot.config).clone();
    let policy =
        pathchord_policy::ValidatedPolicySnapshot::new(Generation::new(1), policy_config.clone())
            .map_err(pathchord_policy::ConfigError::from)?;
    let identity = match args.identity {
        Some(path) => load_identity(&path)?,
        None if policy_config.egresses.is_empty() => generate_static_keypair()?,
        None => return Err(CliError::MissingIdentity),
    };
    let platform = SystemProxyPlatform::current();
    let data_plane = Arc::new(IngressDataPlane::new_with_compiled(
        IngressDataPlaneConfig::new(args.ingress_id, identity, policy),
        (*initial_snapshot.compiled).clone(),
    )?);
    data_plane
        .configure_node_probe(node_probe_config(policy_config.node_probe.as_ref()))
        .await?;
    std::fs::create_dir_all(&args.data_dir)?;
    let credentials = Arc::new(FileTransitCredentialProvider::new(&args.credentials_dir)?);
    let source_dir = if source.directory {
        source.path.clone()
    } else {
        source
            .path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    };
    let adapter_registry = AdapterRegistry::with_native_roots(
        Arc::clone(&credentials),
        pathchord_ingress::DEFAULT_PATH_CONNECT_TIMEOUT,
    )?
    .with_source_dir(source_dir);
    let adapter_registry = Arc::new(adapter_registry);
    for proxy in &policy_config.transit_proxies {
        let adapter = adapter_registry.build(proxy).await?;
        adapter.prepare().await?;
        let capabilities = adapter_capabilities(adapter.as_ref(), &proxy.options);
        data_plane
            .register_transit_adapter(
                proxy.id.clone(),
                adapter,
                TransitProxyRuntimeStatus {
                    state: RuntimeNodeState::Ready,
                    capabilities,
                    labels: BTreeMap::new(),
                    tags: BTreeSet::new(),
                    selection_score: 1,
                    quota_remaining: None,
                    traffic_multiplier_basis_points: None,
                },
            )
            .await?;
    }
    // Durable subscription mutations are authoritative before cache loading,
    // Path warmup, or listener startup. Reconcile only actual declarative
    // changes, then use the effective control snapshot for runtime sources.
    let control_store = Arc::new(IngressControlStore::open(
        args.data_dir.join("ingress-control.db"),
    )?);
    let mut control_service = IngressControlService::open_with_platform_proxy(
        control_store,
        platform_proxy_adapter(&args.data_dir),
    )?;
    control_service.set_reload_handle(reload_handle.clone());
    let (configured_nodes, configured_subscriptions) =
        declarative_control_resources(&policy_config)?;
    control_service.reconcile_declarative_resources(
        1,
        configured_nodes,
        configured_subscriptions,
    )?;
    let control_snapshot = control_service.snapshot();
    let effective_subscriptions = control_snapshot
        .subscriptions
        .values()
        .map(|subscription| subscription.spec.runtime_config())
        .collect::<Result<Vec<_>, _>>()?;
    let mut subscription_ids = BTreeSet::new();
    subscription_ids.extend(
        policy_config
            .subscriptions
            .iter()
            .map(|source| source.id.as_str().to_owned()),
    );
    subscription_ids.extend(policy_config.transit_proxies.iter().filter_map(|node| {
        node.source
            .as_ref()
            .filter(|source| source.source_type != "static")
            .map(|source| source.subscription.clone())
    }));
    subscription_ids.extend(
        control_snapshot
            .subscriptions
            .keys()
            .map(|id| id.as_str().to_owned()),
    );
    for id in subscription_ids {
        let enabled = control_snapshot
            .subscriptions
            .iter()
            .any(|(key, value)| key.as_str() == id && value.spec.enabled);
        data_plane
            .initialize_subscription_visibility(&id, enabled)
            .await;
    }
    let subscription_credentials: Arc<dyn SubscriptionCredentialProvider> = credentials.clone();
    let fetcher = Arc::new(HttpSubscriptionFetcher::with_credentials(
        subscription_credentials,
    )?);
    let mut subscription_manager = SubscriptionManager::new(
        fetcher,
        args.data_dir.join("subscriptions"),
        adapter_registry.available_protocols(),
    );
    subscription_manager.reconcile(&effective_subscriptions);
    for subscription in &effective_subscriptions {
        let _ = subscription_manager.load_cache(subscription).await;
    }
    let prepared = subscription_manager
        .snapshot()
        .prepare_adapters(adapter_registry.as_ref())
        .await;
    subscription_manager.commit_prepared_adapters(prepared)?;
    let initial_adapter_diagnostics =
        publish_dynamic_transit(data_plane.as_ref(), &mut subscription_manager).await;
    let dynamic_snapshot = Arc::new(tokio::sync::RwLock::new(
        subscription_manager.snapshot().clone(),
    ));
    let dns_runtime = if let Some(dns_policy) = policy_config.dns_policy.clone() {
        let mut adapters = DnsAdapters::default();
        if let Some(local) = &dns_policy.local {
            adapters = adapters.with_local(Arc::new(LocalDnsAdapter::new(local.servers.clone())?));
        }
        let remote = data_plane.dns_route_adapter();
        adapters = adapters
            .with_transit(Arc::clone(&remote))
            .with_egress(remote);
        Some(Arc::new(DnsRuntime::new(dns_policy, adapters)?))
    } else {
        None
    };
    // Give startup one bounded opportunity to establish a catch-all Path.
    // Maintenance continues after listeners start even if this node stalls.
    let _ = tokio::time::timeout(Duration::from_secs(1), data_plane.warmup()).await;
    let protected_endpoints = ProtectedEndpointSet::default();
    protected_endpoints.replace(
        collect_protected_endpoints(
            &policy_config,
            dns_runtime.as_deref(),
            Some(subscription_manager.snapshot()),
        )
        .await,
    );
    let tcp_opener: Arc<dyn TcpFlowOpener> = data_plane.clone();
    let udp_opener: Arc<dyn UdpFlowOpener> = data_plane.clone();
    let platform_factories = IngressPlatformFactories {
        listener_credentials: Arc::new(FileListenerCredentialFactory {
            provider: Arc::clone(&credentials),
        }),
        ..IngressPlatformFactories::default()
    };
    let mut platform_config = IngressPlatformConfig::new(args.data_dir.join("platform"));
    platform_config.dns = dns_runtime.clone();
    let mut runtime = IngressPlatformRuntime::bind_with_factories(
        platform_config,
        &policy_config.listeners,
        tcp_opener,
        udp_opener,
        protected_endpoints.clone(),
        platform_factories,
    )
    .await?;
    let mut dispatcher = LocalControlDispatcher::with_service(platform, control_service);
    dispatcher.set_subscription_data_plane(Arc::clone(&data_plane));
    for listener in &policy_config.listeners {
        // TUN and UDP-only TPROXY listeners have no TCP socket address, but
        // they are still runnable resources and must be visible to control
        // inventory/status just like ordinary listeners.
        dispatcher
            .service_mut()
            .register_listener(listener_descriptor(listener.clone())?);
    }
    let observation_handle = dispatcher.service().observation_handle();
    let (runtime_events, mut event_receiver) = tokio::sync::mpsc::unbounded_channel();
    runtime.set_listener_event_sender(runtime_events);
    let server = LocalControlServer::bind(socket.to_owned(), dispatcher)?;
    let control_dispatcher = server.shared_dispatcher();
    let node_control = Arc::clone(&control_dispatcher);
    sync_control_nodes(
        &control_dispatcher,
        data_plane.as_ref(),
        &policy_config,
        subscription_manager.snapshot(),
        &initial_adapter_diagnostics,
        &effective_subscriptions,
        control_snapshot.generation,
    )
    .await?;
    let web_gateway = if let Some(bind) = args.web_bind {
        let bearer_token = args
            .web_token_file
            .as_deref()
            .map(load_web_token)
            .transpose()?;
        let gateway = WebGateway::bind(
            WebGatewayConfig {
                bind,
                bearer_token,
                allowed_origins: args.web_origins.into_iter().collect(),
                protected_transport: args.web_protected_transport,
                ..WebGatewayConfig::default()
            },
            Arc::clone(&control_dispatcher),
        )
        .await?;
        let address = gateway.local_addr()?;
        let mut protected = protected_endpoints.snapshot();
        protected.insert(address);
        protected_endpoints.replace(protected);
        Some(gateway)
    } else {
        None
    };
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let runtime_future = runtime.run_until_shutdown(wait_for_shutdown(shutdown.subscribe()));
    let server_future = server.run_until_shutdown(
        DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS,
        wait_for_shutdown(shutdown.subscribe()),
    );
    let web_future = async {
        match web_gateway {
            Some(gateway) => gateway
                .run_until_shutdown(wait_for_shutdown(shutdown.subscribe()))
                .await
                .map_err(CliError::from),
            None => {
                wait_for_shutdown(shutdown.subscribe()).await;
                Ok(())
            }
        }
    };
    let observation_plane = Arc::clone(&data_plane);
    let observation_dynamic_snapshot = Arc::clone(&dynamic_snapshot);
    let observation_egresses: Vec<String> = policy_config
        .egresses
        .iter()
        .map(|egress| egress.id.as_str().to_owned())
        .collect();
    let mut session_timing: BTreeMap<pathchord_core::SessionId, (u64, u64, String)> =
        BTreeMap::new();
    let observation_shutdown = shutdown.subscribe();
    let observation_future = async move {
        let mut shutdown = observation_shutdown;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok::<(), CliError>(());
                    }
                }
                event = event_receiver.recv() => {
                    let Some(event) = event else {
                        return Ok(());
                    };
                    observation_handle
                        .apply_listener_event(event)
                        .map_err(|error| CliError::Observation(error.to_string()))?;
                }
                _ = interval.tick() => {
                    let captured_at_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis()
                        .min(u128::from(u64::MAX)) as u64;
                    let snapshot = observation_plane.snapshot().await;
                    let session_snapshots = observation_plane.session_snapshots().await;
                    let current_session_ids: BTreeSet<_> = session_snapshots
                        .iter()
                        .map(|entry| entry.session.session_id)
                        .collect();
                    session_timing.retain(|id, _| current_session_ids.contains(id));
                    for egress_id in &observation_egresses {
                        let session = session_snapshots.iter().find(|entry| &entry.egress_id == egress_id);
                        let status = session.and_then(|entry| entry.session.egress_status.as_ref());
                        observation_handle.set_egress_runtime(
                            egress_id.clone(),
                            status.map(|status| status.report.clone()),
                            status.map_or(0, |status| status.age_ms),
                            status.is_some_and(|status| status.fresh),
                            session.map_or(0, |entry| entry.session.active_udp_associations),
                            session.map_or(0, |entry| entry.session.pending_session_controls),
                        ).map_err(|error| CliError::Observation(error.to_string()))?;
                    }
                    let sessions = session_snapshots.iter().map(|entry| {
                        let state = if entry.session.closed {
                            SessionState::Closed
                        } else if entry.session.ready_paths == 0 {
                            SessionState::Connecting
                        } else if entry.session.degraded_paths > 0 {
                            SessionState::Degraded
                        } else {
                            SessionState::Active
                        };
                        let fingerprint = format!(
                            "{state:?}:{}:{}:{}",
                            entry.session.ready_paths,
                            entry.session.active_streams,
                            entry.session.active_udp_associations
                        );
                        let timing = session_timing
                            .entry(entry.session.session_id)
                            .or_insert((captured_at_ms, captured_at_ms, fingerprint.clone()));
                        if timing.2 != fingerprint {
                            timing.1 = captured_at_ms;
                            timing.2 = fingerprint;
                        }
                        SessionObservation {
                            session_id: entry.session.session_id,
                            egress_id: entry.egress_id.clone(),
                            state,
                            admission_generation: None,
                            created_at_ms: Some(timing.0),
                            last_change_at_ms: Some(timing.1),
                            close_reason: None,
                            ready_paths: entry.session.ready_paths,
                            active_streams: entry.session.active_streams,
                            active_udp_associations: entry.session.active_udp_associations,
                            pending_session_controls: entry.session.pending_session_controls,
                            retained_outbound_bytes: entry.session.retained_outbound_bytes,
                            bytes_sent: entry.session.bytes_sent,
                            bytes_received: entry.session.bytes_received,
                            minimum_usable_paths: entry.minimum_usable_paths,
                            target_path_count: entry.session.target_path_count as usize,
                            usable_paths: entry
                                .session
                                .path_states
                                .values()
                                .filter(|state| {
                                    matches!(
                                        state,
                                        pathchord_core::PathState::Active
                                            | pathchord_core::PathState::Degraded
                                    )
                                })
                                .count(),
                            eligible_transit_count: entry.eligible_transit_count,
                            traffic_policy_id: entry.traffic_policy_id.clone(),
                            traffic_policy_generation: None,
                            demand_upstream_bps: None,
                            demand_downstream_bps: None,
                            replication_cap_bps: entry.replication_cap_bps,
                            replication_upstream_used_bps: None,
                            replication_downstream_used_bps: None,
                            endpoint_count: entry.endpoint_states.len(),
                            endpoint_states: entry
                                .endpoint_states
                                .iter()
                                .map(|state| EndpointStateObservation {
                                    state: state.state.to_owned(),
                                    attempts: state.attempts,
                                    failures: state.failures,
                                })
                                .collect(),
                            path_endpoints: entry.path_endpoint.clone(),
                        }
                    });
                    let paths = session_snapshots.iter().flat_map(|entry| {
                        let ready: BTreeSet<_> = entry.session.ready_path_ids.iter().copied().collect();
                        let path_ids: BTreeSet<_> = ready
                            .iter()
                            .copied()
                            .chain(entry.session.path_quality.keys().copied())
                            .collect();
                        path_ids.into_iter().map(move |path_id| {
                            let quality = entry.session.path_quality.get(&path_id);
                            let exclusion_reason = quality
                                .and_then(|quality| quality.exclusion_reason)
                                .map(|reason| format!("{reason:?}").to_ascii_lowercase());
                            let state = match exclusion_reason.as_deref() {
                                Some("draining") => PathState::Draining,
                                Some(_) => PathState::Degraded,
                                None if ready.contains(&path_id) => PathState::Active,
                                None => PathState::Degraded,
                            };
                            PathObservation {
                                path_id,
                                session_id: entry.session.session_id,
                                egress_id: Some(entry.egress_id.clone()),
                                endpoint_index: entry.path_endpoint.get(&path_id).copied(),
                                transit_proxy_id: entry.path_transit.get(&path_id).cloned(),
                                state,
                                ready_since_ms: None,
                                last_change_at_ms: None,
                                rtt_ms: quality.map(|quality| quality.rtt_ms),
                                jitter_ms: quality.map(|quality| quality.jitter_ms),
                                loss_ppm: quality.map(|quality| quality.loss_ppm),
                                throughput_bps: quality.map(|quality| quality.throughput_bps),
                                upstream_throughput_bps: quality
                                    .map(|quality| quality.upstream_throughput_bps),
                                downstream_throughput_bps: quality
                                    .map(|quality| quality.downstream_throughput_bps),
                                available_capacity_bps: quality
                                    .map(|quality| quality.effective_capacity_bps),
                                reordering_events: quality
                                    .map(|quality| quality.reordering_events),
                                control_pending: quality
                                    .map(|quality| quality.control_pending as u64),
                                control_retransmissions: quality
                                    .map(|quality| quality.control_retransmissions),
                                exclusion_reason,
                            }
                        })
                    });
                    observation_handle
                        .replace_session_observations(sessions, paths)
                        .map_err(|error| CliError::Observation(error.to_string()))?;
                    let streams = session_snapshots.iter().flat_map(|entry| {
                        let session_id = entry.session.session_id;
                        entry.session.streams.values().map(move |stream| {
                            let hostname = String::from_utf8_lossy(&stream.target.hostname);
                            StreamObservation {
                                session_id,
                                stream_id: stream.stream_id,
                                state: stream.state,
                                target_display: format!("{hostname}:{}", stream.target.port),
                                bytes_sent: stream.bytes_sent,
                                bytes_received: stream.bytes_received,
                                bytes_acked: stream.bytes_acked,
                                retransmissions: stream.retransmissions,
                                reorder_buffer_bytes: stream.reorder_buffer_bytes,
                                receive_window: stream.receive_window,
                                opened_at_ms: stream.opened_at_ms,
                                closed_at_ms: stream.closed_at_ms,
                                close_reason: stream.close_reason.clone(),
                            }
                        })
                    });
                    observation_handle
                        .replace_stream_observations(streams)
                        .map_err(|error| CliError::Observation(error.to_string()))?;
                    observation_handle
                        .set_runtime_counts(RuntimeCounts {
                            sessions: snapshot.sessions as u64,
                            ready_paths: snapshot.ready_paths as u64,
                            streams: snapshot.streams as u64,
                            // Target connections are maintained from listener
                            // lifecycle events by the observation service.
                            target_connections: 0,
                        })
                        .map_err(|error| CliError::Observation(error.to_string()))?;
                    publish_probe_observations(&node_control, observation_plane.as_ref(), &observation_dynamic_snapshot).await?;
                }
            }
        }
    };
    let subscription_plane = Arc::clone(&data_plane);
    let subscription_registry = Arc::clone(&adapter_registry);
    let subscription_configs = effective_subscriptions;
    let subscription_future = SubscriptionWorker {
        adapter_diagnostics: initial_adapter_diagnostics,
        manager: subscription_manager,
        configs: subscription_configs,
        registry: subscription_registry,
        data_plane: subscription_plane,
        control: Arc::clone(&control_dispatcher),
        reload: reload_handle.clone(),
        protected_endpoints: protected_endpoints.clone(),
        dns_runtime: dns_runtime.clone(),
        dynamic_snapshot: Arc::clone(&dynamic_snapshot),
    }
    .run(shutdown.subscribe());
    let maintenance_future = run_data_plane_maintenance(
        Arc::clone(&data_plane),
        policy_config
            .node_probe
            .as_ref()
            .map(|policy| Duration::from_secs(policy.interval_seconds)),
        shutdown.subscribe(),
    );
    let reload_future = reloader.run_until_shutdown(wait_for_shutdown(shutdown.subscribe()));
    let reload_apply_future = apply_reloaded_policies(
        reload_handle,
        Arc::clone(&data_plane),
        control_dispatcher,
        Arc::clone(&adapter_registry),
        protected_endpoints.clone(),
        dns_runtime.clone(),
        Arc::clone(&dynamic_snapshot),
        shutdown.subscribe(),
    );
    let combined = async {
        let _ = tokio::try_join!(
            async { runtime_future.await.map(|_| ()).map_err(CliError::from) },
            async { server_future.await.map_err(CliError::from) },
            web_future,
            observation_future,
            subscription_future,
            maintenance_future,
            async { reload_future.await.map_err(CliError::from) },
            reload_apply_future,
        )?;
        Ok::<(), CliError>(())
    };
    tokio::pin!(combined);
    let result = tokio::select! {
        result = &mut combined => result,
        signal = service_shutdown_signal() => {
            signal.map_err(|error| CliError::ShutdownSignal(error.to_string()))?;
            let _ = shutdown.send(true);
            combined.await
        }
    };
    let _ = shutdown.send(true);
    let shutdown_result = data_plane.shutdown().await;
    result?;
    shutdown_result?;
    Ok(())
}

async fn run_egress(args: EgressArgs) -> Result<(), CliError> {
    let args = egress_configuration::resolve(args).await?;
    let identity = Arc::new(load_identity(&args.identity)?);
    let authorizations = Arc::new(AuthorizationStore::open(
        &args.authorization_db,
        pathchord_egress::EgressId::new(args.egress_id.clone()),
        *identity.public(),
    )?);
    let node = Arc::new(
        EgressNode::bind(
            EgressNodeConfig {
                binds: args.binds,
                egress_id: args.egress_id,
                keypair: identity,
                authorizations: Arc::clone(&authorizations),
                protocol_limits: ProtocolLimits::default(),
                ready_limits: PathReady {
                    max_frame_payload: ProtocolLimits::HARD_MAX_FRAME_PAYLOAD as u64,
                    max_control_payload: ProtocolLimits::HARD_MAX_CONTROL_PAYLOAD as u64,
                    max_session_buffering: ProtocolLimits::HARD_MAX_SESSION_BUFFERING as u64,
                },
                required_capabilities: 1,
                supported_capabilities: 0b11,
                max_concurrent_paths: args.max_concurrent_paths,
                capacity_bps: args.max_wire_bandwidth_bps,
                max_inbound_target_connections: args.max_inbound_target_connections,
                remote_dns_only: args.remote_dns_only,
                quota_remaining: args.quota_remaining,
                traffic_multiplier_basis_points: args.traffic_multiplier_basis_points,
            },
            TcpTargetConnector::new(),
        )
        .await?,
    );
    let cleanup_node = Arc::clone(&node);
    let status_node = Arc::clone(&node);
    let resources_node = Arc::clone(&node);
    let dispatcher = AuthorizationControlDispatcher::new(authorizations)
        .with_cleanup_hook(move |_| {
            let cleanup_node = Arc::clone(&cleanup_node);
            async move {
                cleanup_node
                    .reconcile_authorizations_until(Duration::from_secs(10))
                    .await
                    .map_err(|error| error.to_string())
            }
        })
        .with_status_hook(move || {
            let status_node = Arc::clone(&status_node);
            async move {
                let snapshot = status_node.snapshot().map_err(|error| error.to_string())?;
                let activity = status_node
                    .authorization_activity()
                    .map_err(|error| error.to_string())?;
                Ok(serde_json::json!({
                    "running": snapshot.running,
                    "local_addr": snapshot.local_addr.to_string(),
                    "accepted_paths": snapshot.accepted_paths,
                    "admitted_paths": snapshot.admitted_paths,
                    "active_paths": snapshot.active_paths,
                    "active_sessions": snapshot.active_sessions,
                    "active_streams": snapshot.active_streams,
                    "active_target_connections": snapshot.active_target_connections,
                    "last_session_end": snapshot.last_session_end,
                    "target_open": {
                        "attempts": snapshot.target_open_attempts,
                        "successes": snapshot.target_open_successes,
                        "failures": snapshot.target_open_failures,
                        "last": snapshot.last_target_open.as_ref().map(|last| serde_json::json!({
                            "hostname": last.hostname,
                            "port": last.port,
                            "phase": last.phase,
                            "result": last.result,
                            "error_kind": last.error_kind,
                        })),
                    },
                    "authorization_activity": activity,
                    "quota_remaining": snapshot.quota_remaining,
                    "traffic_multiplier_basis_points": snapshot.traffic_multiplier_basis_points,
                }))
            }
        })
        .with_resources_hook(move || {
            let resources_node = Arc::clone(&resources_node);
            async move {
                let (path_metrics, stream_metrics) = resources_node.management_resources().map_err(|error| error.to_string())?;
                Ok(serde_json::json!({"path_metrics": path_metrics, "stream_metrics": stream_metrics}))
            }
        });
    let server = LocalControlServer::bind(args.control_socket, dispatcher)?;
    let web_dispatcher = server.shared_dispatcher();
    let web_gateway = if let Some(bind) = args.web_bind {
        Some(
            WebGateway::bind(
                WebGatewayConfig {
                    bind,
                    authorizations_enabled: true,
                    bearer_token: args
                        .web_token_file
                        .as_deref()
                        .map(load_web_token)
                        .transpose()?,
                    allowed_origins: args.web_origins.into_iter().collect(),
                    protected_transport: args.web_protected_transport,
                    ..WebGatewayConfig::default()
                },
                web_dispatcher,
            )
            .await?,
        )
    } else {
        None
    };
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let node_future = node.run_until_shutdown(wait_for_shutdown(shutdown.subscribe()));
    let server_future = server.run_until_shutdown(
        DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS,
        wait_for_shutdown(shutdown.subscribe()),
    );
    let web_future = async {
        match web_gateway {
            Some(gateway) => gateway
                .run_until_shutdown(wait_for_shutdown(shutdown.subscribe()))
                .await
                .map_err(CliError::from),
            None => {
                wait_for_shutdown(shutdown.subscribe()).await;
                Ok(())
            }
        }
    };
    let combined = async {
        let _ = tokio::try_join!(
            async { node_future.await.map(|_| ()).map_err(CliError::from) },
            async { server_future.await.map_err(CliError::from) },
            web_future,
        )?;
        Ok::<(), CliError>(())
    };
    tokio::pin!(combined);
    let result = tokio::select! {
        result = &mut combined => result,
        signal = service_shutdown_signal() => {
            signal.map_err(|error| CliError::ShutdownSignal(error.to_string()))?;
            let _ = shutdown.send(true);
            combined.await
        }
    };
    let _ = shutdown.send(true);
    result
}

async fn wait_for_shutdown(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn service_shutdown_signal() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[derive(Clone)]
struct FileListenerCredentialFactory {
    provider: Arc<FileTransitCredentialProvider>,
}

impl std::fmt::Debug for FileListenerCredentialFactory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FileListenerCredentialFactory([REDACTED])")
    }
}

#[async_trait::async_trait]
impl ListenerCredentialVerifierFactory for FileListenerCredentialFactory {
    async fn verifier_for(
        &self,
        listener: &ListenerConfig,
    ) -> Result<Arc<dyn ListenerCredentialVerifier>, ListenerCredentialError> {
        if listener.authentication == AuthenticationMode::Disabled {
            return Ok(Arc::new(RejectListenerCredentials));
        }
        let reference = listener
            .credentials_ref
            .as_deref()
            .ok_or(ListenerCredentialError::Invalid)?;
        let credential = self
            .provider
            .resolve(reference)
            .await
            .map_err(|error| match error {
                pathchord_transit::TransitCredentialError::Unavailable => {
                    ListenerCredentialError::Unavailable
                }
                pathchord_transit::TransitCredentialError::InvalidReference
                | pathchord_transit::TransitCredentialError::InvalidDocument
                | pathchord_transit::TransitCredentialError::TooLarge
                | pathchord_transit::TransitCredentialError::UnsafeFileType
                | pathchord_transit::TransitCredentialError::InsecurePermissions => {
                    ListenerCredentialError::Invalid
                }
                pathchord_transit::TransitCredentialError::Io => ListenerCredentialError::Provider,
            })?
            .ok_or(ListenerCredentialError::Unavailable)?;
        let username = credential
            .field("username")
            .ok_or(ListenerCredentialError::Invalid)?;
        let password = credential
            .field("password")
            .ok_or(ListenerCredentialError::Invalid)?;
        Ok(Arc::new(StaticListenerCredentialVerifier::new(
            username,
            password.as_bytes(),
        )))
    }
}

#[cfg(windows)]
fn platform_proxy_adapter(data_dir: &std::path::Path) -> Arc<dyn PlatformProxyAdapter> {
    Arc::new(WindowsSystemProxyAdapter::new(
        data_dir.join("system-proxy-journal.json"),
    ))
}

#[cfg(not(windows))]
fn platform_proxy_adapter(_data_dir: &std::path::Path) -> Arc<dyn PlatformProxyAdapter> {
    Arc::new(UnsupportedPlatformProxyAdapter)
}

struct SubscriptionWorker {
    adapter_diagnostics:
        BTreeMap<pathchord_policy::TransitProxyId, pathchord_transit::NodeDiagnostic>,
    manager: SubscriptionManager,
    configs: Vec<pathchord_policy::SubscriptionConfig>,
    registry: Arc<AdapterRegistry<FileTransitCredentialProvider>>,
    data_plane: Arc<IngressDataPlane>,
    control: Arc<tokio::sync::Mutex<LocalControlDispatcher>>,
    reload: ConfigReloadHandle,
    protected_endpoints: ProtectedEndpointSet,
    dns_runtime: Option<Arc<DnsRuntime>>,
    dynamic_snapshot: Arc<tokio::sync::RwLock<DynamicTransitSnapshot>>,
}

impl SubscriptionWorker {
    async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) -> Result<(), CliError> {
        let mut manager = self.manager;
        let mut configs = self.configs;
        let registry = self.registry;
        let data_plane = self.data_plane;
        let control = self.control;
        let reload = self.reload;
        let protected_endpoints = self.protected_endpoints;
        let dns_runtime = self.dns_runtime;
        let dynamic_snapshot = self.dynamic_snapshot;
        let mut adapter_diagnostics = self.adapter_diagnostics;
        let mut due: BTreeMap<_, _> = configs
            .iter()
            .map(|config| (config.id.clone(), tokio::time::Instant::now()))
            .collect();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                _ = tick.tick() => {
                    let mut tick_shutdown = shutdown.clone();
                    let work = async {
                    let mut refreshed = false;
                    let mut releasable = BTreeSet::new();
                    let snapshot = control.lock().await.service().snapshot();
                    let mut observed_generation = snapshot.generation;
                    let latest = snapshot.subscriptions.into_values()
                        .map(|state| state.spec.runtime_config())
                        .collect::<Result<Vec<_>, _>>()?;
                    if latest != configs {
                        let changed_ids: BTreeSet<_> = latest.iter()
                            .filter(|next| configs.iter().find(|old| old.id == next.id) != Some(*next))
                            .map(|config| config.id.clone())
                            .collect();
                        let previous_ids: BTreeSet<_> =
                            configs.iter().map(|config| config.id.clone()).collect();
                        let next_ids: BTreeSet<_> = latest.iter().map(|config| config.id.clone()).collect();
                        manager.reconcile(&latest);
                        let observations = control.lock().await.service().observation_handle();
                        for id in previous_ids.difference(&next_ids) {
                            observations.remove_subscription_runtime(&ControlSubscriptionId::new(id.as_str())?)?;
                        }
                        for config in &latest {
                            if changed_ids.contains(&config.id)
                                && matches!(manager.load_cache(config).await, Ok(pathchord_transit::CacheLoadOutcome::Loaded { .. }))
                            {
                                releasable.insert(config.id.clone());
                            }
                        }
                        configs = latest;
                        refreshed = true;
                        due.retain(|id, _| configs.iter().any(|config| &config.id == id));
                        for config in &configs {
                            if changed_ids.contains(&config.id) {
                                due.insert(config.id.clone(), tokio::time::Instant::now());
                            } else {
                                due.entry(config.id.clone()).or_insert_with(tokio::time::Instant::now);
                            }
                        }
                    }
                    let now = tokio::time::Instant::now();
                    while let Some(requested) = {
                        control
                            .lock()
                            .await
                            .service()
                            .next_queued_subscription_refresh()
                    } {
                        let config = configs
                            .iter()
                            .find(|config| config.id.as_str() == requested.as_str());
                        let Some(config) = config else { return Ok(()); };
                        let Some(candidate) = cancellable_subscription_refresh(
                            &manager, config, observed_generation, &mut tick_shutdown,
                        ).await else { return Ok(()); };
                        let mut dispatcher = control.lock().await;
                        let current = dispatcher.service().snapshot();
                        if current.generation != observed_generation
                            || current.subscriptions.get(&requested)
                                .and_then(|state| state.spec.runtime_config().ok()).as_ref() != Some(config)
                        {
                            return Ok(());
                        }
                        let outcome = commit_subscription_refresh(
                            &mut manager, candidate, observed_generation, &mut dispatcher, &requested, &data_plane, &registry,
                        ).await?;
                        observed_generation = dispatcher.service().snapshot().generation;
                        if matches!(outcome, RefreshOutcome::Published { .. }) { releasable.insert(config.id.clone()); }
                        drop(dispatcher);
                        refreshed = true;
                    }
                    for config in &configs {
                        if !config.enabled
                            || config.source.source_type == SubscriptionSourceType::Static
                        {
                            continue;
                        }
                        let Some(next) = due.get_mut(&config.id) else {
                            continue;
                        };
                        if now < *next {
                            continue;
                        }
                        let Some(candidate) = cancellable_subscription_refresh(
                            &manager, config, observed_generation, &mut tick_shutdown,
                        ).await else { return Ok(()); };
                        let control_id = ControlSubscriptionId::new(config.id.as_str())?;
                        let mut dispatcher = control.lock().await;
                        let current = dispatcher.service().snapshot();
                        if current.generation != observed_generation
                            || current.subscriptions.get(&control_id)
                                .and_then(|state| state.spec.runtime_config().ok()).as_ref() != Some(config)
                        {
                            return Ok(());
                        }
                        let outcome = commit_subscription_refresh(
                            &mut manager, candidate, observed_generation, &mut dispatcher, &control_id, &data_plane, &registry,
                        ).await?;
                        observed_generation = dispatcher.service().snapshot().generation;
                        if matches!(outcome, RefreshOutcome::Published { .. }) { releasable.insert(config.id.clone()); }
                        drop(dispatcher);
                        *next = now + Duration::from_secs(config.refresh.interval_seconds);
                        refreshed = true;
                    }
                    let draining: Vec<_> = manager
                        .snapshot()
                        .nodes
                        .values()
                        .filter(|node| node.state == DynamicNodeState::Draining)
                        .map(|node| node.config.id.clone())
                        .collect();
                    for id in &draining {
                        data_plane.drain_transit(id).await;
                    }
                    let mut completed = BTreeSet::new();
                    for id in draining {
                        if !data_plane.transit_in_use(&id).await {
                            completed.insert(id);
                        }
                    }
                    if !completed.is_empty() {
                        let mut dispatcher = control.lock().await;
                        let current = dispatcher.service().snapshot();
                        let current_configs = current.subscriptions.values()
                            .map(|state| state.spec.runtime_config())
                            .collect::<Result<Vec<_>, _>>()?;
                        if current.generation != observed_generation || current_configs != configs {
                            return Ok(());
                        }
                        manager.complete_draining(&completed);
                        for id in &completed {
                            data_plane.remove_dynamic_transit(id).await;
                            // A new-source candidate may take over this ID as
                            // soon as the old Path has drained. Preserve its
                            // administrator metadata while replacing the adapter.
                            if !manager.snapshot().nodes.contains_key(id) {
                                let id = NodeId::new(id.as_str())?;
                                dispatcher.service().observation_handle().remove_node_metadata(&id)?;
                                dispatcher.service_mut().remove_node(&id)?;
                            }
                        }
                        observed_generation = dispatcher.service().snapshot().generation;
                        refreshed = true;
                    }
                    if refreshed {
                        let prepared = manager.snapshot().prepare_adapters(registry.as_ref()).await;
                        let dispatcher = control.lock().await;
                        let current = dispatcher.service().snapshot();
                        let current_configs = current.subscriptions.values()
                            .map(|state| state.spec.runtime_config())
                            .collect::<Result<Vec<_>, _>>()?;
                        if current.generation != observed_generation || current_configs != configs {
                            return Ok(());
                        }
                        if manager.commit_prepared_adapters(prepared).is_err() { return Ok(()); }
                        for id in &releasable {
                            data_plane.allow_subscription_after_refresh(id.as_str()).await;
                        }
                        adapter_diagnostics = publish_dynamic_transit(data_plane.as_ref(), &mut manager).await;
                        *dynamic_snapshot.write().await = manager.snapshot().clone();
                        drop(dispatcher);
                        let policy = reload.snapshot()?.config;
                        protected_endpoints.replace(
                            collect_protected_endpoints(
                                &policy,
                                dns_runtime.as_deref(),
                                Some(manager.snapshot()),
                            )
                            .await,
                        );
                    }
                    let policy = reload.snapshot()?.config;
                    sync_control_nodes(&control, data_plane.as_ref(), &policy, manager.snapshot(), &adapter_diagnostics, &configs, observed_generation).await?;
                    let observations = control.lock().await.service().observation_handle();
                    for config in &configs {
                        let count = manager.snapshot().nodes.values().filter(|node| {
                            node.state != DynamicNodeState::Draining
                                && node.config.source.as_ref().is_some_and(|source| source.subscription == config.id.as_str())
                        }).count();
                        let next = if config.enabled && config.source.source_type != SubscriptionSourceType::Static {
                            due.get(&config.id).map(|deadline| {
                                let wait = deadline.saturating_duration_since(tokio::time::Instant::now());
                                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default().saturating_add(wait).as_millis().min(u128::from(u64::MAX)) as u64
                            })
                        } else { None };
                        observations.set_subscription_runtime(ControlSubscriptionId::new(config.id.as_str())?, next, count)?;
                    }
                    Ok::<(), CliError>(())
                    };
                    match cancellable_ingress_work(shutdown.clone(), work).await {
                        Some(result) => result?,
                        None => return Ok(()),
                    }
                }
            }
        }
    }
}

async fn cancellable_ingress_work<T>(
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    let cancelled = async move {
        loop {
            if *shutdown.borrow() {
                return;
            }
            if shutdown.changed().await.is_err() {
                return;
            }
        }
    };
    tokio::select! { result = work => Some(result), () = cancelled => None }
}

async fn cancellable_subscription_refresh(
    manager: &SubscriptionManager,
    config: &pathchord_policy::SubscriptionConfig,
    generation: u64,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Option<Result<pathchord_transit::PreparedSubscriptionRefresh, RefreshOutcome>> {
    tokio::select! {
        _ = shutdown.changed() => None,
        outcome = manager.prepare_refresh(config, generation) => Some(outcome),
    }
}

async fn commit_subscription_refresh(
    manager: &mut SubscriptionManager,
    candidate: Result<pathchord_transit::PreparedSubscriptionRefresh, RefreshOutcome>,
    generation: u64,
    dispatcher: &mut LocalControlDispatcher,
    id: &ControlSubscriptionId,
    data_plane: &IngressDataPlane,
    registry: &AdapterRegistry<FileTransitCredentialProvider>,
) -> Result<RefreshOutcome, CliError> {
    // Fence the old adapters before publishing a potentially changed node.
    // A rejected commit restores the previously verified snapshot below.
    let fenced = candidate.is_ok();
    if fenced {
        let invalidated = candidate
            .as_ref()
            .expect("candidate was checked")
            .invalidated_adapters(manager.snapshot());
        data_plane
            .initialize_subscription_visibility(id.as_str(), false)
            .await;
        data_plane.retire_replaced_transit_paths(&invalidated).await;
        manager.suspend_source_admissions(&pathchord_policy::SubscriptionId::new(id.as_str()));
    }
    let mut control_error = None;
    let outcome = match candidate {
        Ok(prepared) => {
            manager
                .commit_prepared_refresh_with(prepared, generation, || {
                    match dispatcher
                        .service_mut()
                        .complete_subscription_refresh(id, true, None)
                    {
                        Ok(_) => Ok(()),
                        Err(error) => {
                            control_error = Some(error);
                            Err(pathchord_transit::SubscriptionError::ControlCommit)
                        }
                    }
                })
                .await
        }
        Err(outcome) => outcome,
    };
    if fenced && !matches!(outcome, RefreshOutcome::Published { .. }) {
        let source = pathchord_policy::SubscriptionId::new(id.as_str());
        let prepared = manager
            .snapshot()
            .prepare_source_adapters(registry, Some(&source))
            .await;
        manager.commit_prepared_adapters(prepared)?;
        data_plane
            .allow_subscription_after_refresh(id.as_str())
            .await;
        let _ = publish_dynamic_transit_for_source(data_plane, manager, Some(&source)).await;
    }
    if let Some(error) = control_error {
        return Err(error.into());
    }
    if let RefreshOutcome::Retained { error, .. } = &outcome {
        // Stale candidates never alter either the control state or cache.
        if *error != pathchord_transit::SubscriptionError::StaleCandidate {
            dispatcher.service_mut().complete_subscription_refresh(
                id,
                false,
                Some(error.to_string()),
            )?;
        }
    }
    Ok(outcome)
}

async fn run_data_plane_maintenance(
    data_plane: Arc<IngressDataPlane>,
    probe_interval: Option<Duration>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), CliError> {
    // Path replacement is a transport-recovery action rather than a slow
    // capacity adjustment. Poll the Session snapshot at one-second cadence so
    // a reserved Path is attached promptly after a disconnect.
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut probe_tick =
        tokio::time::interval(probe_interval.unwrap_or(Duration::from_secs(86_400)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = interval.tick() => {
                if cancellable_ingress_work(shutdown.clone(), data_plane.warmup()).await.is_none() {
                    return Ok(());
                }
            },
            _ = probe_tick.tick(), if probe_interval.is_some() => {
                data_plane.probe_transits().await;
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_reloaded_policies(
    handle: ConfigReloadHandle,
    data_plane: Arc<IngressDataPlane>,
    control: Arc<tokio::sync::Mutex<LocalControlDispatcher>>,
    adapter_registry: Arc<AdapterRegistry<FileTransitCredentialProvider>>,
    protected_endpoints: ProtectedEndpointSet,
    dns_runtime: Option<Arc<DnsRuntime>>,
    dynamic_snapshot: Arc<tokio::sync::RwLock<DynamicTransitSnapshot>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), CliError> {
    let mut applied_generation = handle.status().active_generation;
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = interval.tick() => {
                let Some(snapshot) = handle.pending_snapshot()? else { continue; };
                if snapshot.generation <= applied_generation { continue; }
                let validated = pathchord_policy::ValidatedPolicySnapshot::new(
                    Generation::new(snapshot.generation),
                    (*snapshot.config).clone(),
                ).map_err(pathchord_policy::ConfigError::from)?;
                let prepared = match cancellable_ingress_work(
                    shutdown.clone(),
                    data_plane.prepare_static_snapshot_with_compiled(
                        &validated,
                        (*snapshot.compiled).clone(),
                        adapter_registry.as_ref(),
                    ),
                ).await {
                    Some(Ok(prepared)) => prepared,
                    Some(Err(error)) => {
                        handle.reject_runtime_candidate(snapshot.generation, error.to_string())?;
                        continue;
                    }
                    None => return Ok(()),
                };
                let (nodes, subscriptions) = declarative_control_resources(&snapshot.config)?;
                let mut dispatcher = control.lock().await;
                let previous_subscriptions = dispatcher.service().snapshot().subscriptions;
                let handle_for_commit = handle.clone();
                let outcome = data_plane.commit_static_snapshot_with_subscription_visibility(prepared, move || {
                    let committed = handle_for_commit
                        .commit_runtime_candidate(snapshot.generation, || {
                            dispatcher
                                .service_mut()
                                .reconcile_declarative_resources(
                                    snapshot.generation,
                                    nodes,
                                    subscriptions,
                                )
                                .map_err(|_| pathchord_ingress::ReloadError::ControlCommit)
                        })
                        .map_err(|_| pathchord_ingress::DataPlaneError::ControlCommitRejected)?;
                    if committed {
                        let current = dispatcher.service().snapshot().subscriptions;
                        let mut visibility: BTreeMap<String, (bool, bool)> = previous_subscriptions.keys()
                            .map(|id| (id.as_str().to_owned(), (false, true)))
                            .collect();
                        for (id, state) in current {
                            let changed = previous_subscriptions.get(&id).is_none_or(|previous| previous.spec != state.spec);
                            visibility.insert(id.as_str().to_owned(), (state.spec.enabled, changed));
                        }
                        Ok(visibility)
                    } else {
                        Err(pathchord_ingress::DataPlaneError::ControlCommitRejected)
                    }
                }).await;
                let outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(pathchord_ingress::DataPlaneError::ControlCommitRejected) => continue,
                    Err(error) => {
                        let _ = handle.reject_runtime_candidate(snapshot.generation, error.to_string());
                        continue;
                    }
                };
                data_plane
                    .configure_node_probe(node_probe_config(snapshot.config.node_probe.as_ref()))
                    .await?;
                let dynamic = dynamic_snapshot.read().await.clone();
                let endpoints = cancellable_ingress_work(
                    shutdown.clone(),
                    collect_protected_endpoints(&snapshot.config, dns_runtime.as_deref(), Some(&dynamic)),
                ).await;
                let Some(endpoints) = endpoints else { return Ok(()); };
                protected_endpoints.replace(endpoints);
                applied_generation = outcome.generation;
            }
        }
    }
}

fn declarative_control_resources(
    config: &PolicyConfig,
) -> Result<(Vec<NodeId>, Vec<ControlSubscriptionSpec>), CliError> {
    let nodes = config
        .transit_proxies
        .iter()
        .map(|proxy| NodeId::new(proxy.id.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    let subscriptions = config
        .subscriptions
        .iter()
        .map(|subscription| {
            Ok(ControlSubscriptionSpec {
                id: ControlSubscriptionId::new(subscription.id.as_str())?,
                source_type: subscription.source.source_type.as_str().to_owned(),
                display_name: subscription.id.resource_name().to_owned(),
                enabled: subscription.enabled,
                url: subscription.source.url.clone(),
                credentials_ref: subscription.source.credentials_ref.clone(),
                user_agent: subscription.source.user_agent.clone(),
                refresh: ControlSubscriptionRefreshSpec {
                    interval_seconds: subscription.refresh.interval_seconds,
                    timeout_seconds: subscription.refresh.timeout_seconds,
                    max_attempts: subscription.refresh.max_attempts,
                    backoff_seconds: subscription.refresh.backoff_seconds,
                },
                cache: subscription
                    .cache
                    .as_ref()
                    .map(|cache| ControlSubscriptionCacheSpec {
                        path: cache.path.clone(),
                        max_age_seconds: cache.max_age_seconds,
                    }),
            })
        })
        .collect::<Result<Vec<_>, pathchord_ingress::ControlError>>()?;
    Ok((nodes, subscriptions))
}

async fn collect_protected_endpoints(
    policy: &PolicyConfig,
    dns: Option<&DnsRuntime>,
    dynamic: Option<&DynamicTransitSnapshot>,
) -> BTreeSet<SocketAddr> {
    let mut endpoints = dns.map(DnsRuntime::protected_endpoints).unwrap_or_default();
    for endpoint in policy
        .egresses
        .iter()
        .flat_map(|egress| egress.endpoints.iter())
        .chain(
            policy
                .transit_proxies
                .iter()
                .filter(|proxy| proxy.protocol != "direct")
                .map(|proxy| &proxy.endpoint),
        )
    {
        if let Ok(address) = endpoint.host.parse() {
            endpoints.insert(SocketAddr::new(address, endpoint.port));
            continue;
        }
        if let Ok(addresses) =
            tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port)).await
        {
            endpoints.extend(addresses);
        }
    }
    if let Some(dynamic) = dynamic {
        for node in dynamic.nodes.values() {
            extend_resolved_endpoint(
                &mut endpoints,
                &node.config.endpoint.host,
                node.config.endpoint.port,
            )
            .await;
        }
    }
    for subscription in &policy.subscriptions {
        if let Ok(url) = url::Url::parse(&subscription.source.url)
            && let Some(host) = url.host_str()
        {
            let port = url.port_or_known_default().unwrap_or(443);
            extend_resolved_endpoint(&mut endpoints, host, port).await;
        }
    }
    endpoints
}

async fn extend_resolved_endpoint(endpoints: &mut BTreeSet<SocketAddr>, host: &str, port: u16) {
    if let Ok(address) = host.parse() {
        endpoints.insert(SocketAddr::new(address, port));
    } else if let Ok(addresses) = tokio::net::lookup_host((host, port)).await {
        endpoints.extend(addresses);
    }
}

async fn publish_dynamic_transit(
    data_plane: &IngressDataPlane,
    manager: &mut SubscriptionManager,
) -> BTreeMap<pathchord_policy::TransitProxyId, pathchord_transit::NodeDiagnostic> {
    publish_dynamic_transit_for_source(data_plane, manager, None).await
}

async fn publish_dynamic_transit_for_source(
    data_plane: &IngressDataPlane,
    manager: &mut SubscriptionManager,
    source: Option<&pathchord_policy::SubscriptionId>,
) -> BTreeMap<pathchord_policy::TransitProxyId, pathchord_transit::NodeDiagnostic> {
    let mut diagnostics = BTreeMap::new();
    let snapshot = manager.snapshot().clone();
    for node in snapshot.nodes.values() {
        if source.is_some_and(|source| &node.source_subscription != source) {
            continue;
        }
        let mut status = TransitProxyRuntimeStatus {
            state: match node.state {
                DynamicNodeState::Active => RuntimeNodeState::Ready,
                DynamicNodeState::Pending => RuntimeNodeState::Down,
                DynamicNodeState::Draining => RuntimeNodeState::Draining,
                DynamicNodeState::Unavailable(_) => RuntimeNodeState::Down,
            },
            capabilities: transit_capabilities(&node.config.protocol),
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            selection_score: 1,
            quota_remaining: node
                .usage
                .as_ref()
                .and_then(|usage| usage.remaining_bytes()),
            traffic_multiplier_basis_points: node
                .usage
                .as_ref()
                .and_then(|usage| usage.traffic_multiplier_basis_points),
        };
        if let Some(admission) = snapshot.validated_admission(&node.config.id) {
            let adapter = admission.adapter();
            status.capabilities = adapter_capabilities(adapter.as_ref(), &node.config.options);
            let outcome = data_plane
                .register_verified_dynamic_transit_adapter(node.config.clone(), admission, status)
                .await;
            if outcome == DynamicTransitRegistration::Registered {
                continue;
            }
            manager.reject_admitted_adapter(&node.config.id);
            diagnostics.insert(
                node.config.id.clone(),
                pathchord_transit::NodeDiagnostic {
                    code: pathchord_transit::NodeUnavailableReason::AdapterUnavailable,
                    fields: Vec::new(),
                    message: "node adapter could not be installed".into(),
                },
            );
            continue;
        }
        status.state = match node.state {
            DynamicNodeState::Draining => RuntimeNodeState::Draining,
            _ => RuntimeNodeState::Down,
        };
        status.capabilities.clear();
        data_plane
            .publish_dynamic_transit_status(node.config.clone(), status)
            .await;
    }
    diagnostics
}

type NodeSourceIdentity = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

struct ProbeObservationFence {
    control_generation: u64,
    dynamic_generation: u64,
    policy_generation: u64,
    sources: BTreeMap<NodeId, NodeSourceIdentity>,
}

fn node_source_identities(
    observations: &pathchord_ingress::ObservationSnapshot,
) -> BTreeMap<NodeId, NodeSourceIdentity> {
    observations
        .node_metadata
        .iter()
        .map(|(id, metadata)| {
            (
                id.clone(),
                (
                    metadata.namespace.clone(),
                    metadata.protocol.clone(),
                    metadata.endpoint.clone(),
                    metadata.source_subscription.clone(),
                ),
            )
        })
        .collect()
}

fn configured_node_identity(node: &pathchord_policy::TransitProxyConfig) -> NodeSourceIdentity {
    (
        Some(node.id.namespace().to_owned()),
        Some(node.protocol.clone()),
        Some(format!("{}:{}", node.endpoint.host, node.endpoint.port)),
        node.source
            .as_ref()
            .map(|source| source.subscription.clone()),
    )
}

fn empty_node_observation() -> NodeObservation {
    NodeObservation {
        state: NodeHealthState::Unknown,
        rtt_ms: None,
        jitter_ms: None,
        loss_ppm: None,
        throughput_bps: None,
        effective_capacity_bps: None,
        diagnostic: None,
        usage: None,
    }
}

async fn probe_observation_fence(
    control: &Arc<tokio::sync::Mutex<LocalControlDispatcher>>,
    data_plane: &IngressDataPlane,
    dynamic: &tokio::sync::RwLock<DynamicTransitSnapshot>,
) -> ProbeObservationFence {
    // Publication and reload already acquire control before dynamic. Never
    // retain a data-plane lock while waiting for either of these locks.
    let dispatcher = control.lock().await;
    ProbeObservationFence {
        control_generation: dispatcher.service().snapshot().generation,
        dynamic_generation: dynamic.read().await.generation,
        policy_generation: data_plane.policy_generation(),
        sources: node_source_identities(&dispatcher.service().observation_snapshot()),
    }
}

async fn apply_probe_observations(
    control: &Arc<tokio::sync::Mutex<LocalControlDispatcher>>,
    data_plane: &IngressDataPlane,
    dynamic: &tokio::sync::RwLock<DynamicTransitSnapshot>,
    fence: ProbeObservationFence,
    probes: BTreeMap<pathchord_policy::TransitProxyId, pathchord_ingress::TransitProbeObservation>,
) -> Result<(), CliError> {
    let mut dispatcher = control.lock().await;
    let snapshot = dispatcher.service().snapshot();
    if snapshot.generation != fence.control_generation
        || dynamic.read().await.generation != fence.dynamic_generation
        || data_plane.policy_generation() != fence.policy_generation
    {
        return Ok(());
    }
    let observations = dispatcher.service().observation_snapshot();
    let current_sources = node_source_identities(&observations);
    let existing = observations.nodes;
    for (id, probe) in probes {
        let Ok(node_id) = NodeId::new(id.as_str()) else {
            continue;
        };
        if !snapshot.nodes.contains_key(&node_id)
            || !fence.sources.contains_key(&node_id)
            || fence.sources.get(&node_id) != current_sources.get(&node_id)
        {
            continue;
        }
        let mut observation = existing
            .get(&node_id)
            .cloned()
            .unwrap_or_else(empty_node_observation);
        observation.state = if observation.diagnostic.is_some() {
            NodeHealthState::Down
        } else {
            match probe.state {
                TransitProbeState::Up => NodeHealthState::Up,
                TransitProbeState::Degraded => NodeHealthState::Degraded,
                TransitProbeState::Down => NodeHealthState::Down,
                TransitProbeState::Unknown => NodeHealthState::Unknown,
            }
        };
        observation.rtt_ms = probe
            .rtt_ms
            .map(|value| value.min(u64::from(u32::MAX)) as u32);
        observation.jitter_ms = probe
            .jitter_ms
            .map(|value| value.min(u64::from(u32::MAX)) as u32);
        observation.loss_ppm = probe.loss_ppm;
        observation.throughput_bps = probe.throughput_bps;
        observation.effective_capacity_bps = probe.effective_capacity_bps;
        dispatcher
            .service_mut()
            .set_node_observation(node_id, observation)
            .map_err(|error| CliError::Observation(error.to_string()))?;
    }
    Ok(())
}

async fn publish_probe_observations(
    control: &Arc<tokio::sync::Mutex<LocalControlDispatcher>>,
    data_plane: &IngressDataPlane,
    dynamic: &tokio::sync::RwLock<DynamicTransitSnapshot>,
) -> Result<(), CliError> {
    let fence = probe_observation_fence(control, data_plane, dynamic).await;
    let probes = data_plane.transit_observations().await;
    apply_probe_observations(control, data_plane, dynamic, fence, probes).await
}

#[allow(clippy::too_many_arguments)]
async fn sync_control_nodes(
    control: &Arc<tokio::sync::Mutex<LocalControlDispatcher>>,
    data_plane: &IngressDataPlane,
    policy: &PolicyConfig,
    snapshot: &DynamicTransitSnapshot,
    adapter_diagnostics: &BTreeMap<
        pathchord_policy::TransitProxyId,
        pathchord_transit::NodeDiagnostic,
    >,
    subscriptions: &[pathchord_policy::SubscriptionConfig],
    expected_generation: u64,
) -> Result<(), CliError> {
    let admin = {
        let mut dispatcher = control.lock().await;
        let control_snapshot = dispatcher.service().snapshot();
        if control_snapshot.generation != expected_generation {
            return Ok(());
        }
        let previous = dispatcher.service().observation_snapshot();
        let previous_sources = node_source_identities(&previous);
        let observations = dispatcher.service().observation_handle();
        for node in &policy.transit_proxies {
            let id = NodeId::new(node.id.as_str())?;
            if !control_snapshot.nodes.contains_key(&id) {
                continue;
            }
            if previous.nodes.contains_key(&id)
                && previous_sources.get(&id) != Some(&configured_node_identity(node))
            {
                dispatcher
                    .service_mut()
                    .set_node_observation(id.clone(), empty_node_observation())?;
            }
            observations.set_node_metadata(
                id,
                Some(node.id.namespace().to_owned()),
                Some(node.protocol.clone()),
                Some(format!("{}:{}", node.endpoint.host, node.endpoint.port)),
                node.source
                    .as_ref()
                    .map(|source| source.subscription.clone()),
                node.labels.clone(),
            )?;
        }
        for node in snapshot.nodes.values() {
            // The worker's last snapshot can outlive deletion or replacement
            // of its source. Check and register under the same control lock.
            let source = ControlSubscriptionId::new(node.source_subscription.as_str())?;
            let expected = subscriptions
                .iter()
                .find(|config| config.id == node.source_subscription);
            let current = control_snapshot
                .subscriptions
                .get(&source)
                .and_then(|state| state.spec.runtime_config().ok());
            if expected.is_none() || current.as_ref() != expected {
                continue;
            }
            let id = NodeId::new(node.config.id.as_str())?;
            if node.state == DynamicNodeState::Draining && !control_snapshot.nodes.contains_key(&id)
            {
                continue;
            }
            dispatcher.service_mut().add_node(id.clone())?;
            let same_source =
                previous_sources.get(&id) == Some(&configured_node_identity(&node.config));
            let mut observation = previous
                .nodes
                .get(&id)
                .filter(|_| same_source)
                .cloned()
                .unwrap_or_else(empty_node_observation);
            let had_diagnostic = observation.diagnostic.is_some();
            observation.diagnostic = adapter_diagnostics
                .get(&node.config.id)
                .cloned()
                .or_else(|| node.diagnostic.clone());
            observation.usage = node.usage.clone();
            observation.state = if observation.diagnostic.is_some() {
                NodeHealthState::Down
            } else {
                match node.state {
                    DynamicNodeState::Active if had_diagnostic => NodeHealthState::Unknown,
                    DynamicNodeState::Active => observation.state,
                    DynamicNodeState::Pending => NodeHealthState::Unknown,
                    DynamicNodeState::Draining => NodeHealthState::Degraded,
                    DynamicNodeState::Unavailable(_) => NodeHealthState::Down,
                }
            };
            observations.set_node_metadata(
                id.clone(),
                Some(node.config.id.namespace().to_owned()),
                Some(node.config.protocol.clone()),
                Some(format!(
                    "{}:{}",
                    node.config.endpoint.host, node.config.endpoint.port
                )),
                node.config
                    .source
                    .as_ref()
                    .map(|source| source.subscription.clone()),
                node.config.labels.clone(),
            )?;
            dispatcher
                .service_mut()
                .set_node_observation(id, observation)?;
        }
        dispatcher.service().snapshot().nodes
    };
    for (id, state) in admin {
        let transit_id = pathchord_policy::TransitProxyId::new(id.as_str());
        data_plane
            .apply_transit_admin_metadata(&transit_id, state.labels, state.tags)
            .await;
    }
    Ok(())
}

fn transit_capabilities(protocol: &str) -> BTreeSet<FlowProtocol> {
    if matches!(
        protocol,
        "direct"
            | "socks5"
            | "ss"
            | "trojan"
            | "vless"
            | "vmess"
            | "hysteria"
            | "hysteria2"
            | "tuic"
            | "wireguard"
    ) {
        BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
    } else {
        BTreeSet::from([FlowProtocol::Tcp])
    }
}

fn adapter_capabilities(
    adapter: &dyn pathchord_transit::TransitAdapter,
    options: &pathchord_policy::TransitOptions,
) -> BTreeSet<FlowProtocol> {
    let mut capabilities = BTreeSet::new();
    if adapter.supports_tcp() {
        capabilities.insert(FlowProtocol::Tcp);
    }
    if adapter.supports_udp() && options.udp != Some(false) {
        capabilities.insert(FlowProtocol::Udp);
    }
    capabilities
}

fn node_probe_config(
    spec: Option<&pathchord_policy::NodeProbePolicySpec>,
) -> Option<TransitProbeConfig> {
    spec.map(|spec| {
        let mut config = TransitProbeConfig::new(pathchord_transit::Endpoint {
            host: spec.target.host.clone(),
            port: spec.target.port,
        });
        config.timeout = Duration::from_secs(spec.timeout_seconds);
        config.max_concurrency = spec.max_concurrency;
        config.window_size = spec.window_size;
        config.max_nodes_per_batch = spec.max_nodes_per_batch;
        config
    })
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

fn listener_descriptor(listener: ListenerConfig) -> Result<ListenerDescriptor, CliError> {
    let kind = match listener.kind {
        PolicyListenerKind::Http => ListenerKind::Http,
        PolicyListenerKind::Socks5 => ListenerKind::Socks5,
        PolicyListenerKind::Mixed => ListenerKind::Mixed,
        PolicyListenerKind::Tproxy => ListenerKind::Tproxy,
        PolicyListenerKind::Redirect => ListenerKind::Redirect,
        PolicyListenerKind::Tun => ListenerKind::Tun,
    };
    let bind = listener
        .bind
        .as_ref()
        .map(|bind_endpoint| {
            parse_bind(&bind_endpoint.host, bind_endpoint.port).ok_or_else(|| {
                CliError::InvalidListenerBind {
                    listener_id: listener.id.as_str().to_owned(),
                    bind: format!("{}:{}", bind_endpoint.host, bind_endpoint.port),
                }
            })
        })
        .transpose()?;
    let mut allowed_sources = listener.allowed_sources;
    if let Some(bind) = bind
        && allowed_sources.is_empty()
        && bind.ip().is_loopback()
    {
        let prefix = if bind.is_ipv4() { 32 } else { 128 };
        allowed_sources.push(format!("{}/{}", bind.ip(), prefix));
    }
    Ok(ListenerDescriptor {
        id: listener.id,
        kind,
        bind,
        interface: listener.interface,
        address: listener.address,
        mtu: listener.mtu,
        flow_tags: listener.flow_tags,
        process_metadata: listener.process_metadata,
        allowed_sources,
        authentication_required: matches!(listener.authentication, AuthenticationMode::Required),
    })
}

fn parse_bind(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    let value = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    value.parse().ok()
}

fn load_identity(path: &std::path::Path) -> Result<StaticKeypair, CliError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::InvalidIdentity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::InsecureIdentityPermissions);
        }
    }
    let file = std::fs::File::open(path)?;
    let mut encoded = Zeroizing::new(Vec::new());
    file.take(4097).read_to_end(&mut encoded)?;
    if encoded.len() > 4096 || !encoded.starts_with(IDENTITY_FILE_HEADER) {
        return Err(CliError::InvalidIdentity);
    }
    let body = &encoded[IDENTITY_FILE_HEADER.len()..];
    let body = body.strip_suffix(b"\n").unwrap_or(body);
    if body.is_empty() || body.contains(&b'\n') || body.contains(&b'\r') {
        return Err(CliError::InvalidIdentity);
    }
    let mut decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| CliError::InvalidIdentity)?,
    );
    let private: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| CliError::InvalidIdentity)?;
    decoded.zeroize();
    Ok(StaticKeypair::from_private(private))
}

fn write_identity(path: &std::path::Path, identity: &StaticKeypair) -> Result<(), CliError> {
    let encoded_private = Zeroizing::new(URL_SAFE_NO_PAD.encode(identity.private()));
    let mut contents = Zeroizing::new(Vec::with_capacity(
        IDENTITY_FILE_HEADER.len() + encoded_private.len() + 1,
    ));
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

fn load_web_token(path: &std::path::Path) -> Result<WebBearerToken, CliError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::InvalidWebToken);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::InsecureWebTokenPermissions);
        }
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(CliError::InvalidWebToken);
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(CliError::InvalidWebToken);
    }
    let token =
        Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| CliError::InvalidWebToken)?);
    Ok(WebBearerToken::new(token.as_str()))
}

/// Adapts the concrete Egress TCP connector to the transport-neutral local
/// flow bridge used by listener runtimes.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct TcpIngressDialer {
    connector: TcpTargetConnector,
    policy: BootstrapPolicy,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapPolicy {
    Direct,
    Reject,
    UnsupportedRules,
}

#[cfg(test)]
impl TcpIngressDialer {
    fn new(config: &PolicyConfig) -> Self {
        let policy = if !config.egress_rules.is_empty()
            || !config.transit_rules.is_empty()
            || !config.proxy_rules.is_empty()
        {
            BootstrapPolicy::UnsupportedRules
        } else if config.fallback == Some(FallbackAction::Direct) {
            BootstrapPolicy::Direct
        } else {
            BootstrapPolicy::Reject
        };
        Self {
            connector: TcpTargetConnector::new(),
            policy,
        }
    }
}

#[cfg(test)]
#[async_trait]
impl IngressTargetDialer for TcpIngressDialer {
    async fn connect(
        &self,
        context: pathchord_ingress::ConnectionContext,
    ) -> Result<BoxedLocalConnection, FlowBridgeError> {
        match self.policy {
            BootstrapPolicy::Direct => {}
            BootstrapPolicy::Reject => {
                return Err(FlowBridgeError::Dial(
                    "local policy fallback rejects direct traffic".to_owned(),
                ));
            }
            BootstrapPolicy::UnsupportedRules => {
                return Err(FlowBridgeError::Dial(
                    "configured policy rules require a Session/Transit runtime".to_owned(),
                ));
            }
        }
        let request = target_request(context.target);
        self.connector
            .connect_tcp(request)
            .await
            .map(|stream| Box::new(stream) as BoxedLocalConnection)
            .map_err(|error| FlowBridgeError::Dial(error.to_string()))
    }
}

#[cfg(test)]
fn target_request(target: TargetAddress) -> TargetRequest {
    match target.host {
        TargetHost::Hostname(host) => TargetRequest {
            original_hostname: Some(host),
            resolved_ip_candidates: Vec::new(),
            port: target.port,
        },
        TargetHost::Ip(address) => TargetRequest {
            original_hostname: None,
            resolved_ip_candidates: vec![address],
            port: target.port,
        },
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
async fn call_local(
    socket: &std::path::Path,
    request: RequestEnvelope,
) -> Result<ResponseEnvelope, CliError> {
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(LocalProtocolError::from)?;
    exchange_local(&mut stream, &request).await
}

#[cfg(windows)]
async fn call_local(
    socket: &std::path::Path,
    request: RequestEnvelope,
) -> Result<ResponseEnvelope, CliError> {
    use std::time::Duration;

    use tokio::net::windows::named_pipe::ClientOptions;

    const ERROR_PIPE_BUSY: i32 = 231;
    const MAX_CONNECT_ATTEMPTS: usize = 100;
    const RETRY_DELAY: Duration = Duration::from_millis(50);

    let mut last_busy_error = None;
    for attempt in 0..MAX_CONNECT_ATTEMPTS {
        match ClientOptions::new().open(socket) {
            Ok(mut pipe) => return exchange_local(&mut pipe, &request).await,
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                last_busy_error = Some(error);
                if attempt + 1 < MAX_CONNECT_ATTEMPTS {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
            Err(error) => return Err(LocalProtocolError::from(error).into()),
        }
    }

    match last_busy_error {
        Some(error) => Err(LocalProtocolError::from(error).into()),
        None => {
            Err(LocalProtocolError::Io("named pipe connection retries exhausted".to_owned()).into())
        }
    }
}

#[cfg(not(any(unix, windows)))]
async fn call_local(
    _socket: &std::path::Path,
    _request: RequestEnvelope,
) -> Result<ResponseEnvelope, CliError> {
    Err(CliError::UnsupportedTransport {
        platform: std::env::consts::OS,
    })
}

#[cfg(any(unix, windows, test))]
async fn exchange_local<S>(
    stream: &mut S,
    request: &RequestEnvelope,
) -> Result<ResponseEnvelope, CliError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_object(stream, request).await?;
    Ok(read_object(stream).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[tokio::test]
    async fn shutdown_cancels_inflight_subscription_backend_work() {
        struct DropFlag(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let owner = DropFlag(Arc::clone(&dropped));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (cancel, shutdown) = tokio::sync::watch::channel(false);
        let work = async move {
            let _owner = owner;
            let _ = started.send(());
            std::future::pending::<()>().await;
        };
        let task = tokio::spawn(cancellable_ingress_work(shutdown, work));
        ready.await.unwrap();
        cancel.send(true).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert!(dropped.load(Ordering::SeqCst));
    }
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};

    static NEXT_CONTROL_SOCKET: AtomicU64 = AtomicU64::new(0);

    async fn echo_target() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("target bind");
        let address = listener.local_addr().expect("target address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("target accept");
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.expect("target read");
            stream.write_all(&payload).await.expect("target write");
            payload
        });
        (address, task)
    }

    async fn start_runtime(
        listener: impl pathchord_ingress::IngressListener + 'static,
    ) -> (
        SocketAddr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<pathchord_ingress::RuntimeReport>,
        mpsc::UnboundedReceiver<pathchord_ingress::ListenerRuntimeEvent>,
    ) {
        let mut runtime = ListenerRuntime::new(TcpIngressDialer::new(&PolicyConfig {
            fallback: Some(FallbackAction::Direct),
            ..PolicyConfig::default()
        }));
        let address = listener.local_addr().expect("proxy address");
        runtime.add_listener(listener).expect("runtime listener");
        let (events, receiver) = mpsc::unbounded_channel();
        runtime.set_event_sender(events);
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(async move {
            runtime
                .run_until_shutdown(async move {
                    let _ = signal.await;
                })
                .await
                .expect("runtime")
        });
        (address, shutdown, task, receiver)
    }

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
        assert_eq!(cli.socket, Some(PathBuf::from("/tmp/ingress.sock")));
        assert_eq!(cli.actor, "operator");
        assert_eq!(cli.command, Command::Status);
    }

    #[test]
    fn parses_ingress_config_argument() {
        let cli = Cli::try_parse_from(["pathchord", "ingress", "--config", "config.yaml"])
            .expect("ingress args");
        assert!(matches!(
            cli.command,
            Command::Ingress(IngressArgs { config: Some(config), .. }) if config.as_os_str() == "config.yaml"
        ));
    }

    #[test]
    fn declared_subscriptions_keep_qualified_ids_and_canonical_display_names_in_control() {
        let configs: Vec<_> = ["tenant-a", "tenant-b"]
            .into_iter()
            .map(|namespace| pathchord_policy::SubscriptionConfig {
                id: pathchord_policy::SubscriptionId::in_namespace(namespace, "provider"),
                enabled: true,
                source: pathchord_policy::SubscriptionSource {
                    source_type: pathchord_policy::SubscriptionSourceType::Clash,
                    url: format!("https://example.test/{namespace}"),
                    credentials_ref: Some(format!("{namespace}-secret")),
                    user_agent: None,
                },
                refresh: Default::default(),
                cache: None,
            })
            .collect();
        let config = PolicyConfig {
            subscriptions: configs.clone(),
            ..Default::default()
        };
        let (_, specs) = declarative_control_resources(&config).unwrap();
        assert_ne!(specs[0].id, specs[1].id);
        for (spec, expected) in specs.iter().zip(&configs) {
            assert_eq!(spec.display_name, "provider");
            assert_eq!(spec.runtime_config().unwrap(), *expected);
        }
    }

    #[test]
    fn parses_a_configuration_directory_without_an_implicit_working_directory_file() {
        let cli = Cli::try_parse_from(["pathchord", "ingress", "--config-dir", "conf.d"]).unwrap();
        assert!(
            matches!(cli.command, Command::Ingress(IngressArgs { config: None, config_dir: Some(directory), .. }) if directory == std::path::Path::new("conf.d"))
        );
        let cli = Cli::try_parse_from(["pathchord", "ingress"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Ingress(IngressArgs {
                config: None,
                config_dir: None,
                ..
            })
        ));
        assert!(
            Cli::try_parse_from([
                "pathchord",
                "ingress",
                "--config",
                "a.yaml",
                "--config-dir",
                "conf.d"
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_enrollment_commands() {
        let add = Cli::try_parse_from([
            "pathchord",
            "enroll",
            "add",
            "--ingress-id",
            "ingress-a",
            "--egress-id",
            "egress-a",
            "--public-key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--expected-generation",
            "4",
            "--label",
            "admin.region=jp",
        ])
        .expect("enroll add args");
        assert!(matches!(
            add.command,
            Command::Enroll(EnrollmentArgs {
                command: EnrollmentCommand::Add(EnrollmentAddArgs {
                    ingress_id,
                    egress_id,
                    expected_generation: 4,
                    labels,
                    ..
                })
            }) if ingress_id == "ingress-a"
                && egress_id == "egress-a"
                && labels == vec!["admin.region=jp"]
        ));

        let leading_hyphen_key = "-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let add = Cli::try_parse_from([
            "pathchord",
            "enroll",
            "add",
            "--ingress-id",
            "ingress-a",
            "--egress-id",
            "egress-a",
            "--public-key",
            leading_hyphen_key,
            "--expected-generation",
            "4",
        ])
        .expect("base64url keys can begin with a hyphen");
        assert!(matches!(
            add.command,
            Command::Enroll(EnrollmentArgs {
                command: EnrollmentCommand::Add(EnrollmentAddArgs { public_key, .. })
            }) if public_key == leading_hyphen_key
        ));

        let revoke = Cli::try_parse_from([
            "pathchord",
            "enroll",
            "revoke",
            "--ingress-id",
            "ingress-a",
            "--expected-generation",
            "5",
        ])
        .expect("enroll revoke args");
        assert!(matches!(
            revoke.command,
            Command::Enroll(EnrollmentArgs {
                command: EnrollmentCommand::Revoke(EnrollmentMutationArgs {
                    ingress_id,
                    expected_generation: 5,
                })
            }) if ingress_id == "ingress-a"
        ));
    }

    #[test]
    fn maps_policy_listener_bind_and_kind() {
        for (policy_kind, kind) in [
            (PolicyListenerKind::Http, ListenerKind::Http),
            (PolicyListenerKind::Socks5, ListenerKind::Socks5),
            (PolicyListenerKind::Mixed, ListenerKind::Mixed),
        ] {
            let listener = ListenerConfig {
                id: pathchord_policy::ListenerId::new("local-http"),
                kind: policy_kind,
                platform: "any".to_owned(),
                bind: Some(pathchord_policy::Endpoint {
                    host: "127.0.0.1".into(),
                    port: 8080,
                }),
                allowed_sources: Vec::new(),
                authentication: AuthenticationMode::Required,
                backend: Default::default(),
                credentials_ref: Some("listener-users".to_owned()),
                flow_tags: std::collections::BTreeSet::new(),
                process_metadata: pathchord_policy::ProcessMetadataRequest::default(),
                mark: None,
                route_table: None,
                protocols: std::collections::BTreeSet::from([pathchord_policy::FlowProtocol::Tcp]),
                interface: None,
                address: None,
                mtu: None,
                bypass: Vec::new(),
                proxy_ref: None,
            };
            let descriptor = listener_descriptor(listener).expect("descriptor");
            assert_eq!(descriptor.kind, kind);
            assert_eq!(descriptor.bind.expect("bind").port(), 8080);
            assert_eq!(descriptor.allowed_sources, vec!["127.0.0.1/32"]);
            assert!(descriptor.authentication_required);
        }
    }

    #[test]
    fn preserves_hostname_for_egress_resolution() {
        let request = target_request(TargetAddress {
            host: TargetHost::Hostname("example.test".to_owned()),
            port: 443,
        });
        assert_eq!(request.original_hostname.as_deref(), Some("example.test"));
        assert!(request.resolved_ip_candidates.is_empty());
        assert_eq!(request.port, 443);
    }

    #[test]
    fn maps_ip_target_to_an_explicit_egress_candidate() {
        let address = "192.0.2.10".parse().expect("IP address");
        let request = target_request(TargetAddress {
            host: TargetHost::Ip(address),
            port: 8443,
        });
        assert_eq!(request.original_hostname, None);
        assert_eq!(request.resolved_ip_candidates, vec![address]);
        assert_eq!(request.port, 8443);
    }

    #[tokio::test]
    async fn http_listener_bridges_to_a_tcp_target() {
        let (target_address, target_task) = echo_target().await;
        let descriptor = ListenerDescriptor {
            id: pathchord_ingress::ListenerId::new("http-e2e"),
            kind: ListenerKind::Http,
            bind: Some("127.0.0.1:0".parse().expect("proxy bind")),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: std::collections::BTreeSet::new(),
            process_metadata: pathchord_policy::ProcessMetadataRequest::default(),
            allowed_sources: Vec::new(),
            authentication_required: false,
        };
        let listener = pathchord_ingress::HttpConnectListener::bind(descriptor)
            .await
            .expect("HTTP bind");
        let (proxy_address, shutdown, runtime_task, mut events) = start_runtime(listener).await;

        let mut client = TcpStream::connect(proxy_address)
            .await
            .expect("proxy connect");
        let request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            target_address, target_address
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("HTTP request");
        let mut response = [0_u8; 39];
        client
            .read_exact(&mut response)
            .await
            .expect("HTTP response");
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        client.write_all(b"http-e2e").await.expect("HTTP payload");
        client.shutdown().await.expect("HTTP half-close");
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.expect("HTTP echo");
        assert_eq!(echoed, b"http-e2e");

        loop {
            match events.recv().await {
                Some(pathchord_ingress::ListenerRuntimeEvent::ConnectionCompleted { .. }) => {
                    break;
                }
                Some(_) => {}
                None => panic!("runtime event channel closed before completion"),
            }
        }
        shutdown.send(()).expect("runtime shutdown");
        let report = runtime_task.await.expect("runtime task");
        assert_eq!(report.accepted_connections, 1);
        assert_eq!(report.completed_connections, 1);
        assert_eq!(report.local_to_target_bytes, 8);
        assert_eq!(target_task.await.expect("target task"), b"http-e2e");
    }

    #[tokio::test]
    async fn socks_listener_bridges_to_a_tcp_target() {
        let (target_address, target_task) = echo_target().await;
        let descriptor = ListenerDescriptor {
            id: pathchord_ingress::ListenerId::new("socks-e2e"),
            kind: ListenerKind::Socks5,
            bind: Some("127.0.0.1:0".parse().expect("proxy bind")),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: std::collections::BTreeSet::new(),
            process_metadata: pathchord_policy::ProcessMetadataRequest::default(),
            allowed_sources: Vec::new(),
            authentication_required: false,
        };
        let listener = pathchord_ingress::Socks5Listener::bind(descriptor)
            .await
            .expect("SOCKS bind");
        let (proxy_address, shutdown, runtime_task, mut events) = start_runtime(listener).await;

        let mut client = TcpStream::connect(proxy_address)
            .await
            .expect("proxy connect");
        client.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.expect("SOCKS method");
        assert_eq!(method, [5, 0]);
        let target_ip = match target_address.ip() {
            std::net::IpAddr::V4(address) => address.octets(),
            std::net::IpAddr::V6(_) => panic!("test target must be IPv4"),
        };
        let target_port = target_address.port().to_be_bytes();
        client
            .write_all(&[
                5,
                1,
                0,
                1,
                target_ip[0],
                target_ip[1],
                target_ip[2],
                target_ip[3],
                target_port[0],
                target_port[1],
            ])
            .await
            .expect("SOCKS CONNECT");
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.expect("SOCKS reply");
        assert_eq!(reply[1], 0);
        client.write_all(b"socks-e2e").await.expect("SOCKS payload");
        client.shutdown().await.expect("SOCKS half-close");
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.expect("SOCKS echo");
        assert_eq!(echoed, b"socks-e2e");

        loop {
            match events.recv().await {
                Some(pathchord_ingress::ListenerRuntimeEvent::ConnectionCompleted { .. }) => {
                    break;
                }
                Some(_) => {}
                None => panic!("runtime event channel closed before completion"),
            }
        }
        shutdown.send(()).expect("runtime shutdown");
        let report = runtime_task.await.expect("runtime task");
        assert_eq!(report.accepted_connections, 1);
        assert_eq!(report.completed_connections, 1);
        assert_eq!(report.local_to_target_bytes, 9);
        assert_eq!(target_task.await.expect("target task"), b"socks-e2e");
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

        let list = authorizations_list_request("operator");
        assert_eq!(list.operation, "authorizations.list");
        assert_eq!(list.actor.capabilities, vec!["status:read"]);

        let enroll = authorization_enroll_request(
            "operator",
            "ingress-a",
            "egress-a",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            7,
            BTreeMap::from([("admin.region".to_owned(), "jp".to_owned())]),
        );
        assert_eq!(enroll.operation, "authorizations.enroll");
        assert_eq!(enroll.body["ingress_id"], "ingress-a");
        assert_eq!(enroll.body["administrator_labels"]["admin.region"], "jp");
        assert_eq!(
            enroll.expected_generation,
            Some(pathchord_ingress::GenerationExpectation {
                scope: "authorization".to_owned(),
                value: 7,
            })
        );

        let revoke = authorization_revoke_request("operator", "ingress-a", 8);
        assert_eq!(revoke.operation, "authorizations.revoke");
        assert_eq!(revoke.body["ingress_id"], "ingress-a");
        assert_eq!(revoke.expected_generation.expect("generation").value, 8);
    }

    #[test]
    fn administrator_labels_require_unique_key_value_pairs() {
        assert_eq!(
            parse_labels(vec!["admin.region=jp".to_owned()]).unwrap(),
            BTreeMap::from([("admin.region".to_owned(), "jp".to_owned())])
        );
        assert!(matches!(
            parse_labels(vec!["missing-separator".to_owned()]),
            Err(CliError::InvalidLabel { .. })
        ));
        assert!(matches!(
            parse_labels(vec!["a=1".to_owned(), "a=2".to_owned()]),
            Err(CliError::InvalidLabel { .. })
        ));
    }

    #[test]
    fn parses_node_and_key_generation_commands() {
        let keygen = Cli::try_parse_from(["pathchord", "keygen", "--output", "identity.key"])
            .expect("keygen args");
        assert!(matches!(
            keygen.command,
            Command::Keygen(KeygenArgs { output }) if output.as_os_str() == "identity.key"
        ));

        let egress = Cli::try_parse_from([
            "pathchord",
            "egress",
            "--egress-id",
            "egress-a",
            "--identity",
            "identity.key",
            "--bind",
            "127.0.0.1:7443",
        ])
        .expect("Egress args");
        assert!(matches!(
            egress.command,
            Command::Egress(EgressArgs { egress_id, binds, .. })
                if egress_id.as_deref() == Some("egress-a")
                    && binds == vec!["127.0.0.1:7443".parse().unwrap()]
        ));
    }

    #[test]
    fn identity_file_round_trips_and_is_never_overwritten() {
        let id = NEXT_CONTROL_SOCKET.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("pathchord-identity-{}-{id}", std::process::id()));
        let identity = generate_static_keypair().expect("identity");
        write_identity(&path, &identity).expect("write identity");
        let restored = load_identity(&path).expect("load identity");
        assert_eq!(restored.public(), identity.public());
        assert!(matches!(
            write_identity(&path, &identity),
            Err(CliError::IdentityIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        std::fs::remove_file(path).expect("remove identity");
    }

    #[tokio::test]
    async fn local_exchange_uses_the_canonical_protocol_framing() {
        let request = status_request("operator");
        let expected_request = request.clone();
        let request_id = request.request_id.clone();
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let received: RequestEnvelope = read_object(&mut server).await.expect("read request");
            let response = ResponseEnvelope::success(
                received.request_id.clone(),
                pathchord_ingress::GenerationExpectation {
                    scope: "observation".to_owned(),
                    value: 7,
                },
                serde_json::json!({"data_path_summary": "down"}),
            );
            write_object(&mut server, &response)
                .await
                .expect("write response");
            received
        });

        let response = exchange_local(&mut client, &request)
            .await
            .expect("local exchange");
        assert_eq!(server_task.await.expect("server task"), expected_request);
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.observed_generation.value, 7);
        assert_eq!(
            response.result.expect("result")["data_path_summary"],
            "down"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn generic_local_server_serves_egress_authorizations() {
        let id = NEXT_CONTROL_SOCKET.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pathchord-egress-control-{}-{id}",
            std::process::id()
        ));
        let store = Arc::new(
            pathchord_egress::AuthorizationStore::open(
                ":memory:",
                pathchord_egress::EgressId::new("egress-a"),
                [9; 32],
            )
            .expect("authorization store"),
        );
        let dispatcher = pathchord_egress::AuthorizationControlDispatcher::new(store);
        let server = LocalControlServer::bind(&path, dispatcher).expect("bind Egress control");
        let (shutdown, signal) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .run_until_shutdown(4, async move {
                    let _ = signal.await;
                })
                .await
        });

        let response = call_local(&path, authorizations_list_request("operator"))
            .await
            .expect("authorization list");
        assert!(response.ok);
        assert_eq!(
            response.result.expect("result")["items"]
                .as_array()
                .unwrap()
                .len(),
            0
        );

        shutdown.send(()).expect("shutdown receiver");
        server_task
            .await
            .expect("server task")
            .expect("server shutdown");
        assert!(!path.exists());
    }
}
