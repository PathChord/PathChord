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
use clap::{Args, Parser, Subcommand};
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
    DnsAdapters, DnsRuntime, ErrorCode, IngressControlService, IngressControlStore,
    IngressDataPlane, IngressDataPlaneConfig, IngressPlatformConfig, IngressPlatformFactories,
    IngressPlatformRuntime, LOCAL_API_VERSION, ListenerCredentialError, ListenerCredentialVerifier,
    ListenerCredentialVerifierFactory, ListenerDescriptor, ListenerKind, LocalControlDispatcher,
    LocalControlServer, LocalDnsAdapter, LocalProtocolError, NodeHealthState, NodeId,
    NodeObservation, PathObservation, PlatformProxyAdapter, ProtectedEndpointSet,
    RejectListenerCredentials, RequestEnvelope, ResponseEnvelope, RuntimeCounts, RuntimeError,
    SessionObservation, StaticListenerCredentialVerifier,
    SubscriptionCacheSpec as ControlSubscriptionCacheSpec, SubscriptionId as ControlSubscriptionId,
    SubscriptionRefreshSpec as ControlSubscriptionRefreshSpec,
    SubscriptionSpec as ControlSubscriptionSpec, SystemProxyPlatform, TcpFlowOpener, UdpFlowOpener,
    WebBearerToken, WebGateway, WebGatewayConfig,
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
    AuthenticationMode, FlowProtocol, Generation, KubeConfig, ListenerConfig,
    ListenerKind as PolicyListenerKind, PolicyConfig, RuntimeNodeState, SubscriptionSourceType,
    TransitProxyRuntimeStatus,
};
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
    /// Kubernetes-style PathChord configuration YAML.
    #[arg(long, default_value = "pathchord.yaml")]
    pub config: PathBuf,
    /// Canonical Ingress identity used during Session attachment.
    #[arg(long, default_value = "local-ingress")]
    pub ingress_id: String,
    /// Versioned private identity file. Required when Egress topology is configured.
    #[arg(long)]
    pub identity: Option<PathBuf>,
    /// Runtime cache and durable local data directory.
    #[arg(long, default_value = "pathchord-data")]
    pub data_dir: PathBuf,
    /// Directory containing private JSON credential maps named by credentialsRef.
    #[arg(long, default_value = "pathchord-secrets")]
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
    /// Public Path listener address.
    #[arg(long, default_value = DEFAULT_EGRESS_BIND)]
    pub bind: SocketAddr,
    /// Canonical Egress identity bound into the Noise prologue.
    #[arg(long)]
    pub egress_id: String,
    /// Versioned private identity file.
    #[arg(long)]
    pub identity: PathBuf,
    /// Egress-owned SQLite authorization database.
    #[arg(long, default_value = "pathchord-authorizations.db")]
    pub authorization_db: PathBuf,
    /// Local authorization control socket or Named Pipe.
    #[arg(long, default_value = DEFAULT_EGRESS_SOCKET_PATH)]
    pub control_socket: PathBuf,
    #[arg(long, default_value_t = DEFAULT_MAX_CONCURRENT_PATHS)]
    pub max_concurrent_paths: usize,
    #[arg(long, default_value_t = 1_000_000_000)]
    pub capacity_bps: u64,
    #[arg(long, default_value_t = 1)]
    pub recommended_path_count: u64,
    #[arg(long, default_value_t = 4096)]
    pub max_streams_per_ingress: usize,
    #[arg(long)]
    pub quota_remaining: Option<u64>,
    #[arg(long, default_value_t = 10_000)]
    pub traffic_multiplier_basis_points: u32,
    /// Optional authorization Web Gateway bind.
    #[arg(long)]
    pub web_bind: Option<SocketAddr>,
    #[arg(long)]
    pub web_token_file: Option<PathBuf>,
    #[arg(long = "web-origin")]
    pub web_origins: Vec<String>,
    #[arg(long)]
    pub web_protected_transport: bool,
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
    #[arg(long)]
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
    match command {
        Command::Ingress(args) => run_ingress(&socket, args).await,
        Command::Egress(args) => run_egress(args).await,
        Command::Enroll(args) => run_enrollment(&socket, actor, args.command).await,
        Command::Keygen(args) => run_keygen(args),
        Command::Status => {
            let response = call_local(&socket, status_request(actor)).await?;
            print_response(response)
        }
        Command::SystemProxy(SystemProxyCommand::Enable(args)) => {
            let response = call_local(
                &socket,
                system_proxy_enable_request(actor, args.listener_id),
            )
            .await?;
            print_response(response)
        }
        Command::SystemProxy(SystemProxyCommand::Disable) => {
            let response = call_local(&socket, system_proxy_disable_request(actor)).await?;
            print_response(response)
        }
    }
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
    let yaml = std::fs::read_to_string(&args.config).map_err(|source| CliError::ConfigRead {
        path: args.config.clone(),
        source,
    })?;
    let kube_config = KubeConfig::from_yaml(&yaml)?;
    let policy = kube_config.into_validated_snapshot(Generation::new(1))?;
    let policy_config = policy.config().clone();
    let reloader = ConfigHotReloader::bind(&args.config, 1).await?;
    let reload_handle = reloader.handle();
    let identity = match args.identity {
        Some(path) => load_identity(&path)?,
        None if policy_config.egresses.is_empty() => generate_static_keypair()?,
        None => return Err(CliError::MissingIdentity),
    };
    let platform = SystemProxyPlatform::current();
    let data_plane = Arc::new(IngressDataPlane::new(IngressDataPlaneConfig::new(
        args.ingress_id,
        identity,
        policy,
    ))?);
    std::fs::create_dir_all(&args.data_dir)?;
    let credentials = Arc::new(FileTransitCredentialProvider::new(&args.credentials_dir)?);
    let adapter_registry = Arc::new(if policy_config.subscriptions.is_empty() {
        AdapterRegistry::for_configs(
            Arc::clone(&credentials),
            pathchord_ingress::DEFAULT_PATH_CONNECT_TIMEOUT,
            &policy_config.transit_proxies,
        )?
    } else {
        AdapterRegistry::with_native_roots(
            Arc::clone(&credentials),
            pathchord_ingress::DEFAULT_PATH_CONNECT_TIMEOUT,
        )?
    });
    for proxy in &policy_config.transit_proxies {
        let adapter = adapter_registry.build(proxy).await?;
        data_plane
            .register_transit_adapter(
                proxy.id.clone(),
                adapter,
                TransitProxyRuntimeStatus {
                    state: RuntimeNodeState::Ready,
                    capabilities: transit_capabilities(&proxy.protocol),
                    labels: BTreeMap::new(),
                    tags: BTreeSet::new(),
                    selection_score: 1,
                },
            )
            .await?;
    }
    let subscription_credentials: Arc<dyn SubscriptionCredentialProvider> = credentials.clone();
    let fetcher = Arc::new(HttpSubscriptionFetcher::with_credentials(
        subscription_credentials,
    )?);
    let mut subscription_manager = SubscriptionManager::new(
        fetcher,
        args.data_dir.join("subscriptions"),
        BTreeSet::from([
            "direct".to_owned(),
            "http".to_owned(),
            "https".to_owned(),
            "socks5".to_owned(),
            "ss".to_owned(),
        ]),
    );
    subscription_manager.reconcile(&policy_config.subscriptions);
    for subscription in &policy_config.subscriptions {
        let _ = subscription_manager.load_cache(subscription).await;
    }
    publish_dynamic_transit(
        data_plane.as_ref(),
        adapter_registry.as_ref(),
        subscription_manager.snapshot(),
    )
    .await;
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
    data_plane.warmup().await;
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
    let listener_addresses = runtime.listener_addresses()?;
    let control_store = Arc::new(IngressControlStore::open(
        args.data_dir.join("ingress-control.db"),
    )?);
    let mut control_service = IngressControlService::open_with_platform_proxy(
        control_store,
        platform_proxy_adapter(&args.data_dir),
    )?;
    let (mut configured_nodes, configured_subscriptions) =
        declarative_control_resources(&policy_config)?;
    configured_nodes.extend(
        subscription_manager
            .snapshot()
            .nodes
            .keys()
            .map(|id| NodeId::new(id.as_str()))
            .collect::<Result<Vec<_>, _>>()?,
    );
    control_service.reconcile_declarative_resources(
        1,
        configured_nodes,
        configured_subscriptions,
    )?;
    let mut dispatcher = LocalControlDispatcher::with_service(platform, control_service);
    for listener in &policy_config.listeners {
        if listener_addresses.contains_key(&listener.id) {
            dispatcher
                .service_mut()
                .register_listener(listener_descriptor(listener.clone())?);
        }
    }
    let observation_handle = dispatcher.service().observation_handle();
    let (runtime_events, mut event_receiver) = tokio::sync::mpsc::unbounded_channel();
    runtime.set_listener_event_sender(runtime_events);
    let server = LocalControlServer::bind(socket.to_owned(), dispatcher)?;
    let control_dispatcher = server.shared_dispatcher();
    sync_control_nodes(
        &control_dispatcher,
        data_plane.as_ref(),
        subscription_manager.snapshot(),
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
                    let snapshot = observation_plane.snapshot().await;
                    let session_snapshots = observation_plane.session_snapshots().await;
                    let sessions = session_snapshots.iter().map(|entry| SessionObservation {
                        session_id: entry.session.session_id,
                        egress_id: entry.egress_id.clone(),
                        state: if entry.session.closed {
                            SessionState::Closed
                        } else if entry.session.ready_paths == 0 {
                            SessionState::Connecting
                        } else {
                            SessionState::Active
                        },
                        ready_paths: entry.session.ready_paths,
                        active_streams: entry.session.active_streams,
                        retained_outbound_bytes: entry.session.retained_outbound_bytes,
                        bytes_sent: entry.session.bytes_sent,
                        bytes_received: entry.session.bytes_received,
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
                                state,
                                rtt_ms: quality.map_or(0, |quality| quality.rtt_ms),
                                jitter_ms: quality.map_or(0, |quality| quality.jitter_ms),
                                loss_ppm: quality.map_or(0, |quality| quality.loss_ppm),
                                throughput_bps: quality.map_or(0, |quality| quality.throughput_bps),
                                reordering_events: quality
                                    .map_or(0, |quality| quality.reordering_events),
                                exclusion_reason,
                            }
                        })
                    });
                    observation_handle
                        .replace_session_observations(sessions, paths)
                        .map_err(|error| CliError::Observation(error.to_string()))?;
                    observation_handle
                        .set_runtime_counts(RuntimeCounts {
                            sessions: snapshot.sessions as u64,
                            ready_paths: snapshot.ready_paths as u64,
                            streams: snapshot.streams as u64,
                            target_connections: snapshot.streams as u64,
                        })
                        .map_err(|error| CliError::Observation(error.to_string()))?;
                }
            }
        }
    };
    let subscription_plane = Arc::clone(&data_plane);
    let subscription_registry = Arc::clone(&adapter_registry);
    let subscription_configs = policy_config.subscriptions.clone();
    let subscription_future = SubscriptionWorker {
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
    let maintenance_future =
        run_data_plane_maintenance(Arc::clone(&data_plane), shutdown.subscribe());
    let reload_future = reloader.run_until_shutdown(wait_for_shutdown(shutdown.subscribe()));
    let reload_apply_future = apply_reloaded_policies(
        reload_handle,
        Arc::clone(&data_plane),
        control_dispatcher,
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
        signal = tokio::signal::ctrl_c() => {
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
    let identity = Arc::new(load_identity(&args.identity)?);
    let authorizations = Arc::new(AuthorizationStore::open(
        &args.authorization_db,
        pathchord_egress::EgressId::new(args.egress_id.clone()),
        *identity.public(),
    )?);
    let node = Arc::new(
        EgressNode::bind(
            EgressNodeConfig {
                bind: args.bind,
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
                capacity_bps: args.capacity_bps,
                recommended_path_count: args.recommended_path_count,
                max_streams_per_ingress: args.max_streams_per_ingress,
                quota_remaining: args.quota_remaining,
                traffic_multiplier_basis_points: args.traffic_multiplier_basis_points,
            },
            TcpTargetConnector::new(),
        )
        .await?,
    );
    let cleanup_node = Arc::clone(&node);
    let status_node = Arc::clone(&node);
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
                Ok(serde_json::json!({
                    "running": snapshot.running,
                    "local_addr": snapshot.local_addr.to_string(),
                    "accepted_paths": snapshot.accepted_paths,
                    "admitted_paths": snapshot.admitted_paths,
                    "active_paths": snapshot.active_paths,
                    "active_sessions": snapshot.active_sessions,
                    "active_target_connections": snapshot.active_target_connections,
                    "quota_remaining": snapshot.quota_remaining,
                    "traffic_multiplier_basis_points": snapshot.traffic_multiplier_basis_points,
                }))
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
        signal = tokio::signal::ctrl_c() => {
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
                    let mut refreshed = false;
                    let latest = control
                        .lock()
                        .await
                        .service()
                        .snapshot()
                        .subscriptions
                        .into_values()
                        .map(|state| state.spec.runtime_config())
                        .collect::<Result<Vec<_>, _>>()?;
                    if latest != configs {
                        let previous_ids: BTreeSet<_> =
                            configs.iter().map(|config| config.id.clone()).collect();
                        manager.reconcile(&latest);
                        for config in &latest {
                            if !previous_ids.contains(&config.id) {
                                let _ = manager.load_cache(config).await;
                            }
                        }
                        configs = latest;
                        refreshed = true;
                        due.retain(|id, _| configs.iter().any(|config| &config.id == id));
                        for config in &configs {
                            due.entry(config.id.clone()).or_insert_with(|| {
                                tokio::time::Instant::now()
                            });
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
                        let (success, error) = if let Some(config) = config {
                            let Some(outcome) = cancellable_subscription_refresh(
                                &mut manager,
                                config,
                                &mut shutdown,
                            )
                            .await else {
                                return Ok(());
                            };
                            refresh_result(outcome)
                        } else {
                            (false, Some("subscription is not configured".to_owned()))
                        };
                        control
                            .lock()
                            .await
                            .service_mut()
                            .complete_subscription_refresh(&requested, success, error)?;
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
                        let Some(outcome) = cancellable_subscription_refresh(
                            &mut manager,
                            config,
                            &mut shutdown,
                        )
                        .await else {
                            return Ok(());
                        };
                        let (success, error) = refresh_result(outcome);
                        let control_id = ControlSubscriptionId::new(config.id.as_str())?;
                        control
                            .lock()
                            .await
                            .service_mut()
                            .complete_subscription_refresh(&control_id, success, error)?;
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
                        manager.complete_draining(&completed);
                        for id in &completed {
                            data_plane.remove_dynamic_transit(id).await;
                            control
                                .lock()
                                .await
                                .service_mut()
                                .remove_node(&NodeId::new(id.as_str())?)?;
                        }
                        refreshed = true;
                    }
                    if refreshed {
                    *dynamic_snapshot.write().await = manager.snapshot().clone();
                        publish_dynamic_transit(data_plane.as_ref(), registry.as_ref(), manager.snapshot()).await;
                        data_plane.warmup().await;
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
                    sync_control_nodes(&control, data_plane.as_ref(), manager.snapshot()).await?;
                }
            }
        }
    }
}

async fn cancellable_subscription_refresh(
    manager: &mut SubscriptionManager,
    config: &pathchord_policy::SubscriptionConfig,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Option<RefreshOutcome> {
    tokio::select! {
        _ = shutdown.changed() => None,
        outcome = manager.refresh(config) => Some(outcome),
    }
}

fn refresh_result(outcome: RefreshOutcome) -> (bool, Option<String>) {
    match outcome {
        RefreshOutcome::Published { .. } | RefreshOutcome::Disabled { .. } => (true, None),
        RefreshOutcome::Retained { error, .. } => (false, Some(error.to_string())),
    }
}

async fn run_data_plane_maintenance(
    data_plane: Arc<IngressDataPlane>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), CliError> {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = interval.tick() => data_plane.warmup().await,
        }
    }
}

async fn apply_reloaded_policies(
    handle: ConfigReloadHandle,
    data_plane: Arc<IngressDataPlane>,
    control: Arc<tokio::sync::Mutex<LocalControlDispatcher>>,
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
                let snapshot = handle.snapshot()?;
                if snapshot.generation > applied_generation {
                    data_plane
                        .replace_compiled_policy((*snapshot.compiled).clone())
                        .await;
                    let (nodes, subscriptions) = declarative_control_resources(&snapshot.config)?;
                    control
                        .lock()
                        .await
                        .service_mut()
                        .reconcile_declarative_resources(
                            snapshot.generation,
                            nodes,
                            subscriptions,
                        )?;
                    let dynamic = dynamic_snapshot.read().await.clone();
                    protected_endpoints.replace(
                        collect_protected_endpoints(
                            &snapshot.config,
                            dns_runtime.as_deref(),
                            Some(&dynamic),
                        )
                        .await,
                    );
                    applied_generation = snapshot.generation;
                }
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
                source_type: match subscription.source.source_type {
                    pathchord_policy::SubscriptionSourceType::Static => "static",
                    pathchord_policy::SubscriptionSourceType::Clash => "clash",
                    pathchord_policy::SubscriptionSourceType::Sip008 => "sip008",
                }
                .to_owned(),
                display_name: subscription.id.as_str().to_owned(),
                enabled: subscription.enabled,
                url: subscription.source.url.clone(),
                credentials_ref: subscription.source.credentials_ref.clone(),
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
    for endpoint in policy.egresses.iter().map(|egress| &egress.endpoint).chain(
        policy
            .transit_proxies
            .iter()
            .filter(|proxy| proxy.protocol != "direct")
            .map(|proxy| &proxy.endpoint),
    ) {
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
    registry: &AdapterRegistry<FileTransitCredentialProvider>,
    snapshot: &DynamicTransitSnapshot,
) {
    for node in snapshot.nodes.values() {
        let mut status = TransitProxyRuntimeStatus {
            state: match node.state {
                DynamicNodeState::Active => RuntimeNodeState::Ready,
                DynamicNodeState::Draining => RuntimeNodeState::Draining,
                DynamicNodeState::Unavailable(_) => RuntimeNodeState::Down,
            },
            capabilities: transit_capabilities(&node.config.protocol),
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            selection_score: 1,
        };
        if node.state == DynamicNodeState::Active {
            match registry.build_dynamic(node) {
                Ok(adapter) => {
                    data_plane
                        .register_dynamic_transit_adapter(node.config.clone(), adapter, status)
                        .await;
                    continue;
                }
                Err(_) => status.state = RuntimeNodeState::Down,
            }
        }
        data_plane
            .publish_dynamic_transit_status(node.config.clone(), status)
            .await;
    }
}

async fn sync_control_nodes(
    control: &Arc<tokio::sync::Mutex<LocalControlDispatcher>>,
    data_plane: &IngressDataPlane,
    snapshot: &DynamicTransitSnapshot,
) -> Result<(), CliError> {
    let admin = {
        let mut dispatcher = control.lock().await;
        for node in snapshot.nodes.values() {
            let id = NodeId::new(node.config.id.as_str())?;
            dispatcher.service_mut().add_node(id.clone())?;
            dispatcher.service_mut().set_node_observation(
                id,
                NodeObservation {
                    state: match node.state {
                        DynamicNodeState::Active => NodeHealthState::Up,
                        DynamicNodeState::Draining => NodeHealthState::Degraded,
                        DynamicNodeState::Unavailable(_) => NodeHealthState::Down,
                    },
                    rtt_ms: None,
                    jitter_ms: None,
                    loss_ppm: None,
                    throughput_bps: None,
                    effective_capacity_bps: None,
                },
            )?;
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
    if protocol == "direct" {
        BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
    } else {
        BTreeSet::from([FlowProtocol::Tcp])
    }
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
        assert_eq!(cli.socket, PathBuf::from("/tmp/ingress.sock"));
        assert_eq!(cli.actor, "operator");
        assert_eq!(cli.command, Command::Status);
    }

    #[test]
    fn parses_ingress_config_argument() {
        let cli = Cli::try_parse_from(["pathchord", "ingress", "--config", "config.yaml"])
            .expect("ingress args");
        assert!(matches!(
            cli.command,
            Command::Ingress(IngressArgs { config, .. }) if config.as_os_str() == "config.yaml"
        ));
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
        let listener = ListenerConfig {
            id: pathchord_policy::ListenerId::new("local-http"),
            kind: PolicyListenerKind::Http,
            platform: "any".to_owned(),
            bind: Some(pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port: 8080,
            }),
            allowed_sources: Vec::new(),
            authentication: AuthenticationMode::Required,
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
        assert_eq!(descriptor.kind, ListenerKind::Http);
        assert_eq!(descriptor.bind.expect("bind").port(), 8080);
        assert_eq!(descriptor.allowed_sources, vec!["127.0.0.1/32"]);
        assert!(descriptor.authentication_required);
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
            Command::Egress(EgressArgs { egress_id, bind, .. })
                if egress_id == "egress-a" && bind == "127.0.0.1:7443".parse().unwrap()
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
