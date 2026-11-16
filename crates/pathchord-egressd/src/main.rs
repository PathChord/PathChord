use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use pathchord_config::{
    EgressServiceResource, load_configuration_documents, parse_egress_service_documents,
};
use pathchord_control::{
    DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS, LocalControlServer, WebBearerToken, WebGateway,
    WebGatewayConfig,
};
use pathchord_core::{PathReady, ProtocolLimits};
use pathchord_egress::{
    AuthorizationControlDispatcher, AuthorizationStore, EgressId, EgressNode, EgressNodeConfig,
    TcpTargetConnector,
};
use pathchord_noise::StaticKeypair;
use pathchord_policy::EgressServiceSpec;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};
use zeroize::{Zeroize, Zeroizing};

const IDENTITY_FILE_HEADER: &[u8] = b"PATHCHORD-IDENTITY-V1\n";
const DEFAULT_BIND: &str = "0.0.0.0:7443";
const DEFAULT_MAX_CONCURRENT_PATHS: usize = 256;

#[derive(Debug, Parser)]
#[command(
    name = "pathchord-egressd",
    version,
    about = "PathChord Egress service"
)]
struct Cli {
    #[command(flatten)]
    args: EgressArgs,
}

#[derive(Debug, Clone, Args)]
struct EgressArgs {
    /// Egress resource file; mutually exclusive with --config-dir.
    #[arg(short = 'c', long, conflicts_with = "config_dir")]
    config: Option<PathBuf>,
    /// Egress resource directory; mutually exclusive with --config.
    #[arg(short = 'C', long, conflicts_with = "config")]
    config_dir: Option<PathBuf>,
    #[arg(long)]
    bind: Option<SocketAddr>,
    #[arg(long)]
    egress_id: Option<String>,
    #[arg(long)]
    identity: Option<PathBuf>,
    #[arg(long)]
    authorization_db: Option<PathBuf>,
    #[arg(long)]
    control_socket: Option<PathBuf>,
    #[arg(long)]
    max_wire_bandwidth_bps: Option<u64>,
    #[arg(long)]
    max_inbound_target_connections: Option<usize>,
    #[arg(long)]
    quota_remaining: Option<u64>,
    #[arg(long)]
    traffic_multiplier_basis_points: Option<u32>,
    #[arg(long)]
    web_bind: Option<SocketAddr>,
    #[arg(long)]
    web_token_file: Option<PathBuf>,
    #[arg(long = "web-origin")]
    web_origins: Vec<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    web_protected_transport: Option<bool>,
}

#[derive(Debug, Clone)]
struct EgressConfiguration {
    source_path: Option<PathBuf>,
    bind: SocketAddr,
    egress_id: String,
    identity: PathBuf,
    authorization_db: PathBuf,
    control_socket: PathBuf,
    max_concurrent_paths: usize,
    max_wire_bandwidth_bps: u64,
    max_inbound_target_connections: usize,
    remote_dns_only: bool,
    quota_remaining: Option<u64>,
    traffic_multiplier_basis_points: u32,
    web_bind: Option<SocketAddr>,
    web_token_file: Option<PathBuf>,
    web_origins: Vec<String>,
    web_protected_transport: bool,
}

#[derive(Debug, Error)]
enum ServiceError {
    #[error("configuration source failed: {0}")]
    ConfigurationSource(#[from] pathchord_config::ConfigurationError),
    #[error("Egress configuration is invalid: {0}")]
    Configuration(String),
    #[error("identity file is invalid")]
    InvalidIdentity,
    #[error("identity file permissions must deny group and other access")]
    InsecureIdentityPermissions,
    #[error("identity file I/O failed: {0}")]
    IdentityIo(#[from] std::io::Error),
    #[error("Noise identity operation failed: {0}")]
    Noise(#[from] pathchord_noise::NoiseError),
    #[error("Egress authorization store failed: {0}")]
    AuthorizationStore(#[from] pathchord_egress::AuthorizationStoreError),
    #[error("Egress node failed: {0}")]
    EgressNode(#[from] pathchord_egress::EgressNodeError),
    #[error("local control server failed: {0}")]
    LocalServer(#[from] pathchord_control::LocalServerError),
    #[error("Web Gateway failed: {0}")]
    WebGateway(#[from] pathchord_control::WebGatewayError),
    #[error("service shutdown signal failed: {0}")]
    ShutdownSignal(String),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    match run(Cli::parse().args).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pathchord-egressd: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(args: EgressArgs) -> Result<(), ServiceError> {
    let args = resolve(args).await?;
    let restart_required = Arc::new(AtomicBool::new(false));
    let (watcher_stop, watcher_task) =
        start_restart_watcher(args.source_path.clone(), Arc::clone(&restart_required));
    let identity = Arc::new(load_identity(&args.identity)?);
    let authorizations = Arc::new(AuthorizationStore::open(
        &args.authorization_db,
        EgressId::new(args.egress_id.clone()),
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
            let node = Arc::clone(&cleanup_node);
            async move {
                node.reconcile_authorizations_until(Duration::from_secs(10))
                    .await
                    .map_err(|error| error.to_string())
            }
        })
        .with_status_hook(move || {
            let node = Arc::clone(&status_node);
            let restart_required = Arc::clone(&restart_required);
            async move {
                let snapshot = node.snapshot().map_err(|error| error.to_string())?;
                let activity = node
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
                    "authorization_activity": activity,
                    "quota_remaining": snapshot.quota_remaining,
                    "traffic_multiplier_basis_points": snapshot.traffic_multiplier_basis_points,
                    "configuration": {
                        "state": if restart_required.load(Ordering::Relaxed) {
                            "restart_required"
                        } else {
                            "active"
                        }
                    },
                }))
            }
        })
        .with_resources_hook(move || {
            let node = Arc::clone(&resources_node);
            async move {
                let (path_metrics, stream_metrics) = node
                    .management_resources()
                    .map_err(|error| error.to_string())?;
                Ok(serde_json::json!({
                    "path_metrics": path_metrics,
                    "stream_metrics": stream_metrics
                }))
            }
        });

    let server = LocalControlServer::bind(args.control_socket, dispatcher)?;
    let web_dispatcher = server.shared_dispatcher();
    let web_gateway = match args.web_bind {
        Some(bind) => Some(
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
        ),
        None => None,
    };

    let (shutdown, _) = watch::channel(false);
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
                .map_err(ServiceError::from),
            None => {
                wait_for_shutdown(shutdown.subscribe()).await;
                Ok(())
            }
        }
    };
    tokio::pin!(node_future);
    tokio::pin!(server_future);
    tokio::pin!(web_future);
    let result = tokio::select! {
        result = &mut node_future => result.map(|_| ()).map_err(ServiceError::from),
        result = &mut server_future => result.map_err(ServiceError::from),
        result = &mut web_future => result,
        signal = service_shutdown_signal() => {
            signal.map_err(|error| ServiceError::ShutdownSignal(error.to_string()))?;
            let _ = shutdown.send(true);
            let _ = node_future.await;
            let _ = server_future.await;
            web_future.await
        }
    };
    let _ = shutdown.send(true);
    let _ = watcher_stop.send(());
    let _ = watcher_task.await;
    result
}

async fn resolve(args: EgressArgs) -> Result<EgressConfiguration, ServiceError> {
    let source = select_source(&args)?;
    let Some(source) = source else {
        return merge(args, None, Path::new("."), None);
    };
    let documents = load_configuration_documents(source.clone()).await?;
    let service =
        parse_egress_service_documents(documents.iter().map(|document| document.as_str()))
            .map_err(|error| ServiceError::Configuration(error.to_string()))?;
    let base = if source.is_dir() {
        source.clone()
    } else {
        source.parent().unwrap_or(Path::new(".")).to_owned()
    };
    merge(args, Some(service), &base, Some(source))
}

fn select_source(args: &EgressArgs) -> Result<Option<PathBuf>, ServiceError> {
    if let Some(path) = args.config_dir.clone() {
        return Ok(Some(path));
    }
    if let Some(path) = args.config.clone() {
        return Ok(Some(path));
    }
    let environment_file = std::env::var_os("PATHCHORD_CONFIG")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let environment_directory = std::env::var_os("PATHCHORD_CONFIG_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if environment_file.is_some() && environment_directory.is_some() {
        return Err(ServiceError::Configuration(
            "set only one of PATHCHORD_CONFIG and PATHCHORD_CONFIG_DIR".into(),
        ));
    }
    if let Some(path) = environment_file.or(environment_directory) {
        return Ok(Some(path));
    }
    let default = PathBuf::from("/etc/pathchord/egress");
    Ok(default.is_dir().then_some(default))
}

fn merge(
    args: EgressArgs,
    service: Option<EgressServiceResource>,
    base: &Path,
    source_path: Option<PathBuf>,
) -> Result<EgressConfiguration, ServiceError> {
    let defaults = EgressServiceSpec::default();
    let service_name = service.as_ref().map(|service| service.name.as_str());
    let spec = service.as_ref().map_or(&defaults, |service| &service.spec);
    let path = |cli: Option<PathBuf>, configured: &Option<PathBuf>, fallback: &str| {
        cli.or_else(|| {
            configured.as_ref().map(|value| {
                if value.is_absolute() {
                    value.clone()
                } else {
                    base.join(value)
                }
            })
        })
        .unwrap_or_else(|| PathBuf::from(fallback))
    };
    let egress_id = args
        .egress_id
        .or_else(|| spec.egress_id.clone())
        .or_else(|| service_name.map(str::to_owned))
        .ok_or_else(|| ServiceError::Configuration("egressId or --egress-id is required".into()))?;
    let identity = path(args.identity, &spec.identity, "");
    if identity.as_os_str().is_empty() {
        return Err(ServiceError::Configuration(
            "identity or --identity is required".into(),
        ));
    }
    let control_socket = path(
        args.control_socket,
        &spec.control_socket,
        &default_control_socket().to_string_lossy(),
    );
    let resolved = EgressConfiguration {
        source_path,
        bind: args
            .bind
            .or(spec.bind)
            .unwrap_or_else(|| DEFAULT_BIND.parse().expect("constant address")),
        egress_id,
        identity,
        authorization_db: path(
            args.authorization_db,
            &spec.authorization_db,
            "pathchord-egress-authorizations.db",
        ),
        control_socket,
        max_concurrent_paths: DEFAULT_MAX_CONCURRENT_PATHS,
        max_wire_bandwidth_bps: args
            .max_wire_bandwidth_bps
            .or(spec.max_wire_bandwidth_bps)
            .unwrap_or(1_000_000_000),
        max_inbound_target_connections: args
            .max_inbound_target_connections
            .or(spec.max_inbound_target_connections)
            .unwrap_or(4096),
        remote_dns_only: spec.remote_dns_only.unwrap_or(false),
        quota_remaining: args.quota_remaining.or(spec.quota_remaining),
        traffic_multiplier_basis_points: args
            .traffic_multiplier_basis_points
            .or(spec.traffic_multiplier_basis_points)
            .unwrap_or(10_000),
        web_bind: args.web_bind.or(spec.web_bind),
        web_token_file: args.web_token_file.or_else(|| {
            spec.web_token_file.as_ref().map(|value| {
                if value.is_absolute() {
                    value.clone()
                } else {
                    base.join(value)
                }
            })
        }),
        web_origins: if args.web_origins.is_empty() {
            spec.web_origins.iter().cloned().collect()
        } else {
            args.web_origins
        },
        web_protected_transport: args
            .web_protected_transport
            .or(spec.web_protected_transport)
            .unwrap_or(false),
    };
    validate(resolved)
}

fn validate(config: EgressConfiguration) -> Result<EgressConfiguration, ServiceError> {
    EgressServiceSpec {
        egress_id: Some(config.egress_id.clone()),
        identity: Some(config.identity.clone()),
        authorization_db: Some(config.authorization_db.clone()),
        control_socket: Some(config.control_socket.clone()),
        max_wire_bandwidth_bps: Some(config.max_wire_bandwidth_bps),
        max_inbound_target_connections: Some(config.max_inbound_target_connections),
        traffic_multiplier_basis_points: Some(config.traffic_multiplier_basis_points),
        ..EgressServiceSpec::default()
    }
    .validate()
    .map_err(|error| ServiceError::Configuration(error.to_owned()))?;
    Ok(config)
}

fn start_restart_watcher(
    source_path: Option<PathBuf>,
    restart_required: Arc<AtomicBool>,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let (stop, stop_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let Some(source_path) = source_path else {
            let _ = stop_receiver.await;
            return;
        };
        let (events, mut event_receiver) = mpsc::unbounded_channel();
        let mut watcher: RecommendedWatcher = match notify::recommended_watcher(move |event| {
            let _ = events.send(event);
        }) {
            Ok(watcher) => watcher,
            Err(_) => {
                let _ = stop_receiver.await;
                return;
            }
        };
        let watch_path = if source_path.is_dir() {
            source_path.clone()
        } else {
            source_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        };
        let mode = if watch_path.is_dir() {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        if watcher.watch(&watch_path, mode).is_err() {
            let _ = stop_receiver.await;
            return;
        }
        tokio::pin!(stop_receiver);
        loop {
            tokio::select! {
                _ = &mut stop_receiver => break,
                event = event_receiver.recv() => {
                    if event.is_some() {
                        restart_required.store(true, Ordering::Relaxed);
                    } else {
                        break;
                    }
                }
            }
        }
    });
    (stop, task)
}

fn default_control_socket() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("pathchord/egress.sock");
    }
    PathBuf::from("/run/pathchord/egress.sock")
}

fn load_identity(path: &Path) -> Result<StaticKeypair, ServiceError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ServiceError::InvalidIdentity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ServiceError::InsecureIdentityPermissions);
        }
    }
    let file = std::fs::File::open(path)?;
    let mut encoded = Zeroizing::new(Vec::new());
    file.take(4097).read_to_end(&mut encoded)?;
    if encoded.len() > 4096 || !encoded.starts_with(IDENTITY_FILE_HEADER) {
        return Err(ServiceError::InvalidIdentity);
    }
    let body = encoded[IDENTITY_FILE_HEADER.len()..]
        .strip_suffix(b"\n")
        .unwrap_or(&encoded[IDENTITY_FILE_HEADER.len()..]);
    if body.is_empty() || body.contains(&b'\n') || body.contains(&b'\r') {
        return Err(ServiceError::InvalidIdentity);
    }
    let mut decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| ServiceError::InvalidIdentity)?,
    );
    let private: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| ServiceError::InvalidIdentity)?;
    decoded.zeroize();
    Ok(StaticKeypair::from_private(private))
}

fn load_web_token(path: &Path) -> Result<WebBearerToken, ServiceError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ServiceError::Configuration(
            "web token file is invalid".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ServiceError::Configuration(
                "web token file permissions are insecure".into(),
            ));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(ServiceError::Configuration(
            "web token file is too large".into(),
        ));
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    let token = String::from_utf8(bytes.to_vec())
        .map_err(|_| ServiceError::Configuration("web token file is not UTF-8".into()))?;
    if token.is_empty() || token.contains(['\n', '\r']) {
        return Err(ServiceError::Configuration(
            "web token file is invalid".into(),
        ));
    }
    Ok(WebBearerToken::new(token))
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
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
