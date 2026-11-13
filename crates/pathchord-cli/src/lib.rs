//! Local management client for the PathChord control plane.

use std::path::PathBuf;

use async_trait::async_trait;
use clap::{Args, Parser, Subcommand};
use getrandom::fill;
use pathchord_egress::{TargetRequest, TcpTargetConnector};
use pathchord_ingress::{
    Actor, BoxedLocalConnection, DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS, ErrorCode,
    FlowBridgeError, IngressTargetDialer, LOCAL_API_VERSION, ListenerDescriptor, ListenerKind,
    ListenerRuntime, LocalControlDispatcher, LocalControlServer, LocalProtocolError,
    RequestEnvelope, ResponseEnvelope, RuntimeError, SystemProxyPlatform, TargetAddress,
    TargetHost,
};
#[cfg(unix)]
use pathchord_ingress::{read_object, write_object};
use pathchord_policy::{
    AuthenticationMode, FallbackAction, KubeConfig, ListenerConfig,
    ListenerKind as PolicyListenerKind, PolicyConfig,
};
use serde_json::Value;
use thiserror::Error;

/// Default local control endpoint.
#[cfg(not(windows))]
pub const DEFAULT_SOCKET_PATH: &str = "/run/pathchord/ingress.sock";

#[cfg(windows)]
pub const DEFAULT_SOCKET_PATH: &str = r"\\.\pipe\pathchord-ingress";

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
    Egress,
    /// Query local runtime status.
    Status,
    /// Manage the Windows system-proxy control-plane switch.
    #[command(subcommand)]
    SystemProxy(SystemProxyCommand),
    /// Manage explicit endpoint enrollment.
    Enroll,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct IngressArgs {
    /// Kubernetes-style PathChord configuration YAML.
    #[arg(long, default_value = "pathchord.yaml")]
    pub config: PathBuf,
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
    #[error("listener {listener_id} of kind {kind} is not supported by the current runtime")]
    UnsupportedListenerKind { listener_id: String, kind: String },
    #[error("listener {listener_id} has invalid bind address {bind}")]
    InvalidListenerBind { listener_id: String, bind: String },
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
    let Cli {
        socket,
        actor,
        command,
    } = cli;
    match command {
        Command::Ingress(args) => run_ingress(&socket, &args.config).await,
        Command::Egress | Command::Enroll => Err(CliError::NotImplemented {
            command: command.name(),
        }),
        Command::Status => {
            let response = call_unix(&socket, status_request(actor)).await?;
            print_response(response)
        }
        Command::SystemProxy(SystemProxyCommand::Enable(args)) => {
            let response = call_unix(
                &socket,
                system_proxy_enable_request(actor, args.listener_id),
            )
            .await?;
            print_response(response)
        }
        Command::SystemProxy(SystemProxyCommand::Disable) => {
            let response = call_unix(&socket, system_proxy_disable_request(actor)).await?;
            print_response(response)
        }
    }
}

async fn run_ingress(
    socket: &std::path::Path,
    config_path: &std::path::Path,
) -> Result<(), CliError> {
    let yaml = std::fs::read_to_string(config_path).map_err(|source| CliError::ConfigRead {
        path: config_path.to_owned(),
        source,
    })?;
    let kube_config = KubeConfig::from_yaml(&yaml)?;
    let policy = kube_config.into_policy_config()?;
    let platform = if cfg!(target_os = "windows") {
        SystemProxyPlatform::Windows
    } else {
        SystemProxyPlatform::Linux
    };
    let dialer = TcpIngressDialer::new(&policy);
    let descriptors = policy
        .listeners
        .into_iter()
        .map(listener_descriptor)
        .collect::<Result<Vec<_>, _>>()?;
    let runtime =
        ListenerRuntime::bind_descriptors(dialer, Default::default(), descriptors.clone()).await?;
    let mut dispatcher = LocalControlDispatcher::new(platform);
    for descriptor in descriptors {
        dispatcher.service_mut().register_listener(descriptor);
    }
    let server = LocalControlServer::bind(socket.to_owned(), dispatcher)?;

    // Both surfaces are long-lived. Pinning the futures lets whichever side
    // fails first tear down the other by dropping its owner.
    let runtime_future = runtime.run();
    let server_future = server.run_concurrent(DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS);
    tokio::pin!(runtime_future);
    tokio::pin!(server_future);
    tokio::select! {
        result = &mut runtime_future => {
            result.map(|_| ()).map_err(CliError::from)
        }
        result = &mut server_future => {
            result.map(|_| ()).map_err(CliError::from)
        }
    }
}

fn listener_descriptor(listener: ListenerConfig) -> Result<ListenerDescriptor, CliError> {
    let kind = match listener.kind {
        PolicyListenerKind::Http => ListenerKind::Http,
        PolicyListenerKind::Socks5 => ListenerKind::Socks5,
        PolicyListenerKind::Tproxy => ListenerKind::Tproxy,
        PolicyListenerKind::Redirect => ListenerKind::Redirect,
        PolicyListenerKind::Tun => ListenerKind::Tun,
    };
    let bind_endpoint = listener
        .bind
        .ok_or_else(|| CliError::UnsupportedListenerKind {
            listener_id: listener.id.as_str().to_owned(),
            kind: format!("{kind:?}"),
        })?;
    let bind = parse_bind(&bind_endpoint.host, bind_endpoint.port).ok_or_else(|| {
        CliError::InvalidListenerBind {
            listener_id: listener.id.as_str().to_owned(),
            bind: format!("{}:{}", bind_endpoint.host, bind_endpoint.port),
        }
    })?;
    let mut allowed_sources = listener.allowed_sources;
    if allowed_sources.is_empty() && bind.ip().is_loopback() {
        let prefix = match bind.ip() {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        };
        allowed_sources.push(format!("{}/{}", bind.ip(), prefix));
    }
    Ok(ListenerDescriptor {
        id: listener.id,
        kind,
        bind,
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

/// Adapts the concrete Egress TCP connector to the transport-neutral local
/// flow bridge used by listener runtimes.
#[derive(Debug, Clone, Copy)]
struct TcpIngressDialer {
    connector: TcpTargetConnector,
    policy: BootstrapPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapPolicy {
    Direct,
    Reject,
    UnsupportedRules,
}

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

#[async_trait]
impl IngressTargetDialer for TcpIngressDialer {
    async fn connect(
        &self,
        target: TargetAddress,
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
        let request = target_request(target);
        self.connector
            .connect_tcp(request)
            .await
            .map(|stream| Box::new(stream) as BoxedLocalConnection)
            .map_err(|error| FlowBridgeError::Dial(error.to_string()))
    }
}

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
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};

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
            Command::Ingress(IngressArgs { config }) if config.as_os_str() == "config.yaml"
        ));
    }

    #[test]
    fn maps_policy_listener_bind_and_kind() {
        let listener = ListenerConfig {
            id: pathchord_policy::ListenerId::new("local-http"),
            kind: PolicyListenerKind::Http,
            bind: Some(pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port: 8080,
            }),
            allowed_sources: Vec::new(),
            authentication: AuthenticationMode::Required,
        };
        let descriptor = listener_descriptor(listener).expect("descriptor");
        assert_eq!(descriptor.kind, ListenerKind::Http);
        assert_eq!(descriptor.bind.port(), 8080);
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
            bind: "127.0.0.1:0".parse().expect("proxy bind"),
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
            bind: "127.0.0.1:0".parse().expect("proxy bind"),
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
    }
}
