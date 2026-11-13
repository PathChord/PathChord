//! Optional, supervised sing-box transport backend. Configuration travels on stdin.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use pathchord_policy::{TransitOptions, TransitProxyConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::OnceCell;
use tokio::time::{Instant, timeout};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AdapterKind, BoxedTransitConnection, BoxedTransitDatagram, ConnectRequest,
    Socks5TransitAdapter, TransitAdapter, TransitCredential, TransitDatagram, TransitError,
    TransitMetadata,
};

pub(crate) const PROTOCOLS: &[&str] = &[
    "vless",
    "xtls",
    "vmess",
    "trojan",
    "hysteria",
    "hysteria2",
    "tuic",
    "wireguard",
    "ssh",
    "shadowtls",
    "anytls",
    "socks4",
    "socks4a",
    "snell",
];
const ENGINE_VERSION: &str = "sing-box version 1.14.4";

#[derive(Debug)]
pub(crate) struct OutboundEngine {
    executable: PathBuf,
    state_dir: PathBuf,
    version: OnceCell<()>,
}

impl OutboundEngine {
    pub fn new(executable: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            executable,
            state_dir,
            version: OnceCell::new(),
        }
    }

    async fn check_version(&self, duration: Duration) -> Result<(), TransitError> {
        self.version
            .get_or_try_init(|| async {
                let version = self.command("version").stdout(Stdio::piped()).output();
                let version = timeout(duration, version)
                    .await
                    .map_err(|_| engine_error("outbound engine version timed out"))?
                    .map_err(|_| engine_error("outbound engine could not be started"))?;
                if !version.status.success()
                    || !version
                        .stdout
                        .split(|byte| *byte == b'\n')
                        .any(|line| line == ENGINE_VERSION.as_bytes())
                {
                    return Err(engine_error("outbound engine must be sing-box 1.14.4"));
                }
                Ok(())
            })
            .await
            .copied()
    }

    async fn validate(&self, outbound: &str, duration: Duration) -> Result<(), TransitError> {
        self.check_version(duration).await?;
        let mut outbound: Value = serde_json::from_str(outbound)
            .map_err(|_| engine_error("outbound configuration is invalid"))?;
        outbound["tag"] = json!("pathchord-target");
        let wireguard = outbound["type"] == "wireguard";
        let mut document = json!({"log":{"disabled":true},"route":{"final":"pathchord-target"}});
        document[if wireguard { "endpoints" } else { "outbounds" }] = Value::Array(vec![outbound]);
        let body = Zeroizing::new(
            serde_json::to_vec(&document)
                .map_err(|_| engine_error("outbound configuration cannot be encoded"))?,
        );
        zeroize_json(&mut document);
        let directory = PrivateDirectory::create(&self.state_dir)?;
        if !self
            .config_command("check", &directory.0, &body, duration)
            .await?
        {
            return Err(TransitError::Unsupported(
                "outbound engine rejected node options; no parameters were discarded".into(),
            ));
        }
        Ok(())
    }

    async fn start(
        &self,
        outbound: &str,
        duration: Duration,
    ) -> Result<Arc<EngineProcess>, TransitError> {
        self.check_version(duration).await?;
        let directory = PrivateDirectory::create(&self.state_dir)?;
        let socket = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|_| engine_error("private outbound endpoint could not be reserved"))?;
        let address = socket
            .local_addr()
            .map_err(|_| engine_error("private outbound endpoint is unavailable"))?;
        let username = random_token()?;
        let password = Zeroizing::new(random_token()?);
        let mut outbound: Value = serde_json::from_str(outbound)
            .map_err(|_| engine_error("outbound configuration is invalid"))?;
        outbound["tag"] = json!("pathchord-target");
        let wireguard = outbound["type"] == "wireguard";
        let mut document = json!({
            "log": {"disabled": true},
            "inbounds": [{"type":"socks", "tag":"pathchord-private", "listen":"127.0.0.1", "listen_port":address.port(), "users":[{"username":username,"password":password.as_str()}]}],
            "route": {"final":"pathchord-target"},
        });
        document[if wireguard { "endpoints" } else { "outbounds" }] = Value::Array(vec![outbound]);
        let body = Zeroizing::new(
            serde_json::to_vec(&document)
                .map_err(|_| engine_error("outbound configuration cannot be encoded"))?,
        );
        zeroize_json(&mut document);
        let check = self
            .config_command("check", &directory.0, &body, duration)
            .await?;
        if !check {
            return Err(TransitError::Unsupported(
                "outbound engine rejected node options; no parameters were discarded".into(),
            ));
        }
        drop(socket);
        let mut child = self
            .command("run")
            .arg("-c")
            .arg("stdin")
            .current_dir(&directory.0)
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|_| engine_error("outbound engine could not be started"))?;
        if let Some(mut input) = child.stdin.take() {
            timeout(duration, input.write_all(&body))
                .await
                .map_err(|_| engine_error("outbound engine input timed out"))?
                .map_err(|_| engine_error("outbound engine input failed"))?;
        }
        let deadline = Instant::now() + duration;
        loop {
            if child
                .try_wait()
                .map_err(|_| engine_error("outbound engine state is unavailable"))?
                .is_some()
            {
                return Err(engine_error("outbound engine exited before becoming ready"));
            }
            if timeout(
                Duration::from_millis(200),
                authenticate_endpoint(address, &username, &password),
            )
            .await
            .is_ok_and(|result| result.is_ok())
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(engine_error("outbound engine readiness timed out"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok(Arc::new(EngineProcess {
            child: Mutex::new(Some(child)),
            address,
            username,
            password,
            _directory: directory,
        }))
    }

    fn command(&self, action: &str) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .arg(action)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    async fn config_command(
        &self,
        action: &str,
        directory: &std::path::Path,
        body: &[u8],
        duration: Duration,
    ) -> Result<bool, TransitError> {
        let mut child = self
            .command(action)
            .arg("-c")
            .arg("stdin")
            .current_dir(directory)
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|_| engine_error("outbound engine validation could not start"))?;
        let work = async {
            if let Some(mut input) = child.stdin.take() {
                input.write_all(body).await?;
            }
            child.wait().await
        };
        timeout(duration, work)
            .await
            .map_err(|_| engine_error("outbound engine validation timed out"))?
            .map(|status| status.success())
            .map_err(|_| engine_error("outbound engine validation failed"))
    }
}

struct PrivateDirectory(PathBuf);
impl PrivateDirectory {
    fn create(base: &std::path::Path) -> Result<Self, TransitError> {
        std::fs::create_dir_all(base)
            .map_err(|_| engine_error("outbound state directory is unavailable"))?;
        let path = base.join(format!("node-{}", random_token()?));
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder
            .create(&path)
            .map_err(|_| engine_error("private outbound state directory cannot be created"))?;
        Ok(Self(path))
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct EngineProcess {
    child: Mutex<Option<Child>>,
    address: std::net::SocketAddr,
    username: String,
    password: Zeroizing<String>,
    _directory: PrivateDirectory,
}
impl EngineProcess {
    fn alive(&self) -> bool {
        self.child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_none()))
    }

    fn adapter(&self, timeout: Duration) -> Result<Socks5TransitAdapter, TransitError> {
        let config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("private-outbound"),
            source: None,
            protocol: "socks5".into(),
            endpoint: pathchord_policy::Endpoint {
                host: self.address.ip().to_string(),
                port: self.address.port(),
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: Default::default(),
            weight: 1,
            options: Default::default(),
        };
        let credential = TransitCredential::new(BTreeMap::from([
            ("username".into(), self.username.clone()),
            ("password".into(), self.password.to_string()),
        ]));
        Socks5TransitAdapter::from_config(&config, Some(&credential), timeout)
    }
}
impl Drop for EngineProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self
            .child
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = child.start_kill();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = child.wait().await;
                });
            }
        }
    }
}

pub(crate) struct EngineAdapter {
    metadata: TransitMetadata,
    engine: Arc<OutboundEngine>,
    outbound: Zeroizing<String>,
    process: AsyncMutex<Option<Arc<EngineProcess>>>,
    timeout: Duration,
    tcp: bool,
    udp: bool,
    validated: OnceCell<()>,
}
impl std::fmt::Debug for EngineAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineAdapter")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}
impl EngineAdapter {
    pub fn new(
        config: &TransitProxyConfig,
        credential: &TransitCredential,
        engine: Arc<OutboundEngine>,
        timeout: Duration,
    ) -> Result<Self, TransitError> {
        let mut outbound = outbound_config(config, credential)?;
        let (tcp, udp) = network_capabilities(outbound.get("network"))?;
        let udp = udp
            && config.options.udp != Some(false)
            && !matches!(
                config.protocol.as_str(),
                "http" | "https" | "ssh" | "shadowtls" | "socks4" | "socks4a"
            );
        if !tcp && !udp {
            return Err(TransitError::Unsupported(
                "node network does not enable a supported protocol".to_owned(),
            ));
        }
        let encoded = Zeroizing::new(
            serde_json::to_string(&outbound)
                .map_err(|_| engine_error("outbound configuration cannot be encoded"))?,
        );
        zeroize_json(&mut outbound);
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: config.protocol.clone(),
                },
                labels: config.labels.clone(),
            },
            engine,
            outbound: encoded,
            process: AsyncMutex::new(None),
            timeout,
            tcp,
            udp,
            validated: OnceCell::new(),
        })
    }

    async fn process(&self) -> Result<Arc<EngineProcess>, TransitError> {
        self.prepare().await?;
        let mut process = self.process.lock().await;
        if let Some(process) = process.as_ref().filter(|process| process.alive()) {
            return Ok(Arc::clone(process));
        }
        let started = self.engine.start(&self.outbound, self.timeout).await?;
        *process = Some(Arc::clone(&started));
        Ok(started)
    }
}

fn network_capabilities(network: Option<&Value>) -> Result<(bool, bool), TransitError> {
    let values: Vec<_> = match network {
        None => return Ok((true, true)),
        Some(Value::String(value)) => value.split(',').map(str::trim).collect(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().ok_or_else(|| {
                    TransitError::Unsupported("node network list is invalid".to_owned())
                })
            })
            .collect::<Result<_, _>>()?,
        Some(_) => {
            return Err(TransitError::Unsupported(
                "node network is invalid".to_owned(),
            ));
        }
    };
    if values.iter().any(|value| !matches!(*value, "tcp" | "udp")) {
        return Err(TransitError::Unsupported(
            "node network contains an unsupported protocol".to_owned(),
        ));
    }
    Ok((values.contains(&"tcp"), values.contains(&"udp")))
}
#[async_trait]
impl TransitAdapter for EngineAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }
    fn supports_tcp(&self) -> bool {
        self.tcp
    }
    async fn prepare(&self) -> Result<(), TransitError> {
        self.validated
            .get_or_try_init(|| self.engine.validate(&self.outbound, self.timeout))
            .await
            .copied()
    }
    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        if !self.tcp {
            return Err(TransitError::Unsupported(
                "node does not provide TCP forwarding".to_owned(),
            ));
        }
        let process = self.process().await?;
        let io = process.adapter(self.timeout)?.connect(request).await?;
        Ok(Box::new(EngineConnection {
            io,
            _process: process,
        }))
    }
    fn supports_udp(&self) -> bool {
        self.udp
    }
    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        if !self.udp {
            return Err(TransitError::Unsupported(
                "node does not provide UDP forwarding".into(),
            ));
        }
        let process = self.process().await?;
        let io = process.adapter(self.timeout)?.connect_udp(request).await?;
        Ok(Box::new(EngineDatagram {
            io,
            _process: process,
        }))
    }
}

struct EngineConnection {
    io: BoxedTransitConnection,
    _process: Arc<EngineProcess>,
}
impl AsyncRead for EngineConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for EngineConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
struct EngineDatagram {
    io: BoxedTransitDatagram,
    _process: Arc<EngineProcess>,
}
impl std::fmt::Debug for EngineDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngineDatagram(..)")
    }
}
#[async_trait]
impl TransitDatagram for EngineDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        self.io.send(payload).await
    }
    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        self.io.receive().await
    }
    async fn close(self: Box<Self>) -> Result<(), TransitError> {
        self.io.close().await
    }
}

fn random_token() -> Result<String, TransitError> {
    let mut bytes = [0; 24];
    getrandom::fill(&mut bytes)
        .map_err(|_| engine_error("outbound engine randomness is unavailable"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn engine_error(message: &str) -> TransitError {
    TransitError::Connection(message.to_owned())
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        Value::Object(values) => values.values_mut().for_each(zeroize_json),
        _ => {}
    }
}

async fn authenticate_endpoint(
    address: std::net::SocketAddr,
    username: &str,
    password: &str,
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&[5, 1, 2]).await?;
    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 2] {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let mut auth = Zeroizing::new(vec![1, username.len() as u8]);
    auth.extend_from_slice(username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    stream.write_all(&auth).await?;
    let mut status = [0; 2];
    stream.read_exact(&mut status).await?;
    if status != [1, 0] {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn outbound_config(
    config: &TransitProxyConfig,
    credential: &TransitCredential,
) -> Result<Value, TransitError> {
    if let Some(raw) = credential.field("sing_box_outbound") {
        crate::adapter_registry::validate_credentials(Some(credential), &["sing_box_outbound"])?;
        if config.options != TransitOptions::default() {
            return Err(TransitError::Unsupported(
                "complete sing-box node documents cannot be combined with separate node options"
                    .into(),
            ));
        }
        let mut value: Value = serde_json::from_str(raw).map_err(|_| {
            TransitError::Unsupported("sing-box outbound document is invalid JSON".into())
        })?;
        let object = value.as_object_mut().ok_or_else(|| {
            TransitError::Unsupported("sing-box outbound must be an object".into())
        })?;
        let expected = engine_protocol(&config.protocol);
        if object.get("type").and_then(Value::as_str) != Some(expected) {
            return Err(TransitError::Unsupported(
                "sing-box outbound protocol does not match the node".into(),
            ));
        }
        if expected == "socks" {
            let wanted = match config.protocol.as_str() {
                "socks4" => "4",
                "socks4a" => "4a",
                _ => "5",
            };
            let actual = object.get("version").and_then(Value::as_str).unwrap_or("5");
            if actual != wanted {
                return Err(TransitError::Unsupported(
                    "sing-box SOCKS version does not match the node protocol".into(),
                ));
            }
        }
        if expected != "wireguard"
            && expected != "direct"
            && (object.get("server").and_then(Value::as_str) != Some(config.endpoint.host.as_str())
                || object.get("server_port").and_then(Value::as_u64)
                    != Some(u64::from(config.endpoint.port)))
        {
            return Err(TransitError::Unsupported(
                "sing-box outbound endpoint does not match the node".into(),
            ));
        }
        if object.contains_key("detour") {
            return Err(TransitError::Unsupported(
                "standalone node cannot reference an external detour".into(),
            ));
        }
        validate_external_references(&value, false)?;
        if expected == "wireguard"
            && value
                .get("system")
                .is_some_and(|value| value != &Value::Bool(false))
        {
            return Err(TransitError::Unsupported(
                "subscription WireGuard nodes must use userspace networking".into(),
            ));
        }
        if expected == "shadowsocks" {
            let plugin = value
                .get("plugin")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let Some(plugin) = plugin {
                let options = value.get("plugin_opts").and_then(Value::as_str);
                let (plugin, options) = plugin_options(&plugin, options)?;
                value["plugin"] = json!(plugin);
                value["plugin_opts"] = json!(options);
            }
        }
        return Ok(value);
    }
    let kind = engine_protocol(&config.protocol);
    if !PROTOCOLS.contains(&config.protocol.as_str())
        && !["direct", "http", "https", "socks5", "ss"].contains(&config.protocol.as_str())
    {
        return Err(TransitError::Unsupported(
            "outbound protocol is not supported by the engine adapter".into(),
        ));
    }
    let mut outbound = json!({"type":kind});
    if kind != "direct" {
        outbound["server"] = json!(config.endpoint.host);
        outbound["server_port"] = json!(config.endpoint.port);
    }
    let allowed: &[(&str, &str)] = match config.protocol.as_str() {
        "http" | "https" | "socks5" | "socks4" | "socks4a" => {
            &[("username", "username"), ("password", "password")]
        }
        "ss" => &[
            ("cipher", "method"),
            ("password", "password"),
            ("plugin", "plugin"),
            ("plugin_opts", "plugin_opts"),
        ],
        "vless" | "xtls" => &[("uuid", "uuid"), ("flow", "flow")],
        "vmess" => &[
            ("uuid", "uuid"),
            ("security", "security"),
            ("cipher", "security"),
            ("alter_id", "alter_id"),
        ],
        "trojan" | "anytls" => &[("password", "password")],
        "hysteria2" => &[
            ("password", "password"),
            ("up_mbps", "up_mbps"),
            ("down_mbps", "down_mbps"),
            ("obfs", "obfs"),
            ("obfs_password", "obfs_password"),
            ("server_ports", "server_ports"),
            ("hop_interval", "hop_interval"),
        ],
        "hysteria" => &[
            ("auth", "auth_str"),
            ("password", "auth_str"),
            ("up_mbps", "up_mbps"),
            ("down_mbps", "down_mbps"),
            ("obfs", "obfs"),
            ("server_ports", "server_ports"),
            ("hop_interval", "hop_interval"),
        ],
        "tuic" => &[
            ("uuid", "uuid"),
            ("password", "password"),
            ("congestion_control", "congestion_control"),
            ("udp_relay_mode", "udp_relay_mode"),
            ("heartbeat", "heartbeat"),
            ("zero_rtt_handshake", "zero_rtt_handshake"),
            ("udp_over_stream", "udp_over_stream"),
        ],
        "ssh" => &[
            ("username", "user"),
            ("password", "password"),
            ("private_key", "private_key"),
            ("private_key_passphrase", "private_key_passphrase"),
            ("host_key", "host_key"),
        ],
        "shadowtls" => &[("password", "password"), ("version", "version")],
        "snell" => &[
            ("password", "psk"),
            ("psk", "psk"),
            ("userkey", "userkey"),
            ("version", "version"),
        ],
        "wireguard" => {
            return Err(TransitError::Unsupported(
                "WireGuard requires a complete sing-box endpoint document".into(),
            ));
        }
        _ => &[],
    };
    let mut allowed_names: Vec<_> = allowed.iter().map(|(source, _)| *source).collect();
    allowed_names.extend(
        config
            .options
            .tls
            .as_ref()
            .and_then(|tls| tls.client_key_field.as_deref()),
    );
    crate::adapter_registry::validate_credentials(Some(credential), &allowed_names)?;
    for (source, target) in allowed {
        if let Some(value) = credential.field(source) {
            let mapped = if ["alter_id", "up_mbps", "down_mbps", "version"].contains(target) {
                json!(value.parse::<u64>().map_err(|_| TransitError::Unsupported(
                    "numeric node parameter is invalid".into()
                ))?)
            } else if ["zero_rtt_handshake", "udp_over_stream"].contains(target) {
                json!(
                    value
                        .parse::<bool>()
                        .map_err(|_| TransitError::Unsupported(
                            "boolean node parameter is invalid".into()
                        ))?
                )
            } else {
                json!(value)
            };
            if outbound
                .get(*target)
                .is_some_and(|existing| existing != &mapped)
            {
                return Err(TransitError::Unsupported(
                    "node contains conflicting parameter aliases".into(),
                ));
            }
            outbound[*target] = mapped;
        }
    }
    if config.protocol == "ss" {
        if let Some(plugin) = credential.field("plugin") {
            let (plugin, options) = plugin_options(plugin, credential.field("plugin_opts"))?;
            outbound["plugin"] = json!(plugin);
            outbound["plugin_opts"] = json!(options);
        } else if credential
            .field("plugin_opts")
            .is_some_and(|value| !value.is_empty())
        {
            return Err(TransitError::Unsupported(
                "Shadowsocks plugin options require a plugin".into(),
            ));
        }
    }
    if config.protocol == "hysteria2"
        && (credential.field("obfs").is_some() || credential.field("obfs_password").is_some())
    {
        outbound["obfs"] = json!({"type":credential.field("obfs").unwrap_or("salamander"),"password":credential.field("obfs_password").unwrap_or("")});
        if let Some(object) = outbound.as_object_mut() {
            object.remove("obfs_password");
        }
    }
    if kind == "socks" {
        outbound["version"] = json!(match config.protocol.as_str() {
            "socks4" => "4",
            "socks4a" => "4a",
            _ => "5",
        });
    }
    apply_options(&mut outbound, &config.options, credential, &config.protocol)?;
    Ok(outbound)
}

fn engine_protocol(protocol: &str) -> &str {
    match protocol {
        "ss" => "shadowsocks",
        "https" => "http",
        "socks5" | "socks4" | "socks4a" => "socks",
        "xtls" => "vless",
        other => other,
    }
}

fn validate_external_references(value: &Value, header_map: bool) -> Result<(), TransitError> {
    match value {
        Value::Object(values) => {
            for (name, value) in values {
                if !header_map
                    && (name.ends_with("_path")
                        || name.ends_with("_file")
                        || matches!(
                            name.as_str(),
                            "command" | "exec" | "script" | "credential_file" | "detour"
                        ))
                {
                    return Err(TransitError::Unsupported("node documents must contain inline credentials and cannot reference local files, commands, or external detours".into()));
                }
                validate_external_references(value, name == "headers")?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_external_references(value, header_map)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn plugin_options(plugin: &str, options: Option<&str>) -> Result<(String, String), TransitError> {
    let (canonical, allowed): (&str, &[&str]) = match plugin {
        "obfs" | "obfs-local" | "simple-obfs" => ("obfs-local", &["obfs", "obfs-host", "obfs-uri"]),
        "v2ray-plugin" => (
            "v2ray-plugin",
            &["mode", "host", "path", "tls", "mux", "skip-cert-verify"],
        ),
        _ => {
            return Err(TransitError::Unsupported(
                "Shadowsocks plugin is not a registered engine plugin".into(),
            ));
        }
    };
    let Some(options) = options.filter(|value| !value.is_empty()) else {
        return Ok((canonical.into(), String::new()));
    };
    let mut pairs = Vec::new();
    if options.trim_start().starts_with('{') {
        let object: serde_json::Map<String, Value> =
            serde_json::from_str(options).map_err(|_| {
                TransitError::Unsupported("Shadowsocks plugin options are invalid".into())
            })?;
        for (key, value) in object {
            let key = if canonical == "obfs-local" {
                match key.as_str() {
                    "mode" => "obfs".into(),
                    "host" => "obfs-host".into(),
                    _ => key,
                }
            } else {
                key
            };
            if !allowed.contains(&key.as_str()) {
                return Err(TransitError::Unsupported(
                    "Shadowsocks plugin contains unsupported option names".into(),
                ));
            }
            match value {
                Value::Bool(true) => pairs.push(key),
                Value::Bool(false) => {}
                Value::String(value) if !value.contains(';') => {
                    pairs.push(format!("{key}={value}"))
                }
                _ => {
                    return Err(TransitError::Unsupported(
                        "Shadowsocks plugin option values are invalid".into(),
                    ));
                }
            }
        }
    } else {
        for pair in options.split(';').filter(|value| !value.is_empty()) {
            if !allowed.contains(&pair.split_once('=').map_or(pair, |(name, _)| name)) {
                return Err(TransitError::Unsupported(
                    "Shadowsocks plugin contains unsupported option names".into(),
                ));
            }
            pairs.push(pair.to_owned());
        }
    }
    Ok((canonical.into(), pairs.join(";")))
}

fn apply_options(
    outbound: &mut Value,
    options: &TransitOptions,
    credential: &TransitCredential,
    protocol: &str,
) -> Result<(), TransitError> {
    if let Some(tls) = &options.tls {
        let mut value = json!({"enabled":tls.enabled,"insecure":tls.insecure,"alpn":tls.alpn,"certificate":tls.certificate,"client_certificate":tls.client_certificate});
        if let Some(name) = &tls.server_name {
            value["server_name"] = json!(name);
        }
        if let Some(fingerprint) = &tls.fingerprint {
            value["utls"] = json!({"enabled":true,"fingerprint":fingerprint});
        }
        if let Some(reality) = &tls.reality {
            value["reality"] =
                json!({"enabled":true,"public_key":reality.public_key,"short_id":reality.short_id});
        }
        if let Some(field) = &tls.client_key_field {
            value["client_key"] = json!(
                credential
                    .field(field)
                    .ok_or_else(|| TransitError::Unsupported(
                        "TLS private key is missing".into()
                    ))?
            );
        }
        outbound["tls"] = value;
    } else if protocol == "https" {
        outbound["tls"] = json!({"enabled":true});
    }
    if let Some(transport) = &options.transport {
        if transport.kind != "tcp" {
            let mut value = json!({"type":transport.kind});
            if let Some(path) = &transport.path {
                value["path"] = json!(path);
            }
            if !transport.host.is_empty() {
                match transport.kind.as_str() {
                    "ws" => {
                        if transport.host.len() != 1 {
                            return Err(TransitError::Unsupported(
                                "WebSocket transport requires one Host override".into(),
                            ));
                        }
                        let mut headers = transport.headers.clone();
                        if headers.iter().any(|(name, existing)| {
                            name.eq_ignore_ascii_case("host") && existing != &transport.host[0]
                        }) {
                            return Err(TransitError::Unsupported(
                                "WebSocket Host options conflict".into(),
                            ));
                        }
                        headers.insert("Host".into(), transport.host[0].clone());
                        value["headers"] = json!(headers);
                    }
                    "httpupgrade" => {
                        if transport.host.len() != 1 {
                            return Err(TransitError::Unsupported(
                                "HTTP Upgrade transport requires one Host override".into(),
                            ));
                        }
                        value["host"] = json!(transport.host[0]);
                    }
                    _ => value["host"] = json!(transport.host),
                }
            }
            if !transport.headers.is_empty()
                && !(transport.kind == "ws" && !transport.host.is_empty())
            {
                value["headers"] = json!(transport.headers);
            }
            if let Some(service) = &transport.service_name {
                value["service_name"] = json!(service);
            }
            if let Some(max) = transport.max_early_data {
                value["max_early_data"] = json!(max);
            }
            if let Some(name) = &transport.early_data_header_name {
                value["early_data_header_name"] = json!(name);
            }
            outbound["transport"] = value;
        } else if transport.path.is_some()
            || !transport.host.is_empty()
            || !transport.headers.is_empty()
            || transport.service_name.is_some()
            || transport.max_early_data.is_some()
            || transport.early_data_header_name.is_some()
        {
            return Err(TransitError::Unsupported(
                "TCP transport does not accept HTTP transport parameters".into(),
            ));
        }
    }
    if !options.headers.is_empty() {
        outbound["headers"] = json!(options.headers);
    }
    if let Some(mux) = &options.multiplex {
        let mut value = json!({"enabled":mux.enabled,"padding":mux.padding});
        if let Some(protocol) = &mux.protocol {
            value["protocol"] = json!(protocol);
        }
        if let Some(v) = mux.max_connections {
            value["max_connections"] = json!(v);
        }
        if let Some(v) = mux.min_streams {
            value["min_streams"] = json!(v);
        }
        if let Some(v) = mux.max_streams {
            value["max_streams"] = json!(v);
        }
        outbound["multiplex"] = value;
    }
    if let Some(v) = options.tcp_fast_open {
        outbound["tcp_fast_open"] = json!(v);
    }
    if let Some(v) = &options.bind_interface {
        outbound["bind_interface"] = json!(v);
    }
    if let Some(v) = options.routing_mark {
        outbound["routing_mark"] = json!(v);
    }
    if let Some(v) = &options.packet_encoding {
        outbound["packet_encoding"] = json!(v);
    }
    if options.udp == Some(false) && !["http", "https", "ssh", "shadowtls"].contains(&protocol) {
        outbound["network"] = json!("tcp");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_network_limits_are_reflected_in_adapter_capabilities() {
        let engine = Arc::new(OutboundEngine::new(
            PathBuf::from("unused"),
            std::env::temp_dir(),
        ));
        for (network, tcp, udp) in [
            (json!("tcp"), true, false),
            (json!("udp"), false, true),
            (json!(["tcp"]), true, false),
        ] {
            let config = config("vless", 443);
            let raw = json!({"type":"vless", "server":config.endpoint.host, "server_port":443, "uuid":"test-id", "network":network});
            let credential = TransitCredential::new(BTreeMap::from([(
                "sing_box_outbound".to_owned(),
                raw.to_string(),
            )]));
            let adapter = EngineAdapter::new(
                &config,
                &credential,
                Arc::clone(&engine),
                Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(adapter.supports_tcp(), tcp);
            assert_eq!(adapter.supports_udp(), udp);
        }
    }
    use crate::NoTransitCredentials;
    use pathchord_policy::{Endpoint, TransitProxyId};

    fn config(protocol: &str, port: u16) -> TransitProxyConfig {
        TransitProxyConfig {
            id: TransitProxyId::new("test-node"),
            source: None,
            protocol: protocol.into(),
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: Default::default(),
            tags: Default::default(),
            weight: 1,
            options: Default::default(),
        }
    }

    #[test]
    fn raw_engine_options_are_preserved_and_protocol_mismatch_is_rejected() {
        let node = config("vless", 443);
        let credential=TransitCredential::new(BTreeMap::from([("sing_box_outbound".into(),r#"{"type":"vless","server":"127.0.0.1","server_port":443,"uuid":"secret-uuid","transport":{"type":"ws","path":"/custom"},"unrecognized_flag":true}"#.into())]));
        let value = outbound_config(&node, &credential).unwrap();
        assert_eq!(value["transport"]["path"], "/custom");
        assert_eq!(
            value["unrecognized_flag"], true,
            "engine check must see unknown fields instead of discarding them"
        );
        assert!(outbound_config(&config("trojan", 443), &credential).is_err());
    }

    #[test]
    fn imported_engine_nodes_cannot_read_local_files_or_create_system_interfaces() {
        for outbound in [
            json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":"test","tls":{"enabled":true,"client_key_path":"/private/secret"}}),
            json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":"test","transport":{"type":"ws","path":"/allowed-network-path"},"command":"private-command"}),
        ] {
            let credential = TransitCredential::new(BTreeMap::from([(
                "sing_box_outbound".into(),
                outbound.to_string(),
            )]));
            let error = outbound_config(&config("vless", 443), &credential).unwrap_err();
            assert!(!error.to_string().contains("/private/secret"));
            assert!(!error.to_string().contains("private-command"));
        }
        let credential=TransitCredential::new(BTreeMap::from([("sing_box_outbound".into(),json!({"type":"wireguard","system":true,"private_key":"secret","address":["10.0.0.2/32"]}).to_string())]));
        assert!(outbound_config(&config("wireguard", 443), &credential).is_err());
        let credential=TransitCredential::new(BTreeMap::from([("sing_box_outbound".into(),json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":"test","transport":{"type":"ws","path":"/allowed-network-path"}}).to_string())]));
        assert!(outbound_config(&config("vless", 443), &credential).is_ok());
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn pinned_engine_proxies_a_real_vless_node_and_rejects_unknown_parameters() {
        let executable =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("pinned engine path"));
        let state =
            std::env::temp_dir().join(format!("pathchord-engine-test-{}", random_token().unwrap()));
        let engine = Arc::new(OutboundEngine::new(executable, state.clone()));
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let uuid = "6cbf3f72-3417-4922-bde6-67820d041f25";
        let server_config=Zeroizing::new(serde_json::to_vec(&json!({"log":{"disabled":true},"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":port,"users":[{"uuid":uuid}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})).unwrap());
        let mut server = engine
            .command("run")
            .arg("-c")
            .arg("stdin")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        server
            .stdin
            .take()
            .unwrap()
            .write_all(&server_config)
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "VLESS test server readiness");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut io, _) = echo.accept().await.unwrap();
            let mut bytes = [0; 6];
            io.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"engine");
            io.write_all(&bytes).await.unwrap();
        });
        let registry = crate::AdapterRegistry::new(
            Arc::new(NoTransitCredentials),
            Duration::from_secs(5),
            crate::adapter_registry::native_tls_roots(),
        )
        .with_outbound_engine(engine.executable.clone(), state.clone());
        let adapter = EngineAdapter::new(
            &config("vless", port),
            &TransitCredential::new(BTreeMap::from([("uuid".into(), uuid.into())])),
            Arc::clone(&engine),
            Duration::from_secs(5),
        )
        .unwrap();
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: crate::Endpoint {
                    host: destination.ip().to_string(),
                    port: destination.port(),
                },
            })
            .await
            .unwrap();
        let private_address = adapter.process.lock().await.as_ref().unwrap().address;
        drop(adapter);
        stream.write_all(b"engine").await.unwrap();
        let mut bytes = [0; 6];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"engine");
        drop(stream);
        let deadline = Instant::now() + Duration::from_secs(2);
        while TcpStream::connect(private_address).await.is_ok() {
            assert!(
                Instant::now() < deadline,
                "dropping the last stream must stop the private engine"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        echo_task.await.unwrap();
        let invalid=registry.build_with_credential(&config("vless",port),&TransitCredential::new(BTreeMap::from([("sing_box_outbound".into(),json!({"type":"vless","server":"127.0.0.1","server_port":port,"uuid":uuid,"unrecognized_flag":true}).to_string())]))).unwrap();
        let failure = invalid
            .connect(ConnectRequest {
                destination: crate::Endpoint {
                    host: "127.0.0.1".into(),
                    port: 1,
                },
            })
            .await;
        assert!(matches!(failure, Err(TransitError::Unsupported(_))));
        server.kill().await.unwrap();
        server.wait().await.unwrap();
        drop(invalid);
        drop(registry);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = std::fs::remove_dir_all(state);
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn pinned_engine_interoperates_with_websocket_vless_and_tls_trojan() {
        let executable =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("pinned engine path"));
        let base = std::env::temp_dir().join(format!(
            "pathchord-engine-options-{}",
            random_token().unwrap()
        ));
        let engine = Arc::new(OutboundEngine::new(executable, base.clone()));
        for protocol in ["vless", "trojan"] {
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = reserved.local_addr().unwrap().port();
            drop(reserved);
            let credential_field = if protocol == "vless" {
                "uuid"
            } else {
                "password"
            };
            let secret = if protocol == "vless" {
                "6cbf3f72-3417-4922-bde6-67820d041f25"
            } else {
                "test-trojan-password"
            };
            let mut inbound = json!({"type":protocol,"listen":"127.0.0.1","listen_port":port,"users":[{credential_field:secret}]});
            let mut node = config(protocol, port);
            if protocol == "vless" {
                inbound["transport"] = json!({"type":"ws","path":"/pathchord-interop"});
                node.options.transport = Some(pathchord_policy::TransitTransport {
                    kind: "ws".into(),
                    path: Some("/pathchord-interop".into()),
                    ..Default::default()
                });
            } else {
                let rcgen::CertifiedKey { cert, signing_key } =
                    rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
                inbound["tls"] = json!({"enabled":true,"certificate":cert.pem(),"key":signing_key.serialize_pem()});
                node.options.tls = Some(pathchord_policy::TransitTls {
                    enabled: true,
                    server_name: Some("proxy.test".into()),
                    certificate: vec![cert.pem()],
                    ..Default::default()
                });
            }
            let server_config=Zeroizing::new(serde_json::to_vec(&json!({"log":{"disabled":true},"inbounds":[inbound],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})).unwrap());
            let mut server = engine
                .command("run")
                .arg("-c")
                .arg("stdin")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            server
                .stdin
                .take()
                .unwrap()
                .write_all(&server_config)
                .await
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    break;
                }
                assert!(Instant::now() < deadline, "{protocol} server readiness");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = echo.local_addr().unwrap();
            let echo_task = tokio::spawn(async move {
                let (mut io, _) = echo.accept().await.unwrap();
                let mut buffer = [0; 6];
                io.read_exact(&mut buffer).await.unwrap();
                io.write_all(&buffer).await.unwrap();
            });
            let adapter = EngineAdapter::new(
                &node,
                &TransitCredential::new(BTreeMap::from([(credential_field.into(), secret.into())])),
                Arc::clone(&engine),
                Duration::from_secs(5),
            )
            .unwrap();
            adapter.prepare().await.unwrap();
            let mut stream = adapter
                .connect(ConnectRequest {
                    destination: crate::Endpoint {
                        host: destination.ip().to_string(),
                        port: destination.port(),
                    },
                })
                .await
                .unwrap();
            stream.write_all(b"option").await.unwrap();
            let mut received = [0; 6];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"option");
            drop(stream);
            drop(adapter);
            echo_task.await.unwrap();
            server.kill().await.unwrap();
            server.wait().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = std::fs::remove_dir_all(base);
    }
}
