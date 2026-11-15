//! Supervised local management transport adapters.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use pathchord_core::management::{
    ErrorBody, ErrorCode, GenerationExpectation, ManagementDispatcher, ResponseEnvelope,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

#[cfg(test)]
use crate::read_object;
use crate::{
    LocalControlDispatcher, LocalProtocolError, RequestEnvelope, read_object_with_deadlines,
    write_object,
};

#[derive(Debug, Error)]
pub enum LocalServerError {
    #[error("local control server is unsupported on {platform}")]
    Unsupported { platform: &'static str },
    #[error("local control socket I/O failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("local control protocol failed: {0}")]
    Protocol(#[from] LocalProtocolError),
    #[error("max concurrent control requests must be greater than zero")]
    InvalidConcurrency,
    #[error("local control request task failed: {0}")]
    Task(String),
}

pub const DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS: usize = 64;
const CONTROL_PREFIX_READ_DEADLINE: Duration = Duration::from_secs(5);
const CONTROL_PAYLOAD_READ_DEADLINE: Duration = Duration::from_secs(10);
const CONTROL_DISPATCH_DEADLINE: Duration = Duration::from_secs(30);
const CONTROL_RESPONSE_WRITE_DEADLINE: Duration = Duration::from_secs(10);

#[cfg(unix)]
pub struct LocalControlServer<D = LocalControlDispatcher> {
    listener: tokio::net::UnixListener,
    dispatcher: Arc<Mutex<D>>,
    path: PathBuf,
    ownership: SocketOwnership,
}

#[cfg(unix)]
impl<D> std::fmt::Debug for LocalControlServer<D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalControlServer")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl<D> LocalControlServer<D>
where
    D: ManagementDispatcher,
{
    /// Binds one Unix socket, recovering a stale endpoint only while holding
    /// its exclusive lifetime lock.
    pub fn bind(path: impl Into<PathBuf>, dispatcher: D) -> Result<Self, LocalServerError> {
        let path = path.into();
        create_socket_parent(&path)?;
        let lock = acquire_socket_lock(&path)?;
        prepare_socket_path(&path)?;
        let listener =
            std::os::unix::net::UnixListener::bind(&path).map_err(LocalServerError::Io)?;
        let metadata = std::fs::symlink_metadata(&path).map_err(LocalServerError::Io)?;
        if !metadata.file_type().is_socket() {
            return Err(socket_error(
                std::io::ErrorKind::AlreadyExists,
                "control endpoint changed during binding",
            ));
        }
        let ownership = SocketOwnership {
            path: path.clone(),
            identity: SocketIdentity::from_metadata(&metadata),
            _lock: lock,
        };
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            return Err(LocalServerError::Io(error));
        }
        listener
            .set_nonblocking(true)
            .map_err(LocalServerError::Io)?;
        let listener =
            tokio::net::UnixListener::from_std(listener).map_err(LocalServerError::Io)?;
        Ok(Self {
            listener,
            dispatcher: Arc::new(Mutex::new(dispatcher)),
            path,
            ownership,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn dispatcher_mut(&mut self) -> &mut D {
        Arc::get_mut(&mut self.dispatcher)
            .expect("dispatcher is unique before the server starts")
            .get_mut()
    }

    /// Returns the dispatcher shared by local and optional Web Gateway transports.
    #[must_use]
    pub fn shared_dispatcher(&self) -> Arc<Mutex<D>> {
        Arc::clone(&self.dispatcher)
    }

    /// Serves exactly one accepted connection and one request.
    pub async fn serve_once(&self) -> Result<(), LocalServerError> {
        let (stream, _) = self.listener.accept().await.map_err(LocalServerError::Io)?;
        serve_connection(stream, Arc::clone(&self.dispatcher)).await
    }

    pub async fn run(self) -> Result<(), LocalServerError> {
        self.run_concurrent(DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS)
            .await
    }

    pub async fn run_concurrent(self, max_concurrent: usize) -> Result<(), LocalServerError> {
        self.run_until_shutdown(max_concurrent, std::future::pending())
            .await
    }

    /// Runs until shutdown or a listener failure, then joins every request task.
    pub async fn run_until_shutdown<F>(
        self,
        max_concurrent: usize,
        shutdown: F,
    ) -> Result<(), LocalServerError>
    where
        F: Future<Output = ()> + Send,
    {
        validate_concurrency(max_concurrent)?;
        let permits = Arc::new(Semaphore::new(max_concurrent));
        let rejection_permits = Arc::new(Semaphore::new(max_concurrent));
        let mut tasks = JoinSet::new();
        let mut shutdown = Box::pin(shutdown);

        loop {
            reap_completed(&mut tasks)?;
            let accepted = tokio::select! {
                () = shutdown.as_mut() => {
                    break;
                }
                result = self.listener.accept() => result,
            };
            let (stream, _) = match accepted {
                Ok(stream) => stream,
                Err(error) => {
                    stop_tasks(&mut tasks).await;
                    return Err(LocalServerError::Io(error));
                }
            };
            let dispatcher = Arc::clone(&self.dispatcher);
            match Arc::clone(&permits).try_acquire_owned() {
                Ok(permit) => {
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = serve_connection(stream, dispatcher).await;
                    });
                }
                Err(_) => {
                    let Ok(rejection_permit) = Arc::clone(&rejection_permits).try_acquire_owned()
                    else {
                        drop(stream);
                        continue;
                    };
                    tasks.spawn(async move {
                        let _permit = rejection_permit;
                        let _ = serve_rejected_connection(stream).await;
                    });
                }
            }
        }

        stop_tasks(&mut tasks).await;
        Ok(())
    }

    /// Explicitly removes the owned socket path.
    pub fn shutdown(self) -> Result<(), LocalServerError> {
        self.ownership.remove()
    }
}

#[cfg(windows)]
use interprocess::os::windows::named_pipe::{PipeListenerOptions, pipe_mode, tokio::PipeListener};
#[cfg(windows)]
use interprocess::os::windows::security_descriptor::SecurityDescriptor;

#[cfg(windows)]
type WindowsPipeListener = PipeListener<pipe_mode::Bytes, pipe_mode::Bytes>;

#[cfg(windows)]
pub struct LocalControlServer<D = LocalControlDispatcher> {
    listener: WindowsPipeListener,
    name: PathBuf,
    dispatcher: Arc<Mutex<D>>,
}

#[cfg(windows)]
impl<D> std::fmt::Debug for LocalControlServer<D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalControlServer")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl<D> LocalControlServer<D>
where
    D: ManagementDispatcher,
{
    pub fn bind(path: impl Into<PathBuf>, dispatcher: D) -> Result<Self, LocalServerError> {
        let name = path.into();
        let descriptor_text = widestring::U16CString::from_str(
            "D:P(A;;GA;;;OW)(A;;GA;;;BA)(A;;GA;;;SY)",
        )
        .map_err(|error| {
            LocalServerError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
        })?;
        let descriptor =
            SecurityDescriptor::deserialize(&descriptor_text).map_err(LocalServerError::Io)?;
        let listener = PipeListenerOptions::new()
            .path(name.as_os_str())
            .accept_remote(false)
            .security_descriptor(Some(descriptor))
            .create_tokio_duplex::<pipe_mode::Bytes>()
            .map_err(LocalServerError::Io)?;
        Ok(Self {
            listener,
            name,
            dispatcher: Arc::new(Mutex::new(dispatcher)),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.name
    }

    pub fn dispatcher_mut(&mut self) -> &mut D {
        Arc::get_mut(&mut self.dispatcher)
            .expect("dispatcher is unique before the server starts")
            .get_mut()
    }

    /// Returns the dispatcher shared by local and optional Web Gateway transports.
    #[must_use]
    pub fn shared_dispatcher(&self) -> Arc<Mutex<D>> {
        Arc::clone(&self.dispatcher)
    }

    pub async fn serve_once(&self) -> Result<(), LocalServerError> {
        let connected = self.listener.accept().await.map_err(LocalServerError::Io)?;
        serve_connection(connected, Arc::clone(&self.dispatcher)).await
    }

    pub async fn run(self) -> Result<(), LocalServerError> {
        self.run_concurrent(DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS)
            .await
    }

    pub async fn run_concurrent(self, max_concurrent: usize) -> Result<(), LocalServerError> {
        self.run_until_shutdown(max_concurrent, std::future::pending())
            .await
    }

    /// Maintains one listening instance while bounded connected instances run.
    pub async fn run_until_shutdown<F>(
        self,
        max_concurrent: usize,
        shutdown: F,
    ) -> Result<(), LocalServerError>
    where
        F: Future<Output = ()> + Send,
    {
        validate_concurrency(max_concurrent)?;
        let permits = Arc::new(Semaphore::new(max_concurrent));
        let rejection_permits = Arc::new(Semaphore::new(max_concurrent));
        let mut tasks = JoinSet::new();
        let mut shutdown = Box::pin(shutdown);

        loop {
            reap_completed(&mut tasks)?;
            let connected = tokio::select! {
                () = shutdown.as_mut() => {
                    break;
                }
                result = self.listener.accept() => result,
            };
            let connected = match connected {
                Ok(connected) => connected,
                Err(error) => {
                    stop_tasks(&mut tasks).await;
                    return Err(LocalServerError::Io(error));
                }
            };
            let dispatcher = Arc::clone(&self.dispatcher);
            match Arc::clone(&permits).try_acquire_owned() {
                Ok(permit) => {
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = serve_connection(connected, dispatcher).await;
                    });
                }
                Err(_) => {
                    let Ok(rejection_permit) = Arc::clone(&rejection_permits).try_acquire_owned()
                    else {
                        drop(connected);
                        continue;
                    };
                    tasks.spawn(async move {
                        let _permit = rejection_permit;
                        let _ = serve_rejected_connection(connected).await;
                    });
                }
            }
        }

        stop_tasks(&mut tasks).await;
        Ok(())
    }

    pub fn shutdown(self) -> Result<(), LocalServerError> {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
pub struct LocalControlServer<D = LocalControlDispatcher> {
    dispatcher: D,
}

#[cfg(not(any(unix, windows)))]
impl<D> std::fmt::Debug for LocalControlServer<D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalControlServer(unsupported)")
    }
}

#[cfg(not(any(unix, windows)))]
impl<D> LocalControlServer<D>
where
    D: ManagementDispatcher,
{
    pub fn bind(_path: impl Into<PathBuf>, dispatcher: D) -> Result<Self, LocalServerError> {
        let _ = dispatcher;
        Err(LocalServerError::Unsupported {
            platform: std::env::consts::OS,
        })
    }

    pub fn dispatcher_mut(&mut self) -> &mut D {
        &mut self.dispatcher
    }

    pub async fn run(self) -> Result<(), LocalServerError> {
        Err(LocalServerError::Unsupported {
            platform: std::env::consts::OS,
        })
    }

    pub async fn run_concurrent(self, _max_concurrent: usize) -> Result<(), LocalServerError> {
        Err(LocalServerError::Unsupported {
            platform: std::env::consts::OS,
        })
    }

    pub async fn run_until_shutdown<F>(
        self,
        _max_concurrent: usize,
        _shutdown: F,
    ) -> Result<(), LocalServerError>
    where
        F: Future<Output = ()> + Send,
    {
        Err(LocalServerError::Unsupported {
            platform: std::env::consts::OS,
        })
    }
}

async fn serve_connection<S, D>(
    mut stream: S,
    dispatcher: Arc<Mutex<D>>,
) -> Result<(), LocalServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: ManagementDispatcher,
{
    let mut request: RequestEnvelope = read_object_with_deadlines(
        &mut stream,
        CONTROL_PREFIX_READ_DEADLINE,
        CONTROL_PAYLOAD_READ_DEADLINE,
    )
    .await?;
    request.actor = trusted_local_actor();
    let response = timeout(CONTROL_DISPATCH_DEADLINE, async {
        dispatcher
            .lock()
            .await
            .dispatch_from(request, pathchord_core::management::ManagementSource::Local)
            .await
    })
    .await
    .map_err(|_| LocalProtocolError::Io("dispatcher deadline exceeded".into()))?;
    timeout(
        CONTROL_RESPONSE_WRITE_DEADLINE,
        write_object(&mut stream, &response),
    )
    .await
    .map_err(|_| LocalProtocolError::Io("response write deadline exceeded".into()))??;
    Ok(())
}

async fn serve_rejected_connection<S>(mut stream: S) -> Result<(), LocalServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request: RequestEnvelope = read_object_with_deadlines(
        &mut stream,
        CONTROL_PREFIX_READ_DEADLINE,
        CONTROL_PAYLOAD_READ_DEADLINE,
    )
    .await?;
    let response = ResponseEnvelope::failure(
        request.request_id,
        GenerationExpectation {
            scope: "configuration".to_owned(),
            value: 0,
        },
        ErrorBody {
            code: ErrorCode::ResourceLimit,
            message: "local control request concurrency is exhausted".to_owned(),
            details: Some(serde_json::json!({"retryable": true})),
        },
    );
    timeout(
        CONTROL_RESPONSE_WRITE_DEADLINE,
        write_object(&mut stream, &response),
    )
    .await
    .map_err(|_| LocalProtocolError::Io("response write deadline exceeded".into()))??;
    Ok(())
}

fn trusted_local_actor() -> crate::Actor {
    crate::Actor {
        id: "local-os-owner".to_owned(),
        capabilities: [
            "authorization:write",
            "listeners:read",
            "metrics:read",
            "nodes:read",
            "nodes:write",
            "status:read",
            "subscriptions:write",
            "system_proxy:write",
            "targets:read",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    }
}

fn validate_concurrency(max_concurrent: usize) -> Result<(), LocalServerError> {
    if max_concurrent == 0 {
        Err(LocalServerError::InvalidConcurrency)
    } else {
        Ok(())
    }
}

fn reap_completed(tasks: &mut JoinSet<()>) -> Result<(), LocalServerError> {
    while let Some(result) = tasks.try_join_next() {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            return Err(LocalServerError::Task(error.to_string()));
        }
    }
    Ok(())
}

async fn stop_tasks(tasks: &mut JoinSet<()>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl SocketIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(unix)]
struct SocketOwnership {
    path: PathBuf,
    identity: SocketIdentity,
    // Kept until after socket cleanup. The lock file itself deliberately
    // remains on disk so another opener cannot lock a different inode.
    _lock: std::fs::File,
}

#[cfg(unix)]
impl SocketOwnership {
    fn remove(&self) -> Result<(), LocalServerError> {
        remove_owned_socket(&self.path, self.identity)
    }
}

#[cfg(unix)]
impl Drop for SocketOwnership {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

#[cfg(unix)]
fn create_socket_parent(path: &Path) -> Result<(), LocalServerError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(LocalServerError::Io)?;
    }
    Ok(())
}

#[cfg(unix)]
fn acquire_socket_lock(path: &Path) -> Result<std::fs::File, LocalServerError> {
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    let lock_path = PathBuf::from(lock_name);
    let before = match std::fs::symlink_metadata(&lock_path) {
        Ok(metadata) if metadata.is_file() => Some(SocketIdentity::from_metadata(&metadata)),
        Ok(_) => {
            return Err(socket_error(
                std::io::ErrorKind::AlreadyExists,
                "control lock is not a regular file",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(LocalServerError::Io(error)),
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(LocalServerError::Io)?;
    let opened = file.metadata().map_err(LocalServerError::Io)?;
    let opened_identity = SocketIdentity::from_metadata(&opened);
    let current = std::fs::symlink_metadata(&lock_path).map_err(LocalServerError::Io)?;
    if !opened.is_file()
        || !current.is_file()
        || before.is_some_and(|identity| identity != opened_identity)
        || SocketIdentity::from_metadata(&current) != opened_identity
    {
        return Err(socket_error(
            std::io::ErrorKind::AlreadyExists,
            "control lock changed during open",
        ));
    }
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(socket_error(
                std::io::ErrorKind::AddrInUse,
                "control endpoint is already owned",
            ));
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(LocalServerError::Io(error)),
    }
    let current = std::fs::symlink_metadata(&lock_path).map_err(LocalServerError::Io)?;
    if !current.is_file() || SocketIdentity::from_metadata(&current) != opened_identity {
        return Err(socket_error(
            std::io::ErrorKind::AlreadyExists,
            "control lock changed during acquisition",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn prepare_socket_path(path: &Path) -> Result<(), LocalServerError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            // The lock protects cooperating PathChord instances; also probe
            // older or unrelated listeners which do not use this lock. A
            // nonblocking connect never waits for a full accept backlog.
            let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
                .map_err(LocalServerError::Io)?;
            socket.set_nonblocking(true).map_err(LocalServerError::Io)?;
            let address = socket2::SockAddr::unix(path).map_err(LocalServerError::Io)?;
            match socket.connect(&address) {
                Ok(()) => Err(socket_error(
                    std::io::ErrorKind::AddrInUse,
                    "control endpoint is already listening",
                )),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    remove_owned_socket(path, SocketIdentity::from_metadata(&metadata))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                // Permission errors, EINPROGRESS and a full accept backlog do
                // not prove that a listener is stale. Fail closed.
                Err(error) => Err(LocalServerError::Io(error)),
            }
        }
        Ok(_) => Err(socket_error(
            std::io::ErrorKind::AlreadyExists,
            "control endpoint exists and is not a Unix socket",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LocalServerError::Io(error)),
    }
}

#[cfg(unix)]
fn remove_owned_socket(path: &Path, identity: SocketIdentity) -> Result<(), LocalServerError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && SocketIdentity::from_metadata(&metadata) == identity =>
        {
            std::fs::remove_file(path).map_err(LocalServerError::Io)
        }
        Ok(_) => Err(socket_error(
            std::io::ErrorKind::AlreadyExists,
            "control endpoint no longer belongs to this server",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LocalServerError::Io(error)),
    }
}

#[cfg(unix)]
fn socket_error(kind: std::io::ErrorKind, message: &'static str) -> LocalServerError {
    LocalServerError::Io(std::io::Error::new(kind, message))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{Actor, ErrorCode, LOCAL_API_VERSION, ResponseEnvelope, SystemProxyPlatform};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;
    use tokio::sync::oneshot;

    static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);

    fn socket_path() -> PathBuf {
        let id = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("pathchord-local-{id}-{}", std::process::id()))
    }

    fn request(operation: &str, capabilities: &[&str], body: serde_json::Value) -> RequestEnvelope {
        RequestEnvelope {
            api_version: LOCAL_API_VERSION.to_owned(),
            operation: operation.to_owned(),
            request_id: format!("test-{operation}"),
            actor: Actor {
                id: "test-operator".to_owned(),
                capabilities: capabilities
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
            },
            expected_generation: matches!(
                operation,
                "system_proxy.enable" | "system_proxy.disable"
            )
            .then(|| crate::GenerationExpectation {
                scope: "configuration".into(),
                value: 0,
            }),
            body,
        }
    }

    #[tokio::test]
    async fn serves_status_and_cleans_socket() {
        let path = socket_path();
        let server = LocalControlServer::bind(
            &path,
            LocalControlDispatcher::new(SystemProxyPlatform::Linux),
        )
        .expect("bind");
        let mode = std::fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let mut client = UnixStream::connect(&path).await.expect("connect");
        let request = request("status.get", &["status:read"], json!({}));
        let (server_result, ()) = tokio::join!(server.serve_once(), async {
            write_object(&mut client, &request)
                .await
                .expect("write request");
            let response: ResponseEnvelope = read_object(&mut client).await.expect("read response");
            assert!(response.ok);
            assert_eq!(
                response.result.expect("result")["control_plane"]["state"],
                "running"
            );
        });
        server_result.expect("serve status");
        drop(server);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn serves_linux_system_proxy_rejection() {
        let path = socket_path();
        let mut server = LocalControlServer::bind(
            &path,
            LocalControlDispatcher::new(SystemProxyPlatform::Linux),
        )
        .expect("bind");
        server
            .dispatcher_mut()
            .service_mut()
            .register_listener(crate::ListenerDescriptor {
                id: crate::ListenerId::new("local-http"),
                kind: crate::ListenerKind::Http,
                bind: Some("127.0.0.1:8080".parse().expect("address")),
                interface: None,
                address: None,
                mtu: None,
                flow_tags: std::collections::BTreeSet::new(),
                process_metadata: crate::ProcessMetadataRequest::default(),
                allowed_sources: Vec::new(),
                authentication_required: false,
            });
        let mut client = UnixStream::connect(&path).await.expect("connect");
        let request = request(
            "system_proxy.enable",
            &["system_proxy:write"],
            json!({"listener_id": "local-http"}),
        );
        let (server_result, ()) = tokio::join!(server.serve_once(), async {
            write_object(&mut client, &request)
                .await
                .expect("write request");
            let response: ResponseEnvelope = read_object(&mut client).await.expect("read response");
            assert!(!response.ok);
            assert_eq!(
                response.error.expect("error").code,
                ErrorCode::UnsupportedOperation
            );
        });
        server_result.expect("serve system proxy");
        drop(server);
    }

    #[tokio::test]
    async fn serves_clients_concurrently_and_joins_on_shutdown() {
        let path = socket_path();
        let (dispatched, observed) = std::sync::mpsc::channel();
        let dispatcher = move |request: RequestEnvelope| {
            let _ = dispatched.send(request.operation.clone());
            ResponseEnvelope::success(
                request.request_id,
                crate::GenerationExpectation {
                    scope: "observation".to_owned(),
                    value: 1,
                },
                json!({"ok": true}),
            )
        };
        let server = LocalControlServer::bind(&path, dispatcher).expect("bind");
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .run_until_shutdown(2, async move {
                    let _ = signal.await;
                })
                .await
        });

        let mut first = UnixStream::connect(&path).await.expect("first connect");
        let first_request = request("first", &[], json!({}));
        let first_bytes = crate::encode_object(&first_request).expect("encode first");
        first
            .write_all(&first_bytes[..1])
            .await
            .expect("partial first request");

        let mut second = UnixStream::connect(&path).await.expect("second connect");
        let second_request = request("second", &[], json!({}));
        write_object(&mut second, &second_request)
            .await
            .expect("second request");
        let operation = tokio::task::spawn_blocking(move || {
            observed.recv_timeout(std::time::Duration::from_secs(1))
        })
        .await
        .expect("dispatch observer task")
        .expect("second request was not dispatched concurrently");
        assert_eq!(operation, "second");
        let second_response: ResponseEnvelope =
            read_object(&mut second).await.expect("second response");
        assert!(second_response.ok);

        first
            .write_all(&first_bytes[1..])
            .await
            .expect("finish first request");
        let first_response: ResponseEnvelope =
            read_object(&mut first).await.expect("first response");
        assert!(first_response.ok);

        shutdown.send(()).expect("shutdown receiver");
        task.await.expect("server task").expect("server shutdown");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn rejects_zero_concurrency() {
        let path = socket_path();
        let server = LocalControlServer::bind(
            &path,
            LocalControlDispatcher::new(SystemProxyPlatform::Linux),
        )
        .expect("bind");
        assert!(matches!(
            server.run_concurrent(0).await,
            Err(LocalServerError::InvalidConcurrency)
        ));
    }

    #[tokio::test]
    async fn concurrent_servers_cannot_take_the_same_socket() {
        let path = socket_path();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let runtime = tokio::runtime::Handle::current();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let runtime = runtime.clone();
            tasks.push(tokio::task::spawn_blocking(move || {
                let _entered = runtime.enter();
                barrier.wait();
                let result = LocalControlServer::bind(
                    path,
                    LocalControlDispatcher::new(SystemProxyPlatform::Linux),
                );
                // Keep the winning server and its lock alive until both
                // attempts have completed.
                barrier.wait();
                result
            }));
        }
        let first = tasks.remove(0).await.unwrap();
        let second = tasks.remove(0).await.unwrap();
        let (server, error) = match (first, second) {
            (Ok(server), Err(error)) | (Err(error), Ok(server)) => (server, error),
            _ => panic!("exactly one socket owner must succeed"),
        };
        assert!(
            matches!(error, LocalServerError::Io(ref error) if error.kind() == std::io::ErrorKind::AddrInUse)
        );
        let mut client = UnixStream::connect(&path).await.unwrap();
        let request = request("status.get", &[], json!({}));
        let (server_result, response) = tokio::join!(server.serve_once(), async {
            write_object(&mut client, &request).await.unwrap();
            read_object::<_, ResponseEnvelope>(&mut client)
                .await
                .unwrap()
        });
        server_result.unwrap();
        assert!(response.ok);
        drop(server);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn live_unlocked_socket_is_not_removed_and_stale_socket_recovers() {
        let path = socket_path();
        let legacy = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let result = LocalControlServer::bind(
            &path,
            LocalControlDispatcher::new(SystemProxyPlatform::Linux),
        );
        assert!(
            matches!(result, Err(LocalServerError::Io(ref error)) if error.kind() == std::io::ErrorKind::AddrInUse)
        );
        assert!(path.exists());
        drop(legacy);
        let server = LocalControlServer::bind(
            &path,
            LocalControlDispatcher::new(SystemProxyPlatform::Linux),
        )
        .expect("stale endpoint can be recovered");
        drop(server);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn dropping_old_server_preserves_replaced_socket_inode() {
        let path = socket_path();
        let server = LocalControlServer::bind(
            &path,
            LocalControlDispatcher::new(SystemProxyPlatform::Linux),
        )
        .unwrap();
        std::fs::remove_file(&path).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(server);
        assert!(path.exists(), "old owner must not unlink the replacement");
        let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        drop(replacement);
        std::fs::remove_file(&path).unwrap();
    }
}
