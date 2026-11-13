//! Supervised local management transport adapters.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

use pathchord_core::management::ManagementDispatcher;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

use crate::{
    LocalControlDispatcher, LocalProtocolError, RequestEnvelope, read_object, write_object,
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

#[cfg(unix)]
pub struct LocalControlServer<D = LocalControlDispatcher> {
    listener: tokio::net::UnixListener,
    dispatcher: Arc<Mutex<D>>,
    path: PathBuf,
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
    /// Binds one Unix socket, removing only an existing socket at `path`.
    pub fn bind(path: impl Into<PathBuf>, dispatcher: D) -> Result<Self, LocalServerError> {
        let path = path.into();
        prepare_socket_path(&path)?;
        let listener =
            std::os::unix::net::UnixListener::bind(&path).map_err(LocalServerError::Io)?;
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            let _ = std::fs::remove_file(&path);
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
        let mut tasks = JoinSet::new();
        let mut shutdown = Box::pin(shutdown);

        loop {
            reap_completed(&mut tasks)?;
            let permit = tokio::select! {
                () = shutdown.as_mut() => break,
                result = Arc::clone(&permits).acquire_owned() => result.map_err(|_| {
                    LocalServerError::Io(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "control request budget closed",
                    ))
                })?,
            };
            let accepted = tokio::select! {
                () = shutdown.as_mut() => {
                    drop(permit);
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
            tasks.spawn(async move {
                let _permit = permit;
                let _ = serve_connection(stream, dispatcher).await;
            });
        }

        stop_tasks(&mut tasks).await;
        Ok(())
    }

    /// Explicitly removes the owned socket path.
    pub fn shutdown(self) -> Result<(), LocalServerError> {
        remove_socket_path(&self.path)
    }
}

#[cfg(unix)]
impl<D> Drop for LocalControlServer<D> {
    fn drop(&mut self) {
        let _ = remove_socket_path(&self.path);
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
        let mut tasks = JoinSet::new();
        let mut shutdown = Box::pin(shutdown);

        loop {
            reap_completed(&mut tasks)?;
            let permit = tokio::select! {
                () = shutdown.as_mut() => break,
                result = Arc::clone(&permits).acquire_owned() => result.map_err(|_| {
                    LocalServerError::Io(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "control request budget closed",
                    ))
                })?,
            };
            let connected = tokio::select! {
                () = shutdown.as_mut() => {
                    drop(permit);
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
            tasks.spawn(async move {
                let _permit = permit;
                let _ = serve_connection(connected, dispatcher).await;
            });
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
    let mut request: RequestEnvelope = read_object(&mut stream).await?;
    request.actor = trusted_local_actor();
    let response = dispatcher.lock().await.dispatch(request).await;
    write_object(&mut stream, &response).await?;
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
fn prepare_socket_path(path: &Path) -> Result<(), LocalServerError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => remove_socket_path(path),
        Ok(_) => Err(LocalServerError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "control endpoint exists and is not a Unix socket",
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LocalServerError::Io(error)),
    }
}

#[cfg(unix)]
fn remove_socket_path(path: &Path) -> Result<(), LocalServerError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(LocalServerError::Io)
        }
        Ok(_) => Err(LocalServerError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control endpoint is not a Unix socket",
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LocalServerError::Io(error)),
    }
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
            expected_generation: None,
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
}
