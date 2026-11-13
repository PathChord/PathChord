//! Local management transport adapters.
//!
//! The Unix implementation owns only the socket transport. Request validation,
//! authorization, and response shaping remain in [`LocalControlDispatcher`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};

use crate::{
    LocalControlDispatcher, LocalProtocolError, RequestEnvelope, ResponseEnvelope, read_object,
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
}

pub const DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS: usize = 64;

#[cfg(unix)]
pub struct LocalControlServer {
    listener: tokio::net::UnixListener,
    dispatcher: LocalControlDispatcher,
    path: PathBuf,
}

#[cfg(unix)]
impl std::fmt::Debug for LocalControlServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalControlServer")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl LocalControlServer {
    /// Binds one Unix socket, removing only an existing socket at `path`.
    pub fn bind(
        path: impl Into<PathBuf>,
        dispatcher: LocalControlDispatcher,
    ) -> Result<Self, LocalServerError> {
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
            dispatcher,
            path,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serves exactly one accepted connection and one request.
    pub async fn serve_once(&mut self) -> Result<(), LocalServerError> {
        let (mut stream, _) = self.listener.accept().await.map_err(LocalServerError::Io)?;
        let request: RequestEnvelope = read_object(&mut stream).await?;
        let response: ResponseEnvelope = self.dispatcher.dispatch(request);
        write_object(&mut stream, &response).await?;
        Ok(())
    }

    /// Runs until the listener or a request fails.
    pub async fn run(mut self) -> Result<(), LocalServerError> {
        loop {
            self.serve_once().await?;
        }
    }

    /// Serves multiple local control clients concurrently with a bounded
    /// request budget. The dispatcher lock is held only while shaping one
    /// response; socket reads and writes do not block other clients.
    pub async fn run_concurrent(mut self, max_concurrent: usize) -> Result<(), LocalServerError> {
        if max_concurrent == 0 {
            return Err(LocalServerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "max concurrent control requests must be greater than zero",
            )));
        }
        let dispatcher = Arc::new(Mutex::new(std::mem::take(&mut self.dispatcher)));
        let permits = Arc::new(Semaphore::new(max_concurrent));
        loop {
            let (mut stream, _) = self.listener.accept().await.map_err(LocalServerError::Io)?;
            let permit = permits.clone().acquire_owned().await.map_err(|_| {
                LocalServerError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "control request budget closed",
                ))
            })?;
            let dispatcher = dispatcher.clone();
            tokio::spawn(async move {
                let result = async {
                    let request: RequestEnvelope = read_object(&mut stream).await?;
                    let response = dispatcher.lock().await.dispatch(request);
                    write_object(&mut stream, &response).await?;
                    Ok::<(), LocalServerError>(())
                }
                .await;
                drop(permit);
                if let Err(error) = result {
                    let _ = error;
                }
            });
        }
    }

    /// Returns the dispatcher for registering listeners before serving.
    pub fn dispatcher_mut(&mut self) -> &mut LocalControlDispatcher {
        &mut self.dispatcher
    }

    /// Explicitly removes the owned socket path.
    pub fn shutdown(self) -> Result<(), LocalServerError> {
        remove_socket_path(&self.path)
    }
}

#[cfg(unix)]
impl Drop for LocalControlServer {
    fn drop(&mut self) {
        let _ = remove_socket_path(&self.path);
    }
}

#[cfg(not(unix))]
pub struct LocalControlServer;

#[cfg(not(unix))]
impl std::fmt::Debug for LocalControlServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalControlServer(unsupported)")
    }
}

#[cfg(not(unix))]
impl LocalControlServer {
    pub fn bind(
        _path: impl Into<PathBuf>,
        _dispatcher: LocalControlDispatcher,
    ) -> Result<Self, LocalServerError> {
        Err(LocalServerError::Unsupported {
            platform: std::env::consts::OS,
        })
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
    use crate::{Actor, ErrorCode, LOCAL_API_VERSION, RequestEnvelope, SystemProxyPlatform};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::UnixStream;

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
        let mut server = LocalControlServer::bind(
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
                bind: "127.0.0.1:8080".parse().expect("address"),
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
}
