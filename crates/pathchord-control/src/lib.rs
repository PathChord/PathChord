//! Shared local control transport and service adapters.

mod local_protocol;
mod local_server;
mod metrics_export;
mod web_gateway;

pub use local_protocol::{
    Actor, ErrorBody, ErrorCode, GenerationExpectation, LOCAL_API_VERSION, LocalProtocolError,
    MAX_ENVELOPE_BYTES, RequestEnvelope, ResponseEnvelope, decode_object, encode_object,
    read_object, read_object_with_deadlines, write_object,
};
pub use local_server::{
    DEFAULT_MAX_CONCURRENT_CONTROL_REQUESTS, LocalControlServer, LocalServerError,
};
pub use web_gateway::{
    SharedManagementDispatcher, WebBearerToken, WebGateway, WebGatewayConfig, WebGatewayError,
};

use async_trait::async_trait;
use pathchord_core::management::{
    ErrorBody as CoreErrorBody, ErrorCode as CoreErrorCode,
    GenerationExpectation as CoreGeneration, ManagementDispatcher, RequestEnvelope as CoreRequest,
    ResponseEnvelope as CoreResponse,
};

/// Default type used only when callers rely on `LocalControlServer`'s generic
/// default. Role services always provide their own dispatcher explicitly.
#[derive(Debug, Default)]
pub struct NullManagementDispatcher;

#[async_trait]
impl ManagementDispatcher for NullManagementDispatcher {
    async fn dispatch(&mut self, request: CoreRequest) -> CoreResponse {
        CoreResponse::failure(
            request.request_id,
            CoreGeneration {
                scope: "configuration".to_owned(),
                value: 0,
            },
            CoreErrorBody {
                code: CoreErrorCode::UnsupportedOperation,
                message: "no management dispatcher is attached".to_owned(),
                details: None,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::UnixStream;
    use tokio::sync::oneshot;

    static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);

    fn request(operation: &str) -> RequestEnvelope {
        RequestEnvelope {
            api_version: LOCAL_API_VERSION.to_owned(),
            operation: operation.to_owned(),
            request_id: format!("test-{operation}"),
            actor: Actor {
                id: "test-operator".to_owned(),
                capabilities: vec!["status:read".to_owned()],
            },
            expected_generation: None,
            body: json!({}),
        }
    }

    #[tokio::test]
    async fn local_server_preserves_framing_and_dispatches_without_role_runtime() {
        let path = std::env::temp_dir().join(format!(
            "pathchord-control-{}-{}",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
        ));
        let server = LocalControlServer::bind(&path, |request: RequestEnvelope| {
            ResponseEnvelope::success(
                request.request_id,
                GenerationExpectation {
                    scope: "observation".to_owned(),
                    value: 1,
                },
                json!({"operation": request.operation}),
            )
        })
        .expect("bind local control server");
        let mut client = UnixStream::connect(&path).await.expect("connect");
        let request = request("status.get");
        let (server_result, response) = tokio::join!(server.serve_once(), async {
            write_object(&mut client, &request)
                .await
                .expect("write request");
            read_object::<_, ResponseEnvelope>(&mut client)
                .await
                .expect("read response")
        });
        server_result.expect("serve request");
        assert!(response.ok);
        assert_eq!(response.result.expect("result")["operation"], "status.get");
        drop(server);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn web_gateway_requires_and_accepts_the_configured_bearer_token() {
        let dispatcher =
            std::sync::Arc::new(tokio::sync::Mutex::new(|request: RequestEnvelope| {
                ResponseEnvelope::success(
                    request.request_id,
                    GenerationExpectation {
                        scope: "observation".to_owned(),
                        value: 1,
                    },
                    json!({}),
                )
            }));
        let gateway = WebGateway::bind(
            WebGatewayConfig {
                bind: "127.0.0.1:0".parse().expect("loopback bind"),
                bearer_token: Some(WebBearerToken::new("control-test-token")),
                ..WebGatewayConfig::default()
            },
            dispatcher,
        )
        .await
        .expect("bind web gateway");
        let address = gateway.local_addr().expect("gateway address");
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(gateway.run_until_shutdown(async move {
            let _ = signal.await;
        }));
        let client = reqwest::Client::new();
        let url = format!("http://{address}/api/v1/status");
        assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
        assert_eq!(
            client
                .get(&url)
                .bearer_auth("control-test-token")
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        shutdown.send(()).expect("shutdown gateway");
        task.await.expect("gateway task").expect("gateway shutdown");
    }
}
