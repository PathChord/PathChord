//! HTTP message forwarding over policy-owned TCP flows.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{CONNECTION, HOST, HeaderMap, HeaderName, HeaderValue, UPGRADE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinSet;

use crate::{
    BoxedLocalConnection, ConnectionContext, FlowBridgeError, FlowBridgeStats,
    ListenerCredentialVerifier, TargetAddress, TargetHost, TcpFlowOpener,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

#[derive(Debug, Clone)]
pub(crate) struct HttpForwardConfig {
    pub authentication_required: bool,
    pub credential_verifier: Arc<dyn ListenerCredentialVerifier>,
}

#[derive(Default)]
struct Owner {
    tasks: Mutex<JoinSet<()>>,
    counters: Arc<Counters>,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
}

impl Owner {
    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while tasks.try_join_next().is_some() {}
        tasks.spawn(task);
    }
}

pub(crate) async fn forward_connection<D>(
    io: BoxedLocalConnection,
    context: ConnectionContext,
    dialer: &D,
    config: HttpForwardConfig,
) -> Result<FlowBridgeStats, FlowBridgeError>
where
    D: TcpFlowOpener + ?Sized,
{
    let owner = Arc::new(Owner::default());
    let first_request = AtomicBool::new(true);
    let service = service_fn(|request| {
        handle_request(
            request,
            &context,
            dialer,
            &config,
            first_request.swap(false, Ordering::Relaxed),
            Arc::clone(&owner),
        )
    });
    let result = hyper::server::conn::http1::Builder::new()
        .max_buf_size(crate::HTTP_MAX_HEADER_BYTES)
        .max_header_size(crate::HTTP_MAX_HEADER_BYTES)
        .max_headers(128)
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades()
        .await;
    let mut tasks = {
        let mut tasks = owner
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *tasks)
    };
    if result.is_err() {
        tasks.abort_all();
    }
    while tasks.join_next().await.is_some() {}
    result.map_err(|_| FlowBridgeError::Copy("HTTP proxy connection failed".to_owned()))?;
    Ok(FlowBridgeStats {
        local_to_target_bytes: owner.counters.sent.load(Ordering::Relaxed),
        target_to_local_bytes: owner.counters.received.load(Ordering::Relaxed),
    })
}

async fn handle_request<D>(
    mut request: Request<Incoming>,
    base_context: &ConnectionContext,
    dialer: &D,
    config: &HttpForwardConfig,
    first_request: bool,
    owner: Arc<Owner>,
) -> Result<Response<ProxyBody>, Infallible>
where
    D: TcpFlowOpener + ?Sized,
{
    let mut context = base_context.clone();
    if !first_request {
        context.authentication_identity = None;
        if config.authentication_required {
            let mut values = request.headers().get_all("proxy-authorization").iter();
            let authorization = values.next().and_then(|value| value.to_str().ok());
            if values.next().is_some() {
                return Ok(authentication_failure());
            }
            context.authentication_identity = crate::http_connect::authenticate_basic(
                authorization,
                config.credential_verifier.as_ref(),
            )
            .await;
            if context.authentication_identity.is_none() {
                return Ok(authentication_failure());
            }
        }
    }
    let is_connect = request.method() == Method::CONNECT;
    let target = if is_connect {
        crate::http_connect::parse_authority(&request.uri().to_string())
    } else {
        forward_target(request.uri())
    };
    context.target = match target {
        Ok(target) => target,
        Err(_) => return Ok(error_response(StatusCode::BAD_REQUEST)),
    };
    let close_client = request.version() == Version::HTTP_10
        || header_has_token(request.headers(), "connection", "close")
        || header_has_token(request.headers(), "proxy-connection", "close");
    let upgrade = if header_has_token(request.headers(), "connection", "upgrade") {
        upgrade_value(request.headers())
    } else {
        None
    };
    let target = match dialer.connect(context).await {
        Ok(target) => CountedIo {
            io: target,
            counters: Arc::clone(&owner.counters),
        },
        Err(error) => {
            let status = match error {
                FlowBridgeError::PolicyRejected => StatusCode::FORBIDDEN,
                FlowBridgeError::EgressRejected { .. } | FlowBridgeError::Dial(_) => {
                    StatusCode::BAD_GATEWAY
                }
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            return Ok(error_response(status));
        }
    };
    if is_connect {
        let client = hyper::upgrade::on(&mut request);
        owner.spawn(async move {
            if let Ok(client) = client.await {
                let _ =
                    tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut { target }).await;
            }
        });
        return Ok(Response::new(empty_body()));
    }
    let client_upgrade = upgrade.as_ref().map(|_| hyper::upgrade::on(&mut request));
    let authority = request
        .uri()
        .authority()
        .expect("validated absolute URI")
        .as_str()
        .to_owned();
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    *request.uri_mut() = match path.parse() {
        Ok(uri) => uri,
        Err(_) => return Ok(error_response(StatusCode::BAD_REQUEST)),
    };
    let forbidden = strip_hop_headers(request.headers_mut(), upgrade.clone());
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(&authority).expect("validated authority"),
    );
    let (parts, body) = request.into_parts();
    let request = Request::from_parts(
        parts,
        FilteredBody {
            inner: body,
            forbidden,
        },
    );
    let (mut sender, connection) = match hyper::client::conn::http1::Builder::new()
        .max_buf_size(crate::HTTP_MAX_HEADER_BYTES)
        .max_header_size(crate::HTTP_MAX_HEADER_BYTES)
        .handshake(TokioIo::new(target))
        .await
    {
        Ok(connection) => connection,
        Err(_) => return Ok(error_response(StatusCode::BAD_GATEWAY)),
    };
    owner.spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let mut response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(_) => return Ok(error_response(StatusCode::BAD_GATEWAY)),
    };
    let switching = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    if switching {
        let Some(client_upgrade) = client_upgrade else {
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        };
        let Some(response_upgrade) = upgrade_value(response.headers()) else {
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        };
        if !upgrade
            .as_ref()
            .is_some_and(|requested| selected_upgrade_is_offered(requested, &response_upgrade))
            || !header_has_token(response.headers(), "connection", "upgrade")
        {
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        }
        let target_upgrade = hyper::upgrade::on(&mut response);
        owner.spawn(async move {
            if let Ok((client, target)) = tokio::try_join!(client_upgrade, target_upgrade) {
                let _ = tokio::io::copy_bidirectional(
                    &mut TokioIo::new(client),
                    &mut TokioIo::new(target),
                )
                .await;
            }
        });
        strip_hop_headers(response.headers_mut(), Some(response_upgrade));
    }
    let forbidden = if switching {
        Vec::new()
    } else {
        strip_hop_headers(response.headers_mut(), None)
    };
    if close_client && !switching {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(
        parts,
        FilteredBody {
            inner: body,
            forbidden,
        }
        .map_err(|error| Box::new(error) as BoxError)
        .boxed_unsync(),
    ))
}

pub(crate) fn forward_target(uri: &Uri) -> Result<TargetAddress, String> {
    if !uri
        .scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
        || uri.to_string().contains('#')
    {
        return Err("HTTP forwarding requires an absolute http URI".to_owned());
    }
    let authority = uri
        .authority()
        .ok_or_else(|| "HTTP URI has no authority".to_owned())?
        .as_str();
    if authority.contains('@') || authority.contains('%') {
        return Err("HTTP authority contains invalid characters".to_owned());
    }
    let authority = if authority.starts_with('[') {
        if authority.ends_with(']') {
            format!("{authority}:80")
        } else {
            authority.to_owned()
        }
    } else if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let target = crate::http_connect::parse_authority(&authority)?;
    if let TargetHost::Hostname(host) = &target.host
        && (host.is_empty()
            || host.chars().any(|ch| {
                ch.is_control()
                    || ch.is_whitespace()
                    || matches!(ch, '/' | '\\' | '#' | '?' | '[' | ']')
            }))
    {
        return Err("invalid HTTP target hostname".to_owned());
    }
    Ok(target)
}

fn header_has_token(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(expected))
}

fn upgrade_value(headers: &HeaderMap) -> Option<HeaderValue> {
    let values: Result<Vec<_>, _> = headers
        .get_all(UPGRADE)
        .iter()
        .map(HeaderValue::to_str)
        .collect();
    let values = values.ok()?;
    if values.is_empty() {
        return None;
    }
    HeaderValue::from_str(&values.join(", ")).ok()
}

fn selected_upgrade_is_offered(offered: &HeaderValue, selected: &HeaderValue) -> bool {
    let (Ok(offered), Ok(selected)) = (offered.to_str(), selected.to_str()) else {
        return false;
    };
    selected.split(',').all(|protocol| {
        let protocol = protocol.trim();
        !protocol.is_empty()
            && offered
                .split(',')
                .any(|candidate| candidate.trim().eq_ignore_ascii_case(protocol))
    })
}

const HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn allowed_trailer(name: &HeaderName, forbidden: &[HeaderName]) -> bool {
    !forbidden.contains(name)
        && !HOP_HEADERS.contains(&name.as_str())
        && !matches!(
            name.as_str(),
            "content-length"
                | "host"
                | "authorization"
                | "www-authenticate"
                | "cookie"
                | "set-cookie"
                | "content-type"
                | "content-encoding"
                | "content-range"
        )
}

fn strip_hop_headers(headers: &mut HeaderMap, upgrade: Option<HeaderValue>) -> Vec<HeaderName> {
    let forbidden: Vec<_> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    let trailers: Vec<_> = headers
        .get_all("trailer")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .filter(|name| allowed_trailer(name, &forbidden))
        .collect();
    for name in &forbidden {
        headers.remove(name);
    }
    for name in HOP_HEADERS {
        headers.remove(*name);
    }
    if let Some(upgrade) = upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, upgrade);
    } else if !trailers.is_empty() {
        let names = trailers
            .iter()
            .map(HeaderName::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        headers.insert(
            "trailer",
            HeaderValue::from_str(&names).expect("validated trailer names"),
        );
    }
    forbidden
}

fn empty_body() -> ProxyBody {
    Full::new(Bytes::new())
        .map_err(|error| match error {})
        .boxed_unsync()
}

fn error_response(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(empty_body());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

fn authentication_failure() -> Response<ProxyBody> {
    let mut response = error_response(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    response.headers_mut().insert(
        "proxy-authenticate",
        HeaderValue::from_static("Basic realm=\"PathChord\""),
    );
    response
}

struct FilteredBody<B> {
    inner: B,
    forbidden: Vec<HeaderName>,
}

impl<B: Body<Data = Bytes> + Unpin> Body for FilteredBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_trailers() {
                Ok(mut trailers) => {
                    let rejected: Vec<_> = trailers
                        .keys()
                        .filter(|name| !allowed_trailer(name, &this.forbidden))
                        .cloned()
                        .collect();
                    for name in rejected {
                        trailers.remove(name);
                    }
                    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                }
                Err(frame) => Poll::Ready(Some(Ok(frame))),
            },
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct CountedIo {
    io: BoxedLocalConnection,
    counters: Arc<Counters>,
}

impl AsyncRead for CountedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.io).poll_read(context, buffer);
        self.counters
            .received
            .fetch_add((buffer.filled().len() - before) as u64, Ordering::Relaxed);
        result
    }
}

impl AsyncWrite for CountedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(context, buffer);
        if let Poll::Ready(Ok(length)) = result {
            self.counters
                .sent
                .fetch_add(length as u64, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(context)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(context)
    }
}
