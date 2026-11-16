//! sing-box h2mux, yamux and smux over a native Transit TCP adapter.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use pathchord_policy::TransitMultiplex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

use crate::{
    BoxedTransitConnection, BoxedTransitDatagram, ConnectRequest, Endpoint, TransitAdapter,
    TransitDatagram, TransitError, TransitMetadata,
};

const MAX_CONNECTIONS: usize = 256;
const MAX_STREAMS: usize = 4096;
const MAX_WRITE: usize = 16 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct PoolOptions {
    protocol: MultiplexProtocol,
    padding: bool,
    max_connections: usize,
    min_streams: usize,
    max_streams: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MultiplexProtocol {
    H2,
    Yamux,
    Smux,
}

impl PoolOptions {
    fn parse(options: &TransitMultiplex) -> Result<Self, TransitError> {
        if !options.enabled {
            return Err(unsupported("multiplex is not enabled"));
        }
        let protocol = match options.protocol.as_deref() {
            None | Some("h2mux") => MultiplexProtocol::H2,
            Some("yamux") => MultiplexProtocol::Yamux,
            Some("smux") => MultiplexProtocol::Smux,
            _ => return Err(unsupported("multiplex protocol is not supported")),
        };
        let max_connections = options.max_connections.unwrap_or(0) as usize;
        let min_streams = options.min_streams.unwrap_or(0) as usize;
        let max_streams = options.max_streams.unwrap_or(0) as usize;
        if max_connections > MAX_CONNECTIONS
            || min_streams > MAX_STREAMS
            || max_streams > MAX_STREAMS
        {
            return Err(unsupported(
                "multiplex limits exceed the native resource bounds",
            ));
        }
        if protocol == MultiplexProtocol::Yamux
            && (min_streams > crate::yamux_session::MAX_YAMUX_STREAMS
                || max_streams > crate::yamux_session::MAX_YAMUX_STREAMS)
        {
            return Err(unsupported(
                "yamux stream limits exceed the native resource bounds",
            ));
        }
        if protocol == MultiplexProtocol::Smux
            && (min_streams > crate::sing_smux::MAX_SMUX_STREAMS
                || max_streams > crate::sing_smux::MAX_SMUX_STREAMS)
        {
            return Err(unsupported(
                "smux stream limits exceed the native resource bounds",
            ));
        }
        if max_streams != 0 && (max_connections != 0 || min_streams != 0) {
            return Err(unsupported(
                "multiplex maxStreams conflicts with maxConnections or minStreams",
            ));
        }
        if min_streams != 0 && max_connections == 0 {
            return Err(unsupported("multiplex minStreams requires maxConnections"));
        }
        Ok(Self {
            protocol,
            padding: options.padding,
            max_connections,
            min_streams,
            max_streams,
        })
    }
}

pub(crate) struct MultiplexAdapter {
    inner: Arc<dyn TransitAdapter>,
    pool: Arc<tokio::sync::Mutex<Pool>>,
    signals: Arc<PoolSignals>,
    options: PoolOptions,
    udp_enabled: bool,
    allow_udp_443: bool,
    timeout: Duration,
}

#[derive(Default)]
struct PoolSignals {
    connecting: AtomicUsize,
    available: tokio::sync::Notify,
}

#[derive(Default)]
struct Pool {
    sessions: Vec<Arc<Session>>,
    reaper: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Pool {
    fn drop(&mut self) {
        if let Some(reaper) = self.reaper.take() {
            reaper.abort();
        }
    }
}

struct Session {
    kind: SessionKind,
    active: AtomicUsize,
    dead: AtomicBool,
    idle_since: Mutex<Instant>,
}

enum SessionKind {
    H2 {
        sender: Mutex<h2::client::SendRequest<Bytes>>,
        driver: tokio::task::JoinHandle<()>,
    },
    Yamux(crate::yamux_session::YamuxSession),
    Smux(crate::sing_smux::SmuxSession),
}

impl Session {
    fn is_closed(&self) -> bool {
        self.dead.load(Ordering::Acquire)
            || match &self.kind {
                SessionKind::H2 { driver, .. } => driver.is_finished(),
                SessionKind::Yamux(session) => session.is_closed(),
                SessionKind::Smux(session) => session.is_closed(),
            }
    }

    fn capacity(&self) -> usize {
        match &self.kind {
            SessionKind::H2 { sender, .. } => sender.lock().map_or(0, |sender| {
                sender.current_max_send_streams().min(MAX_STREAMS)
            }),
            SessionKind::Yamux(_) => crate::yamux_session::MAX_YAMUX_STREAMS,
            SessionKind::Smux(session) => {
                if session.can_open() {
                    crate::sing_smux::MAX_SMUX_STREAMS
                } else {
                    0
                }
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let SessionKind::H2 { driver, .. } = &self.kind {
            driver.abort();
        }
    }
}

struct StreamPermit {
    session: Arc<Session>,
    signals: Arc<PoolSignals>,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        if self.session.active.fetch_sub(1, Ordering::AcqRel) == 1
            && let Ok(mut idle_since) = self.session.idle_since.lock()
        {
            *idle_since = Instant::now();
        }
        self.signals.available.notify_one();
    }
}

struct ConnectingPermit(Arc<PoolSignals>);

impl Drop for ConnectingPermit {
    fn drop(&mut self) {
        self.0.connecting.fetch_sub(1, Ordering::AcqRel);
        self.0.available.notify_waiters();
    }
}

impl std::fmt::Debug for MultiplexAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MultiplexAdapter")
            .field("metadata", self.inner.metadata())
            .finish_non_exhaustive()
    }
}

impl MultiplexAdapter {
    pub(crate) fn new(
        inner: Arc<dyn TransitAdapter>,
        options: &TransitMultiplex,
        udp_enabled: bool,
        allow_udp_443: bool,
        timeout: Duration,
    ) -> Result<Self, TransitError> {
        let options = PoolOptions::parse(options)?;
        if !inner.supports_tcp() {
            return Err(unsupported("multiplex requires a TCP Transit adapter"));
        }
        Ok(Self {
            inner,
            pool: Arc::new(tokio::sync::Mutex::new(Pool::default())),
            signals: Arc::new(PoolSignals::default()),
            options,
            udp_enabled,
            allow_udp_443,
            timeout,
        })
    }

    async fn reserve(&self) -> Result<StreamPermit, TransitError> {
        loop {
            let notified = self.signals.available.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let mut pool = self.pool.lock().await;
            if pool.reaper.is_none() {
                let weak = Arc::downgrade(&self.pool);
                pool.reaper = Some(tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(IDLE_TIMEOUT).await;
                        let Some(pool) = weak.upgrade() else { break };
                        let mut pool = pool.lock().await;
                        pool.sessions.retain(|session| {
                            !session.is_closed()
                                && (session.active.load(Ordering::Acquire) != 0
                                    || session
                                        .idle_since
                                        .lock()
                                        .is_ok_and(|idle| idle.elapsed() < IDLE_TIMEOUT))
                        });
                    }
                }));
            }
            pool.sessions.retain(|session| !session.is_closed());
            let connecting = self.signals.connecting.load(Ordering::Acquire);
            let total = pool.sessions.len() + connecting;
            let limit = if self.options.max_connections == 0 {
                MAX_CONNECTIONS
            } else {
                self.options.max_connections
            };
            let selected = pool
                .sessions
                .iter()
                .filter(|session| {
                    let active = session.active.load(Ordering::Acquire);
                    (self.options.max_streams == 0 || active < self.options.max_streams)
                        && active < session.capacity()
                })
                .min_by_key(|session| session.active.load(Ordering::Acquire))
                .cloned();
            let reuse = selected.as_ref().is_some_and(|session| {
                let active = session.active.load(Ordering::Acquire);
                active == 0
                    || total >= limit
                    || if self.options.max_connections > 0 {
                        active < self.options.min_streams
                    } else {
                        self.options.max_streams > 0 && active < self.options.max_streams
                    }
            });
            if reuse {
                let session = selected.expect("selected session was checked");
                session.active.fetch_add(1, Ordering::AcqRel);
                return Ok(StreamPermit {
                    session,
                    signals: Arc::clone(&self.signals),
                });
            }
            if total < limit {
                self.signals.connecting.fetch_add(1, Ordering::AcqRel);
                let reservation = ConnectingPermit(Arc::clone(&self.signals));
                drop(pool);
                let session = self.create_session().await?;
                let mut pool = self.pool.lock().await;
                session.active.fetch_add(1, Ordering::AcqRel);
                pool.sessions.push(Arc::clone(&session));
                drop(reservation);
                return Ok(StreamPermit {
                    session,
                    signals: Arc::clone(&self.signals),
                });
            }
            drop(pool);
            // SETTINGS can increase the peer limit without ending a stream.
            // Periodic rechecks complement FIFO notifications on releases.
            tokio::select! {
                () = notified => {},
                () = tokio::time::sleep(Duration::from_millis(100)) => {},
            }
        }
    }

    async fn create_session(&self) -> Result<Arc<Session>, TransitError> {
        let mut stream = self
            .inner
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "sp.mux.sing-box.arpa".into(),
                    port: 444,
                },
            })
            .await?;
        let protocol = match self.options.protocol {
            MultiplexProtocol::H2 => 2,
            MultiplexProtocol::Yamux => 1,
            MultiplexProtocol::Smux => 0,
        };
        let request = if self.options.padding {
            let padding = crate::sing_mux_padding::padding_len()
                .map_err(|_| connection("multiplex padding initialization failed"))?;
            let mut request = Vec::with_capacity(5 + padding);
            request.extend_from_slice(&[1, protocol, 1]);
            request.extend_from_slice(&(padding as u16).to_be_bytes());
            request.resize(5 + padding, 0);
            request
        } else {
            vec![0, protocol]
        };
        stream
            .write_all(&request)
            .await
            .map_err(|_| connection("multiplex handshake write failed"))?;
        stream
            .flush()
            .await
            .map_err(|_| connection("multiplex handshake flush failed"))?;
        if self.options.padding {
            stream = Box::new(crate::sing_mux_padding::PaddingStream::new(stream));
        }
        let kind = match self.options.protocol {
            MultiplexProtocol::H2 => {
                let (sender, driver) = h2::client::Builder::new()
                    .initial_max_send_streams(1)
                    .handshake(stream)
                    .await
                    .map_err(|_| connection("multiplex HTTP/2 handshake failed"))?;
                let signals = Arc::clone(&self.signals);
                let driver = tokio::spawn(async move {
                    let _ = driver.await;
                    signals.available.notify_waiters();
                });
                SessionKind::H2 {
                    sender: Mutex::new(sender),
                    driver,
                }
            }
            MultiplexProtocol::Yamux => {
                SessionKind::Yamux(crate::yamux_session::YamuxSession::new(
                    stream,
                    crate::yamux_session::MAX_YAMUX_STREAMS,
                )?)
            }
            MultiplexProtocol::Smux => SessionKind::Smux(
                crate::sing_smux::SmuxSession::new(stream, crate::sing_smux::MAX_SMUX_STREAMS)
                    .map_err(|_| connection("multiplex smux session initialization failed"))?,
            ),
        };
        Ok(Arc::new(Session {
            kind,
            active: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
            idle_since: Mutex::new(Instant::now()),
        }))
    }

    async fn open(
        &self,
        destination: &Endpoint,
        udp: bool,
    ) -> Result<BoxedTransitConnection, TransitError> {
        crate::validate_destination(destination)?;
        let request_header = stream_request(destination, udp)?;
        timeout(self.timeout, async {
            for attempt in 0..2 {
                let permit = self.reserve().await?;
                let session = Arc::clone(&permit.session);
                if let SessionKind::Yamux(yamux) = &session.kind {
                    let stream = match yamux.open().await {
                        Ok(stream) => stream,
                        Err(error) => {
                            if yamux.is_closed() {
                                session.dead.store(true, Ordering::Release);
                            }
                            drop(permit);
                            if attempt == 0 && yamux.is_closed() {
                                continue;
                            }
                            return Err(error);
                        }
                    };
                    let mut stream = FramedMuxStream {
                        stream,
                        status_read: false,
                        read_error: false,
                        write_closed: false,
                        _permit: permit,
                    };
                    stream
                        .write_all(&request_header)
                        .await
                        .map_err(|_| connection("multiplex stream request failed"))?;
                    stream
                        .flush()
                        .await
                        .map_err(|_| connection("multiplex stream request failed"))?;
                    return Ok(Box::new(stream) as BoxedTransitConnection);
                }
                if let SessionKind::Smux(smux) = &session.kind {
                    let stream = match smux.open() {
                        Ok(stream) => Box::new(stream) as BoxedTransitConnection,
                        Err(error) => {
                            if smux.is_closed() {
                                session.dead.store(true, Ordering::Release);
                            }
                            drop(permit);
                            if attempt == 0
                                && (smux.is_closed() || error.kind() == io::ErrorKind::WouldBlock)
                            {
                                continue;
                            }
                            return Err(connection("multiplex smux stream could not be opened"));
                        }
                    };
                    let mut stream = FramedMuxStream {
                        stream,
                        status_read: false,
                        read_error: false,
                        write_closed: false,
                        _permit: permit,
                    };
                    stream
                        .write_all(&request_header)
                        .await
                        .map_err(|_| connection("multiplex stream request failed"))?;
                    stream
                        .flush()
                        .await
                        .map_err(|_| connection("multiplex stream request failed"))?;
                    return Ok(Box::new(stream) as BoxedTransitConnection);
                }
                let SessionKind::H2 { sender, .. } = &session.kind else {
                    unreachable!()
                };
                let sender = sender
                    .lock()
                    .map_err(|_| connection("multiplex sender is unavailable"))?
                    .clone();
                let mut sender = match sender.ready().await {
                    Ok(sender) => sender,
                    Err(_) => {
                        session.dead.store(true, Ordering::Release);
                        drop(permit);
                        if attempt == 0 {
                            continue;
                        }
                        return Err(connection("multiplex session is unavailable"));
                    }
                };
                let request = http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("https://localhost")
                    .body(())
                    .map_err(|_| connection("multiplex request is invalid"))?;
                let (response, send) = match sender.send_request(request, false) {
                    Ok(result) => result,
                    Err(_) => {
                        session.dead.store(true, Ordering::Release);
                        drop(permit);
                        if attempt == 0 {
                            continue;
                        }
                        return Err(connection("multiplex stream could not be opened"));
                    }
                };
                let mut stream = MuxStream {
                    response: Some(response),
                    recv: None,
                    send,
                    incoming: Bytes::new(),
                    outgoing: Bytes::new(),
                    read_closed: false,
                    write_closed: false,
                    status_read: false,
                    read_error: false,
                    _permit: permit,
                };
                stream
                    .write_all(&request_header)
                    .await
                    .map_err(|_| connection("multiplex stream request failed"))?;
                stream
                    .flush()
                    .await
                    .map_err(|_| connection("multiplex stream request failed"))?;
                return Ok(Box::new(stream) as BoxedTransitConnection);
            }
            Err(connection("multiplex stream could not be opened"))
        })
        .await
        .map_err(|_| connection("multiplex stream setup timed out"))?
    }
}

#[async_trait]
impl TransitAdapter for MultiplexAdapter {
    fn metadata(&self) -> &TransitMetadata {
        self.inner.metadata()
    }
    fn supports_tcp(&self) -> bool {
        self.inner.supports_tcp()
    }
    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }
    async fn prepare(&self) -> Result<(), TransitError> {
        self.inner.prepare().await
    }
    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        self.open(&request.destination, false).await
    }
    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        if !self.udp_enabled {
            return Err(unsupported("multiplex UDP is disabled"));
        }
        if !self.allow_udp_443 && request.destination.port == 443 {
            return Err(unsupported("VLESS Vision rejects UDP to port 443"));
        }
        let stream = self.open(&request.destination, true).await?;
        Ok(Box::new(MuxDatagram {
            stream: Some(stream),
            input: Vec::new(),
            pending: Vec::new(),
            written: 0,
            failed: false,
            io_timeout: self.timeout,
        }))
    }
}

fn stream_request(destination: &Endpoint, udp: bool) -> Result<Vec<u8>, TransitError> {
    crate::validate_destination(destination)?;
    let mut result = vec![0, u8::from(udp)];
    match destination.host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            result.push(1);
            result.extend_from_slice(&address.octets());
        }
        Ok(std::net::IpAddr::V6(address)) => {
            result.push(4);
            result.extend_from_slice(&address.octets());
        }
        Err(_) => {
            result.extend_from_slice(&[3, destination.host.len() as u8]);
            result.extend_from_slice(destination.host.as_bytes());
        }
    }
    result.extend_from_slice(&destination.port.to_be_bytes());
    Ok(result)
}

struct FramedMuxStream {
    stream: BoxedTransitConnection,
    status_read: bool,
    read_error: bool,
    write_closed: bool,
    _permit: StreamPermit,
}

impl AsyncRead for FramedMuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_error {
            return Poll::Ready(Err(io::Error::other("multiplex stream failed")));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.status_read {
            let mut status = [0; 1];
            let mut input = ReadBuf::new(&mut status);
            match Pin::new(&mut self.stream).poll_read(cx, &mut input) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.read_error = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(())) if input.filled().is_empty() => {
                    self.read_error = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "multiplex response is truncated",
                    )));
                }
                Poll::Ready(Ok(())) => {}
            }
            if status[0] != 0 {
                self.read_error = true;
                return Poll::Ready(Err(io::Error::other(
                    "multiplex peer rejected the destination",
                )));
            }
            self.status_read = true;
        }
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Err(_))) {
            self.read_error = true;
        }
        result
    }
}

impl AsyncWrite for FramedMuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed || self.read_error {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.stream).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

struct MuxStream {
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    send: h2::SendStream<Bytes>,
    incoming: Bytes,
    outgoing: Bytes,
    read_closed: bool,
    write_closed: bool,
    status_read: bool,
    read_error: bool,
    _permit: StreamPermit,
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        if !self.write_closed || !self.read_closed {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}

impl MuxStream {
    fn poll_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.outgoing.is_empty() {
            self.send.reserve_capacity(self.outgoing.len());
            let capacity = if self.send.capacity() == 0 {
                match self.send.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(capacity))) if capacity > 0 => capacity,
                    Poll::Ready(Some(Ok(_))) | Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => return Poll::Ready(Err(io_failure())),
                }
            } else {
                self.send.capacity()
            };
            let bytes = self.outgoing.split_to(capacity.min(self.outgoing.len()));
            self.send
                .send_data(bytes, false)
                .map_err(|_| io_failure())?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 || self.read_closed {
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(Err(error)) = self.poll_outgoing(cx) {
            return Poll::Ready(Err(error));
        }
        if let Some(response) = &mut self.response {
            let response = match Pin::new(response).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(response)) if response.status() == http::StatusCode::OK => response,
                Poll::Ready(_) => return Poll::Ready(Err(io_failure())),
            };
            self.recv = Some(response.into_body());
            self.response = None;
        }
        for _ in 0..32 {
            if !self.incoming.is_empty() {
                if !self.status_read {
                    let status = self.incoming.split_to(1)[0];
                    if status != 0 {
                        return Poll::Ready(Err(io::Error::other(
                            "multiplex peer rejected the destination",
                        )));
                    }
                    self.status_read = true;
                    continue;
                }
                let count = self.incoming.len().min(buf.remaining());
                buf.put_slice(&self.incoming.split_to(count));
                return Poll::Ready(Ok(()));
            }
            let recv = self.recv.as_mut().expect("HTTP/2 response is established");
            match recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(_))) => return Poll::Ready(Err(io_failure())),
                Poll::Ready(Some(Ok(data))) => {
                    recv.flow_control()
                        .release_capacity(data.len())
                        .map_err(|_| io_failure())?;
                    self.incoming = data;
                }
                Poll::Ready(None) if !self.status_read => {
                    self.read_closed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "multiplex response is truncated",
                    )));
                }
                Poll::Ready(None) => {
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_error {
            return Poll::Ready(Err(io_failure()));
        }
        let result = self.poll_read_inner(cx, buf);
        if matches!(result, Poll::Ready(Err(_))) {
            self.read_error = true;
        }
        result
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed || self.read_error {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.poll_outgoing(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let count = bytes.len().min(MAX_WRITE);
        self.outgoing = Bytes::copy_from_slice(&bytes[..count]);
        match self.poll_outgoing(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Ready(Ok(count)),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_outgoing(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        match self.poll_outgoing(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                self.send
                    .send_data(Bytes::new(), true)
                    .map_err(|_| io_failure())?;
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

struct MuxDatagram {
    stream: Option<BoxedTransitConnection>,
    input: Vec<u8>,
    pending: Vec<u8>,
    written: usize,
    failed: bool,
    io_timeout: Duration,
}

impl std::fmt::Debug for MuxDatagram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MuxDatagram(..)")
    }
}

impl MuxDatagram {
    async fn flush_pending(&mut self) -> Result<(), TransitError> {
        while self.written < self.pending.len() {
            match self
                .stream
                .as_mut()
                .expect("live stream")
                .write(&self.pending[self.written..])
                .await
            {
                Ok(0) | Err(_) => {
                    self.failed = true;
                    return Err(connection("multiplex UDP write failed"));
                }
                Ok(written) => self.written += written,
            }
        }
        if !self.pending.is_empty() {
            if self
                .stream
                .as_mut()
                .expect("live stream")
                .flush()
                .await
                .is_err()
            {
                self.failed = true;
                return Err(connection("multiplex UDP flush failed"));
            }
            self.pending.clear();
            self.written = 0;
        }
        Ok(())
    }
    async fn read_until(&mut self, length: usize) -> Result<(), TransitError> {
        while self.input.len() < length {
            let mut bytes = [0; 4096];
            let wanted = (length - self.input.len()).min(bytes.len());
            match self
                .stream
                .as_mut()
                .expect("live stream")
                .read(&mut bytes[..wanted])
                .await
            {
                Ok(0) | Err(_) => {
                    self.failed = true;
                    return Err(connection("multiplex UDP response is truncated"));
                }
                Ok(read) => self.input.extend_from_slice(&bytes[..read]),
            }
        }
        Ok(())
    }
}

#[async_trait]
impl TransitDatagram for MuxDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        if self.failed {
            return Err(connection("multiplex UDP stream is closed"));
        }
        if payload.len() > u16::MAX as usize {
            return Err(unsupported("multiplex UDP datagram exceeds u16 length"));
        }
        match timeout(self.io_timeout, async {
            self.flush_pending().await?;
            self.pending
                .extend_from_slice(&(payload.len() as u16).to_be_bytes());
            self.pending.extend_from_slice(payload);
            self.flush_pending().await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => {
                self.failed = true;
                self.stream.take();
                Err(connection("multiplex UDP send timed out"))
            }
        }
    }
    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        if self.failed {
            return Err(connection("multiplex UDP stream is closed"));
        }
        self.read_until(2).await?;
        let length = usize::from(u16::from_be_bytes([self.input[0], self.input[1]]));
        self.read_until(2 + length).await?;
        let packet = self.input[2..2 + length].to_vec();
        self.input.drain(..2 + length);
        Ok(packet)
    }
    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        if self.failed {
            return Err(connection("multiplex UDP stream is closed"));
        }
        timeout(self.io_timeout, async {
            self.flush_pending().await?;
            self.stream
                .as_mut()
                .expect("live stream")
                .shutdown()
                .await
                .map_err(|_| connection("multiplex UDP shutdown failed"))?;
            let mut discard = [0; 4096];
            loop {
                match self
                    .stream
                    .as_mut()
                    .expect("live stream")
                    .read(&mut discard)
                    .await
                {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(_) => return Err(connection("multiplex UDP close failed")),
                }
            }
        })
        .await
        .map_err(|_| connection("multiplex UDP shutdown timed out"))?
    }
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.into())
}
fn connection(message: &str) -> TransitError {
    TransitError::Connection(message.into())
}
fn io_failure() -> io::Error {
    io::Error::other("multiplex HTTP/2 stream failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterKind, TransitMetadata};
    use std::sync::atomic::AtomicUsize;

    struct FakeAdapter {
        metadata: TransitMetadata,
        connections: AtomicUsize,
        block_first: AtomicBool,
        block_call: AtomicUsize,
        dial_entered: tokio::sync::Notify,
        send_mux_status: bool,
        peer_stream_limit: Option<u32>,
        servers: Mutex<Vec<tokio::task::AbortHandle>>,
    }

    impl FakeAdapter {
        fn new(block_first: bool) -> Self {
            Self {
                metadata: TransitMetadata {
                    adapter_id: "fake".into(),
                    kind: AdapterKind::Direct,
                    labels: Default::default(),
                },
                connections: AtomicUsize::new(0),
                block_first: AtomicBool::new(block_first),
                block_call: AtomicUsize::new(0),
                dial_entered: tokio::sync::Notify::new(),
                send_mux_status: true,
                peer_stream_limit: None,
                servers: Mutex::new(Vec::new()),
            }
        }
        fn count(&self) -> usize {
            self.connections.load(Ordering::Acquire)
        }
        fn stop_servers(&self) {
            for task in self.servers.lock().unwrap().drain(..) {
                task.abort();
            }
        }
    }

    #[async_trait]
    impl TransitAdapter for FakeAdapter {
        fn metadata(&self) -> &TransitMetadata {
            &self.metadata
        }
        async fn connect(
            &self,
            request: ConnectRequest,
        ) -> Result<BoxedTransitConnection, TransitError> {
            assert_eq!(request.destination.host, "sp.mux.sing-box.arpa");
            assert_eq!(request.destination.port, 444);
            let call = self.connections.fetch_add(1, Ordering::AcqRel) + 1;
            if self.block_first.swap(false, Ordering::AcqRel)
                || self.block_call.load(Ordering::Acquire) == call
            {
                self.dial_entered.notify_one();
                std::future::pending::<()>().await;
            }
            let (client, mut server) = tokio::io::duplex(128 * 1024);
            let send_mux_status = self.send_mux_status;
            let peer_stream_limit = self.peer_stream_limit;
            let task = tokio::spawn(async move {
                let mut prefix = [0; 2];
                server.read_exact(&mut prefix).await.unwrap();
                if prefix == [0, 1] {
                    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
                    let mut session = yamux::Connection::new(
                        server.compat(),
                        yamux::Config::default(),
                        yamux::Mode::Server,
                    );
                    while let Some(Ok(stream)) =
                        std::future::poll_fn(|cx| session.poll_next_inbound(cx)).await
                    {
                        tokio::spawn(async move {
                            let mut stream = stream.compat();
                            let mut header = [0; 3];
                            if stream.read_exact(&mut header).await.is_err() {
                                return;
                            }
                            let address_len = match header[2] {
                                1 => 4,
                                4 => 16,
                                3 => match stream.read_u8().await {
                                    Ok(length) => usize::from(length),
                                    Err(_) => return,
                                },
                                _ => return,
                            };
                            let mut address = vec![0; address_len + 2];
                            if stream.read_exact(&mut address).await.is_err() {
                                return;
                            }
                            if send_mux_status && stream.write_all(&[0]).await.is_ok() {
                                let (mut read, mut write) = tokio::io::split(stream);
                                let _ = tokio::io::copy(&mut read, &mut write).await;
                                let _ = write.shutdown().await;
                            }
                        });
                    }
                    return;
                }
                assert_eq!(prefix, [0, 2]);
                let mut builder = h2::server::Builder::new();
                if let Some(limit) = peer_stream_limit {
                    builder.max_concurrent_streams(limit);
                }
                let mut session = builder.handshake(server).await.unwrap();
                while let Some(Ok((request, mut responder))) = session.accept().await {
                    let mut body = request.into_body();
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send = responder.send_response(response, false).unwrap();
                    tokio::spawn(async move {
                        if send_mux_status {
                            let _ = send.send_data(Bytes::from_static(&[0]), false);
                        }
                        let mut prefix = Vec::new();
                        let mut ready = false;
                        while let Some(Ok(bytes)) = body.data().await {
                            let _ = body.flow_control().release_capacity(bytes.len());
                            if ready {
                                if send_mux_status {
                                    let _ = send.send_data(bytes, false);
                                }
                                continue;
                            }
                            prefix.extend_from_slice(&bytes);
                            if prefix.len() >= 4 {
                                let address_len = match prefix[2] {
                                    1 => Some(9),
                                    4 => Some(21),
                                    3 => Some(6 + usize::from(prefix[3])),
                                    _ => None,
                                };
                                if let Some(length) = address_len
                                    && prefix.len() >= length
                                {
                                    ready = true;
                                    if send_mux_status && prefix.len() > length {
                                        let _ = send.send_data(
                                            Bytes::copy_from_slice(&prefix[length..]),
                                            false,
                                        );
                                    }
                                    prefix.clear();
                                }
                            }
                        }
                        let _ = send.send_data(Bytes::new(), true);
                    });
                }
            });
            self.servers.lock().unwrap().push(task.abort_handle());
            Ok(Box::new(client))
        }
    }

    fn settings(
        max_connections: Option<u32>,
        min_streams: Option<u32>,
        max_streams: Option<u32>,
    ) -> TransitMultiplex {
        TransitMultiplex {
            enabled: true,
            protocol: Some("h2mux".into()),
            max_connections,
            min_streams,
            max_streams,
            padding: false,
        }
    }
    fn request() -> ConnectRequest {
        ConnectRequest {
            destination: Endpoint {
                host: "example.test".into(),
                port: 443,
            },
        }
    }

    #[test]
    fn accepts_bounded_yamux_configuration() {
        let mut options = settings(Some(1), None, None);
        options.protocol = Some("yamux".into());
        assert!(PoolOptions::parse(&options).is_ok());
        options.max_connections = None;
        options.max_streams = Some(crate::yamux_session::MAX_YAMUX_STREAMS as u32 + 1);
        assert!(matches!(
            PoolOptions::parse(&options),
            Err(TransitError::Unsupported(_))
        ));
    }

    #[test]
    fn accepts_bounded_smux_configuration() {
        let mut options = settings(Some(1), None, None);
        options.protocol = Some("smux".into());
        assert!(PoolOptions::parse(&options).is_ok());
        options.max_connections = None;
        options.max_streams = Some(crate::sing_smux::MAX_SMUX_STREAMS as u32 + 1);
        assert!(PoolOptions::parse(&options).is_err());
    }

    #[test]
    fn rejects_unimplemented_modes_conflicts_and_out_of_bounds_limits() {
        let base = Arc::new(FakeAdapter::new(false));
        let mut options = settings(None, None, None);
        options.protocol = Some("other".into());
        assert!(
            MultiplexAdapter::new(base.clone(), &options, true, true, Duration::from_secs(1))
                .is_err()
        );
        let mut options = settings(None, None, None);
        options.padding = true;
        assert!(
            MultiplexAdapter::new(base.clone(), &options, true, true, Duration::from_secs(1))
                .is_ok()
        );
        for options in [
            settings(Some(1), None, Some(1)),
            settings(None, Some(1), Some(1)),
            settings(None, Some(1), None),
            settings(Some(MAX_CONNECTIONS as u32 + 1), None, None),
            settings(None, None, Some(MAX_STREAMS as u32 + 1)),
        ] {
            assert!(
                MultiplexAdapter::new(base.clone(), &options, true, true, Duration::from_secs(1))
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn capacity_limits_select_and_reuse_physical_connections() {
        for (options, expected) in [
            (settings(Some(2), Some(2), None), 2),
            (settings(None, None, Some(2)), 3),
        ] {
            let base = Arc::new(FakeAdapter::new(false));
            let adapter =
                MultiplexAdapter::new(base.clone(), &options, true, true, Duration::from_secs(2))
                    .unwrap();
            let mut streams = Vec::new();
            for _ in 0..5 {
                streams.push(adapter.connect(request()).await.unwrap());
            }
            assert_eq!(base.count(), expected);
            drop(streams.pop());
            streams.push(adapter.connect(request()).await.unwrap());
            assert_eq!(
                base.count(),
                expected,
                "a released stream must reuse capacity"
            );
            drop(streams);
            base.stop_servers();
        }
    }

    #[tokio::test]
    async fn yamux_capacity_reuses_stream_slots_and_replaces_failed_sessions() {
        for (mut options, expected) in [
            (settings(Some(2), Some(2), None), 2),
            (settings(None, None, Some(2)), 3),
        ] {
            options.protocol = Some("yamux".into());
            let base = Arc::new(FakeAdapter::new(false));
            let adapter =
                MultiplexAdapter::new(base.clone(), &options, true, true, Duration::from_secs(2))
                    .unwrap();
            let mut streams = Vec::new();
            for _ in 0..5 {
                streams.push(adapter.connect(request()).await.unwrap());
            }
            assert_eq!(base.count(), expected);
            drop(streams.pop());
            streams.push(adapter.connect(request()).await.unwrap());
            assert_eq!(base.count(), expected);
            base.stop_servers();
            timeout(Duration::from_secs(2), async {
                while adapter
                    .pool
                    .lock()
                    .await
                    .sessions
                    .iter()
                    .any(|session| !session.is_closed())
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let mut replacement = adapter.connect(request()).await.unwrap();
            replacement.write_all(b"new-session").await.unwrap();
            replacement.flush().await.unwrap();
            let mut reply = [0; 11];
            replacement.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"new-session");
            assert_eq!(base.count(), expected + 1);
            drop(streams);
            drop(replacement);
            base.stop_servers();
        }
    }

    #[tokio::test]
    async fn cancelled_yamux_setup_releases_connection_reservation() {
        let base = Arc::new(FakeAdapter::new(true));
        let mut options = settings(Some(1), None, None);
        options.protocol = Some("yamux".into());
        let adapter =
            MultiplexAdapter::new(base.clone(), &options, true, true, Duration::from_secs(2))
                .unwrap();
        assert!(
            timeout(Duration::from_millis(30), adapter.connect(request()))
                .await
                .is_err()
        );
        let mut stream = timeout(Duration::from_secs(1), adapter.connect(request()))
            .await
            .unwrap()
            .unwrap();
        stream.write_all(b"ok").await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");
        assert_eq!(base.count(), 2);
        drop(adapter);
        stream.write_all(b"live").await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"live");
        drop(stream);
        base.stop_servers();
    }

    #[tokio::test]
    async fn cancelled_setup_releases_pool_lock_and_failed_sessions_are_replaced() {
        let base = Arc::new(FakeAdapter::new(true));
        let adapter = MultiplexAdapter::new(
            base.clone(),
            &settings(Some(1), None, None),
            true,
            true,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(
            timeout(Duration::from_millis(30), adapter.connect(request()))
                .await
                .is_err()
        );
        let first = timeout(Duration::from_secs(1), adapter.connect(request()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(base.count(), 2);
        base.stop_servers();
        for _ in 0..40 {
            if adapter
                .pool
                .lock()
                .await
                .sessions
                .iter()
                .all(|session| session.is_closed())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let second = timeout(Duration::from_secs(1), adapter.connect(request()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(base.count(), 3);
        drop((first, second));
        base.stop_servers();
    }

    #[tokio::test]
    async fn dropping_the_adapter_keeps_existing_stream_alive_until_it_closes() {
        let base = Arc::new(FakeAdapter::new(false));
        let adapter = MultiplexAdapter::new(
            base.clone(),
            &settings(Some(1), None, None),
            true,
            true,
            Duration::from_secs(2),
        )
        .unwrap();
        let mut stream = adapter.connect(request()).await.unwrap();
        drop(adapter);
        stream.write_all(b"still-open").await.unwrap();
        let mut response = [0; 10];
        timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"still-open");
        stream.shutdown().await.unwrap();
        drop(stream);
        base.stop_servers();
    }

    #[tokio::test]
    async fn mux_preserves_the_vision_udp_443_restriction() {
        let base = Arc::new(FakeAdapter::new(false));
        let adapter = MultiplexAdapter::new(
            base.clone(),
            &settings(Some(1), None, None),
            true,
            false,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            adapter.connect_udp(request()).await,
            Err(TransitError::Unsupported(_))
        ));
        assert_eq!(base.count(), 0);
        let disabled = MultiplexAdapter::new(
            base.clone(),
            &settings(Some(1), None, None),
            false,
            true,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(!disabled.supports_udp());
        assert!(matches!(
            disabled.connect_udp(request()).await,
            Err(TransitError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn udp_partial_read_and_cancelled_write_preserve_frame_boundaries() {
        let (client, mut server) = tokio::io::duplex(2);
        let mut datagram = MuxDatagram {
            stream: Some(Box::new(client)),
            input: Vec::new(),
            pending: Vec::new(),
            written: 0,
            failed: false,
            io_timeout: Duration::from_secs(2),
        };
        assert!(
            timeout(Duration::from_millis(20), datagram.send(b"first"))
                .await
                .is_err()
        );
        let peer = tokio::spawn(async move {
            let mut frames = [0; 13];
            server.read_exact(&mut frames).await.unwrap();
            assert_eq!(&frames, b"\0\x05first\0\x04next");
            server.write_all(&[0]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            server.write_all(b"\x05reply").await.unwrap();
        });
        datagram.send(b"next").await.unwrap();
        assert!(
            timeout(Duration::from_millis(20), datagram.receive())
                .await
                .is_err()
        );
        assert_eq!(datagram.receive().await.unwrap(), b"reply");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn udp_close_requires_a_confirmed_mux_status() {
        for confirmed in [false, true] {
            let mut fake = FakeAdapter::new(false);
            fake.send_mux_status = confirmed;
            let base = Arc::new(fake);
            let adapter = MultiplexAdapter::new(
                base.clone(),
                &settings(Some(1), None, None),
                true,
                true,
                Duration::from_secs(2),
            )
            .unwrap();
            let mut socket = adapter.connect_udp(request()).await.unwrap();
            socket.send(b"packet").await.unwrap();
            let closed = timeout(Duration::from_secs(2), socket.close())
                .await
                .unwrap();
            assert_eq!(
                closed.is_ok(),
                confirmed,
                "HTTP/2 200 alone must not confirm mux admission"
            );
            base.stop_servers();
        }
    }

    #[tokio::test]
    async fn peer_stream_limit_opens_another_session_and_obeys_connection_cap() {
        let mut fake = FakeAdapter::new(false);
        fake.peer_stream_limit = Some(1);
        let base = Arc::new(fake);
        let adapter = MultiplexAdapter::new(
            base.clone(),
            &settings(Some(2), Some(8), None),
            true,
            true,
            Duration::from_secs(2),
        )
        .unwrap();
        let mut first = adapter.connect(request()).await.unwrap();
        first.write_all(b"first").await.unwrap();
        let mut reply = [0; 5];
        first.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"first");
        let mut second = timeout(Duration::from_millis(500), adapter.connect(request()))
            .await
            .expect("another physical connection should provide capacity")
            .unwrap();
        second.write_all(b"other").await.unwrap();
        second.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"other");
        assert_eq!(base.count(), 2);
        assert!(
            timeout(Duration::from_millis(100), adapter.connect(request()))
                .await
                .is_err()
        );
        assert_eq!(
            base.count(),
            2,
            "the configured connection cap is respected"
        );
        drop(first);
        let third = timeout(Duration::from_secs(1), adapter.connect(request()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            base.count(),
            2,
            "released capacity should reuse an existing session"
        );
        drop((second, third));
        base.stop_servers();
    }

    #[tokio::test]
    async fn slow_expansion_does_not_block_reusing_an_idle_session() {
        let base = Arc::new(FakeAdapter::new(false));
        base.block_call.store(2, Ordering::Release);
        let adapter = Arc::new(
            MultiplexAdapter::new(
                base.clone(),
                &settings(Some(2), Some(1), None),
                true,
                true,
                Duration::from_secs(3),
            )
            .unwrap(),
        );
        let first = adapter.connect(request()).await.unwrap();
        let second_adapter = Arc::clone(&adapter);
        let second = tokio::spawn(async move { second_adapter.connect(request()).await });
        timeout(Duration::from_secs(1), base.dial_entered.notified())
            .await
            .unwrap();
        drop(first);
        let reused = timeout(Duration::from_millis(500), adapter.connect(request()))
            .await
            .expect("slow expansion must not lock idle sessions")
            .unwrap();
        assert_eq!(base.count(), 2);
        second.abort();
        assert!(matches!(second.await, Err(error) if error.is_cancelled()));
        drop(reused);
        let again = timeout(Duration::from_secs(1), adapter.connect(request()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(base.count(), 2);
        drop(again);
        base.stop_servers();
    }
}
