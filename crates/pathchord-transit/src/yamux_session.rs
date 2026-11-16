//! Bounded, cancellation-aware Yamux client session for sing-box multiplex.
//!
//! The outer sing-box handshake and each stream's target request are handled by
//! the caller. This module owns only the Yamux session and its byte streams.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::{BoxedTransitConnection, TransitError};

/// Bound the minimum per-stream receive windows to 64 MiB per connection,
/// plus a bounded allowance for streams being closed by the driver.
pub(crate) const MAX_YAMUX_STREAMS: usize = 256;
const MAX_PENDING_OPENS: usize = 64;
const YAMUX_INITIAL_WINDOW: usize = 256 * 1024;
const DRIVER_WORK_BUDGET: usize = 64;

type OpenResult = Result<yamux::Stream, ()>;

struct OpenRequest {
    reply: oneshot::Sender<OpenResult>,
}

struct SessionInner {
    requests: mpsc::Sender<OpenRequest>,
    driver: Mutex<Option<tokio::task::JoinHandle<()>>>,
    active: AtomicUsize,
    dead: AtomicBool,
    max_streams: usize,
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        if let Some(driver) = self
            .driver
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            driver.abort();
        }
    }
}

struct DriverGuard(Weak<SessionInner>);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        if let Some(session) = self.0.upgrade() {
            session.dead.store(true, Ordering::Release);
        }
    }
}

/// A Yamux session owns one driver task and can open bounded, independent streams.
pub(crate) struct YamuxSession {
    inner: Arc<SessionInner>,
}

impl YamuxSession {
    pub(crate) fn new(
        stream: BoxedTransitConnection,
        max_streams: usize,
    ) -> Result<Self, TransitError> {
        if !(1..=MAX_YAMUX_STREAMS).contains(&max_streams) {
            return Err(TransitError::Unsupported(
                "yamux stream limit is invalid".into(),
            ));
        }
        let internal_limit = max_streams + MAX_PENDING_OPENS;
        let mut config = yamux::Config::default();
        config.set_max_num_streams(internal_limit);
        config.set_max_connection_receive_window(Some(internal_limit * YAMUX_INITIAL_WINDOW));
        let connection = yamux::Connection::new(stream.compat(), config, yamux::Mode::Client);
        let (sender, receiver) = mpsc::channel(MAX_PENDING_OPENS.min(max_streams));
        let inner = Arc::new(SessionInner {
            requests: sender,
            driver: Mutex::new(None),
            active: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
            max_streams,
        });
        let driver = tokio::spawn(run_driver(connection, receiver, Arc::downgrade(&inner)));
        *inner.driver.lock().map_err(|_| connection_error())? = Some(driver);
        Ok(Self { inner })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.inner.dead.load(Ordering::Acquire) || self.inner.requests.is_closed()
    }

    pub(crate) async fn open(&self) -> Result<BoxedTransitConnection, TransitError> {
        if self.is_closed() {
            return Err(connection_error());
        }
        self.inner
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.inner.max_streams).then_some(active + 1)
            })
            .map_err(|_| TransitError::Unsupported("yamux stream limit reached".into()))?;
        let permit = StreamPermit(Arc::clone(&self.inner));
        let (sender, receiver) = oneshot::channel();
        self.inner
            .requests
            .send(OpenRequest { reply: sender })
            .await
            .map_err(|_| connection_error())?;
        let stream = receiver
            .await
            .map_err(|_| connection_error())?
            .map_err(|_| connection_error())?;
        Ok(Box::new(YamuxStream {
            io: stream.compat(),
            _permit: permit,
        }))
    }
}

fn connection_error() -> TransitError {
    TransitError::Connection("yamux session is unavailable".into())
}

async fn run_driver(
    mut connection: yamux::Connection<Compat<BoxedTransitConnection>>,
    mut requests: mpsc::Receiver<OpenRequest>,
    session: Weak<SessionInner>,
) {
    let _guard = DriverGuard(session);
    let mut pending: Option<OpenRequest> = None;
    poll_fn(|cx| {
        let mut made_progress = false;
        for _ in 0..DRIVER_WORK_BUDGET {
            match connection.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    drop(stream);
                    made_progress = true;
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => break,
            }
        }
        for _ in 0..DRIVER_WORK_BUDGET {
            if pending.is_none() {
                match requests.poll_recv(cx) {
                    Poll::Ready(Some(request)) => pending = Some(request),
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
            let request = pending.as_mut().expect("pending open request");
            if request.reply.poll_closed(cx).is_ready() {
                pending = None;
                made_progress = true;
                continue;
            }
            match connection.poll_new_outbound(cx) {
                Poll::Ready(Ok(stream)) => {
                    let request = pending.take().expect("pending open request");
                    // If the caller was cancelled, dropping this stream lets
                    // the driver emit RST instead of leaking it in the session.
                    let _ = request.reply.send(Ok(stream));
                    made_progress = true;
                }
                Poll::Ready(Err(_)) => return Poll::Ready(()),
                Poll::Pending => break,
            }
        }
        // `poll_next_inbound` must run again after commands create streams or
        // dropped streams need resets, even when no socket event is pending.
        if made_progress || pending.is_none() && !requests.is_empty() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await;
}

struct StreamPermit(Arc<SessionInner>);

impl Drop for StreamPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct YamuxStream {
    io: Compat<yamux::Stream>,
    _permit: StreamPermit,
}

impl AsyncRead for YamuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for YamuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn read_frame(stream: &mut tokio::io::DuplexStream) -> (u8, u16, u32, Vec<u8>) {
        loop {
            let mut header = [0; 12];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0, "Yamux version");
            let kind = header[1];
            let flags = u16::from_be_bytes([header[2], header[3]]);
            let id = u32::from_be_bytes(header[4..8].try_into().unwrap());
            let length = u32::from_be_bytes(header[8..12].try_into().unwrap());
            if kind == 2 && flags & 1 != 0 {
                header[2..4].copy_from_slice(&2_u16.to_be_bytes());
                stream.write_all(&header).await.unwrap();
                stream.flush().await.unwrap();
                continue;
            }
            let mut payload = vec![0; if kind == 0 { length as usize } else { 0 }];
            stream.read_exact(&mut payload).await.unwrap();
            return (kind, flags, id, payload);
        }
    }

    async fn write_data(stream: &mut tokio::io::DuplexStream, flags: u16, id: u32, bytes: &[u8]) {
        let mut header = vec![0, 0];
        header.extend_from_slice(&flags.to_be_bytes());
        header.extend_from_slice(&id.to_be_bytes());
        header.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        stream.write_all(&header).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn write_window(stream: &mut tokio::io::DuplexStream, id: u32, credit: u32) {
        let mut header = vec![0, 1, 0, 0];
        header.extend_from_slice(&id.to_be_bytes());
        header.extend_from_slice(&credit.to_be_bytes());
        stream.write_all(&header).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn open_peer_stream(stream: &mut tokio::io::DuplexStream, id: u32) {
        let mut header = vec![0, 1, 0, 1];
        header.extend_from_slice(&id.to_be_bytes());
        header.extend_from_slice(&0_u32.to_be_bytes());
        stream.write_all(&header).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[tokio::test]
    async fn exchanges_data_and_half_closes_with_an_independent_wire_peer() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (client, mut peer) = tokio::io::duplex(65_536);
            let session = YamuxSession::new(Box::new(client), 4).unwrap();
            let peer_task = tokio::spawn(async move {
                let (kind, flags, id, data) = read_frame(&mut peer).await;
                assert_eq!((kind, flags & 1, id), (0, 1, 1));
                assert_eq!(data, b"request");
                write_data(&mut peer, 2, id, b"response").await;
                let (kind, flags, close_id, _) = read_frame(&mut peer).await;
                assert_eq!(close_id, id);
                assert!(kind == 0 || kind == 1);
                assert_ne!(flags & 4, 0, "client FIN");
                write_data(&mut peer, 4, id, b" after-fin").await;
            });
            let mut stream = session.open().await.unwrap();
            stream.write_all(b"request").await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0; 8];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"response");
            stream.shutdown().await.unwrap();
            let mut after_fin = Vec::new();
            stream.read_to_end(&mut after_fin).await.unwrap();
            assert_eq!(after_fin, b" after-fin");
            peer_task.await.unwrap();
        })
        .await
        .expect("bounded Yamux exchange");
    }

    #[tokio::test]
    async fn cancelled_open_releases_its_slot_without_opening_a_stream() {
        let (client, _peer) = tokio::io::duplex(4096);
        let session = YamuxSession::new(Box::new(client), 1).unwrap();
        {
            let mut open = pin!(session.open());
            assert!(matches!(
                open.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
            assert_eq!(session.inner.active.load(Ordering::Acquire), 1);
        }
        assert_eq!(session.inner.active.load(Ordering::Acquire), 0);
        let stream = tokio::time::timeout(std::time::Duration::from_secs(2), session.open())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.inner.active.load(Ordering::Acquire), 1);
        drop(stream);
        assert_eq!(session.inner.active.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn dropping_a_live_stream_resets_it_without_closing_the_session() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (client, mut peer) = tokio::io::duplex(65_536);
            let session = YamuxSession::new(Box::new(client), 1).unwrap();
            let (opened, opened_rx) = oneshot::channel();
            let peer_task = tokio::spawn(async move {
                let (kind, flags, first, body) = read_frame(&mut peer).await;
                assert_eq!(
                    (kind, flags & 1, first, body.as_slice()),
                    (0, 1, 1, b"first".as_slice())
                );
                write_data(&mut peer, 2, first, b"ready").await;
                opened.send(()).unwrap();
                let (_, flags, id, _) = read_frame(&mut peer).await;
                assert_eq!(id, first);
                assert_ne!(flags & 8, 0, "dropped stream must reset");
                let (kind, flags, second, body) = read_frame(&mut peer).await;
                assert_eq!(
                    (kind, flags & 1, second, body.as_slice()),
                    (0, 1, 3, b"second".as_slice())
                );
                write_data(&mut peer, 2 | 4, second, b"ok").await;
            });
            let mut first = session.open().await.unwrap();
            first.write_all(b"first").await.unwrap();
            first.flush().await.unwrap();
            opened_rx.await.unwrap();
            let mut response = [0; 5];
            first.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ready");
            assert!(matches!(
                session.open().await,
                Err(TransitError::Unsupported(_))
            ));
            drop(first);
            let mut second = session.open().await.unwrap();
            second.write_all(b"second").await.unwrap();
            second.flush().await.unwrap();
            let mut response = [0; 2];
            second.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ok");
            peer_task.await.unwrap();
        })
        .await
        .expect("bounded Yamux reset test");
    }

    #[tokio::test]
    async fn concurrent_streams_preserve_frame_and_payload_boundaries() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            const COUNT: usize = 12;
            let (client, mut peer) = tokio::io::duplex(131_072);
            let session = Arc::new(YamuxSession::new(Box::new(client), COUNT).unwrap());
            let peer_task = tokio::spawn(async move {
                let mut ids = std::collections::BTreeSet::new();
                while ids.len() < COUNT {
                    let (kind, flags, id, body) = read_frame(&mut peer).await;
                    if kind == 0 && flags & 1 != 0 {
                        assert!(ids.insert(id));
                        assert_eq!(id % 2, 1);
                        assert_eq!(body.len(), 32);
                        write_data(&mut peer, 2 | 4, id, &body).await;
                    }
                }
                ids
            });
            let mut tasks = tokio::task::JoinSet::new();
            for value in 0..COUNT {
                let session = Arc::clone(&session);
                tasks.spawn(async move {
                    let mut stream = session.open().await.unwrap();
                    let payload = [value as u8; 32];
                    stream.write_all(&payload).await.unwrap();
                    stream.flush().await.unwrap();
                    let mut received = [0; 32];
                    stream.read_exact(&mut received).await.unwrap();
                    assert_eq!(received, payload);
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
            assert_eq!(peer_task.await.unwrap().len(), COUNT);
        })
        .await
        .expect("bounded concurrent Yamux test");
    }

    #[tokio::test]
    async fn peer_failure_closes_the_session_and_rejects_new_streams() {
        let (client, peer) = tokio::io::duplex(4096);
        let session = YamuxSession::new(Box::new(client), 4).unwrap();
        drop(peer);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !session.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            session.open().await,
            Err(TransitError::Connection(_))
        ));
    }

    #[tokio::test]
    async fn malformed_frame_closes_the_session_without_opening_more_streams() {
        let (client, mut peer) = tokio::io::duplex(4096);
        let session = YamuxSession::new(Box::new(client), 4).unwrap();
        peer.write_all(&[1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0])
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !session.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            session.open().await,
            Err(TransitError::Connection(_))
        ));
    }

    #[tokio::test]
    async fn unsolicited_inbound_stream_is_reset_and_other_streams_remain_usable() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (client, mut peer) = tokio::io::duplex(65_536);
            let session = YamuxSession::new(Box::new(client), 4).unwrap();
            let (reset_tx, reset_rx) = oneshot::channel();
            let peer_task = tokio::spawn(async move {
                open_peer_stream(&mut peer, 2).await;
                let (_, flags, id, _) = read_frame(&mut peer).await;
                assert_eq!(id, 2);
                assert_ne!(flags & 8, 0, "unsolicited inbound stream must reset");
                reset_tx.send(()).unwrap();
                let (kind, flags, id, data) = read_frame(&mut peer).await;
                assert_eq!(
                    (kind, flags & 1, id, data.as_slice()),
                    (0, 1, 1, b"ok".as_slice())
                );
                write_data(&mut peer, 2 | 4, id, b"reply").await;
            });
            reset_rx.await.unwrap();
            let mut stream = session.open().await.unwrap();
            stream.write_all(b"ok").await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = [0; 5];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
            peer_task.await.unwrap();
        })
        .await
        .expect("bounded unsolicited Yamux stream test");
    }

    #[tokio::test]
    async fn repeated_cancelled_streams_do_not_exhaust_the_session() {
        let (client, _peer) = tokio::io::duplex(65_536);
        let session = YamuxSession::new(Box::new(client), 2).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for _ in 0..1_000 {
                drop(session.open().await.unwrap());
            }
            assert!(!session.is_closed());
        })
        .await
        .expect("repeated opens must not leak Yamux stream slots");
    }

    #[tokio::test]
    async fn rejects_stream_limits_outside_the_bounded_range() {
        for limit in [0, MAX_YAMUX_STREAMS + 1] {
            let (client, _peer) = tokio::io::duplex(64);
            assert!(matches!(
                YamuxSession::new(Box::new(client), limit),
                Err(TransitError::Unsupported(_))
            ));
        }
    }

    #[tokio::test]
    async fn write_waits_for_peer_window_and_resumes_without_losing_bytes() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            const INITIAL_WINDOW: usize = 256 * 1024;
            const TOTAL: usize = INITIAL_WINDOW + 40_000;
            let (client, mut peer) = tokio::io::duplex(65_536);
            let session = YamuxSession::new(Box::new(client), 1).unwrap();
            let (blocked_tx, blocked_rx) = oneshot::channel();
            let (resume_tx, resume_rx) = oneshot::channel();
            let peer_task = tokio::spawn(async move {
                let mut count = 0;
                let mut id = None;
                let mut blocked_tx = Some(blocked_tx);
                let mut resume_rx = Some(resume_rx);
                while count < TOTAL {
                    let (kind, flags, stream_id, bytes) = read_frame(&mut peer).await;
                    if kind != 0 {
                        continue;
                    }
                    if id.is_none() {
                        assert_ne!(flags & 1, 0);
                        id = Some(stream_id);
                        write_data(&mut peer, 2, stream_id, &[]).await;
                    }
                    assert_eq!(Some(stream_id), id);
                    assert!(bytes.iter().all(|byte| *byte == 0x53));
                    count += bytes.len();
                    if count == INITIAL_WINDOW {
                        blocked_tx.take().unwrap().send(()).unwrap();
                        resume_rx.take().unwrap().await.unwrap();
                        write_window(&mut peer, stream_id, 65_536).await;
                    }
                    assert!(count <= TOTAL);
                }
                write_data(&mut peer, 4, id.unwrap(), b"ok").await;
            });
            let mut stream = session.open().await.unwrap();
            let writer = tokio::spawn(async move {
                stream.write_all(&vec![0x53; TOTAL]).await.unwrap();
                stream.flush().await.unwrap();
                stream
            });
            blocked_rx.await.unwrap();
            assert!(
                !writer.is_finished(),
                "write must wait when peer credit is exhausted"
            );
            resume_tx.send(()).unwrap();
            let mut stream = writer.await.unwrap();
            let mut reply = [0; 2];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"ok");
            peer_task.await.unwrap();
        })
        .await
        .expect("bounded Yamux flow-control test");
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_GO_YAMUX_SERVER pointing to a HashiCorp yamux 0.1.2 test peer"]
    async fn interoperates_with_hashicorp_yamux_and_keeps_reading_after_fin() {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let binary = std::env::var_os("PATHCHORD_TEST_GO_YAMUX_SERVER").expect("test peer");
            let mut peer = tokio::process::Command::new(binary)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(peer.stdout.take().unwrap())
                .read_line(&mut line)
                .await
                .unwrap();
            let address: std::net::SocketAddr = line.trim().parse().unwrap();
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let session = YamuxSession::new(Box::new(socket), 4).unwrap();
            let mut stream = session.open().await.unwrap();
            let payload: Vec<u8> = (0..16_000).map(|index| (index % 251) as u8).collect();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload);
            drop(stream);
            drop(session);
            assert!(peer.wait().await.unwrap().success());
        })
        .await
        .expect("HashiCorp Yamux peer timed out");
    }
}
