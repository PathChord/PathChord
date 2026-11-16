use super::*;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

struct SlowWriter {
    inner: DuplexStream,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

struct StalledFlush(DuplexStream);

struct SlowFrameWriter {
    inner: DuplexStream,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl AsyncRead for SlowFrameWriter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}
impl AsyncWrite for SlowFrameWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(40))));
        if timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.timer = None;
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for StalledFlush {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, output)
    }
}

struct ObservedStalledFlush {
    inner: DuplexStream,
    dropped: Arc<AtomicBool>,
}

impl Drop for ObservedStalledFlush {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}
impl AsyncRead for ObservedStalledFlush {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}
impl AsyncWrite for ObservedStalledFlush {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct SlowPaddingCarrier {
    inner: DuplexStream,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl AsyncRead for SlowPaddingCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}
impl AsyncWrite for SlowPaddingCarrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(5))));
        if timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.timer = None;
        Pin::new(&mut self.inner).poll_write(cx, &data[..data.len().min(8)])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncWrite for StalledFlush {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsyncRead for SlowWriter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for SlowWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(30))));
        if timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.timer = None;
        Pin::new(&mut self.inner).poll_write(cx, &data[..1])
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

const DEADLINE: Duration = Duration::from_secs(2);

async fn read_frame(peer: &mut DuplexStream) -> (u8, u32, Vec<u8>) {
    let mut raw = [0; HEADER_LEN];
    tokio::time::timeout(DEADLINE, peer.read_exact(&mut raw))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw[0], VERSION);
    let length = usize::from(u16::from_le_bytes([raw[2], raw[3]]));
    let id = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    let mut payload = vec![0; length];
    peer.read_exact(&mut payload).await.unwrap();
    (raw[1], id, payload)
}

async fn send_frame(peer: &mut DuplexStream, command: u8, id: u32, payload: &[u8]) {
    peer.write_all(&header(command, id, payload.len()))
        .await
        .unwrap();
    peer.write_all(payload).await.unwrap();
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(DEADLINE, async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn overloaded_stream_does_not_block_another_stream() {
    let (client, mut peer) = tokio::io::duplex(512 * 1024);
    let session = SmuxSession::new(client, 2).unwrap();
    let mut stalled = session.open().unwrap();
    let mut healthy = session.open().unwrap();
    assert_eq!(read_frame(&mut peer).await.0, SYN);
    assert_eq!(read_frame(&mut peer).await.0, SYN);

    let packet = vec![0x42; u16::MAX as usize];
    for _ in 0..5 {
        send_frame(&mut peer, PSH, 3, &packet).await;
    }
    send_frame(&mut peer, PSH, 3, b"discarded").await;
    send_frame(&mut peer, PSH, 5, b"healthy").await;
    let mut received = [0; 7];
    tokio::time::timeout(DEADLINE, healthy.read_exact(&mut received))
        .await
        .expect("slow stream must not block an unrelated stream")
        .unwrap();
    assert_eq!(&received, b"healthy");
    assert_eq!(
        stalled.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(read_frame(&mut peer).await, (FIN, 3, Vec::new()));
    assert!(!session.is_closed());
}

#[tokio::test]
async fn global_byte_pressure_evicts_the_buffered_stream_before_the_healthy_stream() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let mut limits = Limits::new(2).unwrap();
    limits.rx_bytes = 8;
    limits.rx_stream_bytes = 8;
    let session = SmuxSession::with_limits(client, limits).unwrap();
    let mut stalled = session.open().unwrap();
    let mut healthy = session.open().unwrap();
    read_frame(&mut peer).await;
    read_frame(&mut peer).await;
    send_frame(&mut peer, PSH, 3, b"12345678").await;
    wait_until(|| session.test_usage().1 == 8).await;
    stalled.read_exact(&mut [0; 1]).await.unwrap();
    assert_eq!(
        session.test_usage().1,
        8,
        "partial consumption must not release allocation budget"
    );
    send_frame(&mut peer, PSH, 5, b"x").await;
    let mut response = [0; 1];
    tokio::time::timeout(DEADLINE, healthy.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"x");
    assert_eq!(
        stalled.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(read_frame(&mut peer).await, (FIN, 3, Vec::new()));
    assert!(!session.is_closed());
}

#[tokio::test]
async fn global_frame_pressure_isolates_the_stream_occupying_the_budget() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let mut limits = Limits::new(2).unwrap();
    limits.rx_frames = 2;
    let session = SmuxSession::with_limits(client, limits).unwrap();
    let mut stalled = session.open().unwrap();
    let mut healthy = session.open().unwrap();
    read_frame(&mut peer).await;
    read_frame(&mut peer).await;
    send_frame(&mut peer, PSH, 3, b"a").await;
    send_frame(&mut peer, PSH, 3, b"b").await;
    send_frame(&mut peer, PSH, 5, b"c").await;
    let mut response = [0; 1];
    tokio::time::timeout(DEADLINE, healthy.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"c");
    assert_eq!(
        stalled.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(read_frame(&mut peer).await, (FIN, 3, Vec::new()));
}

#[tokio::test]
async fn partially_read_frames_remain_charged_until_the_allocation_is_released() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = SmuxSession::new(client, 2).unwrap();
    let mut first = session.open().unwrap();
    let mut second = session.open().unwrap();
    read_frame(&mut peer).await;
    read_frame(&mut peer).await;
    send_frame(&mut peer, PSH, 3, b"1234").await;
    send_frame(&mut peer, PSH, 5, b"5678").await;
    wait_until(|| session.test_usage().2 == 2).await;
    first.read_exact(&mut [0; 1]).await.unwrap();
    second.read_exact(&mut [0; 1]).await.unwrap();
    assert_eq!(
        session.test_usage().1,
        8,
        "both complete frame allocations remain resident"
    );
    let state = session.shared.lock();
    assert_eq!(state.streams[&3].rx_bytes, 4);
    assert_eq!(state.streams[&5].rx_bytes, 4);
}

#[tokio::test]
async fn slow_but_progressing_header_and_payload_are_not_timed_out() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session =
        SmuxSession::with_test_limits(client, 1, 128, 4, 4, Duration::from_millis(100)).unwrap();
    let mut stream = session.open().unwrap();
    read_frame(&mut peer).await;
    let sender = tokio::spawn(async move {
        let mut frame = header(PSH, 3, 8).to_vec();
        frame.extend_from_slice(b"abcdefgh");
        for byte in frame {
            if peer.write_all(&[byte]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    });
    let mut output = [0; 8];
    tokio::time::timeout(DEADLINE, stream.read_exact(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&output, b"abcdefgh");
    sender.await.unwrap();
}

#[tokio::test]
async fn slow_but_progressing_carrier_writes_are_not_timed_out() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = SmuxSession::with_test_limits(
        SlowWriter {
            inner: client,
            timer: None,
        },
        1,
        128,
        4,
        4,
        Duration::from_millis(100),
    )
    .unwrap();
    let _stream = session.open().unwrap();
    assert_eq!(read_frame(&mut peer).await, (SYN, 3, Vec::new()));
    assert!(!session.is_closed());
}

#[tokio::test]
async fn slow_progress_when_discarding_an_unknown_stream_does_not_timeout() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session =
        SmuxSession::with_test_limits(client, 1, 128, 4, 4, Duration::from_millis(100)).unwrap();
    let mut stream = session.open().unwrap();
    read_frame(&mut peer).await;
    let sender = tokio::spawn(async move {
        peer.write_all(&header(PSH, 999, 8)).await.unwrap();
        for byte in b"discard!" {
            if peer.write_all(&[*byte]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        send_frame(&mut peer, PSH, 3, b"ok").await;
    });
    let mut response = [0; 2];
    timeout(DEADLINE, stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"ok");
    sender.await.unwrap();
}

#[tokio::test]
async fn active_stream_does_not_expire_an_unobservable_stalled_flush() {
    let (client, _peer) = tokio::io::duplex(1024);
    let session = SmuxSession::with_test_limits(
        StalledFlush(client),
        1,
        128,
        4,
        4,
        Duration::from_millis(100),
    )
    .unwrap();
    let mut stream = session.open().unwrap();
    assert!(
        timeout(Duration::from_millis(250), stream.flush())
            .await
            .is_err()
    );
    assert!(!session.is_closed());
}

#[tokio::test]
async fn padding_flush_may_progress_for_longer_than_the_idle_grace() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let padded = crate::sing_mux_padding::PaddingStream::new(SlowPaddingCarrier {
        inner: client,
        timer: None,
    });
    let session =
        SmuxSession::with_test_limits(padded, 1, 128, 4, 4, Duration::from_millis(100)).unwrap();
    let _stream = session.open().unwrap();
    let mut record = [0; 4];
    timeout(DEADLINE, peer.read_exact(&mut record))
        .await
        .unwrap()
        .unwrap();
    let length = usize::from(u16::from_be_bytes([record[0], record[1]]));
    let padding = usize::from(u16::from_be_bytes([record[2], record[3]]));
    assert_eq!(length, HEADER_LEN);
    let mut payload = vec![0; length + padding];
    timeout(DEADLINE, peer.read_exact(&mut payload))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&payload[..length], &header(SYN, 3, 0));
    assert!(!session.is_closed());
}

#[tokio::test]
async fn padding_read_can_consume_slow_padding_without_a_false_timeout() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let session = SmuxSession::with_test_limits(
        crate::sing_mux_padding::PaddingStream::new(client),
        1,
        128,
        4,
        4,
        Duration::from_millis(100),
    )
    .unwrap();
    let mut stream = session.open().unwrap();
    let sender = tokio::spawn(async move {
        peer.write_all(&[0, 1, 0, 0, VERSION]).await.unwrap();
        peer.write_all(&[0, 0, 0, 20]).await.unwrap();
        for _ in 0..20 {
            if peer.write_all(&[0]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        peer.write_all(&[0, 10, 0, 0]).await.unwrap();
        peer.write_all(&header(PSH, 3, 3)[1..]).await.unwrap();
        peer.write_all(b"abc").await.unwrap();
    });
    let mut output = [0; 3];
    timeout(DEADLINE, stream.read_exact(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&output, b"abc");
    sender.await.unwrap();
}

#[tokio::test]
async fn dropping_last_owner_cancels_a_stalled_flush() {
    let (client, _peer) = tokio::io::duplex(1024);
    let dropped = Arc::new(AtomicBool::new(false));
    let session = SmuxSession::with_test_limits(
        ObservedStalledFlush {
            inner: client,
            dropped: Arc::clone(&dropped),
        },
        1,
        128,
        4,
        4,
        Duration::from_millis(100),
    )
    .unwrap();
    let stream = session.open().unwrap();
    tokio::task::yield_now().await;
    drop(session);
    drop(stream);
    timeout(DEADLINE, async {
        while !dropped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reopening_a_stream_cancels_pending_idle_drain() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let dropped = Arc::new(AtomicBool::new(false));
    let session = SmuxSession::with_test_limits(
        ObservedStalledFlush {
            inner: client,
            dropped: Arc::clone(&dropped),
        },
        2,
        128,
        4,
        4,
        Duration::from_millis(100),
    )
    .unwrap();
    let first = session.open().unwrap();
    read_frame(&mut peer).await;
    drop(first);
    tokio::time::sleep(Duration::from_millis(60)).await;
    let second = session.open().unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !session.is_closed(),
        "new owner must cancel the pending drain timer"
    );
    assert!(!dropped.load(Ordering::Acquire));
    drop(second);
    timeout(DEADLINE, async {
        while !dropped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reopening_then_dropping_creates_a_new_idle_deadline() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = SmuxSession::with_test_limits(
        StalledFlush(client),
        2,
        128,
        4,
        4,
        Duration::from_millis(200),
    )
    .unwrap();
    let first = session.open().unwrap();
    read_frame(&mut peer).await;
    drop(first);
    let first_deadline = session.shared.lock().idle_deadline.unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    let second = session.open().unwrap();
    assert!(session.shared.lock().idle_deadline.is_none());
    drop(second);
    let second_deadline = session.shared.lock().idle_deadline.unwrap();
    assert!(second_deadline > first_deadline);
    wait_until(|| session.is_closed()).await;
}

#[tokio::test]
async fn idle_grace_is_shared_across_multiple_slow_frames() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = SmuxSession::with_test_limits(
        SlowFrameWriter {
            inner: client,
            timer: None,
        },
        1,
        128,
        4,
        4,
        Duration::from_millis(100),
    )
    .unwrap();
    let mut stream = session.open().unwrap();
    assert_eq!(read_frame(&mut peer).await.0, SYN);
    for _ in 0..3 {
        stream.write_all(b"data").await.unwrap();
    }
    drop(stream);
    let deadline = session.shared.lock().idle_deadline.unwrap();
    timeout(DEADLINE, async {
        while !session.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(tokio::time::Instant::now().duration_since(deadline) < Duration::from_millis(250));
    assert_eq!(
        session.shared.lock().terminal.unwrap().0,
        io::ErrorKind::TimedOut
    );
    let mut remaining = Vec::new();
    timeout(DEADLINE, peer.read_to_end(&mut remaining))
        .await
        .unwrap()
        .unwrap();
    assert!(
        remaining.len() < 3 * (HEADER_LEN + 4),
        "the absolute grace must not reset per frame"
    );
}

#[tokio::test]
async fn opening_and_idle_timeout_have_one_atomic_order() {
    timeout(DEADLINE, async {
        for _ in 0..128 {
            let (client, _peer) = tokio::io::duplex(1024);
            let session = Arc::new(SmuxSession::new(client, 1).unwrap());
            session.shared.lock().idle_deadline = Some(tokio::time::Instant::now());
            let gate = Arc::new(tokio::sync::Barrier::new(3));
            let first_session = Arc::clone(&session);
            let first_gate = Arc::clone(&gate);
            let opener = tokio::spawn(async move {
                first_gate.wait().await;
                first_session.open()
            });
            let second_session = Arc::clone(&session);
            let second_gate = Arc::clone(&gate);
            let expirer = tokio::spawn(async move {
                second_gate.wait().await;
                second_session
                    .shared
                    .fail_if(io::ErrorKind::TimedOut, "idle expired", true)
            });
            gate.wait().await;
            let stream = opener.await.unwrap();
            let expired = expirer.await.unwrap();
            match stream {
                Ok(_stream) => assert!(!expired && !session.is_closed()),
                Err(error) => {
                    assert!(expired && session.is_closed());
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                }
            }
        }
    })
    .await
    .expect("open/expiration race must not deadlock");
}

#[tokio::test]
async fn multiplexes_streams_and_preserves_fin_order() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let session = SmuxSession::new(client, 2).unwrap();
    assert!(session.can_open());
    let mut a = session.open().unwrap();
    let mut b = session.open().unwrap();
    assert!(!session.can_open());
    assert_eq!(
        session.open().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut syn = Vec::new();
        while syn.len() < 2 {
            let (cmd, id, body) = read_frame(&mut peer).await;
            assert_eq!(cmd, 0);
            assert!(body.is_empty());
            syn.push(id);
        }
        assert_eq!(syn, [3, 5]);
        let mut fins = 0;
        while fins < 2 {
            let (cmd, id, body) = read_frame(&mut peer).await;
            match cmd {
                2 => send_frame(&mut peer, 2, id, &body).await,
                1 => {
                    send_frame(&mut peer, 1, id, &[]).await;
                    fins += 1;
                }
                _ => panic!("unexpected frame"),
            }
        }
        let _ = done_rx.await;
    });
    let (ra, rb) = tokio::join!(a.write_all(b"first"), b.write_all(b"second"));
    ra.unwrap();
    rb.unwrap();
    let mut aa = [0; 5];
    let mut bb = [0; 6];
    let (ra, rb) = tokio::join!(a.read_exact(&mut aa), b.read_exact(&mut bb));
    ra.unwrap();
    rb.unwrap();
    assert_eq!(&aa, b"first");
    assert_eq!(&bb, b"second");
    let (ra, rb) = tokio::join!(a.shutdown(), b.shutdown());
    ra.unwrap();
    rb.unwrap();
    assert_eq!(a.read(&mut [0; 1]).await.unwrap(), 0);
    assert_eq!(b.read(&mut [0; 1]).await.unwrap(), 0);
    done_tx.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn cancelled_write_is_bounded_and_drop_drains_before_fin() {
    let (client, mut peer) = tokio::io::duplex(1);
    let session =
        SmuxSession::with_test_limits(client, 1, 20, 1, 4, Duration::from_secs(2)).unwrap();
    let mut stream = session.open().unwrap();
    assert!(
        timeout(Duration::from_millis(30), stream.write_all(&[7; 100]))
            .await
            .is_err()
    );
    let (_, _, _, bytes, frames) = session.test_usage();
    assert!(bytes <= 20);
    assert!(frames <= 1);
    drop(stream);
    assert_eq!(
        session.open().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(read_frame(&mut peer).await, (0, 3, vec![]));
    let (cmd, id, data) = read_frame(&mut peer).await;
    assert_eq!((cmd, id), (2, 3));
    assert_eq!(data, vec![7; 12]);
    assert_eq!(read_frame(&mut peer).await, (1, 3, vec![]));
    wait_until(|| session.test_usage().0 == 0).await;
    assert!(session.can_open());
    let _new_stream = session.open().unwrap();
}

#[tokio::test]
async fn cancelled_shutdown_resumes_without_duplicate_data_or_fin() {
    let (client, mut peer) = tokio::io::duplex(1);
    let session =
        SmuxSession::with_test_limits(client, 1, 128, 4, 4, Duration::from_secs(2)).unwrap();
    let mut stream = session.open().unwrap();
    assert_eq!(read_frame(&mut peer).await, (0, 3, vec![]));
    stream.write_all(b"queued").await.unwrap();
    assert!(
        timeout(Duration::from_millis(20), stream.shutdown())
            .await
            .is_err()
    );
    let drain = tokio::spawn(async move {
        assert_eq!(read_frame(&mut peer).await, (2, 3, b"queued".to_vec()));
        assert_eq!(read_frame(&mut peer).await, (1, 3, vec![]));
    });
    timeout(DEADLINE, stream.shutdown()).await.unwrap().unwrap();
    drain.await.unwrap();
}

#[tokio::test]
async fn malformed_frames_fail_closed_and_stalled_reads_can_be_cancelled() {
    for invalid in [
        [2, 0, 0, 0, 3, 0, 0, 0],
        [1, 7, 0, 0, 3, 0, 0, 0],
        [1, 1, 1, 0, 3, 0, 0, 0],
        [1, 3, 0, 0, 3, 0, 0, 0],
        [1, 0, 0, 0, 2, 0, 0, 0],
    ] {
        let (client, mut peer) = tokio::io::duplex(1024);
        let session =
            SmuxSession::with_test_limits(client, 1, 128, 4, 4, Duration::from_millis(100))
                .unwrap();
        let mut stream = session.open().unwrap();
        read_frame(&mut peer).await;
        peer.write_all(&invalid).await.unwrap();
        wait_until(|| session.is_closed()).await;
        assert!(stream.read(&mut [0; 1]).await.is_err());
    }
    let (client, mut peer) = tokio::io::duplex(1024);
    let session =
        SmuxSession::with_test_limits(client, 1, 128, 4, 4, Duration::from_millis(100)).unwrap();
    let mut stream = session.open().unwrap();
    read_frame(&mut peer).await;
    peer.write_all(&[1]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(150), stream.read(&mut [0; 1]))
            .await
            .is_err()
    );
    assert!(!session.is_closed());
    drop(stream);
    wait_until(|| session.is_closed()).await;
    let (client, mut peer) = tokio::io::duplex(1024);
    let session =
        SmuxSession::with_test_limits(client, 1, 128, 4, 4, Duration::from_millis(100)).unwrap();
    let mut stream = session.open().unwrap();
    read_frame(&mut peer).await;
    peer.write_all(&header(2, 3, 5)).await.unwrap();
    peer.write_all(b"x").await.unwrap();
    assert!(
        timeout(Duration::from_millis(150), stream.read(&mut [0; 1]))
            .await
            .is_err()
    );
    assert!(!session.is_closed());
    drop(stream);
    wait_until(|| session.is_closed()).await;
}

#[tokio::test]
async fn stalled_carrier_write_waits_while_a_stream_is_active() {
    let (client, _peer) = tokio::io::duplex(1);
    let session =
        SmuxSession::with_test_limits(client, 1, 128, 4, 4, Duration::from_millis(100)).unwrap();
    let mut stream = session.open().unwrap();
    stream.write_all(b"data").await.unwrap();
    assert!(
        timeout(Duration::from_millis(250), stream.flush())
            .await
            .is_err()
    );
    assert!(!session.is_closed());
    drop(stream);
    wait_until(|| session.is_closed()).await;
}

#[tokio::test]
async fn fin_drains_buffered_data_and_rejects_subsequent_writes() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = SmuxSession::new(client, 1).unwrap();
    let mut stream = session.open().unwrap();
    read_frame(&mut peer).await;
    send_frame(&mut peer, 2, 3, b"buffered").await;
    send_frame(&mut peer, 1, 3, &[]).await;
    let mut bytes = [0; 8];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"buffered");
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    assert_eq!(
        stream.write_all(b"late").await.unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    stream.shutdown().await.unwrap();
    assert_eq!(read_frame(&mut peer).await, (1, 3, vec![]));
}

#[tokio::test]
async fn shutdown_reports_lost_queued_writes_after_peer_fin() {
    let (client, mut peer) = tokio::io::duplex(8);
    let session = SmuxSession::new(client, 1).unwrap();
    let mut stream = session.open().unwrap();
    read_frame(&mut peer).await;
    stream.write_all(&[0x33; 64]).await.unwrap();
    send_frame(&mut peer, 1, 3, &[]).await;
    assert_eq!(
        timeout(DEADLINE, stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        stream.shutdown().await.unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn pending_shutdown_reports_peer_fin_even_if_fin_is_repeated() {
    let (client, mut peer) = tokio::io::duplex(8);
    let session = SmuxSession::new(client, 1).unwrap();
    let mut stream = session.open().unwrap();
    read_frame(&mut peer).await;
    stream.write_all(&[0x33; 64]).await.unwrap();
    let mut shutdown = Box::pin(stream.shutdown());
    assert!(
        timeout(Duration::from_millis(20), shutdown.as_mut())
            .await
            .is_err()
    );
    send_frame(&mut peer, 1, 3, &[]).await;
    send_frame(&mut peer, 1, 3, &[]).await;
    let result = timeout(DEADLINE, shutdown.as_mut()).await.unwrap();
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn unknown_stream_payload_is_discarded_without_desynchronizing_others() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = SmuxSession::new(client, 1).unwrap();
    let mut stream = session.open().unwrap();
    read_frame(&mut peer).await;
    send_frame(&mut peer, 2, 999, b"unknown").await;
    send_frame(&mut peer, 3, 0, &[]).await;
    send_frame(&mut peer, 2, 3, b"valid").await;
    let mut data = [0; 5];
    stream.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"valid");
    assert!(!session.is_closed());
}

#[tokio::test]
async fn cancelled_read_does_not_discard_a_partially_received_frame() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = SmuxSession::new(client, 1).unwrap();
    let mut stream = session.open().unwrap();
    read_frame(&mut peer).await;
    peer.write_all(&header(2, 3, 5)).await.unwrap();
    peer.write_all(b"he").await.unwrap();
    let mut output = [0; 5];
    assert!(
        timeout(Duration::from_millis(20), stream.read_exact(&mut output))
            .await
            .is_err()
    );
    peer.write_all(b"llo").await.unwrap();
    timeout(DEADLINE, stream.read_exact(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&output, b"hello");
}

#[tokio::test]
async fn dropping_stream_with_partial_incoming_frame_releases_all_tasks() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session =
        SmuxSession::with_test_limits(client, 1, 128, 4, 4, Duration::from_millis(100)).unwrap();
    let stream = session.open().unwrap();
    read_frame(&mut peer).await;
    peer.write_all(&header(2, 3, 100)).await.unwrap();
    peer.write_all(b"short").await.unwrap();
    wait_until(|| session.test_usage().1 == 100).await;
    drop(stream);
    drop(session);
    timeout(DEADLINE, async {
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
    })
    .await
    .expect("timed out cleaning stalled frame");
}

#[tokio::test]
async fn stream_churn_is_bounded_when_carrier_is_blocked() {
    let (client, mut peer) = tokio::io::duplex(1);
    let session =
        SmuxSession::with_test_limits(client, 8, 128, 4, 4, Duration::from_secs(2)).unwrap();
    for _ in 0..8 {
        drop(session.open().unwrap());
    }
    assert_eq!(
        session.open().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(session.test_usage().0, 8);
    let mut opened = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (command, id, _) = read_frame(&mut peer).await;
        match command {
            0 => assert!(opened.insert(id)),
            1 => assert!(opened.remove(&id)),
            _ => panic!("unexpected control frame"),
        };
    }
    assert!(opened.is_empty());
    wait_until(|| session.test_usage().0 == 0).await;
    let _next = session.open().unwrap();
}

#[tokio::test]
async fn retired_session_keeps_existing_stream_and_closes_after_it_drops() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = SmuxSession::new(client, 1).unwrap();
    let mut stream = session.open().unwrap();
    assert_eq!(read_frame(&mut peer).await, (0, 3, vec![]));
    drop(session);
    stream.write_all(b"active").await.unwrap();
    assert_eq!(read_frame(&mut peer).await, (2, 3, b"active".to_vec()));
    send_frame(&mut peer, 2, 3, b"reply").await;
    let mut response = [0; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"reply");
    drop(stream);
    assert_eq!(read_frame(&mut peer).await, (1, 3, vec![]));
    assert_eq!(
        timeout(DEADLINE, peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn simultaneous_writers_obey_global_budget_and_both_make_progress() {
    let (client, mut peer) = tokio::io::duplex(8);
    let session =
        SmuxSession::with_test_limits(client, 2, 80, 2, 4, Duration::from_secs(2)).unwrap();
    let mut a = session.open().unwrap();
    let mut b = session.open().unwrap();
    assert_eq!(read_frame(&mut peer).await.0, 0);
    assert_eq!(read_frame(&mut peer).await.0, 0);
    let first = tokio::spawn(async move {
        a.write_all(&[1; 1024]).await.unwrap();
        a
    });
    let second = tokio::spawn(async move {
        b.write_all(&[2; 1024]).await.unwrap();
        b
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (_, _, _, bytes, frames) = session.test_usage();
    assert!(bytes <= 80);
    assert!(frames <= 2);
    let mut totals = [0usize; 2];
    timeout(DEADLINE, async {
        while totals != [1024, 1024] {
            let (cmd, id, data) = read_frame(&mut peer).await;
            assert_eq!(cmd, 2);
            let index = match id {
                3 => 0,
                5 => 1,
                _ => panic!("unknown stream"),
            };
            assert!(data.iter().all(|value| *value == (index + 1) as u8));
            totals[index] += data.len();
            let (_, _, _, bytes, frames) = session.test_usage();
            assert!(bytes <= 80);
            assert!(frames <= 2);
        }
    })
    .await
    .expect("backpressured streams must both progress");
    let a = first.await.unwrap();
    let b = second.await.unwrap();
    drop((a, b));
}

#[tokio::test]
async fn configured_stream_limit_is_bounded() {
    let (client, _) = tokio::io::duplex(1);
    assert!(SmuxSession::new(client, MAX_SMUX_STREAMS + 1).is_err());
    let (client, _) = tokio::io::duplex(1);
    assert!(SmuxSession::new(client, 0).is_err());
}
