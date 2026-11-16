//! Bounded client-side smux v1 session. The caller writes the sing-mux prefix.
//!
//! A smux FIN follows the Go peer's whole-stream close semantics: once a peer
//! sends FIN, further writes fail, and shutdown sends FIN after queued data.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Notify, watch};

pub(crate) const MAX_SMUX_STREAMS: usize = 256;
const VERSION: u8 = 1;
const SYN: u8 = 0;
const FIN: u8 = 1;
const PSH: u8 = 2;
const NOP: u8 = 3;
const HEADER_LEN: usize = 8;
const WRITE_CHUNK: usize = 32 * 1024;
const MAX_RX_BYTES: usize = 4 * 1024 * 1024;
const MAX_RX_STREAM_BYTES: usize = 256 * 1024;
const MAX_RX_FRAMES: usize = 1024;
const MAX_TX_BYTES: usize = 4 * 1024 * 1024;
const MAX_TX_FRAMES: usize = 512;
const IDLE_DRAIN_GRACE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
struct Limits {
    max_streams: usize,
    rx_bytes: usize,
    rx_stream_bytes: usize,
    rx_frames: usize,
    tx_bytes: usize,
    tx_frames: usize,
    idle_drain_grace: Duration,
}

impl Limits {
    fn new(max_streams: usize) -> io::Result<Self> {
        if !(1..=MAX_SMUX_STREAMS).contains(&max_streams) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "smux stream limit is invalid",
            ));
        }
        Ok(Self {
            max_streams,
            rx_bytes: MAX_RX_BYTES,
            rx_stream_bytes: MAX_RX_STREAM_BYTES,
            rx_frames: MAX_RX_FRAMES,
            tx_bytes: MAX_TX_BYTES,
            tx_frames: MAX_TX_FRAMES,
            idle_drain_grace: IDLE_DRAIN_GRACE,
        })
    }
}

struct StreamState {
    handle_alive: bool,
    syn_pending: bool,
    fin_pending: bool,
    fin_sent: bool,
    in_flight: bool,
    in_flight_data: bool,
    scheduled: bool,
    remote_fin: bool,
    local_fin: bool,
    write_failed: bool,
    failure: Option<(io::ErrorKind, &'static str)>,
    tx: VecDeque<Vec<u8>>,
    rx: VecDeque<Vec<u8>>,
    rx_offset: usize,
    rx_bytes: usize,
    rx_frames: usize,
    rx_reserved: usize,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
}

impl StreamState {
    fn new() -> Self {
        Self {
            handle_alive: true,
            syn_pending: true,
            fin_pending: false,
            fin_sent: false,
            in_flight: false,
            in_flight_data: false,
            scheduled: false,
            remote_fin: false,
            local_fin: false,
            write_failed: false,
            failure: None,
            tx: VecDeque::new(),
            rx: VecDeque::new(),
            rx_offset: 0,
            rx_bytes: 0,
            rx_frames: 0,
            rx_reserved: 0,
            read_waker: None,
            write_waker: None,
            flush_waker: None,
            shutdown_waker: None,
        }
    }

    fn has_output(&self) -> bool {
        !self.in_flight
            && (self.syn_pending || !self.tx.is_empty() || (self.fin_pending && !self.fin_sent))
    }
}

struct State {
    limits: Limits,
    streams: BTreeMap<u32, StreamState>,
    ready: VecDeque<u32>,
    next_id: u32,
    live_streams: usize,
    idle_deadline: Option<tokio::time::Instant>,
    session_alive: bool,
    terminal: Option<(io::ErrorKind, &'static str)>,
    rx_bytes: usize,
    rx_frames: usize,
    tx_bytes: usize,
    tx_frames: usize,
}

struct Shared {
    state: Mutex<State>,
    output: Notify,
    stop: watch::Sender<bool>,
    ownership: watch::Sender<u64>,
}

struct DriverGuard(Arc<Shared>);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0
            .fail(io::ErrorKind::BrokenPipe, "smux driver stopped");
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn fail(&self, kind: io::ErrorKind, message: &'static str) {
        self.fail_if(kind, message, false);
    }

    fn fail_if(&self, kind: io::ErrorKind, message: &'static str, idle_only: bool) -> bool {
        let wake = {
            let mut state = self.lock();
            if state.terminal.is_some() {
                return true;
            }
            if idle_only
                && (state.live_streams != 0
                    || state
                        .idle_deadline
                        .is_none_or(|deadline| tokio::time::Instant::now() < deadline))
            {
                return false;
            }
            state.terminal = Some((kind, message));
            let mut wake = Vec::new();
            for stream in state.streams.values_mut() {
                stream.write_failed |= stream.in_flight_data || !stream.tx.is_empty();
                stream.tx.clear();
                for waker in [
                    &mut stream.read_waker,
                    &mut stream.write_waker,
                    &mut stream.flush_waker,
                    &mut stream.shutdown_waker,
                ] {
                    if let Some(waker) = waker.take() {
                        wake.push(waker);
                    }
                }
            }
            state.tx_bytes = 0;
            state.tx_frames = 0;
            state.ready.clear();
            wake
        };
        self.stop.send_replace(true);
        self.output.notify_waiters();
        for waker in wake {
            waker.wake();
        }
        true
    }
}

fn schedule(state: &mut State, id: u32) {
    if let Some(stream) = state.streams.get_mut(&id)
        && !stream.scheduled
        && stream.has_output()
    {
        stream.scheduled = true;
        state.ready.push_back(id);
    }
}

fn terminal_error(state: &State) -> Option<io::Error> {
    state
        .terminal
        .map(|(kind, message)| io::Error::new(kind, message))
}

fn stream_error(stream: &StreamState) -> Option<io::Error> {
    stream
        .failure
        .map(|(kind, message)| io::Error::new(kind, message))
}

fn isolate_overloaded_stream(state: &mut State, id: u32, wake: &mut Vec<Waker>) {
    let Some(stream) = state.streams.get_mut(&id) else {
        return;
    };
    if stream.failure.is_some() {
        return;
    }
    stream.failure = Some((
        io::ErrorKind::OutOfMemory,
        "smux stream receive limit exceeded",
    ));
    stream.local_fin = true;
    stream.fin_pending = !stream.fin_sent;
    stream.write_failed = true;
    let received_bytes = stream.rx_bytes;
    let received_frames = stream.rx_frames;
    stream.rx.clear();
    stream.rx_offset = 0;
    stream.rx_bytes = 0;
    stream.rx_frames = 0;
    let mut sent_bytes = 0;
    let mut sent_frames = 0;
    for frame in stream.tx.drain(..) {
        sent_bytes += frame.len();
        sent_frames += 1;
    }
    for waker in [
        &mut stream.read_waker,
        &mut stream.write_waker,
        &mut stream.flush_waker,
        &mut stream.shutdown_waker,
    ] {
        if let Some(waker) = waker.take() {
            wake.push(waker);
        }
    }
    state.rx_bytes -= received_bytes;
    state.rx_frames -= received_frames;
    state.tx_bytes -= sent_bytes;
    state.tx_frames -= sent_frames;
    if sent_frames != 0 {
        for stream in state.streams.values_mut() {
            if let Some(waker) = stream.write_waker.take() {
                wake.push(waker);
            }
        }
    }
    schedule(state, id);
}

pub(crate) struct SmuxSession {
    shared: Arc<Shared>,
}

impl SmuxSession {
    pub(crate) fn new<S>(stream: S, max_streams: usize) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::with_limits(stream, Limits::new(max_streams)?)
    }

    fn with_limits<S>(stream: S, limits: Limits) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("smux requires a Tokio runtime"))?;
        let (stop, _) = watch::channel(false);
        let (ownership, _) = watch::channel(0);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                limits,
                streams: BTreeMap::new(),
                ready: VecDeque::new(),
                next_id: 1,
                live_streams: 0,
                idle_deadline: None,
                session_alive: true,
                terminal: None,
                rx_bytes: 0,
                rx_frames: 0,
                tx_bytes: 0,
                tx_frames: 0,
            }),
            output: Notify::new(),
            stop,
            ownership,
        });
        let (read, write) = tokio::io::split(stream);
        runtime.spawn(reader(read, Arc::clone(&shared), shared.stop.subscribe()));
        runtime.spawn(writer(write, Arc::clone(&shared), shared.stop.subscribe()));
        Ok(Self { shared })
    }

    #[cfg(test)]
    pub(crate) fn with_test_limits<S>(
        stream: S,
        max_streams: usize,
        tx_bytes: usize,
        tx_frames: usize,
        rx_frames: usize,
        idle_drain_grace: Duration,
    ) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut limits = Limits::new(max_streams)?;
        assert!(
            tx_bytes > HEADER_LEN && tx_frames > 0 && rx_frames > 0 && !idle_drain_grace.is_zero()
        );
        limits.tx_bytes = tx_bytes;
        limits.tx_frames = tx_frames;
        limits.rx_frames = rx_frames;
        limits.idle_drain_grace = idle_drain_grace;
        Self::with_limits(stream, limits)
    }

    #[cfg(test)]
    pub(crate) fn test_usage(&self) -> (usize, usize, usize, usize, usize) {
        let state = self.shared.lock();
        (
            state.streams.len(),
            state.rx_bytes,
            state.rx_frames,
            state.tx_bytes,
            state.tx_frames,
        )
    }

    pub(crate) fn is_closed(&self) -> bool {
        let state = self.shared.lock();
        !state.session_alive || state.terminal.is_some()
    }

    pub(crate) fn can_open(&self) -> bool {
        let state = self.shared.lock();
        state.session_alive
            && state.terminal.is_none()
            && state.streams.len() < state.limits.max_streams
            && state.next_id.checked_add(2).is_some()
    }

    pub(crate) fn open(&self) -> io::Result<SmuxStream> {
        let mut state = self.shared.lock();
        if let Some(error) = terminal_error(&state) {
            return Err(error);
        }
        if !state.session_alive {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux session is closed",
            ));
        }
        if state.streams.len() >= state.limits.max_streams {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "smux stream limit reached",
            ));
        }
        let id = state.next_id.checked_add(2).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux stream identifiers are exhausted",
            )
        })?;
        state.next_id = id;
        state.streams.insert(id, StreamState::new());
        state.live_streams += 1;
        state.idle_deadline = None;
        schedule(&mut state, id);
        drop(state);
        self.shared
            .ownership
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        self.shared.output.notify_one();
        Ok(SmuxStream {
            shared: Arc::clone(&self.shared),
            id,
        })
    }
}

impl Drop for SmuxSession {
    fn drop(&mut self) {
        self.shared.lock().session_alive = false;
        self.shared
            .ownership
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        self.shared.output.notify_one();
    }
}

pub(crate) struct SmuxStream {
    shared: Arc<Shared>,
    id: u32,
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = self.shared.lock();
        let failure = terminal_error(&state);
        let Some(stream) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux stream is closed",
            )));
        };
        if let Some(error) = stream_error(stream) {
            return Poll::Ready(Err(error));
        }
        if let Some(front) = stream.rx.front() {
            let count = (front.len() - stream.rx_offset).min(output.remaining());
            output.put_slice(&front[stream.rx_offset..stream.rx_offset + count]);
            stream.rx_offset += count;
            let completed = stream.rx_offset == front.len();
            let allocation = front.len();
            if completed {
                stream.rx.pop_front();
                stream.rx_offset = 0;
                stream.rx_bytes -= allocation;
                stream.rx_frames -= 1;
                state.rx_bytes -= allocation;
                state.rx_frames -= 1;
            }
            return Poll::Ready(Ok(()));
        }
        if stream.remote_fin {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = failure {
            return Poll::Ready(Err(error));
        }
        stream.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = self.shared.lock();
        if let Some(error) = terminal_error(&state) {
            return Poll::Ready(Err(error));
        }
        let available = state.limits.tx_bytes.saturating_sub(state.tx_bytes);
        let full = state.tx_frames >= state.limits.tx_frames || available <= HEADER_LEN;
        let Some(stream) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux stream is closed",
            )));
        };
        if let Some(error) = stream_error(stream) {
            return Poll::Ready(Err(error));
        }
        if stream.local_fin || stream.remote_fin || stream.write_failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux stream cannot write",
            )));
        }
        if full {
            stream.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = bytes.len().min(WRITE_CHUNK).min(available - HEADER_LEN);
        let mut frame = Vec::with_capacity(HEADER_LEN + count);
        frame.extend_from_slice(&header(PSH, self.id, count));
        frame.extend_from_slice(&bytes[..count]);
        stream.tx.push_back(frame);
        state.tx_bytes += HEADER_LEN + count;
        state.tx_frames += 1;
        schedule(&mut state, self.id);
        drop(state);
        self.shared.output.notify_one();
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        if let Some(error) = terminal_error(&state) {
            return Poll::Ready(Err(error));
        }
        let Some(stream) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux stream is closed",
            )));
        };
        if let Some(error) = stream_error(stream) {
            return Poll::Ready(Err(error));
        }
        if stream.write_failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux peer closed the stream",
            )));
        }
        if !stream.syn_pending && !stream.in_flight && stream.tx.is_empty() {
            return Poll::Ready(Ok(()));
        }
        stream.flush_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        let failure = terminal_error(&state);
        let Some(stream) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux stream is closed",
            )));
        };
        if let Some(error) = stream_error(stream) {
            return Poll::Ready(Err(error));
        }
        if stream.write_failed {
            if let Some(error) = failure {
                return Poll::Ready(Err(error));
            }
            stream.local_fin = true;
            stream.fin_pending = true;
            schedule(&mut state, self.id);
            drop(state);
            self.shared.output.notify_one();
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux peer closed during a write",
            )));
        }
        if stream.fin_sent {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = failure {
            return Poll::Ready(Err(error));
        }
        stream.local_fin = true;
        stream.fin_pending = true;
        stream.shutdown_waker = Some(cx.waker().clone());
        schedule(&mut state, self.id);
        drop(state);
        self.shared.output.notify_one();
        Poll::Pending
    }
}

impl Drop for SmuxStream {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        let Some(stream) = state.streams.get_mut(&self.id) else {
            return;
        };
        if !stream.handle_alive {
            return;
        }
        stream.handle_alive = false;
        stream.local_fin = true;
        let bytes = stream.rx_bytes;
        let frames = stream.rx_frames;
        stream.rx.clear();
        stream.rx_bytes = 0;
        stream.rx_frames = 0;
        stream.read_waker = None;
        stream.write_waker = None;
        stream.flush_waker = None;
        stream.shutdown_waker = None;
        let remove = stream.fin_sent && stream.rx_reserved == 0;
        if !stream.fin_sent {
            stream.fin_pending = true;
        }
        state.live_streams -= 1;
        if state.live_streams == 0 {
            state.idle_deadline = Some(tokio::time::Instant::now() + state.limits.idle_drain_grace);
        }
        state.rx_bytes -= bytes;
        state.rx_frames -= frames;
        if remove {
            state.streams.remove(&self.id);
        } else {
            schedule(&mut state, self.id);
        }
        drop(state);
        self.shared
            .ownership
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        self.shared.output.notify_one();
    }
}

fn header(command: u8, id: u32, length: usize) -> [u8; HEADER_LEN] {
    let mut header = [0; HEADER_LEN];
    header[0] = VERSION;
    header[1] = command;
    header[2..4].copy_from_slice(&(length as u16).to_le_bytes());
    header[4..8].copy_from_slice(&id.to_le_bytes());
    header
}

/// Generic buffered transports can make invisible progress while returning
/// Pending. Bound only abandoned I/O after the last stream handle is gone.
async fn finish_or_abandon<F: Future<Output = io::Result<()>>>(
    shared: &Shared,
    future: F,
) -> io::Result<()> {
    let mut changes = shared.ownership.subscribe();
    tokio::pin!(future);
    loop {
        changes.borrow_and_update();
        let deadline = shared.lock().idle_deadline;
        if let Some(deadline) = deadline {
            tokio::select! {
                result = &mut future => return result,
                _ = tokio::time::sleep_until(deadline) => {
                    if shared.fail_if(io::ErrorKind::TimedOut, "smux idle drain timed out", true) {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "smux idle drain timed out"));
                    }
                },
                _ = changes.changed() => {},
            }
        } else {
            tokio::select! {
                result = &mut future => return result,
                _ = changes.changed() => {},
            }
        }
    }
}

enum Output {
    Syn(u32),
    Fin(u32),
    Data(u32, Vec<u8>),
}

async fn writer<W: AsyncWrite + Unpin>(
    mut writer: W,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let _guard = DriverGuard(Arc::clone(&shared));
    loop {
        let notified = shared.output.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (next, done) = {
            let mut state = shared.lock();
            if state.terminal.is_some() {
                return;
            }
            let mut next = None;
            while let Some(id) = state.ready.pop_front() {
                let Some(stream) = state.streams.get_mut(&id) else {
                    continue;
                };
                stream.scheduled = false;
                if stream.in_flight {
                    continue;
                }
                if stream.syn_pending {
                    stream.syn_pending = false;
                    stream.in_flight = true;
                    next = Some(Output::Syn(id));
                } else if let Some(frame) = stream.tx.pop_front() {
                    stream.in_flight = true;
                    stream.in_flight_data = true;
                    next = Some(Output::Data(id, frame));
                } else if stream.fin_pending && !stream.fin_sent {
                    stream.fin_pending = false;
                    stream.in_flight = true;
                    next = Some(Output::Fin(id));
                }
                if next.is_some() {
                    break;
                }
            }
            let done = !state.session_alive && state.live_streams == 0 && state.streams.is_empty();
            (next, done)
        };
        if done {
            let _ = finish_or_abandon(&shared, writer.shutdown()).await;
            shared.fail(io::ErrorKind::BrokenPipe, "smux session closed");
            return;
        }
        let Some(next) = next else {
            tokio::select! { ()=&mut notified=>{}, _=stop.changed()=>return }
            continue;
        };
        let (id, size, fin, bytes) = match next {
            Output::Syn(id) => (id, 0, false, header(SYN, id, 0).to_vec()),
            Output::Fin(id) => (id, 0, true, header(FIN, id, 0).to_vec()),
            Output::Data(id, frame) => (id, frame.len(), false, frame),
        };
        let operation = async {
            writer.write_all(&bytes).await?;
            writer.flush().await
        };
        let result = tokio::select! { result=finish_or_abandon(&shared,operation)=>result, _=stop.changed()=>return };
        if let Err(error) = result {
            let kind = if error.kind() == io::ErrorKind::TimedOut {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::BrokenPipe
            };
            shared.fail(kind, "smux carrier write failed");
            return;
        }
        let wake = {
            let mut state = shared.lock();
            if state.terminal.is_some() {
                return;
            }
            if size > 0 {
                state.tx_bytes -= size;
                state.tx_frames -= 1;
            }
            let mut wake = Vec::new();
            let mut remove = false;
            if let Some(stream) = state.streams.get_mut(&id) {
                stream.in_flight = false;
                stream.in_flight_data = false;
                if fin {
                    stream.fin_sent = true;
                }
                if !stream.syn_pending
                    && stream.tx.is_empty()
                    && let Some(waker) = stream.flush_waker.take()
                {
                    wake.push(waker);
                }
                if stream.fin_sent {
                    if let Some(waker) = stream.shutdown_waker.take() {
                        wake.push(waker);
                    }
                    remove = !stream.handle_alive && stream.rx_reserved == 0;
                }
            }
            if remove {
                state.streams.remove(&id);
            } else {
                schedule(&mut state, id);
            }
            if size > 0 {
                for stream in state.streams.values_mut() {
                    if let Some(waker) = stream.write_waker.take() {
                        wake.push(waker);
                    }
                }
            }
            wake
        };
        for waker in wake {
            waker.wake();
        }
        shared.output.notify_one();
    }
}

async fn reader<R: AsyncRead + Unpin>(
    mut reader: R,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let _guard = DriverGuard(Arc::clone(&shared));
    loop {
        let mut raw = [0; HEADER_LEN];
        let result = tokio::select! { result=reader.read_exact(&mut raw[..1])=>result, _=stop.changed()=>return };
        if result.is_err() {
            shared.fail(io::ErrorKind::UnexpectedEof, "smux carrier closed");
            return;
        }
        let operation = async { reader.read_exact(&mut raw[1..]).await.map(|_| ()) };
        let result = tokio::select! { result=finish_or_abandon(&shared,operation)=>result, _=stop.changed()=>return };
        if let Err(error) = result {
            let kind = if error.kind() == io::ErrorKind::TimedOut {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::UnexpectedEof
            };
            shared.fail(kind, "smux frame header is truncated");
            return;
        }
        let version = raw[0];
        let command = raw[1];
        let len = usize::from(u16::from_le_bytes([raw[2], raw[3]]));
        let id = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        if version != VERSION
            || !matches!(command, SYN | FIN | PSH | NOP)
            || (command != PSH && len != 0)
            || (command == NOP && id != 0)
            || (command != NOP && id == 0)
        {
            shared.fail(io::ErrorKind::InvalidData, "smux frame header is invalid");
            return;
        }
        if command == SYN {
            shared.fail(
                io::ErrorKind::InvalidData,
                "smux peer initiated an unsupported stream",
            );
            return;
        }
        if command == NOP {
            continue;
        }
        if command == FIN {
            let wake = {
                let mut state = shared.lock();
                let mut wake = Vec::new();
                let mut released_bytes = 0;
                let mut released_frames = 0;
                if let Some(stream) = state.streams.get_mut(&id) {
                    stream.remote_fin = true;
                    stream.write_failed |= stream.in_flight_data || !stream.tx.is_empty();
                    if !stream.tx.is_empty() {
                        for frame in stream.tx.drain(..) {
                            released_bytes += frame.len();
                            released_frames += 1;
                        }
                    }
                    for waker in [
                        &mut stream.read_waker,
                        &mut stream.write_waker,
                        &mut stream.flush_waker,
                        &mut stream.shutdown_waker,
                    ] {
                        if let Some(waker) = waker.take() {
                            wake.push(waker);
                        }
                    }
                }
                state.tx_bytes -= released_bytes;
                state.tx_frames -= released_frames;
                if released_bytes > 0 {
                    for stream in state.streams.values_mut() {
                        if let Some(waker) = stream.write_waker.take() {
                            wake.push(waker);
                        }
                    }
                }
                wake
            };
            for waker in wake {
                waker.wake();
            }
            continue;
        }
        if len == 0 {
            continue;
        }
        let (reserve, wake, evicted, invalid) = {
            let mut state = shared.lock();
            if state.terminal.is_some() {
                return;
            }
            let mut wake = Vec::new();
            let mut evicted = false;
            let mut invalid = false;
            let reserve = loop {
                let Some(stream) = state.streams.get(&id) else {
                    break false;
                };
                if !stream.handle_alive || stream.failure.is_some() {
                    break false;
                }
                if stream.remote_fin {
                    invalid = true;
                    break false;
                }
                if stream
                    .rx_bytes
                    .saturating_add(stream.rx_reserved)
                    .saturating_add(len)
                    > state.limits.rx_stream_bytes
                {
                    isolate_overloaded_stream(&mut state, id, &mut wake);
                    evicted = true;
                    break false;
                }
                let bytes_full = state.rx_bytes.saturating_add(len) > state.limits.rx_bytes;
                let frames_full = state.rx_frames >= state.limits.rx_frames;
                if !bytes_full && !frames_full {
                    state
                        .streams
                        .get_mut(&id)
                        .expect("stream was checked")
                        .rx_reserved += len;
                    state.rx_bytes += len;
                    state.rx_frames += 1;
                    break true;
                }
                // Reclaim the largest buffered allocation first so one idle
                // consumer cannot sacrifice every unrelated active stream.
                let victim = state
                    .streams
                    .iter()
                    .filter(|(_, stream)| {
                        stream.handle_alive && stream.failure.is_none() && stream.rx_frames != 0
                    })
                    .max_by_key(|(victim, stream)| {
                        let primary = if frames_full {
                            stream.rx_frames
                        } else {
                            stream.rx_bytes
                        };
                        (primary, **victim != id)
                    })
                    .map(|(victim, _)| *victim)
                    .unwrap_or(id);
                isolate_overloaded_stream(&mut state, victim, &mut wake);
                evicted = true;
                if victim == id {
                    break false;
                }
            };
            (reserve, wake, evicted, invalid)
        };
        for waker in wake {
            waker.wake();
        }
        if evicted {
            shared.output.notify_one();
        }
        if invalid {
            shared.fail(io::ErrorKind::InvalidData, "smux data followed FIN");
            return;
        }
        if reserve {
            let mut data = vec![0; len];
            let operation = async { reader.read_exact(&mut data).await.map(|_| ()) };
            let result = tokio::select! { result=finish_or_abandon(&shared,operation)=>result, _=stop.changed()=>return };
            if let Err(error) = result {
                let kind = if error.kind() == io::ErrorKind::TimedOut {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::UnexpectedEof
                };
                shared.fail(kind, "smux frame payload is truncated");
                return;
            }
            let wake = {
                let mut state = shared.lock();
                let mut wake = None;
                let mut discard = true;
                let mut remove = false;
                if let Some(stream) = state.streams.get_mut(&id) {
                    stream.rx_reserved -= len;
                    if stream.handle_alive && stream.failure.is_none() {
                        stream.rx_bytes += len;
                        stream.rx_frames += 1;
                        stream.rx.push_back(data);
                        wake = stream.read_waker.take();
                        discard = false;
                    } else {
                        remove = stream.fin_sent && stream.rx_reserved == 0;
                    }
                }
                if discard {
                    state.rx_bytes -= len;
                    state.rx_frames -= 1;
                }
                if remove {
                    state.streams.remove(&id);
                }
                wake
            };
            if let Some(waker) = wake {
                waker.wake();
            }
            shared.output.notify_one();
        } else {
            let mut remaining = len;
            let mut discard = [0; 4096];
            let result = tokio::select! {
                result=finish_or_abandon(&shared,async {
                    while remaining>0 { let count=remaining.min(discard.len()); reader.read_exact(&mut discard[..count]).await?; remaining-=count; }
                    Ok::<_,io::Error>(())
                })=>result,
                _=stop.changed()=>return,
            };
            if let Err(error) = result {
                let kind = if error.kind() == io::ErrorKind::TimedOut {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::UnexpectedEof
                };
                shared.fail(kind, "smux frame payload is truncated");
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "sing_smux_tests.rs"]
mod tests;
