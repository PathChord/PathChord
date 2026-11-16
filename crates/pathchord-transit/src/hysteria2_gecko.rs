//! Gecko framing around the existing Salamander UDP socket.

use std::collections::{BTreeMap, VecDeque};
use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::Notify;

const HEADER_LEN: usize = 5;
const SALAMANDER_SALT_LEN: usize = 8;
const MIN_CHUNKS: u8 = 2;
const MAX_CHUNKS: u8 = 8;
const MAX_MESSAGE: usize = 65_535;
const MAX_PENDING: usize = 32;
const MAX_INCOMPLETE_PER_SOURCE: usize = 8;
const MAX_INCOMPLETE: usize = 256;
const REASSEMBLY_TTL: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug)]
pub(super) struct GeckoConfig {
    min_packet_size: usize,
    max_packet_size: usize,
}

impl Default for GeckoConfig {
    fn default() -> Self {
        Self {
            min_packet_size: 512,
            max_packet_size: 1200,
        }
    }
}

impl GeckoConfig {
    pub(super) fn parse(minimum: Option<&str>, maximum: Option<&str>) -> io::Result<Self> {
        fn size(value: Option<&str>, default: usize) -> io::Result<usize> {
            match value {
                None => Ok(default),
                Some(value) => value
                    .parse::<usize>()
                    .ok()
                    .filter(|size| *size <= 2048)
                    .map(|size| if size == 0 { default } else { size })
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid Gecko packet size")
                    }),
            }
        }
        let defaults = Self::default();
        let min_packet_size = size(minimum, defaults.min_packet_size)?;
        let max_packet_size = size(maximum, defaults.max_packet_size)?;
        if min_packet_size > max_packet_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Gecko packet size range",
            ));
        }
        Ok(Self {
            min_packet_size,
            max_packet_size,
        })
    }
}

pub(super) fn random_below(bound: u32) -> io::Result<u32> {
    let limit = u32::MAX - u32::MAX % bound;
    loop {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| io::Error::other("Gecko randomness failed"))?;
        let value = u32::from_ne_bytes(bytes);
        if value < limit {
            return Ok(value % bound);
        }
    }
}

fn encode(packet: &[u8], message_id: u8, config: GeckoConfig) -> io::Result<Vec<Vec<u8>>> {
    if packet.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Gecko packet is too large",
        ));
    }
    if packet.is_empty() {
        return Ok(Vec::new());
    }
    if packet[0] & 0x80 == 0 {
        return Ok(vec![packet.to_vec()]);
    }
    let count = MIN_CHUNKS + random_below(u32::from(MAX_CHUNKS - MIN_CHUNKS + 1))? as u8;
    let chunk_size = packet.len() / usize::from(count);
    let mut output = Vec::with_capacity(usize::from(count));
    for index in 0..count {
        let start = usize::from(index) * chunk_size;
        let end = if index + 1 == count {
            packet.len()
        } else {
            start + chunk_size
        };
        let chunk = &packet[start..end];
        let base = SALAMANDER_SALT_LEN + HEADER_LEN + chunk.len();
        let low = base.max(config.min_packet_size);
        let padding = if low > config.max_packet_size {
            0
        } else {
            low - base + random_below((config.max_packet_size - low + 1) as u32)? as usize
        };
        let mut frame = vec![0_u8; HEADER_LEN + padding + chunk.len()];
        frame[0] = 0x80;
        frame[1] = message_id;
        frame[2] = (index << 4) | count;
        frame[3..5].copy_from_slice(&(padding as u16).to_be_bytes());
        getrandom::fill(&mut frame[HEADER_LEN..HEADER_LEN + padding])
            .map_err(|_| io::Error::other("Gecko padding randomness failed"))?;
        frame[HEADER_LEN + padding..].copy_from_slice(chunk);
        output.push(frame);
    }
    Ok(output)
}

struct Incomplete {
    chunks: Vec<Option<Vec<u8>>>,
    bytes: usize,
    deadline: Instant,
}

#[derive(Default)]
struct Reassembly {
    messages: BTreeMap<(SocketAddr, u8), Incomplete>,
}

impl Reassembly {
    fn accept(&mut self, source: SocketAddr, frame: &[u8], now: Instant) -> Option<Vec<u8>> {
        if frame.is_empty() {
            return None;
        }
        if frame[0] & 0x80 == 0 {
            return Some(frame.to_vec());
        }
        if frame.len() < HEADER_LEN {
            return None;
        }
        let id = frame[1];
        let index = frame[2] >> 4;
        let total = frame[2] & 0x0f;
        if !(MIN_CHUNKS..=MAX_CHUNKS).contains(&total) || index >= total {
            return None;
        }
        let start = HEADER_LEN + usize::from(u16::from_be_bytes([frame[3], frame[4]]));
        let payload = frame.get(start..)?;
        self.messages.retain(|_, entry| now < entry.deadline);
        let key = (source, id);
        if !self.messages.contains_key(&key) {
            if self
                .messages
                .keys()
                .filter(|(addr, _)| *addr == source)
                .count()
                >= MAX_INCOMPLETE_PER_SOURCE
            {
                return None;
            }
            if self.messages.len() >= MAX_INCOMPLETE
                && let Some(oldest) = self
                    .messages
                    .iter()
                    .min_by_key(|(_, entry)| entry.deadline)
                    .map(|(key, _)| *key)
            {
                self.messages.remove(&oldest);
            }
            self.messages.insert(
                key,
                Incomplete {
                    chunks: vec![None; usize::from(total)],
                    bytes: 0,
                    deadline: now + REASSEMBLY_TTL,
                },
            );
        }
        let entry = self.messages.get_mut(&key)?;
        if entry.chunks.len() != usize::from(total) || entry.chunks[usize::from(index)].is_some() {
            return None;
        }
        entry.bytes = entry.bytes.checked_add(payload.len())?;
        if entry.bytes > MAX_MESSAGE {
            self.messages.remove(&key);
            return None;
        }
        entry.chunks[usize::from(index)] = Some(payload.to_vec());
        if entry.chunks.iter().any(Option::is_none) {
            return None;
        }
        let entry = self.messages.remove(&key)?;
        let mut packet = Vec::with_capacity(entry.bytes);
        for chunk in entry.chunks.into_iter().flatten() {
            packet.extend_from_slice(&chunk);
        }
        Some(packet)
    }
}

#[derive(Debug)]
struct OwnedTransmit {
    destination: SocketAddr,
    ecn: Option<EcnCodepoint>,
    src_ip: Option<IpAddr>,
    frames: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Queue {
    packets: VecDeque<OwnedTransmit>,
    waiters: BTreeMap<usize, Waker>,
    error: Option<io::ErrorKind>,
}

struct Shared {
    inner: Arc<dyn AsyncUdpSocket>,
    queue: Mutex<Queue>,
    notify: Notify,
    next_poller: AtomicUsize,
}

impl Shared {
    fn wake_waiters(queue: &mut Queue) {
        for (_, waker) in std::mem::take(&mut queue.waiters) {
            waker.wake();
        }
    }
}

pub(super) struct GeckoSocket {
    shared: Arc<Shared>,
    config: GeckoConfig,
    message_id: AtomicU8,
    reassembly: Mutex<Reassembly>,
    worker: tokio::task::AbortHandle,
}

impl std::fmt::Debug for GeckoSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GeckoSocket(..)")
    }
}

impl GeckoSocket {
    pub(super) fn new(inner: Arc<dyn AsyncUdpSocket>, config: GeckoConfig) -> Self {
        let shared = Arc::new(Shared {
            inner,
            queue: Mutex::new(Queue::default()),
            notify: Notify::new(),
            next_poller: AtomicUsize::new(0),
        });
        let sender = Arc::clone(&shared);
        let task = tokio::spawn(async move { send_worker(sender).await });
        Self {
            shared,
            config,
            message_id: AtomicU8::new(0),
            reassembly: Mutex::new(Reassembly::default()),
            worker: task.abort_handle(),
        }
    }
}

impl Drop for GeckoSocket {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

async fn send_worker(shared: Arc<Shared>) {
    let mut poller = Arc::clone(&shared.inner).create_io_poller();
    loop {
        let packet = {
            let Ok(mut queue) = shared.queue.lock() else {
                return;
            };
            let packet = queue.packets.pop_front();
            if packet.is_some() {
                Shared::wake_waiters(&mut queue);
            }
            packet
        };
        let Some(packet) = packet else {
            shared.notify.notified().await;
            continue;
        };
        for frame in packet.frames {
            let transmit = Transmit {
                destination: packet.destination,
                ecn: packet.ecn,
                contents: &frame,
                segment_size: None,
                src_ip: packet.src_ip,
            };
            let result = poll_fn(|cx| {
                loop {
                    match shared.inner.try_send(&transmit) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            match poller.as_mut().poll_writable(cx) {
                                Poll::Ready(Ok(())) => continue,
                                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        result => return Poll::Ready(result),
                    }
                }
            })
            .await;
            if let Err(error) = result {
                if let Ok(mut queue) = shared.queue.lock() {
                    queue.error = Some(error.kind());
                    queue.packets.clear();
                    Shared::wake_waiters(&mut queue);
                }
                return;
            }
        }
    }
}

struct GeckoPoller {
    shared: Arc<Shared>,
    id: usize,
}
impl std::fmt::Debug for GeckoPoller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GeckoPoller(..)")
    }
}
impl Drop for GeckoPoller {
    fn drop(&mut self) {
        if let Ok(mut queue) = self.shared.queue.lock() {
            queue.waiters.remove(&self.id);
        }
    }
}
impl UdpPoller for GeckoPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut queue = this
            .shared
            .queue
            .lock()
            .map_err(|_| io::Error::other("Gecko send queue is unavailable"))?;
        if let Some(error) = queue.error {
            return Poll::Ready(Err(error.into()));
        }
        if queue.packets.len() < MAX_PENDING {
            return Poll::Ready(Ok(()));
        }
        queue.waiters.insert(this.id, cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncUdpSocket for GeckoSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(GeckoPoller {
            id: self.shared.next_poller.fetch_add(1, Ordering::Relaxed),
            shared: Arc::clone(&self.shared),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Gecko does not support UDP segmentation",
            ));
        }
        let mut queue = self
            .shared
            .queue
            .lock()
            .map_err(|_| io::Error::other("Gecko send queue is unavailable"))?;
        if let Some(error) = queue.error {
            return Err(error.into());
        }
        if queue.packets.len() >= MAX_PENDING {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let frames = encode(
            transmit.contents,
            self.message_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1),
            self.config,
        )?;
        if !frames.is_empty() {
            queue.packets.push_back(OwnedTransmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                src_ip: transmit.src_ip,
                frames,
            });
            self.shared.notify.notify_one();
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut scratch = vec![0_u8; 65_536];
        let mut scratch_meta = [RecvMeta::default()];
        // Bound work on malformed or incomplete packets while ensuring that a
        // stream of fragments is not misreported as a closed socket.
        for _ in 0..64 {
            let mut input = [IoSliceMut::new(&mut scratch)];
            match self
                .shared
                .inner
                .poll_recv(cx, &mut input, &mut scratch_meta)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => continue,
                Poll::Ready(Ok(_)) => {}
            }
            let metadata = scratch_meta[0];
            let Some(frame) = scratch.get(..metadata.len) else {
                continue;
            };
            let packet = self
                .reassembly
                .lock()
                .map_err(|_| io::Error::other("Gecko receive state is unavailable"))?
                .accept(metadata.addr, frame, Instant::now());
            let Some(packet) = packet else { continue };
            if packet.len() > bufs[0].len() {
                continue;
            }
            bufs[0][..packet.len()].copy_from_slice(&packet);
            meta[0] = RecvMeta {
                len: packet.len(),
                stride: packet.len(),
                ..metadata
            };
            return Poll::Ready(Ok(1));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        1
    }
    fn may_fragment(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use tokio::time::timeout;

    fn source(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn fragments_long_headers_and_reassembles_reordered_frames() {
        let mut packet = vec![0x42; 1400];
        packet[0] = 0xc0;
        let frames = encode(&packet, 42, GeckoConfig::default()).unwrap();
        assert!((2..=8).contains(&frames.len()));
        assert!(
            frames
                .iter()
                .all(|frame| (512..=1200).contains(&(frame.len() + SALAMANDER_SALT_LEN)))
        );
        let mut state = Reassembly::default();
        let now = Instant::now();
        for frame in frames.iter().rev().take(frames.len() - 1) {
            assert!(state.accept(source(1), frame, now).is_none());
            assert!(state.accept(source(1), frame, now).is_none());
        }
        assert_eq!(state.accept(source(1), &frames[0], now), Some(packet));
        assert!(state.messages.is_empty());
        assert_eq!(
            encode(&[0x40, 1, 2], 1, GeckoConfig::default()).unwrap(),
            vec![vec![0x40, 1, 2]]
        );
    }

    #[test]
    fn custom_sizes_match_sing_box_defaults_and_bounds() {
        let packet = vec![0xc0; 1200];
        for (minimum, maximum) in [("700", "700"), ("800", "1600"), ("2048", "2048")] {
            let settings = GeckoConfig::parse(Some(minimum), Some(maximum)).unwrap();
            let frames = encode(&packet, 7, settings).unwrap();
            let low = minimum.parse::<usize>().unwrap();
            let high = maximum.parse::<usize>().unwrap();
            assert!(
                frames
                    .iter()
                    .all(|frame| (low..=high).contains(&(frame.len() + SALAMANDER_SALT_LEN)))
            );
            let mut reassembly = Reassembly::default();
            let result = frames
                .iter()
                .filter_map(|frame| reassembly.accept(source(1), frame, Instant::now()))
                .next();
            assert_eq!(result.as_deref(), Some(packet.as_slice()));
        }
        let defaults = GeckoConfig::parse(Some("0"), Some("0")).unwrap();
        assert_eq!(
            (defaults.min_packet_size, defaults.max_packet_size),
            (512, 1200)
        );
        assert!(GeckoConfig::parse(Some("1201"), None).is_err());
        assert!(GeckoConfig::parse(Some("-1"), Some("1200")).is_err());
        assert!(GeckoConfig::parse(None, Some("2049")).is_err());
    }

    #[test]
    fn rejects_invalid_frames_and_bounds_reassembly() {
        let mut state = Reassembly::default();
        let now = Instant::now();
        for frame in [
            &[0x80][..],
            &[0x80, 0, 0x01, 0, 0],
            &[0x80, 0, 0x22, 0, 0],
            &[0x80, 0, 0x02, 0xff, 0xff],
        ] {
            assert!(state.accept(source(1), frame, now).is_none());
        }
        for id in 0..MAX_INCOMPLETE_PER_SOURCE as u8 {
            assert!(
                state
                    .accept(source(1), &[0x80, id, 0x02, 0, 0, 1], now)
                    .is_none()
            );
        }
        assert!(
            state
                .accept(source(1), &[0x80, 99, 0x02, 0, 0, 1], now)
                .is_none()
        );
        assert_eq!(state.messages.len(), MAX_INCOMPLETE_PER_SOURCE);
        assert!(
            state
                .accept(source(2), &[0x80, 99, 0x02, 0, 0, 1], now + REASSEMBLY_TTL)
                .is_none()
        );
        assert_eq!(state.messages.len(), 1);
        let huge = vec![0_u8; MAX_MESSAGE + 1];
        assert!(encode(&huge, 0, GeckoConfig::default()).is_err());
    }

    #[derive(Debug)]
    struct MockSocket {
        blocked: AtomicBool,
        notify: Arc<Notify>,
        frames: Mutex<Vec<Vec<u8>>>,
    }

    struct MockPoller {
        notify: Arc<Notify>,
        waiting: Mutex<Option<Pin<Box<dyn std::future::Future<Output = ()> + Send>>>>,
    }
    impl std::fmt::Debug for MockPoller {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("MockPoller(..)")
        }
    }

    impl UdpPoller for MockPoller {
        fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let mut waiting = this.waiting.lock().unwrap();
            let future = waiting.get_or_insert_with(|| {
                let notify = Arc::clone(&this.notify);
                Box::pin(async move { notify.notified().await })
            });
            match future.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => {
                    *waiting = None;
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    impl AsyncUdpSocket for MockSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(MockPoller {
                notify: Arc::clone(&self.notify),
                waiting: Mutex::new(None),
            })
        }
        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            if self.blocked.load(Ordering::Acquire) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.frames.lock().unwrap().push(transmit.contents.to_vec());
            Ok(())
        }
        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            _bufs: &mut [IoSliceMut<'_>],
            _meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(source(0))
        }
    }

    #[tokio::test]
    async fn backpressure_resumes_queued_fragments_without_replaying_them() {
        let inner = Arc::new(MockSocket {
            blocked: AtomicBool::new(true),
            notify: Arc::new(Notify::new()),
            frames: Mutex::new(Vec::new()),
        });
        let socket = GeckoSocket::new(inner.clone(), GeckoConfig::default());
        let packet = [0xc0_u8; 1200];
        socket
            .try_send(&Transmit {
                destination: source(9),
                ecn: None,
                contents: &packet,
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        tokio::task::yield_now().await;
        assert!(inner.frames.lock().unwrap().is_empty());
        inner.blocked.store(false, Ordering::Release);
        inner.notify.notify_one();
        timeout(Duration::from_secs(1), async {
            loop {
                let frames = inner.frames.lock().unwrap().clone();
                if !frames.is_empty() && frames.len() == usize::from(frames[0][2] & 0x0f) {
                    let mut state = Reassembly::default();
                    let mut decoded = None;
                    for frame in &frames {
                        decoded = state.accept(source(9), frame, Instant::now()).or(decoded);
                    }
                    assert_eq!(decoded.as_deref(), Some(packet.as_slice()));
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
