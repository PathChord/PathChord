//! VLESS Vision padding over an authenticated TLS transport.
//!
//! Vision's upload and download framing and raw handoffs are independent.

use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::{Arc, Mutex, atomic::Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::{Sleep, sleep};
use zeroize::{Zeroize, Zeroizing};

use crate::vision_transport::VisionSwitch;

pub const FLOW_VISION: &str = "xtls-rprx-vision";
pub const FLOW_VISION_UDP443: &str = "xtls-rprx-vision-udp443";
const CONTINUE: u8 = 0;
const END: u8 = 1;
const DIRECT: u8 = 2;
const MAX_FRAME_CONTENT: usize = 4096;
const INITIAL_FRAMES: u8 = 8;
const MAX_PROBE_BYTES: usize = 128 * 1024;
const MAX_PROBE_FRAMES: usize = 65_536;
const MAX_TLS_RECORD: usize = 18_432;
const MAX_HELLO: usize = 65_536;
const INITIAL_REQUEST_WAIT: Duration = Duration::from_millis(500);
const LONG_PADDING_MIN: usize = 900;
const LONG_PADDING_VARIATION: u16 = 500;

#[derive(Default)]
struct TlsRecordProbe {
    header: [u8; 5],
    header_len: usize,
    remaining: usize,
    record_type: u8,
    hello: Vec<u8>,
    hello_length: Option<usize>,
    complete: bool,
    rejected: bool,
    observed: usize,
}

impl TlsRecordProbe {
    /// Parse a stream of inner TLS records without relying on I/O boundaries.
    /// When enabled, stop exactly after a complete application-data record.
    fn feed(&mut self, input: &[u8], hello_type: u8, stop_at_application: bool) -> (usize, bool) {
        if self.rejected {
            return (input.len(), false);
        }
        let mut offset = 0;
        while offset < input.len() {
            if self.header_len < 5 {
                let byte = input[offset];
                if (self.header_len == 0 && !matches!(byte, 0x14..=0x17))
                    || (self.header_len == 1 && byte != 3)
                    || (self.header_len == 2 && byte > 3)
                {
                    self.rejected = true;
                    return (input.len(), false);
                }
                self.header[self.header_len] = byte;
                self.header_len += 1;
                offset += 1;
                self.observed += 1;
                if self.header_len < 5 {
                    continue;
                }
                self.record_type = self.header[0];
                self.remaining = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                if self.remaining == 0
                    || self.remaining > MAX_TLS_RECORD
                    || (!self.complete && self.record_type != 0x16)
                {
                    self.rejected = true;
                    return (input.len(), false);
                }
            }
            let count = self.remaining.min(input.len() - offset);
            if !self.complete {
                let bytes = &input[offset..offset + count];
                for &byte in bytes {
                    if self.hello.len() >= MAX_HELLO {
                        self.rejected = true;
                        return (input.len(), false);
                    }
                    self.hello.push(byte);
                    if self.hello.len() == 1 && byte != hello_type {
                        self.rejected = true;
                        return (input.len(), false);
                    }
                    if self.hello.len() == 4 {
                        let length = (usize::from(self.hello[1]) << 16)
                            | (usize::from(self.hello[2]) << 8)
                            | usize::from(self.hello[3]);
                        if length == 0 || length + 4 > MAX_HELLO {
                            self.rejected = true;
                            return (input.len(), false);
                        }
                        self.hello_length = Some(length + 4);
                    }
                    if self.hello_length == Some(self.hello.len()) {
                        self.complete = true;
                        break;
                    }
                }
            }
            self.remaining -= count;
            self.observed += count;
            offset += count;
            if self.observed > MAX_PROBE_BYTES {
                self.rejected = true;
                return (input.len(), false);
            }
            if self.remaining == 0 {
                let record_length =
                    usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                let application = self.record_type == 0x17
                    && self.header[1..3] == [3, 3]
                    && (17..=16_640).contains(&record_length)
                    && self.complete;
                self.header_len = 0;
                if stop_at_application && application {
                    return (offset, true);
                }
            }
        }
        (offset, false)
    }

    fn possible_tls(&self) -> bool {
        !self.rejected && (self.header_len > 0 || !self.hello.is_empty() || self.complete)
    }
}

#[derive(Default)]
struct TlsProbe {
    upload: TlsRecordProbe,
    download: TlsRecordProbe,
    client: Option<ClientHelloInfo>,
    server: Option<ServerHelloInfo>,
}

impl TlsProbe {
    fn confirmed_tls13(&self) -> bool {
        if !self.upload.complete
            || self.upload.rejected
            || !self.download.complete
            || self.download.rejected
        {
            return false;
        }
        self.client
            .as_ref()
            .zip(self.server.as_ref())
            .is_some_and(|(client, server)| {
                client.session_id == server.session_id && client.ciphers.contains(&server.cipher)
            })
    }

    fn observe_download(&mut self, data: &[u8]) {
        if !self.download.complete && !self.download.rejected {
            self.download.feed(data, 2, false);
            if self.download.complete {
                self.server = parse_server_hello(&self.download.hello);
                self.download.rejected = self.server.is_none();
            }
        }
    }

    fn observe_upload(&mut self, data: &[u8], direct_available: bool) -> (usize, bool) {
        let direct_ready = direct_available && self.confirmed_tls13();
        let result = self.upload.feed(data, 1, direct_ready);
        if self.upload.complete && self.client.is_none() && !self.upload.rejected {
            self.client = parse_client_hello(&self.upload.hello);
            self.upload.rejected = self.client.is_none();
        }
        result
    }
}

struct ClientHelloInfo {
    session_id: Vec<u8>,
    ciphers: Vec<u16>,
}

struct ServerHelloInfo {
    session_id: Vec<u8>,
    cipher: u16,
}

struct SliceCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(count)?;
        let result = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(result)
    }

    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn short(&mut self) -> Option<usize> {
        let bytes = self.take(2)?;
        Some(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn supported_versions(extensions: &[u8], client: bool) -> Option<bool> {
    let mut extensions = SliceCursor::new(extensions);
    let mut version = None;
    while !extensions.done() {
        let kind = extensions.short()?;
        let length = extensions.short()?;
        let value = extensions.take(length)?;
        if kind == 0x002b {
            if version.is_some() {
                return None;
            }
            version = Some(if client {
                value.first().is_some_and(|size| {
                    usize::from(*size) == value.len() - 1
                        && usize::from(*size).is_multiple_of(2)
                        && value[1..]
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .any(|bytes| bytes == &[3, 4])
                })
            } else {
                value == [3, 4]
            });
        }
    }
    version
}

fn parse_client_hello(hello: &[u8]) -> Option<ClientHelloInfo> {
    let mut input = SliceCursor::new(hello.get(4..)?);
    if input.take(2)? != [3, 3] {
        return None;
    }
    input.take(32)?;
    let session_len = usize::from(input.byte()?);
    if session_len > 32 {
        return None;
    }
    let session_id = input.take(session_len)?.to_vec();
    let cipher_len = input.short()?;
    if cipher_len < 2 || !cipher_len.is_multiple_of(2) {
        return None;
    }
    let ciphers = input
        .take(cipher_len)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|value| u16::from_be_bytes([value[0], value[1]]))
        .collect();
    let compression_len = usize::from(input.byte()?);
    if compression_len == 0 || !input.take(compression_len)?.contains(&0) {
        return None;
    }
    let extension_len = input.short()?;
    let extensions = input.take(extension_len)?;
    if !input.done() || !supported_versions(extensions, true)? {
        return None;
    }
    Some(ClientHelloInfo {
        session_id,
        ciphers,
    })
}

fn parse_server_hello(hello: &[u8]) -> Option<ServerHelloInfo> {
    // TLS 1.3 HelloRetryRequest is encoded as a ServerHello but does not
    // establish the negotiated session and must never trigger DIRECT.
    const HELLO_RETRY_RANDOM: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    let mut input = SliceCursor::new(hello.get(4..)?);
    if input.take(2)? != [3, 3] || input.take(32)? == HELLO_RETRY_RANDOM {
        return None;
    }
    let session_len = usize::from(input.byte()?);
    if session_len > 32 {
        return None;
    }
    let session_id = input.take(session_len)?.to_vec();
    let cipher = input.short()? as u16;
    if !matches!(cipher, 0x1301..=0x1304) || input.byte()? != 0 {
        return None;
    }
    let extension_len = input.short()?;
    let extensions = input.take(extension_len)?;
    if !input.done() || !supported_versions(extensions, false)? {
        return None;
    }
    Some(ServerHelloInfo { session_id, cipher })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisionFlow {
    pub allow_udp_443: bool,
}

impl VisionFlow {
    pub fn parse(value: Option<&str>) -> Result<Option<Self>, &'static str> {
        match value.filter(|value| !value.is_empty()) {
            None => Ok(None),
            Some(FLOW_VISION) => Ok(Some(Self {
                allow_udp_443: false,
            })),
            Some(FLOW_VISION_UDP443) => Ok(Some(Self {
                allow_udp_443: true,
            })),
            Some(_) => Err("unsupported VLESS flow"),
        }
    }
}

pub struct VisionContext {
    uuid: [u8; 16],
}

impl VisionContext {
    #[must_use]
    pub fn new(uuid: &[u8; 16]) -> Self {
        Self { uuid: *uuid }
    }
}

impl Drop for VisionContext {
    fn drop(&mut self) {
        self.uuid.zeroize();
    }
}

#[derive(Debug)]
enum ReadPhase {
    Probe,
    Header,
    Frame {
        command: u8,
        content: usize,
        padding: usize,
    },
    Plain,
    DirectUnsupported,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WritePhase {
    Framed,
    Plain,
    DirectFlush,
    Direct,
}

#[derive(Clone, Copy)]
enum DrainSide {
    Reader,
    Writer,
    Background,
}

#[derive(Default)]
struct DrainWaiters {
    reader: Option<Waker>,
    writer: Option<Waker>,
    background: Option<Waker>,
}

#[derive(Default)]
struct DrainWake(Mutex<DrainWaiters>);

impl DrainWake {
    fn register(&self, side: DrainSide, waker: &Waker) {
        let mut waiters = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = match side {
            DrainSide::Reader => &mut waiters.reader,
            DrainSide::Writer => &mut waiters.writer,
            DrainSide::Background => &mut waiters.background,
        };
        if slot
            .as_ref()
            .is_none_or(|previous| !previous.will_wake(waker))
        {
            *slot = Some(waker.clone());
        }
    }

    fn clear(&self, side: DrainSide) {
        let mut waiters = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match side {
            DrainSide::Reader => waiters.reader = None,
            DrainSide::Writer => waiters.writer = None,
            DrainSide::Background => waiters.background = None,
        }
    }

    fn wake_all(&self) {
        let wakers = {
            let waiters = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            [
                waiters.reader.clone(),
                waiters.writer.clone(),
                waiters.background.clone(),
            ]
        };
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }

    fn clear_all(&self) {
        let mut waiters = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *waiters = DrainWaiters::default();
    }
}

impl Wake for DrainWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

pub struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    direct: Option<Arc<VisionSwitch>>,
    read_phase: ReadPhase,
    read_input: VecDeque<u8>,
    read_output: VecDeque<u8>,
    tls_probe: TlsProbe,
    first_write: bool,
    write_frames_remaining: u8,
    probe_frames: usize,
    write_phase: WritePhase,
    pending_write: Vec<u8>,
    pending_offset: usize,
    write_failed: bool,
    drain_wake: Arc<DrainWake>,
    request_header: Option<Zeroizing<Vec<u8>>>,
    request_deadline: Option<Pin<Box<Sleep>>>,
    request_needs_flush: bool,
    request_read_waker: Option<Waker>,
    request_finished: Arc<Notify>,
}

impl<S> Drop for VisionStream<S> {
    fn drop(&mut self) {
        // The carrier can retain the fan-out waker after an operation is
        // cancelled. Break task-waker references even when the carrier (or a
        // test retaining its waker) outlives this stream.
        self.drain_wake.clear_all();
        self.request_read_waker = None;
        self.uuid.zeroize();
        self.pending_write.zeroize();
    }
}

impl<S> VisionStream<S> {
    #[must_use]
    pub fn new(inner: S, context: VisionContext) -> Self {
        Self {
            inner,
            uuid: context.uuid,
            direct: None,
            read_phase: ReadPhase::Probe,
            read_input: VecDeque::new(),
            read_output: VecDeque::new(),
            tls_probe: TlsProbe::default(),
            first_write: true,
            write_frames_remaining: INITIAL_FRAMES,
            probe_frames: 0,
            write_phase: WritePhase::Framed,
            pending_write: Vec::new(),
            pending_offset: 0,
            write_failed: false,
            drain_wake: Arc::new(DrainWake::default()),
            request_header: None,
            request_deadline: None,
            request_needs_flush: false,
            request_read_waker: None,
            request_finished: Arc::new(Notify::new()),
        }
    }

    /// Hold the VLESS request until it can be written with the first Vision
    /// frame. A read-only caller emits a padded empty frame after the deadline.
    pub(crate) fn with_request_header(mut self, header: Zeroizing<Vec<u8>>) -> Self {
        self.request_header = Some(header);
        self.request_deadline = Some(Box::pin(sleep(INITIAL_REQUEST_WAIT)));
        self
    }

    pub(crate) fn with_direct_signal(mut self, direct: Arc<VisionSwitch>) -> Self {
        self.direct = Some(direct);
        self
    }

    fn decode_available(&mut self) -> io::Result<()> {
        loop {
            match self.read_phase {
                ReadPhase::Probe => {
                    let matches_prefix = self
                        .read_input
                        .iter()
                        .zip(self.uuid.iter())
                        .all(|(actual, expected)| actual == expected);
                    if !matches_prefix {
                        self.read_phase = ReadPhase::Plain;
                    } else if self.read_input.len() < self.uuid.len() {
                        return Ok(());
                    } else {
                        self.read_input.drain(..self.uuid.len());
                        self.read_phase = ReadPhase::Header;
                    }
                }
                ReadPhase::Header => {
                    if self.read_input.len() < 5 {
                        return Ok(());
                    }
                    let command = self.read_input.pop_front().expect("header length checked");
                    if !matches!(command, CONTINUE | END | DIRECT) {
                        return Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "invalid Vision command",
                        ));
                    }
                    let content = usize::from(u16::from_be_bytes([
                        self.read_input.pop_front().expect("header length checked"),
                        self.read_input.pop_front().expect("header length checked"),
                    ]));
                    let padding = usize::from(u16::from_be_bytes([
                        self.read_input.pop_front().expect("header length checked"),
                        self.read_input.pop_front().expect("header length checked"),
                    ]));
                    self.read_phase = ReadPhase::Frame {
                        command,
                        content,
                        padding,
                    };
                }
                ReadPhase::Frame {
                    command,
                    mut content,
                    mut padding,
                } => {
                    let content_count = content.min(self.read_input.len());
                    let content_bytes: Vec<_> = self.read_input.drain(..content_count).collect();
                    self.tls_probe.observe_download(&content_bytes);
                    self.read_output.extend(content_bytes);
                    content -= content_count;
                    if content == 0 {
                        let padding_count = padding.min(self.read_input.len());
                        self.read_input.drain(..padding_count);
                        padding -= padding_count;
                    }
                    if content != 0 || padding != 0 {
                        self.read_phase = ReadPhase::Frame {
                            command,
                            content,
                            padding,
                        };
                        return Ok(());
                    }
                    self.read_phase = match command {
                        CONTINUE => ReadPhase::Header,
                        END => ReadPhase::Plain,
                        DIRECT => {
                            if let Some(direct) = &self.direct {
                                direct.read_direct.store(true, Ordering::Release);
                                ReadPhase::Plain
                            } else {
                                ReadPhase::DirectUnsupported
                            }
                        }
                        _ => unreachable!("command was validated"),
                    };
                }
                ReadPhase::Plain => {
                    let content_bytes: Vec<_> = self.read_input.drain(..).collect();
                    self.tls_probe.observe_download(&content_bytes);
                    self.read_output.extend(content_bytes);
                    return Ok(());
                }
                ReadPhase::DirectUnsupported => return Ok(()),
            }
        }
    }

    fn read_eof(&self) -> io::Result<()> {
        match self.read_phase {
            ReadPhase::Plain => Ok(()),
            ReadPhase::Probe if self.read_input.is_empty() => Ok(()),
            // CONTINUE announces the next frame if any; a peer may close at
            // this boundary without emitting a final END frame.
            ReadPhase::Header if self.read_input.is_empty() => Ok(()),
            ReadPhase::DirectUnsupported => Err(io::Error::new(
                ErrorKind::Unsupported,
                "Vision DIRECT requires a raw TLS transport handoff",
            )),
            _ => Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "truncated Vision frame",
            )),
        }
    }

    fn frame(&mut self, content: &[u8], command: u8, long_padding: bool) -> io::Result<()> {
        let padding = if long_padding && content.len() < LONG_PADDING_MIN {
            LONG_PADDING_MIN - content.len() + usize::from(random_below(LONG_PADDING_VARIATION)?)
        } else {
            usize::from(random_below(256)?)
        };
        self.pending_write.zeroize();
        self.pending_offset = 0;
        if let Some(header) = self.request_header.take() {
            self.pending_write.extend_from_slice(&header);
            self.request_deadline = None;
            self.request_needs_flush = true;
            if let Some(waker) = self.request_read_waker.take() {
                waker.wake();
            }
        }
        if self.first_write {
            self.pending_write.extend_from_slice(&self.uuid);
            self.first_write = false;
        }
        self.pending_write.push(command);
        self.pending_write
            .extend_from_slice(&(content.len() as u16).to_be_bytes());
        self.pending_write
            .extend_from_slice(&(padding as u16).to_be_bytes());
        self.pending_write.extend_from_slice(content);
        self.pending_write
            .resize(self.pending_write.len() + padding, 0);
        self.write_frames_remaining = self.write_frames_remaining.saturating_sub(1);
        self.probe_frames += 1;
        self.write_phase = match command {
            END => WritePhase::Plain,
            DIRECT => WritePhase::DirectFlush,
            _ => WritePhase::Framed,
        };
        Ok(())
    }
}

fn random_below(bound: u16) -> io::Result<u16> {
    // Rejection avoids bias for the 500-value long-padding range.
    let limit = (u32::from(u16::MAX) + 1) / u32::from(bound) * u32::from(bound);
    loop {
        let mut random = [0_u8; 2];
        getrandom::fill(&mut random)
            .map_err(|_| io::Error::other("Vision padding randomness failed"))?;
        let value = u16::from_ne_bytes(random);
        if u32::from(value) < limit {
            return Ok(value % bound);
        }
    }
}

impl<S: AsyncWrite + Unpin> VisionStream<S> {
    fn poll_pending(&mut self, cx: &mut Context<'_>, side: DrainSide) -> Poll<io::Result<()>> {
        if self.write_failed {
            self.drain_wake.clear(side);
            return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
        }
        if self.pending_write.is_empty()
            && !self.request_needs_flush
            && self.write_phase != WritePhase::DirectFlush
        {
            return Poll::Ready(Ok(()));
        }
        // Readers, writers and the request driver can all drain the same
        // pending frame. Some transports retain only one write-side waker;
        // supply a stable fan-out waker so no waiting half is displaced.
        self.drain_wake.register(side, cx.waker());
        let waker = Waker::from(Arc::clone(&self.drain_wake));
        let mut drain_context = Context::from_waker(&waker);
        let result = self.poll_pending_inner(&mut drain_context);
        if result.is_ready() {
            // Finishing a drain wakes every waiter but must not unregister a
            // pending underlying read or flush on another task. Each poller
            // clears its own slot when its outer operation completes.
            self.drain_wake.clear(side);
            self.drain_wake.wake_all();
        }
        result
    }

    fn poll_pending_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_failed {
            return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
        }
        while self.pending_offset < self.pending_write.len() {
            match Pin::new(&mut self.inner)
                .poll_write(cx, &self.pending_write[self.pending_offset..])
            {
                Poll::Ready(Ok(0)) => {
                    self.write_failed = true;
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "Vision transport wrote zero bytes",
                    )));
                }
                Poll::Ready(Ok(count)) => self.pending_offset += count,
                Poll::Ready(Err(error)) => {
                    self.write_failed = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_write.zeroize();
        self.pending_offset = 0;
        if self.request_needs_flush {
            if let Err(error) = std::task::ready!(Pin::new(&mut self.inner).poll_flush(cx)) {
                self.write_failed = true;
                return Poll::Ready(Err(error));
            }
            self.request_needs_flush = false;
            self.request_finished.notify_one();
        }
        if self.write_phase == WritePhase::DirectFlush {
            if let Err(error) = std::task::ready!(Pin::new(&mut self.inner).poll_flush(cx)) {
                self.write_failed = true;
                return Poll::Ready(Err(error));
            }
            self.direct
                .as_ref()
                .expect("DIRECT requires a transport handoff")
                .write_direct
                .store(true, Ordering::Release);
            self.write_phase = WritePhase::Direct;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_flush_side(&mut self, cx: &mut Context<'_>, side: DrainSide) -> Poll<io::Result<()>> {
        if self.request_deadline.is_some() {
            self.frame(&[], CONTINUE, true)?;
        }
        match self.poll_pending(cx, side) {
            Poll::Ready(Ok(())) => {
                self.drain_wake.register(side, cx.waker());
                let waker = Waker::from(Arc::clone(&self.drain_wake));
                let result = Pin::new(&mut self.inner).poll_flush(&mut Context::from_waker(&waker));
                if result.is_ready() {
                    self.drain_wake.clear(side);
                }
                result
            }
            other => other,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Give a first application write a chance to share the outer TLS
        // record with the request. A server-first connection must still make
        // progress after the bounded wait.
        if let Some(deadline) = &mut this.request_deadline {
            if deadline.as_mut().poll(cx).is_pending() {
                this.request_read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            this.frame(&[], CONTINUE, true)?;
        }
        if this.request_needs_flush {
            std::task::ready!(this.poll_pending(cx, DrainSide::Reader))?;
        }
        // A previously accepted frame can be waiting on a short write. Make
        // progress while reading as well, without blocking the receive path.
        // A write-side failure must not close the independent read half.
        // poll_pending records it for the next write/flush/shutdown call.
        let _ = this.poll_pending(cx, DrainSide::Reader);
        // A stream can deliver many padding-only records. Yield after a bound
        // instead of reporting a false EOF or monopolising the executor.
        let result = (|| {
            for _ in 0..32 {
                this.decode_available()?;
                if !this.read_output.is_empty() {
                    let count = output.remaining().min(this.read_output.len());
                    for byte in this.read_output.drain(..count) {
                        output.put_slice(&[byte]);
                    }
                    return Poll::Ready(Ok(()));
                }
                if matches!(this.read_phase, ReadPhase::DirectUnsupported) {
                    return Poll::Ready(this.read_eof());
                }
                let mut raw = [0_u8; 8192];
                let mut read = ReadBuf::new(&mut raw);
                // TLS reads may write an alert while handling an invalid record.
                // Use the same fan-out waker on both underlying I/O directions so
                // that this rare write cannot replace a pending writer's wakeup.
                this.drain_wake.register(DrainSide::Reader, cx.waker());
                let waker = Waker::from(Arc::clone(&this.drain_wake));
                match Pin::new(&mut this.inner)
                    .poll_read(&mut Context::from_waker(&waker), &mut read)
                {
                    Poll::Ready(Ok(())) if read.filled().is_empty() => {
                        return Poll::Ready(this.read_eof());
                    }
                    Poll::Ready(Ok(())) => this.read_input.extend(read.filled()),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        })();
        if result.is_ready() {
            this.drain_wake.clear(DrainSide::Reader);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_pending(cx, DrainSide::Writer) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if matches!(this.write_phase, WritePhase::Plain | WritePhase::Direct) {
            this.drain_wake.register(DrainSide::Writer, cx.waker());
            let waker = Waker::from(Arc::clone(&this.drain_wake));
            let result =
                Pin::new(&mut this.inner).poll_write(&mut Context::from_waker(&waker), data);
            if result.is_ready() {
                this.drain_wake.clear(DrainSide::Writer);
            }
            return result;
        }
        let limit = data.len().min(MAX_FRAME_CONTENT);
        let (count, direct) = this
            .tls_probe
            .observe_upload(&data[..limit], this.direct.is_some());
        let command = if direct {
            DIRECT
        } else if this.probe_frames >= MAX_PROBE_FRAMES
            || this.tls_probe.upload.observed > MAX_PROBE_BYTES
            || (this.write_frames_remaining <= 1
                && (this.direct.is_none()
                    || !this.tls_probe.upload.possible_tls()
                    || this.tls_probe.download.rejected))
        {
            END
        } else {
            CONTINUE
        };
        let long_padding = this.tls_probe.upload.possible_tls();
        this.frame(&data[..count], command, long_padding)?;
        // The complete bounded frame is now owned by this stream. The peer
        // may already have received its content even if writing the padding
        // or flushing DIRECT fails; report the accepted count and surface the
        // recorded failure on the next write, flush, or shutdown.
        let _ = this.poll_pending(cx, DrainSide::Writer);
        this.drain_wake.clear(DrainSide::Writer);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.poll_flush_side(cx, DrainSide::Writer)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.request_deadline.is_some() {
            this.frame(&[], CONTINUE, true)?;
        }
        match this.poll_pending(cx, DrainSide::Writer) {
            Poll::Ready(Ok(())) => {
                this.drain_wake.register(DrainSide::Writer, cx.waker());
                let waker = Waker::from(Arc::clone(&this.drain_wake));
                let result =
                    Pin::new(&mut this.inner).poll_shutdown(&mut Context::from_waker(&waker));
                if result.is_ready() {
                    this.drain_wake.clear(DrainSide::Writer);
                }
                result
            }
            other => other,
        }
    }
}

/// Drive a pending initial request even if the application performs no I/O.
/// The mutex is held only for individual poll calls, never across an await.
pub(crate) struct DrivenVisionStream<S> {
    inner: Arc<Mutex<VisionStream<S>>>,
    request_finished: Arc<Notify>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> VisionStream<S> {
    pub(crate) fn drive_request(self) -> DrivenVisionStream<S> {
        let request_finished = Arc::clone(&self.request_finished);
        let inner = Arc::new(Mutex::new(self));
        let weak = Arc::downgrade(&inner);
        let finished = Arc::clone(&request_finished);
        tokio::spawn(async move {
            sleep(INITIAL_REQUEST_WAIT).await;
            let Some(inner) = weak.upgrade() else {
                return;
            };
            tokio::select! {
                _ = finished.notified() => {}
                result = std::future::poll_fn(|cx| {
                    let mut stream = match inner.lock() {
                        Ok(stream) => stream,
                        Err(_) => return Poll::Ready(Err(io::Error::other("Vision stream lock poisoned"))),
                    };
                    if stream.request_header.is_none() && !stream.request_needs_flush {
                        return Poll::Ready(Ok(()));
                    }
                    stream.poll_flush_side(cx, DrainSide::Background)
                }) => {
                    if result.is_err()
                        && let Ok(mut stream) = inner.lock()
                    {
                        stream.write_failed = true;
                        stream.request_deadline = None;
                        stream.request_needs_flush = true;
                        if let Some(waker) = stream.request_read_waker.take() {
                            waker.wake();
                        }
                    }
                }
            }
        });
        DrivenVisionStream {
            inner,
            request_finished,
        }
    }
}

impl<S> Drop for DrivenVisionStream<S> {
    fn drop(&mut self) {
        // Also release a background write that is blocked when its owner drops.
        self.request_finished.notify_one();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for DrivenVisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Poll::Ready(Err(io::Error::other("Vision stream lock poisoned"))),
        };
        Pin::new(&mut *inner).poll_read(cx, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DrivenVisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Poll::Ready(Err(io::Error::other("Vision stream lock poisoned"))),
        };
        Pin::new(&mut *inner).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Poll::Ready(Err(io::Error::other("Vision stream lock poisoned"))),
        };
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Poll::Ready(Err(io::Error::other("Vision stream lock poisoned"))),
        };
        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut result = vec![kind, 3, 3];
        result.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        result.extend_from_slice(payload);
        result
    }

    fn hello(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut result = vec![kind, 0, (body.len() >> 8) as u8, body.len() as u8];
        result.extend_from_slice(body);
        result
    }

    fn client_hello() -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[1; 32]);
        body.extend_from_slice(&[3, 1, 2, 3]);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&[0, 7, 0, 0x2b, 0, 3, 2, 3, 4]);
        hello(1, &body)
    }

    fn server_hello(cipher: u16, version: u8, session: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[2; 32]);
        body.push(session.len() as u8);
        body.extend_from_slice(session);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0, 6, 0, 0x2b, 0, 2, 3, version]);
        hello(2, &body)
    }

    fn confirmed_probe() -> TlsProbe {
        let mut probe = TlsProbe::default();
        let client = client_hello();
        let server = server_hello(0x1301, 4, &[1, 2, 3]);
        // Both handshake messages span records and each record arrives in
        // smaller I/O fragments; neither packetization is a TLS boundary.
        let client_wire = [record(0x16, &client[..11]), record(0x16, &client[11..])].concat();
        let server_wire = [record(0x16, &server[..9]), record(0x16, &server[9..])].concat();
        for byte in client_wire {
            assert_eq!(probe.observe_upload(&[byte], true), (1, false));
        }
        for chunk in server_wire.chunks(3) {
            probe.observe_download(chunk);
        }
        assert!(probe.confirmed_tls13());
        probe
    }

    fn frame(prefix: Option<&[u8; 16]>, command: u8, content: &[u8], padding: usize) -> Vec<u8> {
        let mut output = prefix.map_or_else(Vec::new, |value| value.to_vec());
        output.push(command);
        output.extend_from_slice(&(content.len() as u16).to_be_bytes());
        output.extend_from_slice(&(padding as u16).to_be_bytes());
        output.extend_from_slice(content);
        output.resize(output.len() + padding, 0);
        output
    }

    #[tokio::test]
    async fn decodes_fragmented_frames_and_padding_without_false_eof() {
        let uuid = [7_u8; 16];
        let mut wire = frame(Some(&uuid), CONTINUE, b"first", 7);
        wire.extend(frame(None, CONTINUE, b"", 9));
        wire.extend(frame(None, END, b"second", 2));
        wire.extend_from_slice(b"tail");
        let (client, mut peer) = tokio::io::duplex(1);
        let sender = tokio::spawn(async move {
            for byte in wire {
                peer.write_all(&[byte]).await.unwrap();
            }
            peer.shutdown().await.unwrap();
        });
        let mut stream = VisionStream::new(client, VisionContext::new(&uuid));
        let mut actual = Vec::new();
        stream.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, b"firstsecondtail");
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn preserves_large_writes_and_flushes_short_writes() {
        let uuid = [8_u8; 16];
        let payload: Vec<u8> = (0..200_000).map(|value| value as u8).collect();
        let expected = payload.clone();
        let (client, mut peer) = tokio::io::duplex(19);
        let sender = tokio::spawn(async move {
            let mut stream = VisionStream::new(client, VisionContext::new(&uuid));
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut wire = Vec::new();
        peer.read_to_end(&mut wire).await.unwrap();
        let mut decoder = VisionStream::new(tokio::io::empty(), VisionContext::new(&uuid));
        decoder.read_input.extend(wire);
        decoder.decode_available().unwrap();
        assert_eq!(
            decoder.read_output.iter().copied().collect::<Vec<_>>(),
            expected
        );
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_direct_until_raw_tls_handoff_is_available() {
        let uuid = [9_u8; 16];
        let wire = frame(Some(&uuid), DIRECT, b"before", 0);
        let (io, mut peer) = tokio::io::duplex(128);
        peer.write_all(&wire).await.unwrap();
        let mut stream = VisionStream::new(io, VisionContext::new(&uuid));
        let mut content = [0_u8; 6];
        stream.read_exact(&mut content).await.unwrap();
        assert_eq!(&content, b"before");
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn parses_both_registered_vision_flows() {
        assert!(
            !VisionFlow::parse(Some(FLOW_VISION))
                .unwrap()
                .unwrap()
                .allow_udp_443
        );
        assert!(
            VisionFlow::parse(Some(FLOW_VISION_UDP443))
                .unwrap()
                .unwrap()
                .allow_udp_443
        );
        assert!(VisionFlow::parse(Some("xtls-rprx-vision-other")).is_err());
    }

    #[tokio::test]
    async fn first_tls_payload_shares_the_request_and_receives_long_padding() {
        let uuid = [7; 16];
        let header = b"vless-header";
        let hello = record(0x16, &client_hello());
        let (io, mut peer) = tokio::io::duplex(4096);
        let mut stream = VisionStream::new(io, VisionContext::new(&uuid))
            .with_request_header(Zeroizing::new(header.to_vec()));
        stream.write_all(&hello).await.unwrap();
        stream.flush().await.unwrap();

        let mut prefix = vec![0; header.len() + uuid.len() + 5];
        peer.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[..header.len()], header);
        assert_eq!(&prefix[header.len()..header.len() + 16], &uuid);
        let frame = &prefix[header.len() + 16..];
        assert_eq!(frame[0], CONTINUE);
        let content = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
        let padding = usize::from(u16::from_be_bytes([frame[3], frame[4]]));
        assert_eq!(content, hello.len());
        assert!((900..1400).contains(&(content + padding)));
        let mut body = vec![0; content + padding];
        peer.read_exact(&mut body).await.unwrap();
        assert_eq!(&body[..content], hello);
    }

    #[tokio::test]
    async fn server_first_timeout_survives_cancelled_read() {
        let uuid = [7; 16];
        let header = b"vless-header";
        let (io, mut peer) = tokio::io::duplex(4096);
        let mut stream = VisionStream::new(io, VisionContext::new(&uuid))
            .with_request_header(Zeroizing::new(header.to_vec()));
        let started = tokio::time::Instant::now();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.read_u8())
                .await
                .is_err()
        );
        let client = tokio::spawn(async move {
            assert_eq!(stream.read_u8().await.unwrap(), b'r');
        });
        let mut prefix = vec![0; header.len() + uuid.len() + 5];
        tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut prefix))
            .await
            .unwrap()
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert_eq!(&prefix[..header.len()], header);
        let frame = &prefix[header.len() + 16..];
        assert_eq!(&frame[..3], &[CONTINUE, 0, 0]);
        let padding = usize::from(u16::from_be_bytes([frame[3], frame[4]]));
        assert!((900..1400).contains(&padding));
        let mut ignored = vec![0; padding];
        peer.read_exact(&mut ignored).await.unwrap();
        peer.write_all(b"r").await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn idle_connection_sends_the_request_after_the_deadline() {
        let uuid = [7; 16];
        let header = b"vless-header";
        let (io, mut peer) = tokio::io::duplex(4096);
        let stream = VisionStream::new(io, VisionContext::new(&uuid))
            .with_request_header(Zeroizing::new(header.to_vec()))
            .drive_request();
        // Keep the stream alive without polling it: the deadline must still
        // publish the request to the peer.
        let started = tokio::time::Instant::now();
        let mut prefix = vec![0; header.len() + uuid.len() + 5];
        tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut prefix))
            .await
            .unwrap()
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert_eq!(&prefix[..header.len()], header);
        assert_eq!(
            &prefix[header.len() + 16..header.len() + 19],
            &[CONTINUE, 0, 0]
        );
        drop(stream);
    }

    #[tokio::test]
    async fn first_write_wakes_a_read_waiting_for_the_request() {
        let uuid = [7; 16];
        let header = b"vless-header";
        let (io, mut peer) = tokio::io::duplex(4096);
        let stream = VisionStream::new(io, VisionContext::new(&uuid))
            .with_request_header(Zeroizing::new(header.to_vec()))
            .drive_request();
        let (mut read, mut write) = tokio::io::split(stream);
        let reader = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(300), read.read_u8())
                .await
                .unwrap()
                .unwrap()
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        write.write_all(b"hello").await.unwrap();
        write.flush().await.unwrap();
        let mut prefix = vec![0; header.len() + uuid.len() + 5];
        peer.read_exact(&mut prefix).await.unwrap();
        let frame = &prefix[header.len() + 16..];
        let content = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
        let padding = usize::from(u16::from_be_bytes([frame[3], frame[4]]));
        let mut body = vec![0; content + padding];
        peer.read_exact(&mut body).await.unwrap();
        assert_eq!(&body[..content], b"hello");
        peer.write_all(b"r").await.unwrap();
        assert_eq!(reader.await.unwrap(), b'r');
    }

    #[derive(Default)]
    struct SplitGate {
        write_blocked: bool,
        flush_blocked: bool,
        write_polls: usize,
        read_polls: usize,
        flush_polls: usize,
        shutdowns: usize,
        read_touches_writer: bool,
        writer: Option<Waker>,
        reader: Option<Waker>,
        incoming: VecDeque<u8>,
        written: Vec<u8>,
    }

    struct SplitGateIo(Arc<Mutex<SplitGate>>);

    impl AsyncRead for SplitGateIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut state = self.0.lock().unwrap();
            state.read_polls += 1;
            if state.read_touches_writer {
                state.writer = Some(cx.waker().clone());
            }
            if state.incoming.is_empty() {
                state.reader = Some(cx.waker().clone());
                Poll::Pending
            } else {
                let count = output.remaining().min(state.incoming.len());
                for byte in state.incoming.drain(..count) {
                    output.put_slice(&[byte]);
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for SplitGateIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.0.lock().unwrap();
            state.write_polls += 1;
            if state.write_blocked {
                state.writer = Some(cx.waker().clone());
                Poll::Pending
            } else {
                state.written.extend_from_slice(bytes);
                Poll::Ready(Ok(bytes.len()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut state = self.0.lock().unwrap();
            state.flush_polls += 1;
            if state.flush_blocked {
                state.writer = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.0.lock().unwrap().shutdowns += 1;
            Poll::Ready(Ok(()))
        }
    }

    async fn wait_for_gate(mut predicate: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !predicate() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("gate was not polled");
    }

    #[tokio::test]
    async fn split_reader_and_writer_both_wake_for_pending_frame() {
        let gate = Arc::new(Mutex::new(SplitGate {
            write_blocked: true,
            ..SplitGate::default()
        }));
        let stream = VisionStream::new(SplitGateIo(gate.clone()), VisionContext::new(&[7; 16]));
        let (mut read, mut write) = tokio::io::split(stream);
        write.write_all(b"x").await.unwrap();
        let writer = tokio::spawn(async move { write.flush().await });
        wait_for_gate(|| gate.lock().unwrap().write_polls >= 2).await;
        let reader = tokio::spawn(async move { read.read_u8().await });
        wait_for_gate(|| gate.lock().unwrap().write_polls >= 3).await;
        let waker = {
            let mut state = gate.lock().unwrap();
            state.write_blocked = false;
            state.writer.take().unwrap()
        };
        waker.wake();
        tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("reader replaced the pending writer's wakeup")
            .unwrap()
            .unwrap();
        let written = &gate.lock().unwrap().written;
        assert_eq!(&written[..16], &[7; 16]);
        assert_eq!(written[21], b'x');
        reader.abort();
    }

    #[test]
    fn completing_write_retains_pending_read_wakeup_until_read_finishes() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct WakeCounter(AtomicUsize);
        impl Wake for WakeCounter {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let gate = Arc::new(Mutex::new(SplitGate {
            write_blocked: true,
            ..SplitGate::default()
        }));
        let mut stream = VisionStream::new(SplitGateIo(gate.clone()), VisionContext::new(&[7; 16]));
        let writer = Waker::from(Arc::new(WakeCounter(AtomicUsize::new(0))));
        let reader_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let reader = Waker::from(reader_counter.clone());
        let mut writer_cx = Context::from_waker(&writer);
        let mut reader_cx = Context::from_waker(&reader);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut writer_cx, b"x"),
            Poll::Ready(Ok(1))
        ));
        let mut output = [0];
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut reader_cx, &mut ReadBuf::new(&mut output))
                .is_pending()
        );
        assert!(gate.lock().unwrap().reader.is_some());

        // Complete the write and leave the read task unpolled. Consuming the
        // write wake deliberately models another readiness event occurring
        // before the executor schedules the previously woken reader again.
        gate.lock().unwrap().write_blocked = false;
        assert!(Pin::new(&mut stream).poll_flush(&mut writer_cx).is_ready());
        let after_write = reader_counter.0.load(Ordering::SeqCst);
        let read_waker = {
            let mut state = gate.lock().unwrap();
            state.incoming.push_back(b'r');
            state.reader.take().unwrap()
        };
        read_waker.wake();
        assert!(
            reader_counter.0.load(Ordering::SeqCst) > after_write,
            "read readiness lost after write completion"
        );
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut reader_cx, &mut ReadBuf::new(&mut output)),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(output, [b'r']);
        let waiters = stream.drain_wake.0.lock().unwrap();
        assert!(waiters.reader.is_none());
    }

    #[test]
    fn dropping_cancelled_stream_releases_fanout_waiters() {
        struct TaskWake(std::sync::atomic::AtomicBool);
        impl Wake for TaskWake {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let gate = Arc::new(Mutex::new(SplitGate {
            write_blocked: true,
            ..SplitGate::default()
        }));
        let mut stream = VisionStream::new(SplitGateIo(gate.clone()), VisionContext::new(&[7; 16]));
        let reader = Arc::new(TaskWake(std::sync::atomic::AtomicBool::new(false)));
        let writer = Arc::new(TaskWake(std::sync::atomic::AtomicBool::new(false)));
        let reader_weak = Arc::downgrade(&reader);
        let writer_weak = Arc::downgrade(&writer);
        let reader_waker = Waker::from(reader);
        let writer_waker = Waker::from(writer);
        let mut reader_cx = Context::from_waker(&reader_waker);
        let mut writer_cx = Context::from_waker(&writer_waker);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut writer_cx, b"x"),
            Poll::Ready(Ok(1))
        ));
        assert!(
            Pin::new(&mut stream)
                .poll_flush(&mut writer_cx)
                .is_pending()
        );
        let mut bytes = [0];
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut reader_cx, &mut ReadBuf::new(&mut bytes))
                .is_pending()
        );
        let fanout = Arc::downgrade(&stream.drain_wake);
        drop(reader_waker);
        drop(writer_waker);
        assert!(reader_weak.upgrade().is_some());
        assert!(writer_weak.upgrade().is_some());

        // The gate deliberately retains both carrier wakers after the stream
        // is dropped, as a real transport or readiness registry may do.
        drop(stream);
        assert!(fanout.upgrade().is_some());
        assert!(reader_weak.upgrade().is_none());
        assert!(writer_weak.upgrade().is_none());
        let mut state = gate.lock().unwrap();
        state.reader = None;
        state.writer = None;
        assert!(fanout.upgrade().is_none());
    }

    #[tokio::test]
    async fn split_tls_read_side_write_does_not_replace_writer_wakeup() {
        let gate = Arc::new(Mutex::new(SplitGate {
            flush_blocked: true,
            read_touches_writer: true,
            ..SplitGate::default()
        }));
        let stream = VisionStream::new(SplitGateIo(gate.clone()), VisionContext::new(&[7; 16]));
        let (mut read, mut write) = tokio::io::split(stream);
        let writer = tokio::spawn(async move { write.flush().await });
        wait_for_gate(|| gate.lock().unwrap().flush_polls >= 1).await;
        let reader = tokio::spawn(async move { read.read_u8().await });
        wait_for_gate(|| gate.lock().unwrap().read_polls >= 1).await;
        let waker = {
            let mut state = gate.lock().unwrap();
            state.flush_blocked = false;
            state.writer.take().unwrap()
        };
        waker.wake();
        tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("read-side TLS write replaced the writer's wakeup")
            .unwrap()
            .unwrap();
        reader.abort();
    }

    #[tokio::test]
    async fn stale_complete_frame_is_cleared_before_read() {
        let gate = Arc::new(Mutex::new(SplitGate {
            read_touches_writer: true,
            ..SplitGate::default()
        }));
        let mut stream = VisionStream::new(SplitGateIo(gate.clone()), VisionContext::new(&[7; 16]));
        stream.pending_write = vec![0xa5; 16];
        stream.pending_offset = stream.pending_write.len();
        let mut bytes = [0; 1];
        let mut output = ReadBuf::new(&mut bytes);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut cx, &mut output)
                .is_pending()
        );
        assert!(stream.pending_write.is_empty());
        assert_eq!(stream.pending_offset, 0);
    }

    #[tokio::test]
    async fn split_request_flush_survives_cancelled_writer_and_wakes_reader() {
        let gate = Arc::new(Mutex::new(SplitGate {
            flush_blocked: true,
            ..SplitGate::default()
        }));
        let stream = VisionStream::new(SplitGateIo(gate.clone()), VisionContext::new(&[7; 16]))
            .with_request_header(Zeroizing::new(b"request".to_vec()));
        let (mut read, mut write) = tokio::io::split(stream);
        write.write_all(b"payload").await.unwrap();
        let writer = tokio::spawn(async move { write.flush().await });
        wait_for_gate(|| gate.lock().unwrap().flush_polls >= 2).await;
        let reader = tokio::spawn(async move { read.read_u8().await });
        wait_for_gate(|| gate.lock().unwrap().flush_polls >= 3).await;
        writer.abort();
        assert!(writer.await.unwrap_err().is_cancelled());
        let waker = {
            let mut state = gate.lock().unwrap();
            state.flush_blocked = false;
            state.writer.take().unwrap()
        };
        waker.wake();
        wait_for_gate(|| gate.lock().unwrap().flush_polls >= 4).await;
        let written = &gate.lock().unwrap().written;
        assert_eq!(&written[..7], b"request");
        assert_eq!(&written[7..23], &[7; 16]);
        assert_eq!(&written[28..35], b"payload");
        reader.abort();
    }

    #[tokio::test]
    async fn split_direct_flush_wakes_writer_and_preserves_half_close() {
        let gate = Arc::new(Mutex::new(SplitGate {
            flush_blocked: true,
            ..SplitGate::default()
        }));
        let direct = Arc::new(VisionSwitch::default());
        let mut stream = VisionStream::new(SplitGateIo(gate.clone()), VisionContext::new(&[3; 16]))
            .with_direct_signal(direct.clone());
        stream.tls_probe = confirmed_probe();
        let application = record(0x17, &[0x42; 20]);
        let (mut read, mut write) = tokio::io::split(stream);
        write.write_all(&application).await.unwrap();
        assert!(!direct.write_direct.load(Ordering::Acquire));
        let writer = tokio::spawn(async move {
            write.write_all(b"raw").await?;
            write.shutdown().await
        });
        wait_for_gate(|| gate.lock().unwrap().flush_polls >= 2).await;
        let reader = tokio::spawn(async move { read.read_u8().await });
        wait_for_gate(|| gate.lock().unwrap().flush_polls >= 3).await;
        let waker = {
            let mut state = gate.lock().unwrap();
            state.flush_blocked = false;
            state.writer.take().unwrap()
        };
        waker.wake();
        tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("DIRECT flush did not wake the writer")
            .unwrap()
            .unwrap();
        assert!(direct.write_direct.load(Ordering::Acquire));
        let state = gate.lock().unwrap();
        assert_eq!(&state.written[..16], &[3; 16]);
        assert_eq!(state.written[16], DIRECT);
        let content = usize::from(u16::from_be_bytes([state.written[17], state.written[18]]));
        let padding = usize::from(u16::from_be_bytes([state.written[19], state.written[20]]));
        assert_eq!(&state.written[21..21 + content], application);
        assert_eq!(&state.written[21 + content + padding..], b"raw");
        assert_eq!(state.shutdowns, 1);
        reader.abort();
    }

    #[tokio::test]
    async fn split_direct_raw_write_wakes_after_read_touches_write_waker() {
        let gate = Arc::new(Mutex::new(SplitGate {
            write_blocked: true,
            read_touches_writer: true,
            ..SplitGate::default()
        }));
        let direct = Arc::new(VisionSwitch::default());
        direct.write_direct.store(true, Ordering::Release);
        let mut stream = VisionStream::new(SplitGateIo(gate.clone()), VisionContext::new(&[3; 16]))
            .with_direct_signal(direct);
        stream.write_phase = WritePhase::Direct;
        let (mut read, mut write) = tokio::io::split(stream);
        let writer = tokio::spawn(async move { write.write_all(b"raw").await });
        wait_for_gate(|| gate.lock().unwrap().write_polls >= 1).await;
        let reader = tokio::spawn(async move { read.read_u8().await });
        wait_for_gate(|| gate.lock().unwrap().read_polls >= 1).await;
        let waker = {
            let mut state = gate.lock().unwrap();
            state.write_blocked = false;
            state.writer.take().unwrap()
        };
        waker.wake();
        tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("read-side I/O replaced the raw writer's wakeup")
            .unwrap()
            .unwrap();
        assert_eq!(gate.lock().unwrap().written, b"raw");
        reader.abort();
    }

    #[tokio::test]
    async fn background_request_flush_does_not_replace_split_writer() {
        let gate = Arc::new(Mutex::new(SplitGate {
            flush_blocked: true,
            ..SplitGate::default()
        }));
        let stream = VisionStream::new(SplitGateIo(gate.clone()), VisionContext::new(&[7; 16]))
            .with_request_header(Zeroizing::new(b"request".to_vec()))
            .drive_request();
        let (mut read, mut write) = tokio::io::split(stream);
        write.write_all(b"payload").await.unwrap();
        let writer = tokio::spawn(async move { write.flush().await });
        wait_for_gate(|| gate.lock().unwrap().flush_polls >= 2).await;
        let reader = tokio::spawn(async move { read.read_u8().await });
        wait_for_gate(|| gate.lock().unwrap().flush_polls >= 3).await;
        // The background driver begins after the bounded initial request wait.
        wait_for_gate(|| gate.lock().unwrap().flush_polls >= 4).await;
        let waker = {
            let mut state = gate.lock().unwrap();
            state.flush_blocked = false;
            state.writer.take().unwrap()
        };
        waker.wake();
        tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("background request driver replaced the writer's wakeup")
            .unwrap()
            .unwrap();
        reader.abort();
    }

    #[tokio::test]
    async fn clean_eof_after_complete_continue_is_not_a_truncated_frame() {
        let uuid = [9; 16];
        let (io, mut peer) = tokio::io::duplex(128);
        peer.write_all(&frame(Some(&uuid), CONTINUE, b"short", 3))
            .await
            .unwrap();
        peer.shutdown().await.unwrap();
        let mut stream = VisionStream::new(io, VisionContext::new(&uuid));
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(&output, b"short");

        let (io, mut peer) = tokio::io::duplex(128);
        let mut truncated = frame(Some(&uuid), CONTINUE, b"short", 3);
        truncated.pop();
        peer.write_all(&truncated).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut stream = VisionStream::new(io, VisionContext::new(&uuid));
        assert_eq!(
            stream
                .read_to_end(&mut Vec::new())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn tls13_detection_requires_both_valid_matching_hellos() {
        let mut probe = confirmed_probe();
        let too_short = record(0x17, &[0; 4]);
        assert_eq!(probe.observe_upload(&too_short, true), (9, false));
        let application = record(0x17, &[7; 20]);
        assert_eq!(probe.observe_upload(&application[..7], true), (7, false));
        let rest = [&application[7..], &record(0x17, &[8; 4])].concat();
        assert_eq!(
            probe.observe_upload(&rest, true),
            (application.len() - 7, true)
        );

        for server in [
            server_hello(0x1305, 4, &[1, 2, 3]),
            server_hello(0x1301, 3, &[1, 2, 3]),
            server_hello(0x1301, 4, &[4, 5, 6]),
        ] {
            let mut probe = TlsProbe::default();
            probe.observe_upload(&record(0x16, &client_hello()), true);
            probe.observe_download(&record(0x16, &server));
            assert!(!probe.confirmed_tls13());
            assert_eq!(
                probe.observe_upload(&record(0x17, &[7; 20]), true),
                (25, false)
            );
        }
    }

    struct ShortWriter {
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
        flush_allowed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl AsyncWrite for ShortWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let count = data.len().min(3);
            self.bytes.lock().unwrap().extend_from_slice(&data[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.flush_allowed.load(Ordering::Acquire) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn direct_waits_for_record_boundary_and_flush_across_cancelled_writes() {
        use std::{future::Future, task::Waker};

        let uuid = [3; 16];
        let written = Arc::new(std::sync::Mutex::new(Vec::new()));
        let flush_allowed = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let direct = Arc::new(VisionSwitch::default());
        let inner = ShortWriter {
            bytes: Arc::clone(&written),
            flush_allowed: Arc::clone(&flush_allowed),
        };
        let mut stream = VisionStream::new(inner, VisionContext::new(&uuid))
            .with_direct_signal(Arc::clone(&direct));
        stream.tls_probe = confirmed_probe();
        let application = record(0x17, &[0x42; 20]);
        stream.write_all(&application[..7]).await.unwrap();
        stream.flush().await.unwrap();
        assert!(!direct.write_direct.load(Ordering::Acquire));
        let next_record = record(0x17, &[0x43; 3]);
        let tail = [&application[7..], &next_record].concat();
        flush_allowed.store(false, Ordering::Release);
        assert_eq!(stream.write(&tail).await.unwrap(), application.len() - 7);
        assert!(!direct.write_direct.load(Ordering::Acquire));
        {
            let mut blocked = std::pin::pin!(stream.write_all(&next_record));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(blocked.as_mut().poll(&mut cx).is_pending());
        }
        assert!(!direct.write_direct.load(Ordering::Acquire));
        flush_allowed.store(true, Ordering::Release);
        stream.flush().await.unwrap();
        assert!(direct.write_direct.load(Ordering::Acquire));
        stream.write_all(&next_record).await.unwrap();
        let wire = written.lock().unwrap();
        assert_eq!(wire[16], CONTINUE);
        let first_content = usize::from(u16::from_be_bytes([wire[17], wire[18]]));
        let first_padding = usize::from(u16::from_be_bytes([wire[19], wire[20]]));
        let second = 21 + first_content + first_padding;
        assert_eq!(wire[second], DIRECT);
        let second_content = usize::from(u16::from_be_bytes([wire[second + 1], wire[second + 2]]));
        let second_padding = usize::from(u16::from_be_bytes([wire[second + 3], wire[second + 4]]));
        let raw = second + 5 + second_content + second_padding;
        assert_eq!(&wire[raw..], next_record);
    }

    struct FailedWriter {
        incoming: &'static [u8],
    }

    impl AsyncRead for FailedWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let count = output.remaining().min(this.incoming.len());
            output.put_slice(&this.incoming[..count]);
            this.incoming = &this.incoming[count..];
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FailedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct FailAfterPayload {
        bytes: Arc<Mutex<Vec<u8>>>,
        prefix_len: usize,
        fail_with_zero: bool,
    }

    impl AsyncWrite for FailAfterPayload {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut written = self.bytes.lock().unwrap();
            if written.len() >= self.prefix_len {
                return if self.fail_with_zero {
                    Poll::Ready(Ok(0))
                } else {
                    Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
                };
            }
            let count = data.len().min(self.prefix_len - written.len());
            written.extend_from_slice(&data[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn accepted_frame_does_not_report_failure_after_payload_was_written() {
        let uuid = [7; 16];
        let payload = record(0x16, &client_hello());
        for fail_with_zero in [false, true] {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let inner = FailAfterPayload {
                bytes: bytes.clone(),
                prefix_len: uuid.len() + 5 + payload.len(),
                fail_with_zero,
            };
            let mut stream = VisionStream::new(inner, VisionContext::new(&uuid));
            assert_eq!(stream.write(&payload).await.unwrap(), payload.len());
            let delivered = bytes.lock().unwrap().clone();
            assert_eq!(&delivered[..16], &uuid);
            assert_eq!(&delivered[21..], payload);
            assert!(usize::from(u16::from_be_bytes([delivered[19], delivered[20]])) > 0);
            for result in [
                stream.flush().await,
                stream.write(b"retry").await.map(|_| ()),
                stream.shutdown().await,
            ] {
                assert!(matches!(result, Err(error) if error.kind() == ErrorKind::BrokenPipe));
            }
            assert_eq!(*bytes.lock().unwrap(), delivered);
        }
    }

    struct FailOnFlush {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for FailOnFlush {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.bytes.lock().unwrap().extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn accepted_request_and_direct_frames_report_flush_failure_later() {
        let uuid = [3; 16];
        for is_direct in [false, true] {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let inner = FailOnFlush {
                bytes: bytes.clone(),
            };
            let mut stream = VisionStream::new(inner, VisionContext::new(&uuid));
            let direct = Arc::new(VisionSwitch::default());
            let payload = if is_direct {
                stream = stream.with_direct_signal(direct.clone());
                stream.tls_probe = confirmed_probe();
                record(0x17, &[0x42; 20])
            } else {
                stream = stream.with_request_header(Zeroizing::new(b"request".to_vec()));
                b"payload".to_vec()
            };
            assert_eq!(stream.write(&payload).await.unwrap(), payload.len());
            let delivered = bytes.lock().unwrap().clone();
            let offset = if is_direct { 0 } else { b"request".len() };
            assert_eq!(&delivered[offset..offset + 16], &uuid);
            assert_eq!(
                delivered[offset + 16],
                if is_direct { DIRECT } else { CONTINUE }
            );
            assert_eq!(
                &delivered[offset + 21..offset + 21 + payload.len()],
                payload
            );
            assert!(!direct.write_direct.load(Ordering::Acquire));
            for result in [
                stream.flush().await,
                stream.write(b"retry").await.map(|_| ()),
                stream.shutdown().await,
            ] {
                assert!(matches!(result, Err(error) if error.kind() == ErrorKind::BrokenPipe));
            }
            assert_eq!(*bytes.lock().unwrap(), delivered);
        }
    }

    #[tokio::test]
    async fn write_failure_does_not_suppress_remaining_downlink() {
        let inner = FailedWriter {
            incoming: b"remaining response",
        };
        let mut stream = VisionStream::new(inner, VisionContext::new(&[1; 16]));
        assert_eq!(stream.write(b"request").await.unwrap(), b"request".len());
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"remaining response");
        assert!(matches!(
            stream.flush().await,
            Err(error) if error.kind() == ErrorKind::BrokenPipe
        ));
    }
}
