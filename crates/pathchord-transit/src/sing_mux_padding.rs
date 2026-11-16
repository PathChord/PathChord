//! sing-mux v1 padding, applied to the physical connection before multiplexing.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const PADDED_FRAMES: u8 = 16;
const MAX_DATA: usize = u16::MAX as usize;
const MIN_PADDING: usize = 256;
const PADDING_CHOICES: u16 = 512;

#[derive(Clone, Copy)]
enum DrainSide {
    Reader,
    Writer,
}

#[derive(Default)]
struct DrainWaiters {
    reader: Option<Waker>,
    writer: Option<Waker>,
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
        }
    }

    fn finish(&self) {
        let (reader, writer) = {
            let mut waiters = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (waiters.reader.take(), waiters.writer.take())
        };
        if let Some(waker) = reader {
            waker.wake();
        }
        if let Some(waker) = writer {
            waker.wake();
        }
    }
}

impl Wake for DrainWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let (reader, writer) = {
            let waiters = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (waiters.reader.clone(), waiters.writer.clone())
        };
        if let Some(waker) = reader {
            waker.wake();
        }
        if let Some(waker) = writer {
            waker.wake();
        }
    }
}

/// Generate the initial session padding and the length of each padded frame.
pub(crate) fn padding_len() -> io::Result<usize> {
    let mut random = [0; 2];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    Ok(MIN_PADDING + usize::from(u16::from_be_bytes(random) % PADDING_CHOICES))
}

pub(crate) struct PaddingStream<T> {
    inner: T,
    read_frames: u8,
    read_header: [u8; 4],
    read_header_len: usize,
    read_in_frame: bool,
    read_data_left: usize,
    read_padding_left: usize,
    write_frames: u8,
    write_buffer: Vec<u8>,
    write_pos: usize,
    write_failed: bool,
    drain_wake: Arc<DrainWake>,
}

impl<T> PaddingStream<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            read_frames: 0,
            read_header: [0; 4],
            read_header_len: 0,
            read_in_frame: false,
            read_data_left: 0,
            read_padding_left: 0,
            write_frames: 0,
            write_buffer: Vec::new(),
            write_pos: 0,
            write_failed: false,
            drain_wake: Arc::new(DrainWake::default()),
        }
    }
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated multiplex padding")
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for PaddingStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // A write can have accepted a whole frame while the carrier was
        // blocked. Continue that write while waiting for a peer response,
        // without preventing reads or hiding an already-arrived response if
        // the write side fails. The failure remains visible to the writer.
        if !this.write_failed && !this.write_buffer.is_empty() {
            let _ = this.poll_drain(cx, DrainSide::Reader);
        }
        let result = (|| loop {
            if this.read_frames == PADDED_FRAMES {
                return Pin::new(&mut this.inner).poll_read(cx, output);
            }
            if !this.read_in_frame {
                let mut header = ReadBuf::new(&mut this.read_header[this.read_header_len..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut header) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if header.filled().is_empty() => {
                        return Poll::Ready(if this.read_header_len == 0 {
                            Ok(())
                        } else {
                            Err(truncated())
                        });
                    }
                    Poll::Ready(Ok(())) => this.read_header_len += header.filled().len(),
                }
                if this.read_header_len < this.read_header.len() {
                    continue;
                }
                this.read_data_left = usize::from(u16::from_be_bytes([
                    this.read_header[0],
                    this.read_header[1],
                ]));
                this.read_padding_left = usize::from(u16::from_be_bytes([
                    this.read_header[2],
                    this.read_header[3],
                ]));
                this.read_in_frame = true;
            }
            if this.read_data_left > 0 {
                let capacity = output.remaining().min(this.read_data_left);
                let buffer = output.initialize_unfilled_to(capacity);
                let mut read = ReadBuf::new(buffer);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if read.filled().is_empty() => {
                        return Poll::Ready(Err(truncated()));
                    }
                    Poll::Ready(Ok(())) => {
                        let count = read.filled().len();
                        this.read_data_left -= count;
                        output.advance(count);
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            if this.read_padding_left > 0 {
                let mut scratch = [0; 4096];
                let size = scratch.len().min(this.read_padding_left);
                let mut read = ReadBuf::new(&mut scratch[..size]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if read.filled().is_empty() => {
                        return Poll::Ready(Err(truncated()));
                    }
                    Poll::Ready(Ok(())) => this.read_padding_left -= read.filled().len(),
                }
                continue;
            }
            this.read_frames += 1;
            this.read_header_len = 0;
            this.read_in_frame = false;
        })();
        if result.is_ready() {
            this.drain_wake.clear(DrainSide::Reader);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> PaddingStream<T> {
    fn poll_drain(&mut self, cx: &mut Context<'_>, side: DrainSide) -> Poll<io::Result<()>> {
        if self.write_failed {
            return Poll::Ready(Err(io::Error::other("multiplex padding writer failed")));
        }
        if self.write_buffer.is_empty() {
            return Poll::Ready(Ok(()));
        }
        // Reading can also drive a buffered write. A physical socket may keep
        // only its most recent write waker, so give it one stable waker which
        // fans readiness out to both halves of a split stream.
        self.drain_wake.register(side, cx.waker());
        let waker = Waker::from(Arc::clone(&self.drain_wake));
        let mut drain_context = Context::from_waker(&waker);
        while self.write_pos < self.write_buffer.len() {
            match Pin::new(&mut self.inner)
                .poll_write(&mut drain_context, &self.write_buffer[self.write_pos..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    self.write_failed = true;
                    self.drain_wake.finish();
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "multiplex padding write returned zero",
                    )));
                }
                Poll::Ready(Ok(count)) => self.write_pos += count,
                Poll::Ready(Err(error)) => {
                    self.write_failed = true;
                    self.drain_wake.finish();
                    return Poll::Ready(Err(error));
                }
            }
        }
        self.write_buffer.clear();
        self.write_pos = 0;
        self.drain_wake.finish();
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PaddingStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.poll_drain(cx, DrainSide::Writer) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if this.write_frames == PADDED_FRAMES {
            return Pin::new(&mut this.inner).poll_write(cx, input);
        }
        let data_len = input.len().min(MAX_DATA);
        let padding = match padding_len() {
            Ok(padding) => padding,
            Err(error) => return Poll::Ready(Err(error)),
        };
        this.write_buffer.reserve(4 + data_len + padding);
        this.write_buffer
            .extend_from_slice(&(data_len as u16).to_be_bytes());
        this.write_buffer
            .extend_from_slice(&(padding as u16).to_be_bytes());
        this.write_buffer.extend_from_slice(&input[..data_len]);
        this.write_buffer.resize(4 + data_len + padding, 0);
        this.write_frames += 1;
        // A single bounded frame is now owned by this stream. Returning the
        // accepted length even if the carrier blocks prevents cancelled writes
        // from replaying a partially transmitted header or payload.
        // Once accepted, report the payload length even if the carrier fails
        // during this poll: the peer may already have received the payload.
        // poll_drain records the error for the next write, flush, or shutdown.
        let _ = this.poll_drain(cx, DrainSide::Writer);
        this.drain_wake.clear(DrainSide::Writer);
        Poll::Ready(Ok(data_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx, DrainSide::Writer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx, DrainSide::Writer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::timeout;

    #[tokio::test]
    async fn reads_fragmented_headers_payloads_and_padding_before_raw_data() {
        let (client, mut peer) = duplex(31);
        let mut stream = PaddingStream::new(client);
        let writer = tokio::spawn(async move {
            for frame in 0..PADDED_FRAMES {
                let data = if frame == 4 {
                    Vec::new()
                } else {
                    vec![frame; 17]
                };
                let padding = if frame == 7 { u16::MAX } else { 9 };
                let mut record = Vec::new();
                record.extend_from_slice(&(data.len() as u16).to_be_bytes());
                record.extend_from_slice(&padding.to_be_bytes());
                record.extend_from_slice(&data);
                record.resize(record.len() + usize::from(padding), 0x9a);
                for chunk in record.chunks(7) {
                    peer.write_all(chunk).await.unwrap();
                }
            }
            peer.write_all(b"raw-after-sixteen").await.unwrap();
            peer.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        timeout(Duration::from_secs(10), stream.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        let mut expected = Vec::new();
        for frame in 0..PADDED_FRAMES {
            if frame != 4 {
                expected.extend_from_slice(&[frame; 17]);
            }
        }
        expected.extend_from_slice(b"raw-after-sixteen");
        assert_eq!(received, expected);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_reads_preserve_partial_header_payload_and_padding() {
        let (client, mut peer) = duplex(32);
        let mut stream = PaddingStream::new(client);
        let mut output = [0; 8];
        peer.write_all(&[0, 4]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(10), stream.read(&mut output))
                .await
                .is_err()
        );
        peer.write_all(&[0, 3, b'a', b'b']).await.unwrap();
        assert_eq!(stream.read(&mut output).await.unwrap(), 2);
        assert_eq!(&output[..2], b"ab");
        assert!(
            timeout(Duration::from_millis(10), stream.read(&mut output))
                .await
                .is_err()
        );
        peer.write_all(b"cdx").await.unwrap();
        assert_eq!(stream.read(&mut output).await.unwrap(), 2);
        assert_eq!(&output[..2], b"cd");
        assert!(
            timeout(Duration::from_millis(10), stream.read(&mut output))
                .await
                .is_err()
        );
        peer.write_all(&[0, 0, 0, 1, 0, 0, b'z']).await.unwrap();
        assert_eq!(stream.read(&mut output).await.unwrap(), 1);
        assert_eq!(output[0], b'z');
    }

    #[tokio::test]
    async fn truncated_frame_reports_unexpected_eof() {
        for input in [&[0_u8][..], &[0, 2, 0, 0, 1][..], &[0, 0, 0, 2, 1][..]] {
            let (client, mut peer) = duplex(32);
            peer.write_all(input).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut stream = PaddingStream::new(client);
            let mut output = Vec::new();
            let error = stream.read_to_end(&mut output).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[tokio::test]
    async fn writes_sixteen_bounded_records_then_unframed_data() {
        let (client, mut peer) = duplex(31);
        let writer = tokio::spawn(async move {
            let mut stream = PaddingStream::new(client);
            for frame in 0..PADDED_FRAMES {
                stream.write_all(&[frame; 17]).await.unwrap();
                stream.flush().await.unwrap();
            }
            stream.write_all(b"raw-after-sixteen").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        for frame in 0..PADDED_FRAMES {
            let mut header = [0; 4];
            peer.read_exact(&mut header).await.unwrap();
            let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let padding = usize::from(u16::from_be_bytes([header[2], header[3]]));
            assert_eq!(length, 17);
            assert!((256..=767).contains(&padding));
            let mut data = vec![0; length + padding];
            peer.read_exact(&mut data).await.unwrap();
            assert_eq!(&data[..length], &[frame; 17]);
        }
        let mut tail = Vec::new();
        peer.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"raw-after-sixteen");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_flush_retains_a_single_bounded_pending_frame() {
        let (client, mut peer) = duplex(8);
        let mut stream = PaddingStream::new(client);
        let payload = vec![0x42; MAX_DATA + 1];
        assert_eq!(stream.write(&payload).await.unwrap(), MAX_DATA);
        assert!(stream.write_buffer.len() <= 4 + MAX_DATA + 767);
        assert!(
            timeout(Duration::from_millis(10), stream.flush())
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(10), stream.write(b"next"))
                .await
                .is_err()
        );
        let reader = tokio::spawn(async move {
            let mut header = [0; 4];
            peer.read_exact(&mut header).await.unwrap();
            let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let padding = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let mut data = vec![0; length + padding];
            peer.read_exact(&mut data).await.unwrap();
            assert_eq!(&data[..length], &vec![0x42; MAX_DATA]);
            peer.read_exact(&mut header).await.unwrap();
            let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let padding = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let mut data = vec![0; length + padding];
            peer.read_exact(&mut data).await.unwrap();
            assert_eq!(&data[..length], b"next");
        });
        stream.write_all(b"next").await.unwrap();
        stream.flush().await.unwrap();
        reader.await.unwrap();
    }

    #[tokio::test]
    async fn read_after_a_buffered_write_drives_the_pending_record() {
        let (client, mut peer) = duplex(8);
        let mut stream = PaddingStream::new(client);
        let server = tokio::spawn(async move {
            let mut header = [0; 4];
            peer.read_exact(&mut header).await.unwrap();
            let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let padding = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let mut data = vec![0; length + padding];
            peer.read_exact(&mut data).await.unwrap();
            assert_eq!(&data[..length], &[0x42; 64]);
            peer.write_all(&[0, 1, 0, 0, b'!']).await.unwrap();
        });
        stream.write_all(&[0x42; 64]).await.unwrap();
        let mut reply = [0; 1];
        timeout(Duration::from_secs(1), stream.read_exact(&mut reply))
            .await
            .expect("read must continue driving the buffered write")
            .unwrap();
        assert_eq!(reply, [b'!']);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn split_reader_and_writer_both_wake_when_the_carrier_can_write() {
        #[derive(Default)]
        struct Gate {
            open: bool,
            polls: usize,
            writer: Option<Waker>,
            sent: Vec<u8>,
        }
        struct Carrier(Arc<Mutex<Gate>>);

        impl AsyncRead for Carrier {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

        impl AsyncWrite for Carrier {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                let mut gate = self.0.lock().unwrap();
                if gate.open {
                    gate.sent.extend_from_slice(bytes);
                    Poll::Ready(Ok(bytes.len()))
                } else {
                    gate.polls += 1;
                    // Match sockets that retain only the latest write waker.
                    gate.writer = Some(cx.waker().clone());
                    Poll::Pending
                }
            }

            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        async fn wait_for_polls(gate: &Mutex<Gate>, count: usize) {
            timeout(Duration::from_secs(2), async {
                while gate.lock().unwrap().polls < count {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }

        let gate = Arc::new(Mutex::new(Gate::default()));
        let (mut reader, mut writer) = tokio::io::split(PaddingStream::new(Carrier(gate.clone())));
        writer.write_all(b"x").await.unwrap();
        let writer = tokio::spawn(async move { writer.flush().await });
        wait_for_polls(&gate, 2).await;
        let reader = tokio::spawn(async move { reader.read(&mut [0; 1]).await });
        wait_for_polls(&gate, 3).await;
        let wake = {
            let mut gate = gate.lock().unwrap();
            gate.open = true;
            gate.writer.take().unwrap()
        };
        wake.wake();
        timeout(Duration::from_secs(2), writer)
            .await
            .expect("writer must be woken when the reader drives the frame")
            .unwrap()
            .unwrap();
        let gate = gate.lock().unwrap();
        let padding = usize::from(u16::from_be_bytes([gate.sent[2], gate.sent[3]]));
        assert_eq!(gate.sent.len(), 5 + padding);
        drop(gate);
        reader.abort();
    }

    #[tokio::test]
    async fn accepted_payload_and_read_direction_survive_a_padding_write_failure() {
        struct FailingCarrier {
            sent: Vec<u8>,
            response_pos: usize,
        }

        impl AsyncRead for FailingCarrier {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                output: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let response = [0, 1, 0, 0, b'!'];
                let length = output.remaining().min(response.len() - self.response_pos);
                output.put_slice(&response[self.response_pos..self.response_pos + length]);
                self.response_pos += length;
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for FailingCarrier {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.sent.is_empty() {
                    let count = bytes.len().min(5);
                    self.sent.extend_from_slice(&bytes[..count]);
                    Poll::Ready(Ok(count))
                } else {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
                }
            }

            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let mut stream = PaddingStream::new(FailingCarrier {
            sent: Vec::new(),
            response_pos: 0,
        });
        assert_eq!(stream.write(b"a").await.unwrap(), 1);
        assert_eq!(&stream.inner.sent[4..], b"a");
        let mut response = [0; 1];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [b'!']);
        assert!(stream.flush().await.is_err());
        assert!(stream.write(b"b").await.is_err());
    }
}
