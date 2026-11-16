//! One bounded V2Ray mux stream over the v2ray-plugin WebSocket connection.

use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxedTransitConnection;

const MAX_METADATA: usize = 512;
const MAX_WRITE: usize = 16 * 1024;

#[derive(Clone, Copy)]
enum Phase {
    Length,
    Metadata,
    PayloadLength { discard: bool },
    Payload { discard: bool },
    Ready,
    Ended,
    Failed,
}

pub(super) struct MuxStream {
    inner: BoxedTransitConnection,
    started: bool,
    write_closed: bool,
    ending: bool,
    write_failed: bool,
    write_buf: Vec<u8>,
    write_pos: usize,
    phase: Phase,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl MuxStream {
    pub(super) fn new(inner: BoxedTransitConnection) -> Self {
        Self {
            inner,
            started: false,
            write_closed: false,
            ending: false,
            write_failed: false,
            write_buf: Vec::new(),
            write_pos: 0,
            phase: Phase::Length,
            read_buf: vec![0; 2],
            read_pos: 0,
        }
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_failed {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "v2ray-plugin mux write failed",
            )));
        }
        while self.write_pos < self.write_buf.len() {
            match std::task::ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..])
            ) {
                Ok(0) => {
                    self.write_failed = true;
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "v2ray-plugin mux write failed",
                    )));
                }
                Ok(size) => self.write_pos += size,
                Err(error) => {
                    self.write_failed = true;
                    return Poll::Ready(Err(error));
                }
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn reset_read(&mut self, phase: Phase, size: usize) {
        self.phase = phase;
        self.read_buf = vec![0; size];
        self.read_pos = 0;
    }

    fn frame(&mut self, data: &[u8]) {
        if self.started {
            self.write_buf.extend_from_slice(&[0, 4, 0, 0, 2, 1]);
        } else {
            // The plugin server forwards this logical stream to its fixed
            // Shadowsocks backend, regardless of the mux destination.
            self.write_buf
                .extend_from_slice(&[0, 20, 0, 0, 1, 1, 1, 2, 154, 2, 11]);
            self.write_buf.extend_from_slice(b"v1.mux.cool");
            self.started = true;
        }
        self.write_buf
            .extend_from_slice(&(data.len() as u16).to_be_bytes());
        self.write_buf.extend_from_slice(data);
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed || self.ending {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "v2ray-plugin mux is closed",
            )));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.poll_pending(cx))?;
        let length = data.len().min(MAX_WRITE);
        self.frame(&data[..length]);
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_pending(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        if !self.ending {
            std::task::ready!(self.poll_pending(cx))?;
            if self.started {
                self.write_buf.extend_from_slice(&[0, 4, 0, 0, 3, 0]);
            }
            self.ending = true;
        }
        std::task::ready!(self.poll_pending(cx))?;
        std::task::ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        self.write_closed = true;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(self.poll_pending(cx))?;
        let this = self.as_mut().get_mut();
        let mut controls = 0;
        loop {
            match this.phase {
                Phase::Ended => return Poll::Ready(Ok(())),
                Phase::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "v2ray-plugin mux has failed",
                    )));
                }
                Phase::Ready => {
                    let size = out.remaining().min(this.read_buf.len() - this.read_pos);
                    out.put_slice(&this.read_buf[this.read_pos..this.read_pos + size]);
                    this.read_pos += size;
                    if this.read_pos == this.read_buf.len() {
                        this.reset_read(Phase::Length, 2);
                    }
                    return Poll::Ready(Ok(()));
                }
                _ => {}
            }
            while this.read_pos < this.read_buf.len() {
                let mut read = ReadBuf::new(&mut this.read_buf[this.read_pos..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        this.phase = Phase::Failed;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) if read.filled().is_empty() => {
                        if this.read_pos == 0 && matches!(this.phase, Phase::Length) {
                            this.phase = Phase::Ended;
                            return Poll::Ready(Ok(()));
                        }
                        this.phase = Phase::Failed;
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "truncated v2ray-plugin mux frame",
                        )));
                    }
                    Poll::Ready(Ok(())) => this.read_pos += read.filled().len(),
                }
            }
            let phase = this.phase;
            this.phase = Phase::Failed;
            match phase {
                Phase::Length => {
                    let length =
                        usize::from(u16::from_be_bytes([this.read_buf[0], this.read_buf[1]]));
                    if !(4..=MAX_METADATA).contains(&length) {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "invalid v2ray-plugin mux metadata",
                        )));
                    }
                    this.reset_read(Phase::Metadata, length);
                }
                Phase::Metadata => {
                    let metadata = &this.read_buf;
                    let status = metadata[2];
                    let options = metadata[3];
                    if (status != 4 && metadata[..2] != [0, 0])
                        || options & !3 != 0
                        || options & 2 != 0
                    {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "invalid v2ray-plugin mux response",
                        )));
                    }
                    match status {
                        2 | 4 if options & 1 != 0 => this.reset_read(
                            Phase::PayloadLength {
                                discard: status == 4,
                            },
                            2,
                        ),
                        2 | 4 => {
                            this.reset_read(Phase::Length, 2);
                            controls += 1;
                        }
                        3 if options == 0 => this.phase = Phase::Ended,
                        _ => {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "unexpected v2ray-plugin mux status",
                            )));
                        }
                    }
                }
                Phase::PayloadLength { discard } => {
                    let length =
                        usize::from(u16::from_be_bytes([this.read_buf[0], this.read_buf[1]]));
                    this.reset_read(Phase::Payload { discard }, length);
                }
                Phase::Payload { discard } => {
                    if discard || this.read_buf.is_empty() {
                        this.reset_read(Phase::Length, 2);
                        controls += 1;
                    } else {
                        this.phase = Phase::Ready;
                        this.read_pos = 0;
                    }
                }
                _ => unreachable!(),
            }
            if controls >= 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    #[tokio::test]
    async fn fragmented_frames_and_cancelled_short_write_preserve_payload() {
        timeout(Duration::from_secs(5), async {
            let (local, mut peer) = tokio::io::duplex(1);
            let mut stream = MuxStream::new(Box::new(local));
            stream.write_all(b"A").await.unwrap();
            assert!(
                timeout(Duration::from_millis(20), stream.write(b"B"))
                    .await
                    .is_err()
            );
            let task = tokio::spawn(async move {
                let mut first = vec![0; 25];
                peer.read_exact(&mut first).await.unwrap();
                assert_eq!(&first[..11], &[0, 20, 0, 0, 1, 1, 1, 2, 154, 2, 11]);
                assert_eq!(&first[11..22], b"v1.mux.cool");
                assert_eq!(&first[22..], &[0, 1, b'A']);
                let mut second = [0; 9];
                peer.read_exact(&mut second).await.unwrap();
                assert_eq!(&second, &[0, 4, 0, 0, 2, 1, 0, 1, b'B']);
                let mut end = [0; 6];
                peer.read_exact(&mut end).await.unwrap();
                assert_eq!(&end, &[0, 4, 0, 0, 3, 0]);
                peer.write_all(&[0, 4, 0, 0, 4, 0]).await.unwrap();
                peer.write_all(&[0, 4, 0, 0, 2, 1, 0, 5]).await.unwrap();
                peer.write_all(b"reply").await.unwrap();
                peer.write_all(&[0, 4, 0, 0, 3, 0]).await.unwrap();
            });
            stream.write_all(b"B").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut result = Vec::new();
            stream.read_to_end(&mut result).await.unwrap();
            assert_eq!(result, b"reply");
            task.await.unwrap();
        })
        .await
        .expect("fragmented v2ray-plugin mux exchange timed out");
    }

    #[tokio::test]
    async fn malformed_response_and_remote_error_are_terminal() {
        for reply in [
            vec![0, 3],
            vec![0, 4, 0, 1, 2, 0],
            vec![0, 4, 0, 0, 1, 0],
            vec![0, 4, 0, 0, 2, 0x80],
            vec![0, 4, 0, 0, 3, 2],
        ] {
            let (local, mut peer) = tokio::io::duplex(256);
            let mut stream = MuxStream::new(Box::new(local));
            peer.write_all(&reply).await.unwrap();
            let mut out = [0; 32];
            assert_eq!(
                stream.read(&mut out).await.unwrap_err().kind(),
                ErrorKind::InvalidData
            );
            assert_eq!(
                stream.read(&mut out).await.unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn truncated_frame_returns_unexpected_eof_and_never_plaintext() {
        let (local, mut peer) = tokio::io::duplex(256);
        let mut stream = MuxStream::new(Box::new(local));
        peer.write_all(&[0, 4, 0]).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut out = [0; 8];
        assert_eq!(
            stream.read(&mut out).await.unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
        assert_eq!(
            stream.read(&mut out).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }
}
