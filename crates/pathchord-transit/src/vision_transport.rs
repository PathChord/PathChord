//! TLS transport that can hand each direction to Vision DIRECT.
//!
//! Install `RecordLimitedIo` before the TLS handshake.  Every TLS read made
//! after the handshake must go through `VisionTlsIo`, including the VLESS
//! response header.  The Vision decoder sets `direct` only after consuming the
//! complete DIRECT frame and its padding.

use std::io::{self, Read};
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;

use crate::BoxedTransitConnection;

/// Receive and send handoffs are independent within one Vision connection.
#[derive(Default)]
pub(crate) struct VisionSwitch {
    pub(crate) read_direct: AtomicBool,
    pub(crate) write_direct: AtomicBool,
}

/// Limit reads supplied to rustls to one TLS record, starting at handshake.
///
/// Without this bound, a TCP read can put the following DIRECT bytes in the
/// rustls deframer, where they are no longer available as raw stream bytes.
pub(crate) struct RecordLimitedIo {
    inner: BoxedTransitConnection,
    header: [u8; 5],
    header_len: usize,
    body_remaining: usize,
    block_tls_writes: bool,
}

impl RecordLimitedIo {
    pub(crate) fn new(inner: BoxedTransitConnection) -> Self {
        Self {
            inner,
            header: [0; 5],
            header_len: 0,
            body_remaining: 0,
            block_tls_writes: false,
        }
    }

    fn at_record_boundary(&self) -> bool {
        self.header_len == 0
    }
}

impl AsyncRead for RecordLimitedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let in_header = this.header_len < this.header.len();
        let remaining = if in_header {
            this.header.len() - this.header_len
        } else {
            this.body_remaining
        };
        debug_assert!(remaining > 0);
        let limit = remaining.min(output.remaining());
        let count = {
            let mut limited = ReadBuf::new(output.initialize_unfilled_to(limit));
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
            let bytes = limited.filled();
            if in_header {
                let end = this.header_len + bytes.len();
                this.header[this.header_len..end].copy_from_slice(bytes);
                this.header_len = end;
            } else {
                this.body_remaining -= bytes.len();
            }
            bytes.len()
        };
        output.advance(count);
        if in_header && this.header_len == this.header.len() {
            this.body_remaining = usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
        }
        if this.header_len == this.header.len() && this.body_remaining == 0 {
            this.header_len = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordLimitedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.block_tls_writes {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "outer TLS writes are disabled after Vision DIRECT",
            )));
        }
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShutdownState {
    Open,
    Flush,
    Tls,
    Raw,
    Done,
}

/// Preserves rustls while switching either direction to raw I/O.
pub(crate) struct VisionTlsIo {
    tls: TlsStream<RecordLimitedIo>,
    direct: Arc<VisionSwitch>,
    shutdown: ShutdownState,
}

impl VisionTlsIo {
    pub(crate) fn new(tls: TlsStream<RecordLimitedIo>, direct: Arc<VisionSwitch>) -> Self {
        Self {
            tls,
            direct,
            shutdown: ShutdownState::Open,
        }
    }
}

impl AsyncRead for VisionTlsIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.direct.write_direct.load(Ordering::Acquire) {
            // rustls can attempt an alert write while processing an invalid
            // inbound record. Never emit outer TLS after the uplink handoff.
            this.tls.get_mut().0.block_tls_writes = true;
        }
        if this.direct.read_direct.load(Ordering::Acquire) {
            // Drain only already decrypted data: calling poll_fill_buf here
            // would ask rustls to consume the following raw TCP bytes.
            match this
                .tls
                .get_mut()
                .1
                .reader()
                .read(output.initialize_unfilled())
            {
                Ok(count) if count > 0 => {
                    output.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            let io = this.tls.get_mut().0;
            if !io.at_record_boundary() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Vision DIRECT started inside an outer TLS record",
                )));
            }
            return Pin::new(&mut io.inner).poll_read(cx, output);
        }

        // `TlsStream::poll_read` batches calls to poll_fill_buf and can read
        // past the DIRECT frame. Return at most one plaintext chunk per poll.
        let plaintext = ready!(Pin::new(&mut this.tls).poll_fill_buf(cx))?;
        let count = plaintext.len().min(output.remaining());
        output.put_slice(&plaintext[..count]);
        Pin::new(&mut this.tls).consume(count);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VisionTlsIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown != ShutdownState::Open {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.direct.write_direct.load(Ordering::Acquire) {
            let io = this.tls.get_mut().0;
            io.block_tls_writes = true;
            Pin::new(&mut io.inner).poll_write(cx, bytes)
        } else {
            Pin::new(&mut this.tls).poll_write(cx, bytes)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown == ShutdownState::Done {
            return Poll::Ready(Ok(()));
        }
        if this.direct.write_direct.load(Ordering::Acquire) {
            let io = this.tls.get_mut().0;
            io.block_tls_writes = true;
            return Pin::new(&mut io.inner).poll_flush(cx);
        }
        if this.shutdown == ShutdownState::Raw
            || (this.shutdown == ShutdownState::Tls
                && this.direct.read_direct.load(Ordering::Acquire))
        {
            return Pin::new(&mut this.tls.get_mut().0.inner).poll_flush(cx);
        }
        Pin::new(&mut this.tls).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.shutdown {
                ShutdownState::Open => this.shutdown = ShutdownState::Flush,
                ShutdownState::Flush => {
                    // Flush application data before deciding whether TLS may
                    // send close_notify. This also makes a later transition
                    // during a pending shutdown unable to lose application data.
                    if this.direct.write_direct.load(Ordering::Acquire) {
                        let io = this.tls.get_mut().0;
                        io.block_tls_writes = true;
                        ready!(Pin::new(&mut io.inner).poll_flush(cx))?;
                    } else {
                        ready!(Pin::new(&mut this.tls).poll_flush(cx))?;
                    }
                    this.shutdown = if this.direct.read_direct.load(Ordering::Acquire)
                        || this.direct.write_direct.load(Ordering::Acquire)
                    {
                        ShutdownState::Raw
                    } else {
                        ShutdownState::Tls
                    };
                }
                ShutdownState::Tls => {
                    if this.direct.read_direct.load(Ordering::Acquire)
                        || this.direct.write_direct.load(Ordering::Acquire)
                    {
                        // If a preceding poll already started TLS shutdown,
                        // never resume its queued close_notify after DIRECT.
                        this.shutdown = ShutdownState::Raw;
                        continue;
                    }
                    ready!(Pin::new(&mut this.tls).poll_shutdown(cx))?;
                    this.shutdown = ShutdownState::Done;
                }
                ShutdownState::Raw => {
                    let io = this.tls.get_mut().0;
                    ready!(Pin::new(&mut io.inner).poll_shutdown(cx))?;
                    this.shutdown = ShutdownState::Done;
                }
                ShutdownState::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    struct FragmentIo {
        inner: DuplexStream,
        maximum_read: usize,
        block_writes: Arc<AtomicBool>,
    }

    impl AsyncRead for FragmentIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let limit = output.remaining().min(this.maximum_read);
            let count = {
                let mut limited = ReadBuf::new(output.initialize_unfilled_to(limit));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
                limited.filled().len()
            };
            output.advance(count);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FragmentIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.block_writes.load(Ordering::Acquire) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    async fn pair(
        maximum_read: usize,
    ) -> (
        VisionTlsIo,
        tokio_rustls::server::TlsStream<DuplexStream>,
        Arc<VisionSwitch>,
    ) {
        pair_with_gate(maximum_read, Arc::new(AtomicBool::new(false))).await
    }

    async fn pair_with_gate(
        maximum_read: usize,
        block_writes: Arc<AtomicBool>,
    ) -> (
        VisionTlsIo,
        tokio_rustls::server::TlsStream<DuplexStream>,
        Arc<VisionSwitch>,
    ) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (client_io, server_io) = duplex(131_072);
        let server = tokio::spawn(async move {
            TlsAcceptor::from(Arc::new(server))
                .accept(server_io)
                .await
                .unwrap()
        });
        let guarded = RecordLimitedIo::new(Box::new(FragmentIo {
            inner: client_io,
            maximum_read,
            block_writes,
        }));
        let tls = TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from("proxy.test").unwrap(), guarded)
            .await
            .unwrap();
        let direct = Arc::new(VisionSwitch::default());
        (
            VisionTlsIo::new(tls, Arc::clone(&direct)),
            server.await.unwrap(),
            direct,
        )
    }

    #[tokio::test]
    async fn limits_each_read_to_one_record_even_for_coalesced_input() {
        let (client, mut peer) = duplex(128);
        let mut io = RecordLimitedIo::new(Box::new(client));
        let records = [
            23, 3, 3, 0, 3, b'a', b'b', b'c', 22, 3, 3, 0, 0, 23, 3, 3, 0, 1, b'd',
        ];
        peer.write_all(&records).await.unwrap();
        let mut output = [0; 128];
        for expected in [
            &records[0..5],
            &records[5..8],
            &records[8..13],
            &records[13..18],
            &records[18..19],
        ] {
            let count = io.read(&mut output).await.unwrap();
            assert_eq!(&output[..count], expected);
        }
        assert!(io.at_record_boundary());
    }

    #[tokio::test]
    async fn direct_preserves_tls_plaintext_and_coalesced_raw_bytes() {
        for maximum_read in [1, 131_072] {
            let (mut client, mut server, direct) = pair(maximum_read).await;
            // A single TLS record includes the marker and additional
            // plaintext; a TLS-looking raw record immediately follows it.
            let raw = [
                0x17, 0x03, 0x03, 0, 20, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            ];
            server.write_all(b"markerTAIL").await.unwrap();
            server.flush().await.unwrap();
            server.get_mut().0.write_all(&raw).await.unwrap();
            let mut marker = [0; 6];
            client.read_exact(&mut marker).await.unwrap();
            assert_eq!(&marker, b"marker");
            direct.read_direct.store(true, Ordering::Release);
            let mut rest = vec![0; 4 + raw.len()];
            client.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest[..4], b"TAIL");
            assert_eq!(&rest[4..], raw);
        }
    }

    #[tokio::test]
    async fn direct_read_keeps_uplink_encrypted_and_suppresses_close_notify() {
        let (mut client, mut server, direct) = pair(131_072).await;
        server.write_all(b"marker").await.unwrap();
        server.flush().await.unwrap();
        let mut marker = [0; 6];
        client.read_exact(&mut marker).await.unwrap();
        direct.read_direct.store(true, Ordering::Release);
        client.write_all(b"uplink").await.unwrap();
        client.shutdown().await.unwrap();
        assert!(matches!(
            client.write_all(b"after shutdown").await,
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe
        ));

        let mut request = [0; 6];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"uplink");
        let mut next = [0; 1];
        assert!(matches!(
            server.read(&mut next).await,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        // A write half-close must not prevent reading the raw downlink.
        server.get_mut().0.write_all(b"downlink").await.unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"downlink");
    }

    #[tokio::test]
    async fn normal_tls_shutdown_sends_close_notify() {
        let (mut client, mut server, _) = pair(131_072).await;
        client.write_all(b"uplink").await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"uplink");
    }

    #[tokio::test]
    async fn direct_write_keeps_downlink_encrypted_and_half_closes_raw_socket() {
        let (mut client, mut server, direct) = pair(131_072).await;
        client.write_all(b"tls-marker").await.unwrap();
        client.flush().await.unwrap();
        let mut marker = [0; 10];
        server.read_exact(&mut marker).await.unwrap();
        assert_eq!(&marker, b"tls-marker");

        direct.write_direct.store(true, Ordering::Release);
        client.write_all(b"raw-uplink").await.unwrap();
        client.flush().await.unwrap();
        let mut raw = [0; 10];
        server.get_mut().0.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw-uplink");

        server.write_all(b"tls-downlink").await.unwrap();
        server.flush().await.unwrap();
        let mut response = [0; 12];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"tls-downlink");

        client.shutdown().await.unwrap();
        let mut next = [0; 1];
        assert_eq!(server.get_mut().0.read(&mut next).await.unwrap(), 0);
        server.write_all(b"after-fin").await.unwrap();
        server.flush().await.unwrap();
        let mut after_fin = [0; 9];
        client.read_exact(&mut after_fin).await.unwrap();
        assert_eq!(&after_fin, b"after-fin");
    }

    #[tokio::test]
    async fn direct_write_blocks_outer_tls_alerts_after_invalid_downlink() {
        let (mut client, mut server, direct) = pair(131_072).await;
        direct.write_direct.store(true, Ordering::Release);
        server
            .get_mut()
            .0
            .write_all(&[0x17, 0x03, 0x03, 0, 1, 0xff])
            .await
            .unwrap();
        assert!(client.read(&mut [0; 1]).await.is_err());
        drop(client);
        let mut remaining = Vec::new();
        server
            .get_mut()
            .0
            .read_to_end(&mut remaining)
            .await
            .unwrap();
        assert!(remaining.is_empty(), "outer TLS alert leaked after DIRECT");
    }

    #[tokio::test]
    async fn direct_during_pending_shutdown_flushes_uplink_without_close_notify() {
        use std::{future::Future, task::Waker};

        let blocked = Arc::new(AtomicBool::new(false));
        let (mut client, mut server, direct) = pair_with_gate(131_072, Arc::clone(&blocked)).await;
        blocked.store(true, Ordering::Release);
        client.write_all(b"uplink").await.unwrap();
        {
            let mut shutdown = std::pin::pin!(client.shutdown());
            let mut context = Context::from_waker(Waker::noop());
            assert!(shutdown.as_mut().poll(&mut context).is_pending());
            direct.read_direct.store(true, Ordering::Release);
            blocked.store(false, Ordering::Release);
            shutdown.await.unwrap();
        }
        let mut request = [0; 6];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"uplink");
        let mut next = [0; 1];
        assert!(matches!(
            server.read(&mut next).await,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[tokio::test]
    async fn direct_rejects_a_partially_consumed_outer_record() {
        let (mut client, _server, direct) = pair(131_072).await;
        client.tls.get_mut().0.header_len = 1;
        direct.read_direct.store(true, Ordering::Release);
        let mut output = [0; 1];
        assert!(matches!(
            client.read(&mut output).await,
            Err(error) if error.kind() == io::ErrorKind::InvalidData
        ));
    }
}
