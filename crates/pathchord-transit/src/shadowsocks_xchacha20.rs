//! Shadowsocks legacy XChaCha20, absent from shadowsocks-rust's cipher registry.

use std::fmt;
use std::io::{self, Cursor, ErrorKind};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use shadowsocks::relay::socks5::Address;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::{
    BoxedTransitConnection, BoxedTransitDatagram, Endpoint, TransitDatagram, TransitError,
};

use super::Plugin;
use super::shadowsocks_legacy_common::{
    MAX_PACKET, NONCE_LEN, Salts, SharedSalts, connection, fresh_salt, master_key,
    matches_destination, protocol, remember, target_address,
};

const KEY_LEN: usize = 32;
const MAX_WRITE: usize = 16 * 1024;

fn cipher(key: &[u8; KEY_LEN], iv: &[u8; NONCE_LEN]) -> io::Result<XChaCha20> {
    XChaCha20::new_from_slices(key, iv)
        .map_err(|_| io::Error::other("Shadowsocks key or IV is invalid"))
}

fn crypt(cipher: &mut XChaCha20, data: &mut [u8]) -> io::Result<()> {
    cipher
        .try_apply_keystream(data)
        .map_err(|_| io::Error::other("Shadowsocks stream cipher exhausted"))
}

#[derive(Clone)]
pub(super) struct Config {
    server: Endpoint,
    key: Zeroizing<[u8; KEY_LEN]>,
    ivs: SharedSalts,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XChaCha20Config").finish_non_exhaustive()
    }
}

impl Config {
    pub(super) fn new(server: Endpoint, password: &str) -> Self {
        Self {
            server,
            key: master_key(password.as_bytes()),
            ivs: Arc::new(Mutex::new(Salts::default())),
        }
    }

    pub(super) async fn connect(
        &self,
        destination: Endpoint,
        plugin: Option<&Plugin>,
        connect_timeout: Duration,
    ) -> Result<BoxedTransitConnection, TransitError> {
        timeout(connect_timeout, async {
            let raw = crate::connect_tcp_endpoint(&self.server, connect_timeout).await?;
            let inner: BoxedTransitConnection = match plugin {
                Some(plugin) => plugin.wrap(Box::new(raw), connect_timeout).await?,
                None => Box::new(raw),
            };
            let iv = fresh_salt(&self.ivs).map_err(|_| connection())?;
            let mut stream = Stream::new(inner, self.key.clone(), self.ivs.clone(), iv)
                .map_err(|_| connection())?;
            let mut address = Vec::new();
            target_address(&destination).write_to_buf(&mut address);
            stream.write_all(&address).await.map_err(|_| connection())?;
            stream.flush().await.map_err(|_| connection())?;
            Ok::<BoxedTransitConnection, TransitError>(Box::new(stream))
        })
        .await
        .map_err(|_| TransitError::Connection("Shadowsocks connection timed out".into()))?
    }

    pub(super) async fn connect_udp(
        &self,
        destination: Endpoint,
        connect_timeout: Duration,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        crate::validate_destination(&destination)?;
        let socket = timeout(connect_timeout, async {
            let addresses = lookup_host((self.server.host.as_str(), self.server.port)).await?;
            for address in addresses {
                let bind = if address.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                if let Ok(socket) = UdpSocket::bind(bind).await
                    && socket.connect(address).await.is_ok()
                {
                    return Ok(socket);
                }
            }
            Err(io::Error::other("Shadowsocks UDP connect failed"))
        })
        .await
        .map_err(|_| TransitError::Connection("Shadowsocks UDP connection timed out".into()))?
        .map_err(|_| connection())?;
        Ok(Box::new(Datagram {
            socket,
            config: self.clone(),
            destination,
        }))
    }
}

#[derive(Debug)]
struct Datagram {
    socket: UdpSocket,
    config: Config,
    destination: Endpoint,
}

#[async_trait]
impl TransitDatagram for Datagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        let target = target_address(&self.destination);
        if payload
            .len()
            .saturating_add(NONCE_LEN + target.serialized_len())
            > MAX_PACKET
        {
            return Err(TransitError::Unsupported(
                "UDP datagram exceeds the transport limit".into(),
            ));
        }
        let iv = fresh_salt(&self.config.ivs).map_err(|_| connection())?;
        let mut cipher = cipher(&self.config.key, &iv).map_err(|_| connection())?;
        let mut packet = Vec::with_capacity(NONCE_LEN + target.serialized_len() + payload.len());
        packet.extend_from_slice(&iv);
        target.write_to_buf(&mut packet);
        packet.extend_from_slice(payload);
        crypt(&mut cipher, &mut packet[NONCE_LEN..]).map_err(|_| connection())?;
        self.socket.send(&packet).await.map_err(|_| connection())?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        let mut packet = vec![0; 65_536];
        let size = self
            .socket
            .recv(&mut packet)
            .await
            .map_err(|_| connection())?;
        if size <= NONCE_LEN {
            return Err(protocol("Shadowsocks UDP response is truncated"));
        }
        let iv: [u8; NONCE_LEN] = packet[..NONCE_LEN].try_into().expect("checked IV length");
        let mut cipher = cipher(&self.config.key, &iv).map_err(|_| connection())?;
        crypt(&mut cipher, &mut packet[NONCE_LEN..size])
            .map_err(|_| protocol("Shadowsocks UDP response decryption failed"))?;
        let body = &packet[NONCE_LEN..size];
        let mut reader = Cursor::new(body);
        let source = Address::read_cursor(&mut reader)
            .map_err(|_| protocol("Shadowsocks UDP response address is invalid"))?;
        if !matches_destination(&self.destination, &source) {
            return Err(protocol(
                "Shadowsocks UDP response source does not match its target",
            ));
        }
        if !remember(&self.config.ivs, iv) {
            return Err(protocol("Shadowsocks UDP response IV was replayed"));
        }
        Ok(body[reader.position() as usize..].to_vec())
    }
}

struct Stream {
    inner: BoxedTransitConnection,
    key: Option<Zeroizing<[u8; KEY_LEN]>>,
    ivs: SharedSalts,
    outgoing: XChaCha20,
    incoming: Option<XChaCha20>,
    incoming_iv: [u8; NONCE_LEN],
    incoming_pos: usize,
    read_failed: bool,
    write_buf: Vec<u8>,
    write_pos: usize,
    write_failed: bool,
}

impl Stream {
    fn new(
        inner: BoxedTransitConnection,
        key: Zeroizing<[u8; KEY_LEN]>,
        ivs: SharedSalts,
        iv: [u8; NONCE_LEN],
    ) -> io::Result<Self> {
        let outgoing = cipher(&key, &iv)?;
        Ok(Self {
            inner,
            key: Some(key),
            ivs,
            outgoing,
            incoming: None,
            incoming_iv: [0; NONCE_LEN],
            incoming_pos: 0,
            read_failed: false,
            write_buf: iv.to_vec(),
            write_pos: 0,
            write_failed: false,
        })
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_failed {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "Shadowsocks stream has failed",
            )));
        }
        while self.write_pos < self.write_buf.len() {
            let result = std::task::ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..])
            );
            match result {
                Ok(0) => {
                    self.write_failed = true;
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "Shadowsocks write failed",
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
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.poll_pending(cx))?;
        let length = data.len().min(MAX_WRITE);
        let mut payload = data[..length].to_vec();
        if let Err(error) = crypt(&mut self.outgoing, &mut payload) {
            self.write_failed = true;
            return Poll::Ready(Err(error));
        }
        self.write_buf = payload;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_pending(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_pending(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for Stream {
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
        if this.read_failed {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::InvalidData,
                "Shadowsocks stream has failed",
            )));
        }
        if this.incoming.is_none() {
            while this.incoming_pos < NONCE_LEN {
                let mut buf = ReadBuf::new(&mut this.incoming_iv[this.incoming_pos..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        this.read_failed = true;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                        if this.incoming_pos == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.read_failed = true;
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "truncated Shadowsocks IV",
                        )));
                    }
                    Poll::Ready(Ok(())) => this.incoming_pos += buf.filled().len(),
                }
            }
            if !remember(&this.ivs, this.incoming_iv) {
                this.read_failed = true;
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Shadowsocks IV was replayed",
                )));
            }
            match cipher(
                this.key.as_ref().expect("key present until IV"),
                &this.incoming_iv,
            ) {
                Ok(cipher) => this.incoming = Some(cipher),
                Err(error) => {
                    this.read_failed = true;
                    return Poll::Ready(Err(error));
                }
            }
            this.key = None;
        }
        let mut buffer = ReadBuf::new(out.initialize_unfilled());
        match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.read_failed = true;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(())) => {
                let size = buffer.filled().len();
                if let Err(error) = crypt(
                    this.incoming.as_mut().expect("cipher initialized"),
                    buffer.filled_mut(),
                ) {
                    this.read_failed = true;
                    return Poll::Ready(Err(error));
                }
                out.advance(size);
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn fragmented_iv_cancel_and_half_close_preserve_both_directions() {
        timeout(Duration::from_secs(5), async {
            let key = master_key::<KEY_LEN>(b"password");
            let (local, mut peer) = tokio::io::duplex(1);
            let ivs = Arc::new(Mutex::new(Salts::default()));
            let iv = fresh_salt(&ivs).unwrap();
            let mut stream = Stream::new(Box::new(local), key.clone(), ivs, iv).unwrap();
            assert!(
                timeout(Duration::from_millis(20), stream.write(b"A"))
                    .await
                    .is_err()
            );
            let peer_task = tokio::spawn(async move {
                let mut wire = Vec::new();
                peer.read_to_end(&mut wire).await.unwrap();
                let client_iv = wire[..NONCE_LEN].try_into().unwrap();
                let mut decoder = cipher(&key, &client_iv).unwrap();
                crypt(&mut decoder, &mut wire[NONCE_LEN..]).unwrap();
                assert_eq!(&wire[NONCE_LEN..], b"AB");
                let server_iv = [9; NONCE_LEN];
                let mut encoder = cipher(&key, &server_iv).unwrap();
                let mut response = b"reply".to_vec();
                crypt(&mut encoder, &mut response).unwrap();
                peer.write_all(&server_iv).await.unwrap();
                peer.write_all(&response).await.unwrap();
                peer.shutdown().await.unwrap();
            });
            stream.write_all(b"A").await.unwrap();
            stream.write_all(b"B").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut result = Vec::new();
            stream.read_to_end(&mut result).await.unwrap();
            assert_eq!(result, b"reply");
            peer_task.await.unwrap();
        })
        .await
        .expect("fragmented half-close exchange timed out");
    }

    #[tokio::test]
    async fn reflected_tcp_iv_is_rejected_and_read_failure_is_terminal() {
        let key = master_key::<KEY_LEN>(b"password");
        let (local, mut peer) = tokio::io::duplex(256);
        let ivs = Arc::new(Mutex::new(Salts::default()));
        let iv = fresh_salt(&ivs).unwrap();
        let mut stream = Stream::new(Box::new(local), key, ivs, iv).unwrap();
        peer.write_all(&iv).await.unwrap();
        let mut output = [0; 16];
        assert_eq!(
            stream.read(&mut output).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            stream.read(&mut output).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn udp_rejects_wrong_source_replayed_iv_and_oversized_payload() {
        timeout(Duration::from_secs(5), async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            let config = Config::new(
                Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                "password",
            );
            let destination = Endpoint {
                host: "udp.example.test".into(),
                port: 3478,
            };
            let mut client = config
                .connect_udp(destination.clone(), Duration::from_secs(1))
                .await
                .unwrap();
            client.send(b"request").await.unwrap();
            let mut packet = [0; 512];
            let (size, peer) = server.recv_from(&mut packet).await.unwrap();
            server.send_to(&packet[..size], peer).await.unwrap();
            assert!(matches!(
                client.receive().await,
                Err(TransitError::Protocol(_))
            ));

            fn response(key: &[u8; KEY_LEN], iv: [u8; NONCE_LEN], target: &Endpoint) -> Vec<u8> {
                let mut packet = iv.to_vec();
                target_address(target).write_to_buf(&mut packet);
                packet.extend_from_slice(b"reply");
                crypt(&mut cipher(key, &iv).unwrap(), &mut packet[NONCE_LEN..]).unwrap();
                packet
            }
            let wrong = Endpoint {
                host: "wrong.example.test".into(),
                port: 3478,
            };
            server
                .send_to(&response(&config.key, [7; NONCE_LEN], &wrong), peer)
                .await
                .unwrap();
            assert!(matches!(
                client.receive().await,
                Err(TransitError::Protocol(_))
            ));
            let valid = response(&config.key, [8; NONCE_LEN], &destination);
            server.send_to(&valid, peer).await.unwrap();
            assert_eq!(client.receive().await.unwrap(), b"reply");
            server.send_to(&valid, peer).await.unwrap();
            assert!(matches!(
                client.receive().await,
                Err(TransitError::Protocol(_))
            ));
            assert!(matches!(
                client.send(&vec![0; MAX_PACKET]).await,
                Err(TransitError::Unsupported(_))
            ));
        })
        .await
        .unwrap();
    }
}
