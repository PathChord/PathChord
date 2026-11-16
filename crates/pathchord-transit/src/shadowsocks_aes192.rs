//! SIP004 AES-192-GCM, absent from the upstream Shadowsocks cipher registry.

use std::fmt;
use std::io::{self, Cursor, ErrorKind};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use aes::Aes192;
use aes_gcm::aead::{Aead, KeyInit, consts::U12};
use aes_gcm::{AesGcm, Nonce};
use async_trait::async_trait;
use hkdf::Hkdf;
use sha1::Sha1;
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
    MAX_PACKET, Salts, SharedSalts, connection, fresh_salt, master_key, matches_destination,
    protocol, remember, target_address,
};

type Aes192Gcm = AesGcm<Aes192, U12>;
const KEY_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MAX_CHUNK: usize = 0x3fff;
struct RecordCipher {
    cipher: Aes192Gcm,
    nonce: [u8; 12],
    exhausted: bool,
}

impl RecordCipher {
    fn new(master: &[u8; KEY_LEN], salt: &[u8; KEY_LEN]) -> io::Result<Self> {
        let mut subkey = Zeroizing::new([0; KEY_LEN]);
        Hkdf::<Sha1>::new(Some(salt), master)
            .expand(b"ss-subkey", subkey.as_mut())
            .map_err(|_| io::Error::other("Shadowsocks key derivation failed"))?;
        let cipher = Aes192Gcm::new_from_slice(subkey.as_slice())
            .map_err(|_| io::Error::other("Shadowsocks key is invalid"))?;
        Ok(Self {
            cipher,
            nonce: [0; 12],
            exhausted: false,
        })
    }

    fn advance(&mut self) {
        for byte in &mut self.nonce {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                return;
            }
        }
        self.exhausted = true;
    }

    fn encrypt(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        if self.exhausted {
            return Err(io::Error::other("Shadowsocks nonce exhausted"));
        }
        let result = self
            .cipher
            .encrypt(Nonce::from_slice(&self.nonce), data)
            .map_err(|_| io::Error::other("Shadowsocks encryption failed"))?;
        self.advance();
        Ok(result)
    }

    fn decrypt(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        if self.exhausted {
            return Err(io::Error::other("Shadowsocks nonce exhausted"));
        }
        let result = self
            .cipher
            .decrypt(Nonce::from_slice(&self.nonce), data)
            .map_err(|_| {
                io::Error::new(ErrorKind::InvalidData, "Shadowsocks authentication failed")
            })?;
        self.advance();
        Ok(result)
    }
}

#[derive(Clone)]
pub(super) struct Config {
    server: Endpoint,
    master: Zeroizing<[u8; KEY_LEN]>,
    salts: SharedSalts,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes192Config").finish_non_exhaustive()
    }
}

impl Config {
    pub(super) fn new(server: Endpoint, password: &str) -> Self {
        Self {
            server,
            master: master_key(password.as_bytes()),
            salts: Arc::new(Mutex::new(Salts::default())),
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
            let salt = fresh_salt(&self.salts).map_err(|_| connection())?;
            let mut stream = Stream::new(inner, self.master.clone(), self.salts.clone(), salt)
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
            .saturating_add(KEY_LEN + TAG_LEN + target.serialized_len())
            > MAX_PACKET
        {
            return Err(TransitError::Unsupported(
                "UDP datagram exceeds the transport limit".into(),
            ));
        }
        let salt = fresh_salt(&self.config.salts).map_err(|_| connection())?;
        let mut cipher = RecordCipher::new(&self.config.master, &salt).map_err(|_| connection())?;
        let mut body = Vec::with_capacity(target.serialized_len() + payload.len());
        target.write_to_buf(&mut body);
        body.extend_from_slice(payload);
        let encrypted = cipher.encrypt(&body).map_err(|_| connection())?;
        let mut packet = Vec::with_capacity(KEY_LEN + encrypted.len());
        packet.extend_from_slice(&salt);
        packet.extend_from_slice(&encrypted);
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
        if size < KEY_LEN + TAG_LEN + 1 {
            return Err(protocol("Shadowsocks UDP response is truncated"));
        }
        let salt: [u8; KEY_LEN] = packet[..KEY_LEN].try_into().expect("checked salt length");
        let mut cipher = RecordCipher::new(&self.config.master, &salt).map_err(|_| connection())?;
        let body = cipher
            .decrypt(&packet[KEY_LEN..size])
            .map_err(|_| protocol("Shadowsocks UDP response failed authentication"))?;
        let mut reader = Cursor::new(body.as_slice());
        let source = Address::read_cursor(&mut reader)
            .map_err(|_| protocol("Shadowsocks UDP response address is invalid"))?;
        if !matches_destination(&self.destination, &source) {
            return Err(protocol(
                "Shadowsocks UDP response source does not match its target",
            ));
        }
        if !remember(&self.config.salts, salt) {
            return Err(protocol("Shadowsocks UDP response salt was replayed"));
        }
        Ok(body[reader.position() as usize..].to_vec())
    }
}

#[derive(Clone, Copy)]
enum ReadPhase {
    Salt,
    Header,
    Payload,
    Ready,
    Eof,
    Failed,
}

struct Stream {
    inner: BoxedTransitConnection,
    master: Option<Zeroizing<[u8; KEY_LEN]>>,
    salts: SharedSalts,
    peer_salt: Option<[u8; KEY_LEN]>,
    outgoing: RecordCipher,
    incoming: Option<RecordCipher>,
    write_buf: Vec<u8>,
    write_pos: usize,
    write_failed: bool,
    phase: ReadPhase,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl Stream {
    fn new(
        inner: BoxedTransitConnection,
        master: Zeroizing<[u8; KEY_LEN]>,
        salts: SharedSalts,
        salt: [u8; KEY_LEN],
    ) -> io::Result<Self> {
        let outgoing = RecordCipher::new(&master, &salt)?;
        Ok(Self {
            inner,
            master: Some(master),
            salts,
            peer_salt: None,
            outgoing,
            incoming: None,
            write_buf: salt.to_vec(),
            write_pos: 0,
            write_failed: false,
            phase: ReadPhase::Salt,
            read_buf: vec![0; KEY_LEN],
            read_pos: 0,
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

    fn reset_read(&mut self, phase: ReadPhase, len: usize) {
        self.phase = phase;
        self.read_buf = vec![0; len];
        self.read_pos = 0;
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
        let length = data.len().min(MAX_CHUNK);
        let header = match self.outgoing.encrypt(&(length as u16).to_be_bytes()) {
            Ok(header) => header,
            Err(error) => {
                self.write_failed = true;
                return Poll::Ready(Err(error));
            }
        };
        let payload = match self.outgoing.encrypt(&data[..length]) {
            Ok(payload) => payload,
            Err(error) => {
                self.write_failed = true;
                return Poll::Ready(Err(error));
            }
        };
        self.write_buf.extend_from_slice(&header);
        self.write_buf.extend_from_slice(&payload);
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
        let mut empty_frames = 0;
        loop {
            match this.phase {
                ReadPhase::Eof => return Poll::Ready(Ok(())),
                ReadPhase::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "Shadowsocks stream has failed",
                    )));
                }
                ReadPhase::Ready => {
                    let length = out.remaining().min(this.read_buf.len() - this.read_pos);
                    out.put_slice(&this.read_buf[this.read_pos..this.read_pos + length]);
                    this.read_pos += length;
                    if this.read_pos == this.read_buf.len() {
                        this.reset_read(ReadPhase::Header, 2 + TAG_LEN);
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadPhase::Salt | ReadPhase::Header | ReadPhase::Payload => {}
            }
            while this.read_pos < this.read_buf.len() {
                let mut buffer = ReadBuf::new(&mut this.read_buf[this.read_pos..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        this.phase = ReadPhase::Failed;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                        if this.read_pos == 0
                            && matches!(this.phase, ReadPhase::Salt | ReadPhase::Header)
                        {
                            this.phase = ReadPhase::Eof;
                            return Poll::Ready(Ok(()));
                        }
                        this.phase = ReadPhase::Failed;
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "truncated Shadowsocks record",
                        )));
                    }
                    Poll::Ready(Ok(())) => this.read_pos += buffer.filled().len(),
                }
            }
            let phase = this.phase;
            this.phase = ReadPhase::Failed;
            match phase {
                ReadPhase::Salt => {
                    let salt: [u8; KEY_LEN] = this
                        .read_buf
                        .as_slice()
                        .try_into()
                        .expect("fixed salt length");
                    this.incoming = Some(RecordCipher::new(
                        this.master.as_ref().expect("key present until salt"),
                        &salt,
                    )?);
                    this.master = None;
                    this.peer_salt = Some(salt);
                    this.reset_read(ReadPhase::Header, 2 + TAG_LEN);
                }
                ReadPhase::Header => {
                    let body = this
                        .incoming
                        .as_mut()
                        .expect("cipher initialized")
                        .decrypt(&this.read_buf)?;
                    let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
                    if len > MAX_CHUNK {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "Shadowsocks record is too large",
                        )));
                    }
                    if let Some(salt) = this.peer_salt.take()
                        && !remember(&this.salts, salt)
                    {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "Shadowsocks salt was replayed",
                        )));
                    }
                    this.reset_read(ReadPhase::Payload, len + TAG_LEN);
                }
                ReadPhase::Payload => {
                    let body = this
                        .incoming
                        .as_mut()
                        .expect("cipher initialized")
                        .decrypt(&this.read_buf)?;
                    if body.is_empty() {
                        this.reset_read(ReadPhase::Header, 2 + TAG_LEN);
                        empty_frames += 1;
                        if empty_frames >= 32 {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    } else {
                        this.phase = ReadPhase::Ready;
                        this.read_buf = body;
                        this.read_pos = 0;
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn sip004_password_derivation_matches_openssl_vector() {
        assert_eq!(
            master_key::<KEY_LEN>(b"password").as_slice(),
            &[
                0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27, 0xde, 0xb8, 0x82,
                0xcf, 0x99, 0x2b, 0x95, 0x99, 0x0a, 0x91, 0x51, 0x37, 0x4a,
            ]
        );
    }

    #[test]
    fn record_nonce_never_wraps_and_reuses_a_nonce() {
        let mut cipher = RecordCipher::new(&[1; KEY_LEN], &[2; KEY_LEN]).unwrap();
        cipher.nonce = [0xff; 12];
        cipher.encrypt(b"last").unwrap();
        assert!(cipher.encrypt(b"duplicate").is_err());
    }

    fn response(
        master: &[u8; KEY_LEN],
        salt: [u8; KEY_LEN],
        target: &Endpoint,
        data: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        target_address(target).write_to_buf(&mut body);
        body.extend_from_slice(data);
        let mut cipher = RecordCipher::new(master, &salt).unwrap();
        let mut packet = salt.to_vec();
        packet.extend_from_slice(&cipher.encrypt(&body).unwrap());
        packet
    }

    #[tokio::test]
    async fn udp_rejects_reflection_tampering_wrong_source_and_replayed_salts() {
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
            let mut request = [0; 512];
            let (size, peer) = server.recv_from(&mut request).await.unwrap();
            server.send_to(&request[..size], peer).await.unwrap();
            assert!(matches!(
                client.receive().await,
                Err(TransitError::Protocol(_))
            ));

            let valid = response(&config.master, [7; KEY_LEN], &destination, b"reply");
            let mut corrupt = valid.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            server.send_to(&corrupt, peer).await.unwrap();
            assert!(matches!(
                client.receive().await,
                Err(TransitError::Protocol(_))
            ));
            let wrong = Endpoint {
                host: "wrong.example.test".into(),
                port: 3478,
            };
            server
                .send_to(
                    &response(&config.master, [8; KEY_LEN], &wrong, b"wrong"),
                    peer,
                )
                .await
                .unwrap();
            assert!(matches!(
                client.receive().await,
                Err(TransitError::Protocol(_))
            ));
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

    #[tokio::test]
    async fn tcp_rejects_invalid_authentication_without_falling_back_to_plaintext() {
        let (local, mut peer) = tokio::io::duplex(256);
        let salts = Arc::new(Mutex::new(Salts::default()));
        let salt = fresh_salt(&salts).unwrap();
        let mut stream =
            Stream::new(Box::new(local), master_key(b"password"), salts, salt).unwrap();
        let mut invalid = vec![4; KEY_LEN];
        invalid.extend_from_slice(&[0; 2 + TAG_LEN]);
        invalid.extend_from_slice(b"not-plaintext");
        peer.write_all(&invalid).await.unwrap();
        let mut out = [0; 64];
        assert_eq!(
            stream.read(&mut out).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            stream.read(&mut out).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn fragmented_tcp_cancel_and_half_close_preserve_both_directions() {
        timeout(Duration::from_secs(5), async {
            let master = master_key(b"password");
            let (local, mut peer) = tokio::io::duplex(1);
            let salts = Arc::new(Mutex::new(Salts::default()));
            let salt = fresh_salt(&salts).unwrap();
            let mut stream = Stream::new(Box::new(local), master.clone(), salts, salt).unwrap();
            assert!(
                timeout(Duration::from_millis(20), stream.write(b"A"))
                    .await
                    .is_err()
            );
            let peer_task = tokio::spawn(async move {
                let mut wire = Vec::new();
                peer.read_to_end(&mut wire).await.unwrap();
                let client_salt = wire[..KEY_LEN].try_into().unwrap();
                let mut cipher = RecordCipher::new(&master, &client_salt).unwrap();
                let mut pos = KEY_LEN;
                let mut plaintext = Vec::new();
                while pos < wire.len() {
                    let length = cipher.decrypt(&wire[pos..pos + 2 + TAG_LEN]).unwrap();
                    pos += 2 + TAG_LEN;
                    let len = usize::from(u16::from_be_bytes([length[0], length[1]]));
                    plaintext.extend_from_slice(
                        &cipher.decrypt(&wire[pos..pos + len + TAG_LEN]).unwrap(),
                    );
                    pos += len + TAG_LEN;
                }
                assert_eq!(plaintext, b"AB");
                let server_salt = [9; KEY_LEN];
                let mut cipher = RecordCipher::new(&master, &server_salt).unwrap();
                let mut wire = server_salt.to_vec();
                // An authenticated empty frame must not be mistaken for EOF.
                wire.extend_from_slice(&cipher.encrypt(&0_u16.to_be_bytes()).unwrap());
                wire.extend_from_slice(&cipher.encrypt(b"").unwrap());
                wire.extend_from_slice(&cipher.encrypt(&5_u16.to_be_bytes()).unwrap());
                wire.extend_from_slice(&cipher.encrypt(b"reply").unwrap());
                peer.write_all(&wire).await.unwrap();
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
}
