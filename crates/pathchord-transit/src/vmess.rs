#![allow(deprecated)]
//! Small, pure Rust VMess AEAD client.
//!
//! VMess keeps its protocol framing independent from the outer byte transport,
//! so the same implementation can run over TCP, TLS, WebSocket, or WSS.  The
//! native adapter implements both AEAD and legacy alter-ID header profiles,
//! modern AEAD body ciphers and explicitly configured plaintext bodies.

use std::sync::Arc;
use std::time::Duration;

use aes::cipher::BlockCipherEncrypt;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use pathchord_policy::TransitProxyConfig;
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, XofReader};
use shake::{Shake128, Shake128Reader};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::Zeroize;

use crate::{
    AdapterKind, BoxedTransitConnection, BoxedTransitDatagram, ConnectRequest, Endpoint,
    TransitAdapter, TransitCredential, TransitDatagram, TransitError, TransitMetadata,
};

const MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const ALTER_ID_MAGIC: &[u8] = b"16167dc8-16b6-4e6d-b8bb-65dd68113a81";
const ALTER_ID_RETRY: &[u8] = b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2";
const MAX_RECORD: usize = 16_368;

pub(crate) struct VmessAdapter {
    metadata: TransitMetadata,
    cmd_key: [u8; 16],
    header_mode: HeaderMode,
    transport: crate::native_transport::NativeTransport,
    cipher: BodyCipherKind,
    framing: VmessFramingOptions,
    packet_encoding: PacketEncoding,
    udp_enabled: bool,
    timeout: Duration,
}

impl std::fmt::Debug for VmessAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessAdapter")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl VmessAdapter {
    pub fn from_config(
        config: &TransitProxyConfig,
        credential: &TransitCredential,
        timeout: Duration,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, TransitError> {
        let mut allowed = vec!["uuid", "security", "cipher", "alter_id"];
        if config
            .options
            .transport
            .as_ref()
            .is_some_and(|transport| transport.kind == "meek")
        {
            allowed.push("meek_url");
        }
        if let Some(field) = config
            .options
            .tls
            .as_ref()
            .and_then(|tls| tls.client_key_field.as_deref())
        {
            allowed.push(field);
        }
        crate::adapter_registry::validate_credentials(Some(credential), &allowed)?;
        let alter_id = credential.field("alter_id").map_or(Ok(0_u16), |value| {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(unsupported(
                    "VMess alter_id must be an integer between 0 and 65535",
                ));
            }
            value
                .parse::<u16>()
                .map_err(|_| unsupported("VMess alter_id must be an integer between 0 and 65535"))
        })?;
        let uuid = credential
            .field("uuid")
            .ok_or_else(|| unsupported("VMess UUID is missing"))?;
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| unsupported("VMess UUID is invalid"))?;
        let security = credential
            .field("security")
            .map(BodyCipherKind::parse)
            .transpose()?;
        let cipher = credential
            .field("cipher")
            .map(BodyCipherKind::parse)
            .transpose()?;
        if let (Some(security), Some(cipher)) = (security, cipher)
            && security != cipher
        {
            return Err(unsupported("VMess security and cipher aliases conflict"));
        }
        let cipher = security.or(cipher).unwrap_or(BodyCipherKind::Aes128Gcm);
        let framing =
            config
                .options
                .vmess
                .as_ref()
                .map_or_else(VmessFramingOptions::default, |options| {
                    VmessFramingOptions {
                        global_padding: options.global_padding,
                        authenticated_length: options.authenticated_length,
                    }
                });
        framing.validate(cipher)?;
        let packet_encoding = match config.options.packet_encoding.as_deref() {
            None | Some("") => PacketEncoding::Plain,
            Some("xudp") => PacketEncoding::Xudp,
            Some("packetaddr") => PacketEncoding::PacketAddr,
            Some(_) => return Err(unsupported("VMess packet encoding is unsupported")),
        };
        let mut transport_config = config.clone();
        transport_config.options.vmess = None;
        transport_config.options.packet_encoding = None;
        let transport = crate::native_transport::NativeTransport::new(
            &transport_config,
            credential,
            tls,
            timeout,
        )?;
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "vmess".to_owned(),
                },
                labels: config.labels.clone(),
            },
            cmd_key: cmd_key(uuid.as_bytes()),
            header_mode: if alter_id == 0 {
                HeaderMode::Aead
            } else {
                HeaderMode::Legacy(alter_key(uuid.as_bytes()))
            },
            transport,
            cipher,
            framing,
            packet_encoding,
            udp_enabled: config.options.udp != Some(false),
            timeout,
        })
    }

    async fn open(
        &self,
        destination: &Endpoint,
        command: u8,
    ) -> Result<BoxedTransitConnection, TransitError> {
        crate::validate_destination(destination)?;
        self.framing.validate(self.cipher)?;
        timeout(self.timeout, async {
            let stream = self.transport.connect().await?;
            let sealed = seal_header(
                &self.cmd_key,
                self.header_mode,
                destination,
                command,
                self.cipher,
                self.framing,
            )?;
            let mut stream = stream;
            stream
                .write_all(&sealed.bytes)
                .await
                .map_err(|_| protocol("VMess request header write failed"))?;
            stream
                .flush()
                .await
                .map_err(|_| protocol("VMess request header flush failed"))?;
            Ok(spawn_duplex(stream, sealed, self.cipher, self.framing))
        })
        .await
        .map_err(|_| TransitError::Connection("VMess opening timed out".to_owned()))?
    }
}

#[async_trait]
impl TransitAdapter for VmessAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }
    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        if !self.udp_enabled {
            return Err(unsupported("VMess UDP is disabled"));
        }
        self.framing.validate(self.cipher)?;
        crate::validate_destination(&request.destination)?;
        if self.packet_encoding == PacketEncoding::Xudp {
            return crate::xudp::xudp_datagram(
                self.open(&request.destination, 3).await?,
                request.destination,
            );
        }
        if self.packet_encoding == PacketEncoding::PacketAddr
            && request
                .destination
                .host
                .parse::<std::net::IpAddr>()
                .is_err()
        {
            return Err(unsupported("VMess packetaddr requires an IP destination"));
        }
        timeout(self.timeout, async {
            let mut stream = self.transport.connect().await?;
            let destination = if self.packet_encoding == PacketEncoding::PacketAddr {
                Endpoint {
                    host: "sp.packet-addr.v2fly.arpa".into(),
                    port: 0,
                }
            } else {
                request.destination.clone()
            };
            let sealed = seal_header(
                &self.cmd_key,
                self.header_mode,
                &destination,
                2,
                self.cipher,
                self.framing,
            )?;
            stream
                .write_all(&sealed.bytes)
                .await
                .map_err(|_| protocol("VMess UDP request header write failed"))?;
            stream
                .flush()
                .await
                .map_err(|_| protocol("VMess UDP request header flush failed"))?;
            let datagram: BoxedTransitDatagram = Box::new(VmessDatagram::new(
                stream,
                sealed,
                self.cipher,
                self.framing,
            ));
            if self.packet_encoding == PacketEncoding::PacketAddr {
                Ok(Box::new(PacketAddrDatagram::new(
                    datagram,
                    request.destination,
                    MAX_RECORD,
                )?) as BoxedTransitDatagram)
            } else {
                Ok(datagram)
            }
        })
        .await
        .map_err(|_| TransitError::Connection("VMess UDP opening timed out".to_owned()))?
    }
    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        self.open(&request.destination, 1).await
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PacketEncoding {
    Plain,
    Xudp,
    PacketAddr,
}

pub(crate) struct PacketAddrDatagram {
    inner: BoxedTransitDatagram,
    address: std::net::SocketAddr,
    header: Vec<u8>,
    max_frame: usize,
}

impl std::fmt::Debug for PacketAddrDatagram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PacketAddrDatagram(..)")
    }
}

impl PacketAddrDatagram {
    pub(crate) fn new(
        inner: BoxedTransitDatagram,
        destination: Endpoint,
        max_frame: usize,
    ) -> Result<Self, TransitError> {
        let ip = destination
            .host
            .parse::<std::net::IpAddr>()
            .map_err(|_| unsupported("packetaddr requires an IP destination"))?;
        let address = std::net::SocketAddr::new(ip, destination.port);
        let mut header = Vec::new();
        match ip {
            std::net::IpAddr::V4(ip) => {
                header.push(1);
                header.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                header.push(2);
                header.extend_from_slice(&ip.octets());
            }
        }
        header.extend_from_slice(&destination.port.to_be_bytes());
        Ok(Self {
            inner,
            address,
            header,
            max_frame,
        })
    }
}

#[async_trait]
impl TransitDatagram for PacketAddrDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        if payload.len() > self.max_frame.saturating_sub(self.header.len()) {
            return Err(unsupported("packetaddr packet exceeds the frame limit"));
        }
        let mut frame = Vec::with_capacity(self.header.len() + payload.len());
        frame.extend_from_slice(&self.header);
        frame.extend_from_slice(payload);
        self.inner.send(&frame).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        let packet = self.inner.receive().await?;
        let (ip, offset) = match packet.first() {
            Some(1) if packet.len() >= 7 => (
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    packet[1], packet[2], packet[3], packet[4],
                )),
                5,
            ),
            Some(2) if packet.len() >= 19 => (
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&packet[1..17]).expect("length checked"),
                )),
                17,
            ),
            _ => return Err(protocol("packetaddr reply address is invalid")),
        };
        let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        if std::net::SocketAddr::new(ip, port) != self.address {
            return Err(protocol(
                "packetaddr reply address differs from the bound destination",
            ));
        }
        Ok(packet[offset + 2..].to_vec())
    }

    async fn close(self: Box<Self>) -> Result<(), TransitError> {
        self.inner.close().await
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct VmessFramingOptions {
    pub(crate) global_padding: bool,
    pub(crate) authenticated_length: bool,
}

impl VmessFramingOptions {
    fn validate(self, cipher: BodyCipherKind) -> Result<(), TransitError> {
        if (self.global_padding || self.authenticated_length)
            && !matches!(
                cipher,
                BodyCipherKind::Aes128Gcm | BodyCipherKind::ChaCha20Poly1305
            )
        {
            return Err(unsupported(
                "VMess padding and authenticated length require an AEAD body cipher",
            ));
        }
        Ok(())
    }
}

struct Sealed {
    bytes: Vec<u8>,
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_v: u8,
    command: u8,
    legacy: bool,
}

#[derive(Clone, Copy)]
enum HeaderMode {
    Aead,
    Legacy([u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyCipherKind {
    Aes128Gcm,
    ChaCha20Poly1305,
    Aes128Cfb,
    Plain,
}

impl BodyCipherKind {
    fn parse(value: &str) -> Result<Self, TransitError> {
        match value.to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "auto" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            "aes-128-cfb" => Ok(Self::Aes128Cfb),
            "none" | "zero" => Ok(Self::Plain),
            _ => Err(unsupported("VMess security is unsupported")),
        }
    }
}

enum BodyCipher {
    Aes(Box<Aes128Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
    Plain,
}

impl BodyCipher {
    fn new(kind: BodyCipherKind, key: &[u8; 16]) -> Self {
        match kind {
            BodyCipherKind::Aes128Gcm => Self::Aes(Box::new(
                Aes128Gcm::new_from_slice(key).expect("VMess AES key"),
            )),
            BodyCipherKind::ChaCha20Poly1305 => Self::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(&chacha_key(key)).expect("VMess ChaCha key"),
            )),
            BodyCipherKind::Plain => Self::Plain,
            BodyCipherKind::Aes128Cfb => unreachable!("CFB uses a stateful stream"),
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes(cipher) => cipher
                .encrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| ()),
            Self::ChaCha(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(|_| ()),
            Self::Plain => Ok(payload.to_vec()),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Self::Aes(cipher) => cipher
                .decrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| ()),
            Self::ChaCha(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(|_| ()),
            Self::Plain => Ok(payload.to_vec()),
        }
    }
}

struct RecordCodec {
    body: BodyCipher,
    body_iv: [u8; 16],
    length_cipher: Option<BodyCipher>,
    length_iv: [u8; 16],
    framing: VmessFramingOptions,
    shake: Option<Shake128Reader>,
    counter: u32,
    failed: bool,
}

#[derive(Clone, Copy)]
struct RecordHeader {
    ciphertext_len: usize,
    padding_len: usize,
}

impl RecordCodec {
    fn new(
        kind: BodyCipherKind,
        request_key: &[u8; 16],
        request_iv: &[u8; 16],
        body_key: &[u8; 16],
        body_iv: &[u8; 16],
        framing: VmessFramingOptions,
    ) -> Self {
        let length_cipher = framing
            .authenticated_length
            .then(|| BodyCipher::new(kind, &kdf16(request_key, &[b"auth_len"])));
        let shake = framing.global_padding.then(|| {
            let mut hash = Shake128::default();
            sha3::digest::Update::update(&mut hash, body_iv);
            hash.finalize_xof()
        });
        Self {
            body: BodyCipher::new(kind, body_key),
            body_iv: *body_iv,
            length_cipher,
            length_iv: *request_iv,
            framing,
            shake,
            counter: 0,
            failed: false,
        }
    }

    fn counter(&self) -> Result<u16, TransitError> {
        if matches!(self.body, BodyCipher::Plain) && self.length_cipher.is_none() {
            return Ok(0);
        }
        u16::try_from(self.counter).map_err(|_| protocol("VMess record nonce exhausted"))
    }

    fn next_shake(&mut self) -> u16 {
        let mut bytes = [0; 2];
        self.shake
            .as_mut()
            .expect("padding SHAKE state")
            .read(&mut bytes);
        u16::from_be_bytes(bytes)
    }

    fn encode(&mut self, payload: &[u8]) -> Result<Vec<u8>, TransitError> {
        if self.failed {
            return Err(protocol("VMess record encoder is invalid"));
        }
        self.failed = true;
        let counter = self.counter()?;
        let body = self
            .body
            .encrypt(&record_nonce(&self.body_iv, counter), payload)
            .map_err(|_| protocol("VMess record encryption failed"))?;
        let padding = if self.framing.global_padding {
            usize::from(self.next_shake() % 64)
        } else {
            0
        };
        let body_len = body.len() + padding;
        let header = if let Some(cipher) = &self.length_cipher {
            let length = u16::try_from(
                body_len
                    .checked_sub(16)
                    .ok_or_else(|| protocol("VMess record length is invalid"))?,
            )
            .map_err(|_| protocol("VMess record length overflow"))?;
            cipher
                .encrypt(
                    &record_nonce(&self.length_iv, counter),
                    &length.to_be_bytes(),
                )
                .map_err(|_| protocol("VMess record length encryption failed"))?
        } else {
            let mut length =
                u16::try_from(body_len).map_err(|_| protocol("VMess record length overflow"))?;
            if self.framing.global_padding {
                length ^= self.next_shake();
            }
            length.to_be_bytes().to_vec()
        };
        let mut output = Vec::with_capacity(header.len() + body_len);
        output.extend_from_slice(&header);
        output.extend_from_slice(&body);
        let start = output.len();
        output.resize(start + padding, 0);
        if padding != 0 {
            getrandom::fill(&mut output[start..])
                .map_err(|_| protocol("VMess padding generation failed"))?;
        }
        self.counter = self.counter.saturating_add(1);
        self.failed = false;
        Ok(output)
    }

    fn header_len(&self) -> usize {
        if self.framing.authenticated_length {
            18
        } else {
            2
        }
    }

    fn decode_header(&mut self, bytes: &[u8]) -> Result<RecordHeader, TransitError> {
        if self.failed {
            return Err(protocol("VMess record decoder is invalid"));
        }
        self.failed = true;
        let counter = self.counter()?;
        let mut length = if let Some(cipher) = &self.length_cipher {
            let decoded = cipher
                .decrypt(&record_nonce(&self.length_iv, counter), bytes)
                .map_err(|_| protocol("VMess record length authentication failed"))?;
            let length: [u8; 2] = decoded
                .try_into()
                .map_err(|_| protocol("VMess record length is invalid"))?;
            usize::from(u16::from_be_bytes(length)) + 16
        } else {
            let length: [u8; 2] = bytes
                .try_into()
                .map_err(|_| protocol("VMess record length is invalid"))?;
            usize::from(u16::from_be_bytes(length))
        };
        let padding = if self.framing.global_padding {
            usize::from(self.next_shake() % 64)
        } else {
            0
        };
        if self.framing.global_padding && self.length_cipher.is_none() {
            length ^= usize::from(self.next_shake());
        }
        let ciphertext_len = length
            .checked_sub(padding)
            .ok_or_else(|| protocol("VMess record padding exceeds its length"))?;
        let overhead = match self.body {
            BodyCipher::Plain => 0,
            _ => 16,
        };
        if !(overhead..=MAX_RECORD + overhead).contains(&ciphertext_len) {
            return Err(protocol("VMess record length is invalid"));
        }
        self.failed = false;
        Ok(RecordHeader {
            ciphertext_len,
            padding_len: padding,
        })
    }

    fn decode_body(&mut self, header: RecordHeader, bytes: &[u8]) -> Result<Vec<u8>, TransitError> {
        if self.failed {
            return Err(protocol("VMess record decoder is invalid"));
        }
        self.failed = true;
        if bytes.len() != header.ciphertext_len + header.padding_len {
            return Err(protocol("VMess record body length is invalid"));
        }
        let counter = self.counter()?;
        let payload = self
            .body
            .decrypt(
                &record_nonce(&self.body_iv, counter),
                &bytes[..header.ciphertext_len],
            )
            .map_err(|_| protocol("VMess record authentication failed"))?;
        self.counter = self.counter.saturating_add(1);
        self.failed = false;
        Ok(payload)
    }
}

/// VMess legacy mode encrypts length, checksum, and payload as one continuous
/// AES-CFB128 stream; the feedback register must survive record boundaries.
struct CfbStream {
    cipher: aes::Aes128,
    feedback: [u8; 16],
    mask: [u8; 16],
    offset: usize,
}

impl CfbStream {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            cipher: aes::Aes128::new_from_slice(key).expect("VMess AES key"),
            feedback: *iv,
            mask: [0; 16],
            offset: 0,
        }
    }

    fn apply(&mut self, bytes: &mut [u8], decrypt: bool) {
        for byte in bytes {
            if self.offset == 0 {
                let mut block = aes::cipher::Block::<aes::Aes128>::clone_from_slice(&self.feedback);
                self.cipher.encrypt_block(&mut block);
                self.mask.copy_from_slice(&block);
            }
            let ciphertext = if decrypt {
                *byte
            } else {
                *byte ^ self.mask[self.offset]
            };
            *byte ^= self.mask[self.offset];
            self.feedback[self.offset] = ciphertext;
            self.offset = (self.offset + 1) % 16;
        }
    }
}

impl Drop for CfbStream {
    fn drop(&mut self) {
        self.feedback.zeroize();
        self.mask.zeroize();
    }
}

fn cfb_record(cipher: &mut CfbStream, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(payload.len() + 6);
    record.extend_from_slice(&((payload.len() + 4) as u16).to_be_bytes());
    record.extend_from_slice(&fnv1a32(payload).to_be_bytes());
    record.extend_from_slice(payload);
    cipher.apply(&mut record, false);
    record
}

fn cfb_payload(record: &[u8]) -> Result<Vec<u8>, TransitError> {
    if record.len() < 4 {
        return Err(protocol("VMess CFB response checksum is truncated"));
    }
    let (checksum, payload) = record.split_at(4);
    if u32::from_be_bytes(checksum.try_into().expect("checksum length checked")) != fnv1a32(payload)
    {
        return Err(protocol("VMess CFB response checksum failed"));
    }
    Ok(payload.to_vec())
}

fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(uuid);
    digest.update(MAGIC);
    digest.finalize().into()
}

fn alter_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(uuid);
    digest.update(ALTER_ID_MAGIC);
    loop {
        let next: [u8; 16] = digest.clone().finalize().into();
        if &next != uuid {
            return next;
        }
        digest.update(ALTER_ID_RETRY);
    }
}

fn seal_legacy_request(
    cmd_key: &[u8; 16],
    alter_key: &[u8; 16],
    timestamp: u64,
    mut header: Vec<u8>,
) -> Result<Vec<u8>, TransitError> {
    let timestamp = timestamp.to_be_bytes();
    let mut id = Hmac::<Md5>::new_from_slice(alter_key)
        .map_err(|_| protocol("VMess legacy authentication initialization failed"))?;
    Mac::update(&mut id, &timestamp);
    let mut time_hash = Md5::new();
    for _ in 0..4 {
        time_hash.update(timestamp);
    }
    let iv: [u8; 16] = time_hash.finalize().into();
    CfbStream::new(cmd_key, &iv).apply(&mut header, false);
    let mut bytes = Vec::with_capacity(16 + header.len());
    bytes.extend_from_slice(&id.finalize().into_bytes());
    bytes.extend_from_slice(&header);
    Ok(bytes)
}

trait DigestState: Clone {
    fn update(&mut self, bytes: &[u8]);
    fn finish(self) -> [u8; 32];
}

impl DigestState for Hmac<Sha256> {
    fn update(&mut self, bytes: &[u8]) {
        Mac::update(self, bytes);
    }

    fn finish(self) -> [u8; 32] {
        self.finalize().into_bytes().into()
    }
}

#[derive(Clone)]
struct WrappedDigest<H: DigestState> {
    inner: H,
    outer: H,
    opad: [u8; 64],
}

impl<H: DigestState> DigestState for WrappedDigest<H> {
    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    fn finish(mut self) -> [u8; 32] {
        let inner = self.inner.finish();
        self.outer.update(&self.opad);
        self.outer.update(&inner);
        self.outer.finish()
    }
}

fn wrap_digest<H: DigestState>(mut state: H, key: &[u8]) -> WrappedDigest<H> {
    let mut normalized = [0u8; 64];
    let key = if key.len() > 64 {
        let mut digest = state.clone();
        digest.update(key);
        digest.finish().to_vec()
    } else {
        key.to_vec()
    };
    normalized[..key.len()].copy_from_slice(&key);
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for (index, value) in normalized.iter().enumerate() {
        ipad[index] = value ^ 0x36;
        opad[index] = value ^ 0x5c;
    }
    let outer = state.clone();
    state.update(&ipad);
    WrappedDigest {
        inner: state,
        outer,
        opad,
    }
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let salt = Hmac::<Sha256>::new_from_slice(b"VMess AEAD KDF").expect("valid KDF salt");
    match path {
        [] => {
            let mut state = salt;
            DigestState::update(&mut state, key);
            state.finish()
        }
        [first] => {
            let mut state = wrap_digest(salt, first);
            DigestState::update(&mut state, key);
            state.finish()
        }
        [first, second] => {
            let mut state = wrap_digest(wrap_digest(salt, first), second);
            DigestState::update(&mut state, key);
            state.finish()
        }
        [first, second, third] => {
            let mut state = wrap_digest(wrap_digest(wrap_digest(salt, first), second), third);
            DigestState::update(&mut state, key);
            state.finish()
        }
        _ => panic!("VMess KDF path is bounded to three salts"),
    }
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let digest = kdf(key, path);
    digest[..16].try_into().expect("fixed digest length")
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let digest = kdf(key, path);
    digest[..12].try_into().expect("fixed digest length")
}

fn seal_header(
    cmd_key: &[u8; 16],
    header_mode: HeaderMode,
    target: &Endpoint,
    command: u8,
    cipher: BodyCipherKind,
    framing: VmessFramingOptions,
) -> Result<Sealed, TransitError> {
    let mut req_key = [0u8; 16];
    let mut req_iv = [0u8; 16];
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| protocol("VMess random generation failed"))?;
    req_key.copy_from_slice(&random[..16]);
    req_iv.copy_from_slice(&random[16..]);
    random.zeroize();
    let resp_v = req_iv[0];
    let mut nonce_bytes = [0u8; 8];
    getrandom::fill(&mut nonce_bytes).map_err(|_| protocol("VMess random generation failed"))?;
    let mut auth = [0u8; 16];
    let mut now = [0u8; 8];
    now.copy_from_slice(
        &(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs())
        .to_be_bytes(),
    );
    auth[..8].copy_from_slice(&now);
    auth[8..12].copy_from_slice(&nonce_bytes[..4]);
    let auth_crc = crc32fast::hash(&auth[..12]).to_be_bytes();
    auth[12..].copy_from_slice(&auth_crc);
    let auth_key = kdf16(cmd_key, &[b"AES Auth ID Encryption"]);
    let auth_cipher =
        aes::Aes128::new_from_slice(&auth_key).map_err(|_| protocol("VMess Auth ID key failed"))?;
    auth_cipher.encrypt_block(aes::Block::from_mut_slice(&mut auth));

    let padding = (nonce_bytes[4] & 0x0f) as usize;
    let mut plain = vec![1];
    plain.extend_from_slice(&req_iv);
    plain.extend_from_slice(&req_key);
    let method = match cipher {
        BodyCipherKind::Aes128Gcm => 3,
        BodyCipherKind::ChaCha20Poly1305 => 4,
        BodyCipherKind::Aes128Cfb => 1,
        BodyCipherKind::Plain => 5,
    };
    // Unencrypted TCP is a raw stream. UDP still uses length-delimited chunks
    // so that packet boundaries survive the byte transport.
    let mut options = u8::from(cipher != BodyCipherKind::Plain || command != 1);
    if framing.global_padding || framing.authenticated_length {
        options |= 4;
        options |= u8::from(framing.global_padding) << 3;
        options |= u8::from(framing.authenticated_length) << 4;
    }
    plain.extend_from_slice(&[resp_v, options, ((padding as u8) << 4) | method, 0, command]);
    if command != 3 {
        plain.extend_from_slice(&target.port.to_be_bytes());
        encode_target(&mut plain, target)?;
    }
    plain.extend(std::iter::repeat_n(0, padding));
    plain.extend_from_slice(&fnv1a32(&plain).to_be_bytes());

    if let HeaderMode::Legacy(alter_key) = header_mode {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| protocol("VMess system time precedes the Unix epoch"))?
            .as_secs();
        let bytes = seal_legacy_request(cmd_key, &alter_key, timestamp, plain)?;
        return Ok(Sealed {
            bytes,
            req_key,
            req_iv,
            resp_v,
            command,
            legacy: true,
        });
    }

    let length_key = kdf16(
        cmd_key,
        &[b"VMess Header AEAD Key_Length", &auth, &nonce_bytes],
    );
    let length_iv = kdf12(
        cmd_key,
        &[b"VMess Header AEAD Nonce_Length", &auth, &nonce_bytes],
    );
    let length = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|_| protocol("VMess length key failed"))?
        .encrypt(
            Nonce::from_slice(&length_iv),
            Payload {
                msg: &(plain.len() as u16).to_be_bytes(),
                aad: &auth,
            },
        )
        .map_err(|_| protocol("VMess length encryption failed"))?;
    let header_key = kdf16(cmd_key, &[b"VMess Header AEAD Key", &auth, &nonce_bytes]);
    let header_iv = kdf12(cmd_key, &[b"VMess Header AEAD Nonce", &auth, &nonce_bytes]);
    let encrypted = Aes128Gcm::new_from_slice(&header_key)
        .map_err(|_| protocol("VMess header key failed"))?
        .encrypt(
            Nonce::from_slice(&header_iv),
            Payload {
                msg: &plain,
                aad: &auth,
            },
        )
        .map_err(|_| protocol("VMess header encryption failed"))?;
    let mut bytes = Vec::with_capacity(42 + length.len() + encrypted.len());
    bytes.extend_from_slice(&auth);
    bytes.extend_from_slice(&length);
    bytes.extend_from_slice(&nonce_bytes);
    bytes.extend_from_slice(&encrypted);
    Ok(Sealed {
        bytes,
        req_key,
        req_iv,
        resp_v,
        command,
        legacy: false,
    })
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

fn response_io_error(error: TransitError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

fn spawn_duplex(
    upstream: BoxedTransitConnection,
    sealed: Sealed,
    cipher_kind: BodyCipherKind,
    framing: VmessFramingOptions,
) -> BoxedTransitConnection {
    let plain_framed = sealed.command == 3;
    let (client, server) = tokio::io::duplex(32 * 1024);
    let read_error = Arc::new(std::sync::Mutex::new(None));
    let response_error = Arc::clone(&read_error);
    let (mut client_read, mut client_write) = tokio::io::split(server);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let write_key = sealed.req_key;
    let write_iv = sealed.req_iv;
    let (resp_key, resp_iv) =
        selected_response_keys(&sealed.req_key, &sealed.req_iv, sealed.legacy);
    let resp_v = sealed.resp_v;
    let legacy = sealed.legacy;
    tokio::spawn(async move {
        if cipher_kind == BodyCipherKind::Plain && !plain_framed {
            let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
            let _ = upstream_write.shutdown().await;
            return;
        }
        if cipher_kind == BodyCipherKind::Aes128Cfb {
            let mut cipher = CfbStream::new(&write_key, &write_iv);
            let mut buffer = vec![0; MAX_RECORD];
            while let Ok(size) = client_read.read(&mut buffer).await {
                if size == 0
                    || upstream_write
                        .write_all(&cfb_record(&mut cipher, &buffer[..size]))
                        .await
                        .is_err()
                    || upstream_write.flush().await.is_err()
                {
                    break;
                }
            }
            let _ = upstream_write.shutdown().await;
            return;
        }
        let mut codec = RecordCodec::new(
            cipher_kind,
            &write_key,
            &write_iv,
            &write_key,
            &write_iv,
            framing,
        );
        let mut buf = vec![0u8; MAX_RECORD];
        while let Ok(size) = client_read.read(&mut buf).await {
            if size == 0 {
                break;
            }
            let Ok(encoded) = codec.encode(&buf[..size]) else {
                break;
            };
            if upstream_write.write_all(&encoded).await.is_err()
                || upstream_write.flush().await.is_err()
            {
                break;
            }
        }
        let _ = upstream_write.shutdown().await;
    });
    tokio::spawn(async move {
        let response_cfb =
            match read_response_header(&mut upstream_read, &resp_key, &resp_iv, resp_v, legacy)
                .await
            {
                Ok(cipher) => cipher,
                Err(error) => {
                    *response_error
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(std::io::Error::new(std::io::ErrorKind::InvalidData, error));
                    let _ = client_write.shutdown().await;
                    return;
                }
            };
        if cipher_kind == BodyCipherKind::Plain && !plain_framed {
            let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
            let _ = client_write.shutdown().await;
            return;
        }
        if cipher_kind == BodyCipherKind::Aes128Cfb {
            let mut cipher = response_cfb.unwrap_or_else(|| CfbStream::new(&resp_key, &resp_iv));
            loop {
                let Some(length_bytes) = read_optional_frame(
                    &mut upstream_read,
                    2,
                    "VMess CFB response length is truncated",
                )
                .await
                .map_err(|error| *response_error.lock().unwrap() = Some(response_io_error(error)))
                .ok()
                .flatten() else {
                    break;
                };
                let mut length = [length_bytes[0], length_bytes[1]];
                cipher.apply(&mut length, true);
                let length = usize::from(u16::from_be_bytes(length));
                if !(4..=MAX_RECORD + 4).contains(&length) {
                    *response_error.lock().unwrap() = Some(response_io_error(protocol(
                        "VMess CFB response length is invalid",
                    )));
                    break;
                }
                let mut body = match read_required_frame(
                    &mut upstream_read,
                    length,
                    "VMess CFB response body is truncated",
                )
                .await
                {
                    Ok(body) => body,
                    Err(error) => {
                        *response_error.lock().unwrap() = Some(response_io_error(error));
                        break;
                    }
                };
                cipher.apply(&mut body, true);
                let Ok(payload) = cfb_payload(&body) else {
                    *response_error.lock().unwrap() = Some(response_io_error(protocol(
                        "VMess CFB response checksum failed",
                    )));
                    break;
                };
                if client_write.write_all(&payload).await.is_err() {
                    break;
                }
            }
            let _ = client_write.shutdown().await;
            return;
        }
        let mut codec = RecordCodec::new(
            cipher_kind,
            &write_key,
            &write_iv,
            &resp_key,
            &resp_iv,
            framing,
        );
        loop {
            let Some(length) = read_optional_frame(
                &mut upstream_read,
                codec.header_len(),
                "VMess response record length is truncated",
            )
            .await
            .map_err(|error| *response_error.lock().unwrap() = Some(response_io_error(error)))
            .ok()
            .flatten() else {
                break;
            };
            let Ok(header) = codec.decode_header(&length) else {
                *response_error.lock().unwrap() = Some(response_io_error(protocol(
                    "VMess response record length authentication failed",
                )));
                break;
            };
            let body = match read_required_frame(
                &mut upstream_read,
                header.ciphertext_len + header.padding_len,
                "VMess response record body is truncated",
            )
            .await
            {
                Ok(body) => body,
                Err(error) => {
                    *response_error.lock().unwrap() = Some(response_io_error(error));
                    break;
                }
            };
            let Ok(plain) = codec.decode_body(header, &body) else {
                *response_error.lock().unwrap() = Some(response_io_error(protocol(
                    "VMess response record authentication failed",
                )));
                break;
            };
            if client_write.write_all(&plain).await.is_err() {
                break;
            }
        }
        let _ = client_write.shutdown().await;
    });
    Box::new(VmessConnection {
        inner: client,
        read_error,
    })
}

struct VmessConnection {
    inner: tokio::io::DuplexStream,
    read_error: Arc<std::sync::Mutex<Option<std::io::Error>>>,
}

impl tokio::io::AsyncRead for VmessConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = output.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, output);
        if output.remaining() != 0
            && output.filled().len() == before
            && matches!(result, std::task::Poll::Ready(Ok(())))
        {
            let error = self
                .read_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(error) = error {
                return std::task::Poll::Ready(Err(error));
            }
        }
        result
    }
}

impl tokio::io::AsyncWrite for VmessConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn response_keys(key: &[u8; 16], iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let key_hash: [u8; 32] = Sha256::digest(key).into();
    let iv_hash: [u8; 32] = Sha256::digest(iv).into();
    (
        key_hash[..16].try_into().unwrap(),
        iv_hash[..16].try_into().unwrap(),
    )
}

fn selected_response_keys(key: &[u8; 16], iv: &[u8; 16], legacy: bool) -> ([u8; 16], [u8; 16]) {
    if legacy {
        (Md5::digest(key).into(), Md5::digest(iv).into())
    } else {
        response_keys(key, iv)
    }
}

fn record_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first: [u8; 16] = Md5::digest(key).into();
    let second: [u8; 16] = Md5::digest(first).into();
    let mut output = [0_u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

fn encode_target(output: &mut Vec<u8>, target: &Endpoint) -> Result<(), TransitError> {
    match target.host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Ok(std::net::IpAddr::V6(address)) => {
            output.push(3);
            output.extend_from_slice(&address.octets());
        }
        Err(_) => {
            if target.host.is_empty()
                || target.host.len() > 255
                || target
                    .host
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            {
                return Err(unsupported("VMess target hostname is invalid"));
            }
            output.push(2);
            output.push(target.host.len() as u8);
            output.extend_from_slice(target.host.as_bytes());
        }
    }
    Ok(())
}

struct VmessDatagram {
    stream: BoxedTransitConnection,
    sealed: Sealed,
    response_ready: bool,
    response_buffer: Vec<u8>,
    cfb_read: Option<CfbStream>,
    cfb_write: Option<CfbStream>,
    cfb_frame_length: Option<usize>,
    cfb_read_failed: bool,
    record_read: Option<RecordCodec>,
    record_write: Option<RecordCodec>,
    pending_record: Option<RecordHeader>,
    record_read_failed: bool,
    write_interrupted: bool,
}

impl std::fmt::Debug for VmessDatagram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VmessDatagram(..)")
    }
}

impl VmessDatagram {
    fn new(
        stream: BoxedTransitConnection,
        sealed: Sealed,
        cipher_kind: BodyCipherKind,
        framing: VmessFramingOptions,
    ) -> Self {
        let (resp_key, resp_iv) =
            selected_response_keys(&sealed.req_key, &sealed.req_iv, sealed.legacy);
        let cfb_read =
            (cipher_kind == BodyCipherKind::Aes128Cfb).then(|| CfbStream::new(&resp_key, &resp_iv));
        let cfb_write = (cipher_kind == BodyCipherKind::Aes128Cfb)
            .then(|| CfbStream::new(&sealed.req_key, &sealed.req_iv));
        let record_read = (cipher_kind != BodyCipherKind::Aes128Cfb).then(|| {
            RecordCodec::new(
                cipher_kind,
                &sealed.req_key,
                &sealed.req_iv,
                &resp_key,
                &resp_iv,
                framing,
            )
        });
        let record_write = (cipher_kind != BodyCipherKind::Aes128Cfb).then(|| {
            RecordCodec::new(
                cipher_kind,
                &sealed.req_key,
                &sealed.req_iv,
                &sealed.req_key,
                &sealed.req_iv,
                framing,
            )
        });
        Self {
            stream,
            sealed,
            response_ready: false,
            response_buffer: Vec::new(),
            cfb_read,
            cfb_write,
            cfb_frame_length: None,
            cfb_read_failed: false,
            record_read,
            record_write,
            pending_record: None,
            record_read_failed: false,
            write_interrupted: false,
        }
    }

    async fn ensure_response_header(&mut self) -> Result<(), TransitError> {
        if self.response_ready {
            return Ok(());
        }
        let (key, iv) = selected_response_keys(
            &self.sealed.req_key,
            &self.sealed.req_iv,
            self.sealed.legacy,
        );
        if self.sealed.legacy {
            self.fill_response_buffer(4, "VMess legacy response header is truncated")
                .await?;
            let cipher = decode_legacy_response_header(
                &self.response_buffer,
                &key,
                &iv,
                self.sealed.resp_v,
            )?;
            if self.cfb_read.is_some() {
                self.cfb_read = Some(cipher);
            }
            self.response_buffer.clear();
            self.response_ready = true;
            return Ok(());
        }
        self.fill_response_buffer(18, "VMess response header length is truncated")
            .await?;
        let header_len = decode_response_header_length(&self.response_buffer[..18], &key, &iv)?;
        self.fill_response_buffer(18 + header_len + 16, "VMess response header is truncated")
            .await?;
        verify_response_header(&self.response_buffer[18..], &key, &iv, self.sealed.resp_v)?;
        self.response_buffer.clear();
        self.response_ready = true;
        Ok(())
    }

    async fn fill_response_buffer(
        &mut self,
        needed: usize,
        error: &'static str,
    ) -> Result<(), TransitError> {
        while self.response_buffer.len() < needed {
            let mut chunk = [0_u8; 4096];
            let remaining = (needed - self.response_buffer.len()).min(chunk.len());
            // `read` is cancellation-safe: retain every completed read on the
            // datagram before awaiting the next chunk.
            let count = self
                .stream
                .read(&mut chunk[..remaining])
                .await
                .map_err(|_| protocol(error))?;
            if count == 0 {
                return Err(protocol(error));
            }
            self.response_buffer.extend_from_slice(&chunk[..count]);
        }
        Ok(())
    }
}

#[async_trait]
impl TransitDatagram for VmessDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        if self.write_interrupted {
            return Err(protocol("VMess UDP write was interrupted"));
        }
        if payload.len() > MAX_RECORD {
            return Err(unsupported("VMess UDP packet exceeds the frame limit"));
        }
        if let Some(cipher) = &mut self.cfb_write {
            self.write_interrupted = true;
            let frame = cfb_record(cipher, payload);
            self.stream
                .write_all(&frame)
                .await
                .map_err(|_| protocol("VMess UDP packet write failed"))?;
            self.stream
                .flush()
                .await
                .map_err(|_| protocol("VMess UDP packet flush failed"))?;
            self.write_interrupted = false;
            return Ok(());
        }
        self.write_interrupted = true;
        let encoded = self
            .record_write
            .as_mut()
            .expect("record encoder")
            .encode(payload)?;
        self.stream
            .write_all(&encoded)
            .await
            .map_err(|_| protocol("VMess UDP packet write failed"))?;
        self.stream
            .flush()
            .await
            .map_err(|_| protocol("VMess UDP packet flush failed"))?;
        self.write_interrupted = false;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        self.ensure_response_header().await?;
        if self.cfb_read_failed {
            return Err(protocol("VMess UDP response stream is invalid"));
        }
        if self.cfb_read.is_some() {
            if self.cfb_frame_length.is_none() {
                self.fill_response_buffer(2, "VMess UDP response length is truncated")
                    .await?;
                self.cfb_read
                    .as_mut()
                    .expect("CFB state")
                    .apply(&mut self.response_buffer, true);
                let length = usize::from(u16::from_be_bytes([
                    self.response_buffer[0],
                    self.response_buffer[1],
                ]));
                self.response_buffer.clear();
                if !(4..=MAX_RECORD + 4).contains(&length) {
                    self.cfb_read_failed = true;
                    return Err(protocol("VMess UDP response length is invalid"));
                }
                self.cfb_frame_length = Some(length);
            }
            let length = self.cfb_frame_length.expect("CFB frame length");
            self.fill_response_buffer(length, "VMess UDP response packet is truncated")
                .await?;
            self.cfb_read
                .as_mut()
                .expect("CFB state")
                .apply(&mut self.response_buffer, true);
            let payload = cfb_payload(&self.response_buffer);
            self.response_buffer.clear();
            self.cfb_frame_length = None;
            self.cfb_read_failed = payload.is_err();
            return payload;
        }
        if self.record_read_failed {
            return Err(protocol("VMess UDP response stream is invalid"));
        }
        if self.pending_record.is_none() {
            let length = self
                .record_read
                .as_ref()
                .expect("record decoder")
                .header_len();
            self.fill_response_buffer(length, "VMess UDP response length is truncated")
                .await?;
            let header = self
                .record_read
                .as_mut()
                .expect("record decoder")
                .decode_header(&self.response_buffer);
            self.response_buffer.clear();
            self.pending_record = match header {
                Ok(header) => Some(header),
                Err(error) => {
                    self.record_read_failed = true;
                    return Err(error);
                }
            };
        }
        let header = self.pending_record.expect("pending record");
        self.fill_response_buffer(
            header.ciphertext_len + header.padding_len,
            "VMess UDP response packet is truncated",
        )
        .await?;
        let payload = self
            .record_read
            .as_mut()
            .expect("record decoder")
            .decode_body(header, &self.response_buffer);
        self.response_buffer.clear();
        self.pending_record = None;
        self.record_read_failed = payload.is_err();
        payload
    }

    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        self.stream
            .shutdown()
            .await
            .map_err(|_| protocol("VMess UDP shutdown failed"))
    }
}

async fn read_optional_frame<S: tokio::io::AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    length: usize,
    message: &'static str,
) -> Result<Option<Vec<u8>>, TransitError> {
    if length == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut output = vec![0_u8; length];
    let count = stream
        .read(&mut output[..1])
        .await
        .map_err(|_| protocol(message))?;
    if count == 0 {
        return Ok(None);
    }
    stream
        .read_exact(&mut output[1..])
        .await
        .map_err(|_| protocol(message))?;
    Ok(Some(output))
}

async fn read_required_frame<S: tokio::io::AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    length: usize,
    message: &'static str,
) -> Result<Vec<u8>, TransitError> {
    read_optional_frame(stream, length, message)
        .await?
        .ok_or_else(|| protocol(message))
}

async fn read_response_header<S: tokio::io::AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    response_value: u8,
    legacy: bool,
) -> Result<Option<CfbStream>, TransitError> {
    if legacy {
        let mut header = [0_u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| protocol("VMess legacy response header is truncated"))?;
        return decode_legacy_response_header(&header, resp_key, resp_iv, response_value).map(Some);
    }
    let mut encrypted_length = [0_u8; 18];
    stream
        .read_exact(&mut encrypted_length)
        .await
        .map_err(|_| protocol("VMess response header length is truncated"))?;
    let header_len = decode_response_header_length(&encrypted_length, resp_key, resp_iv)?;
    let mut header = vec![0_u8; header_len + 16];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| protocol("VMess response header is truncated"))?;
    verify_response_header(&header, resp_key, resp_iv, response_value)?;
    Ok(None)
}

fn decode_legacy_response_header(
    encrypted: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
    response_value: u8,
) -> Result<CfbStream, TransitError> {
    let mut header: [u8; 4] = encrypted
        .try_into()
        .map_err(|_| protocol("VMess legacy response header is truncated"))?;
    let mut cipher = CfbStream::new(key, iv);
    cipher.apply(&mut header, true);
    if header[0] != response_value {
        return Err(protocol(
            "VMess legacy response authentication value is invalid",
        ));
    }
    if header[2] != 0 || header[3] != 0 {
        return Err(unsupported(
            "VMess legacy response commands are unsupported",
        ));
    }
    Ok(cipher)
}

fn decode_response_header_length(
    encrypted_length: &[u8],
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
) -> Result<usize, TransitError> {
    let length_key = kdf16(resp_key, &[b"AEAD Resp Header Len Key"]);
    let length_iv = kdf12(resp_iv, &[b"AEAD Resp Header Len IV"]);
    let length_plain = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|_| protocol("VMess response header length key failed"))?
        .decrypt(
            Nonce::from_slice(&length_iv),
            Payload {
                msg: encrypted_length,
                aad: &[],
            },
        )
        .map_err(|_| protocol("VMess response header length authentication failed"))?;
    if length_plain.len() != 2 {
        return Err(protocol("VMess response header length is invalid"));
    }
    let header_len = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
    if !(4..=1024).contains(&header_len) {
        return Err(protocol("VMess response header length is invalid"));
    }
    Ok(header_len)
}

fn verify_response_header(
    header: &[u8],
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    response_value: u8,
) -> Result<(), TransitError> {
    let header_key = kdf16(resp_key, &[b"AEAD Resp Header Key"]);
    let header_iv = kdf12(resp_iv, &[b"AEAD Resp Header IV"]);
    // VMess AEAD response headers always use AES-128-GCM, independently of
    // the security method selected for the body.
    let header_plain = Aes128Gcm::new_from_slice(&header_key)
        .map_err(|_| protocol("VMess response header key failed"))?
        .decrypt(Nonce::from_slice(&header_iv), header)
        .map_err(|_| protocol("VMess response header authentication failed"))?;
    if header_plain.first().copied() != Some(response_value) {
        return Err(protocol("VMess response authentication value is invalid"));
    }
    Ok(())
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}
fn protocol(message: &str) -> TransitError {
    TransitError::Protocol(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::process::Stdio;
    use tokio::process::Command;

    #[test]
    fn kdf_and_command_key_are_stable() {
        println!("kdf={:02x?}", kdf(b"key", &[b"label"]));
        assert_eq!(kdf(b"key", &[b"label"]), kdf(b"key", &[b"label"]));
        assert_ne!(kdf(b"key", &[b"label"]), [0; 32]);
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
        let uuid = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        assert_ne!(cmd_key(&uuid), [0; 16]);
    }

    #[test]
    fn legacy_authentication_matches_fixed_timestamp_vector() {
        let uuid = uuid::Uuid::parse_str("6cbf3f72-3417-4922-bde6-67820d041f25").unwrap();
        let alter = alter_key(uuid.as_bytes());
        assert_eq!(
            alter,
            [
                0x9f, 0x4c, 0x67, 0x3e, 0xcb, 0x44, 0xfd, 0xe6, 0x9c, 0x19, 0x27, 0xd9, 0x09, 0xc6,
                0x3e, 0xdd
            ]
        );
        let plain = b"legacy request header";
        let bytes = seal_legacy_request(
            &cmd_key(uuid.as_bytes()),
            &alter,
            1_700_000_000,
            plain.to_vec(),
        )
        .unwrap();
        assert_eq!(
            &bytes[..16],
            &[
                0x33, 0x5b, 0x5a, 0xb7, 0x4c, 0x3d, 0x13, 0xb9, 0xc4, 0x1c, 0x01, 0xee, 0xd1, 0x6e,
                0x44, 0xa3
            ]
        );
        let iv = [
            0x7a, 0x29, 0xd7, 0xbd, 0xc9, 0x72, 0xaa, 0xef, 0xb1, 0xf5, 0x4e, 0x52, 0x05, 0x58,
            0x9e, 0x78,
        ];
        let mut decoded = bytes[16..].to_vec();
        CfbStream::new(&cmd_key(uuid.as_bytes()), &iv).apply(&mut decoded, true);
        assert_eq!(decoded, plain);
    }

    #[test]
    fn native_credentials_accept_equivalent_vmess_cipher_aliases() {
        let config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("vmess-cipher-alias"),
            source: None,
            protocol: "vmess".into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 1,
            options: Default::default(),
        };
        let tls = crate::adapter_registry::native_tls_roots();
        let build = |aliases: &[(&str, &str)]| {
            let mut fields =
                BTreeMap::from([("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into())]);
            fields.extend(
                aliases
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string())),
            );
            VmessAdapter::from_config(
                &config,
                &TransitCredential::new(fields),
                Duration::from_secs(1),
                Arc::clone(&tls),
            )
        };
        for aliases in [
            &[("cipher", "chacha20-poly1305")][..],
            &[
                ("security", "chacha20-ietf-poly1305"),
                ("cipher", "CHACHA20-POLY1305"),
            ][..],
        ] {
            assert_eq!(
                build(aliases).unwrap().cipher,
                BodyCipherKind::ChaCha20Poly1305
            );
        }
        assert!(matches!(
            build(&[("security", "aes-128-gcm"), ("cipher", "none")]),
            Err(TransitError::Unsupported(reason)) if reason.contains("aliases conflict")
        ));
    }

    #[test]
    fn alter_id_is_bounded_and_rejects_invalid_values() {
        let config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("vmess-alter-bound"),
            source: None,
            protocol: "vmess".into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 1,
            options: Default::default(),
        };
        for (value, valid) in [
            ("0", true),
            ("1", true),
            ("65535", true),
            ("65536", false),
            ("", false),
            ("-1", false),
            ("+1", false),
            ("1.0", false),
            ("999999999999999999999", false),
        ] {
            let credential = TransitCredential::new(BTreeMap::from([
                ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
                ("alter_id".into(), value.into()),
            ]));
            let result = VmessAdapter::from_config(
                &config,
                &credential,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots(),
            );
            assert_eq!(result.is_ok(), valid, "alter_id={value:?}");
            if let Err(error) = result {
                assert!(matches!(error, TransitError::Unsupported(_)));
            }
        }
    }

    #[tokio::test]
    async fn legacy_udp_header_survives_cancellation_and_keeps_cfb_state() {
        let sealed = Sealed {
            bytes: Vec::new(),
            req_key: [0x21; 16],
            req_iv: [0x37; 16],
            resp_v: 0x42,
            command: 2,
            legacy: true,
        };
        let (key, iv) = selected_response_keys(&sealed.req_key, &sealed.req_iv, true);
        let mut cipher = CfbStream::new(&key, &iv);
        let mut header = [0x42, 1, 0, 0];
        cipher.apply(&mut header, false);
        let body = cfb_record(&mut cipher, b"reply");
        let (client, mut server) = tokio::io::duplex(128);
        let mut datagram = VmessDatagram::new(
            Box::new(client),
            sealed,
            BodyCipherKind::Aes128Cfb,
            VmessFramingOptions::default(),
        );
        server.write_all(&header[..2]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(10), datagram.receive())
                .await
                .is_err()
        );
        server.write_all(&header[2..]).await.unwrap();
        server.write_all(&body[..3]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(10), datagram.receive())
                .await
                .is_err()
        );
        server.write_all(&body[3..]).await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"reply");
    }

    #[test]
    fn legacy_response_rejects_bad_token_and_unsupported_command() {
        let key = [0x21; 16];
        let iv = [0x37; 16];
        for (mut header, expected_unsupported) in [
            ([0x41, 0, 0, 0], false),
            ([0x42, 0, 1, 5], true),
            ([0x42, 0, 0, 5], true),
        ] {
            CfbStream::new(&key, &iv).apply(&mut header, false);
            let result = decode_legacy_response_header(&header, &key, &iv, 0x42);
            assert!(matches!(result, Err(TransitError::Unsupported(_))) == expected_unsupported);
            if !expected_unsupported {
                assert!(matches!(result, Err(TransitError::Protocol(_))));
            }
        }
        assert!(matches!(
            decode_legacy_response_header(&[0, 1], &key, &iv, 0x42),
            Err(TransitError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn buffered_tcp_upload_flushes_partial_final_records() {
        for kind in [BodyCipherKind::Aes128Gcm, BodyCipherKind::Aes128Cfb] {
            let sealed = Sealed {
                bytes: Vec::new(),
                req_key: [0x21; 16],
                req_iv: [0x37; 16],
                resp_v: 0x42,
                command: 1,
                legacy: false,
            };
            let framing = VmessFramingOptions::default();
            let mut codec = (kind != BodyCipherKind::Aes128Cfb).then(|| {
                RecordCodec::new(
                    kind,
                    &sealed.req_key,
                    &sealed.req_iv,
                    &sealed.req_key,
                    &sealed.req_iv,
                    framing,
                )
            });
            let mut cfb = CfbStream::new(&sealed.req_key, &sealed.req_iv);
            let (upstream, mut peer) = tokio::io::duplex(8192);
            let buffered = tokio::io::BufWriter::with_capacity(8192, upstream);
            let mut stream = spawn_duplex(Box::new(buffered), sealed, kind, framing);
            let payload: Vec<_> = (0..131_071).map(|index| (index % 251) as u8).collect();
            let expected_len = payload.len();
            let mut peer_task = tokio::spawn(async move {
                let mut received = Vec::new();
                while received.len() < expected_len {
                    let mut length = [0; 2];
                    peer.read_exact(&mut length).await.unwrap();
                    if kind == BodyCipherKind::Aes128Cfb {
                        cfb.apply(&mut length, true);
                        let mut body = vec![0; u16::from_be_bytes(length) as usize];
                        peer.read_exact(&mut body).await.unwrap();
                        cfb.apply(&mut body, true);
                        received.extend(cfb_payload(&body).unwrap());
                    } else {
                        let codec = codec.as_mut().unwrap();
                        let header = codec.decode_header(&length).unwrap();
                        let mut body = vec![0; header.ciphertext_len + header.padding_len];
                        peer.read_exact(&mut body).await.unwrap();
                        received.extend(codec.decode_body(header, &body).unwrap());
                    }
                }
                received
            });
            let result = timeout(Duration::from_secs(2), async {
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
                (&mut peer_task).await.unwrap()
            })
            .await;
            drop(stream);
            if result.is_err() {
                peer_task.abort();
                let _ = peer_task.await;
            }
            assert_eq!(
                result.expect("a partial VMess record must be flushed before application shutdown"),
                payload
            );
        }
    }

    #[tokio::test]
    async fn legacy_tcp_response_errors_reach_the_caller() {
        for header in [[0x41, 0, 0, 0], [0x42, 0, 1, 5]] {
            let sealed = Sealed {
                bytes: Vec::new(),
                req_key: [0x21; 16],
                req_iv: [0x37; 16],
                resp_v: 0x42,
                command: 1,
                legacy: true,
            };
            let (key, iv) = selected_response_keys(&sealed.req_key, &sealed.req_iv, true);
            let mut encrypted = header;
            CfbStream::new(&key, &iv).apply(&mut encrypted, false);
            let (client, mut peer) = tokio::io::duplex(128);
            let mut stream = spawn_duplex(
                Box::new(client),
                sealed,
                BodyCipherKind::Aes128Cfb,
                VmessFramingOptions::default(),
            );
            peer.write_all(&encrypted).await.unwrap();
            let error = timeout(Duration::from_secs(1), stream.read_u8())
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            let message = error.to_string();
            assert!(message.contains(if header[0] == 0x41 {
                "authentication value"
            } else {
                "response commands"
            }));
        }
    }

    #[tokio::test]
    async fn tcp_aead_response_errors_reach_the_caller_but_clean_eof_does_not() {
        for mode in ["clean", "truncated", "tampered"] {
            let sealed = Sealed {
                bytes: Vec::new(),
                req_key: [0x21; 16],
                req_iv: [0x37; 16],
                resp_v: 0x42,
                command: 1,
                legacy: false,
            };
            let (resp_key, resp_iv) = response_keys(&sealed.req_key, &sealed.req_iv);
            let length_key = kdf16(&resp_key, &[b"AEAD Resp Header Len Key"]);
            let length_iv = kdf12(&resp_iv, &[b"AEAD Resp Header Len IV"]);
            let header_key = kdf16(&resp_key, &[b"AEAD Resp Header Key"]);
            let header_iv = kdf12(&resp_iv, &[b"AEAD Resp Header IV"]);
            let encrypted_length = Aes128Gcm::new_from_slice(&length_key)
                .unwrap()
                .encrypt(Nonce::from_slice(&length_iv), &[0, 4][..])
                .unwrap();
            let encrypted_header = Aes128Gcm::new_from_slice(&header_key)
                .unwrap()
                .encrypt(Nonce::from_slice(&header_iv), &[sealed.resp_v, 0, 0, 0][..])
                .unwrap();
            let mut codec = RecordCodec::new(
                BodyCipherKind::Aes128Gcm,
                &sealed.req_key,
                &sealed.req_iv,
                &resp_key,
                &resp_iv,
                VmessFramingOptions::default(),
            );
            let encoded = codec.encode(b"response").unwrap();
            let (client, mut peer) = tokio::io::duplex(4096);
            let mut stream = spawn_duplex(
                Box::new(client),
                sealed,
                BodyCipherKind::Aes128Gcm,
                VmessFramingOptions::default(),
            );
            peer.write_all(&encrypted_length).await.unwrap();
            peer.write_all(&encrypted_header).await.unwrap();
            match mode {
                "clean" => {
                    peer.write_all(&encoded).await.unwrap();
                    peer.shutdown().await.unwrap();
                    let mut output = [0; 8];
                    stream.read_exact(&mut output).await.unwrap();
                    assert_eq!(&output, b"response");
                    let mut one = [0; 1];
                    assert_eq!(stream.read(&mut one).await.unwrap(), 0);
                }
                "truncated" => {
                    peer.write_all(&encoded[..encoded.len() - 1]).await.unwrap();
                    peer.shutdown().await.unwrap();
                    let error = stream.read_u8().await.unwrap_err();
                    assert!(error.to_string().contains("record body is truncated"));
                }
                "tampered" => {
                    let mut corrupted = encoded;
                    corrupted[2] ^= 0x80;
                    peer.write_all(&corrupted).await.unwrap();
                    peer.shutdown().await.unwrap();
                    let error = stream.read_u8().await.unwrap_err();
                    assert!(
                        error.to_string().contains("record body authentication")
                            || error.to_string().contains("record length authentication")
                            || error.to_string().contains("response record authentication"),
                        "unexpected corruption error: {error}"
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    #[tokio::test]
    async fn tcp_cfb_response_checksum_and_truncation_reach_the_caller() {
        for corrupt in [false, true] {
            let sealed = Sealed {
                bytes: Vec::new(),
                req_key: [0x21; 16],
                req_iv: [0x37; 16],
                resp_v: 0x42,
                command: 1,
                legacy: false,
            };
            let (resp_key, resp_iv) = response_keys(&sealed.req_key, &sealed.req_iv);
            let length_key = kdf16(&resp_key, &[b"AEAD Resp Header Len Key"]);
            let length_iv = kdf12(&resp_iv, &[b"AEAD Resp Header Len IV"]);
            let header_key = kdf16(&resp_key, &[b"AEAD Resp Header Key"]);
            let header_iv = kdf12(&resp_iv, &[b"AEAD Resp Header IV"]);
            let encrypted_length = Aes128Gcm::new_from_slice(&length_key)
                .unwrap()
                .encrypt(Nonce::from_slice(&length_iv), &[0, 4][..])
                .unwrap();
            let encrypted_header = Aes128Gcm::new_from_slice(&header_key)
                .unwrap()
                .encrypt(Nonce::from_slice(&header_iv), &[sealed.resp_v, 0, 0, 0][..])
                .unwrap();
            let mut cfb = CfbStream::new(&resp_key, &resp_iv);
            let mut encoded = cfb_record(&mut cfb, b"cfb-response");
            if corrupt {
                encoded[3] ^= 0x40;
            } else {
                encoded.pop();
            }
            let (client, mut peer) = tokio::io::duplex(4096);
            let mut stream = spawn_duplex(
                Box::new(client),
                sealed,
                BodyCipherKind::Aes128Cfb,
                VmessFramingOptions::default(),
            );
            peer.write_all(&encrypted_length).await.unwrap();
            peer.write_all(&encrypted_header).await.unwrap();
            peer.write_all(&encoded).await.unwrap();
            peer.shutdown().await.unwrap();
            let error = stream.read_u8().await.unwrap_err();
            assert!(
                error.to_string().contains("CFB response body is truncated")
                    || error.to_string().contains("CFB response checksum failed"),
                "unexpected CFB error: {error}"
            );
        }
    }

    #[test]
    fn body_cipher_round_trips_aes_and_chacha_records() {
        let key = [9_u8; 16];
        let nonce = [3_u8; 12];
        for kind in [BodyCipherKind::Aes128Gcm, BodyCipherKind::ChaCha20Poly1305] {
            let cipher = BodyCipher::new(kind, &key);
            let encrypted = cipher.encrypt(&nonce, b"vmess body").unwrap();
            assert_eq!(cipher.decrypt(&nonce, &encrypted).unwrap(), b"vmess body");
        }
    }

    #[test]
    fn aes_cfb128_matches_nist_vector_across_fragment_boundaries() {
        fn bytes(hex: &str) -> Vec<u8> {
            hex.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
                .collect()
        }
        let key: [u8; 16] = bytes("2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();
        let iv: [u8; 16] = bytes("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plain = bytes(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        ));
        let expected = bytes(concat!(
            "3b3fd92eb72dad20333449f8e83cfb4a",
            "c8a64537a0b3a93fcde3cdad9f1ce58b",
            "26751f67a3cbb140b1808cf187a4f4df",
            "c04b05357c5d1c0eeac4c66f9ff7f2e6",
        ));
        let mut ciphertext = plain.clone();
        let mut encrypt = CfbStream::new(&key, &iv);
        for fragment in ciphertext.chunks_mut(7) {
            encrypt.apply(fragment, false);
        }
        assert_eq!(ciphertext, expected);
        let mut decrypt = CfbStream::new(&key, &iv);
        for fragment in ciphertext.chunks_mut(3) {
            decrypt.apply(fragment, true);
        }
        assert_eq!(ciphertext, plain);
    }

    #[test]
    fn authenticated_record_framing_rejects_tampering_and_nonce_reuse() {
        let req_key = [0x21; 16];
        let req_iv = [0x37; 16];
        let (body_key, body_iv) = response_keys(&req_key, &req_iv);
        let framing = VmessFramingOptions {
            global_padding: true,
            authenticated_length: true,
        };
        for kind in [BodyCipherKind::Aes128Gcm, BodyCipherKind::ChaCha20Poly1305] {
            let make = || RecordCodec::new(kind, &req_key, &req_iv, &body_key, &body_iv, framing);
            let mut sender = make();
            let frame = sender.encode(b"protected data").unwrap();
            let mut bad_length = frame[..18].to_vec();
            bad_length[0] ^= 1;
            let mut receiver = make();
            assert!(
                matches!(receiver.decode_header(&bad_length), Err(TransitError::Protocol(reason)) if reason.contains("length authentication"))
            );
            assert!(receiver.decode_header(&frame[..18]).is_err());

            let mut receiver = make();
            let header = receiver.decode_header(&frame[..18]).unwrap();
            let mut bad_body = frame[18..].to_vec();
            bad_body[0] ^= 1;
            assert!(
                matches!(receiver.decode_body(header, &bad_body), Err(TransitError::Protocol(reason)) if reason.contains("record authentication"))
            );
            assert!(receiver.decode_header(&frame[..18]).is_err());

            let mut receiver = make();
            let header = receiver.decode_header(&frame[..18]).unwrap();
            assert!(
                matches!(receiver.decode_body(header, &frame[18..frame.len()-1]), Err(TransitError::Protocol(reason)) if reason.contains("body length"))
            );

            let mut sender = make();
            sender.counter = u16::MAX.into();
            let final_frame = sender.encode(b"last").unwrap();
            assert!(
                matches!(sender.encode(b"reused"), Err(TransitError::Protocol(reason)) if reason.contains("nonce exhausted"))
            );
            let mut receiver = make();
            receiver.counter = u16::MAX.into();
            let header = receiver.decode_header(&final_frame[..18]).unwrap();
            assert_eq!(
                receiver.decode_body(header, &final_frame[18..]).unwrap(),
                b"last"
            );
            assert!(receiver.decode_header(&final_frame[..18]).is_err());
        }
    }

    #[test]
    fn masked_record_rejects_invalid_padding_length() {
        let key = [0x21; 16];
        let iv = [0x37; 16];
        let framing = VmessFramingOptions {
            global_padding: true,
            authenticated_length: false,
        };
        let make = || RecordCodec::new(BodyCipherKind::Aes128Gcm, &key, &iv, &key, &iv, framing);
        let mut oracle = make();
        let padding = oracle.next_shake() % 64;
        let mask = oracle.next_shake();
        let invalid = padding.saturating_sub(1) ^ mask;
        let mut receiver = make();
        assert!(receiver.decode_header(&invalid.to_be_bytes()).is_err());
        assert!(receiver.decode_header(&invalid.to_be_bytes()).is_err());
    }

    #[test]
    fn framing_options_are_validated_before_dialing() {
        let mut config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("vmess-framing-test"),
            source: None,
            protocol: "vmess".into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 1,
            options: Default::default(),
        };
        for (global_padding, authenticated_length) in [(true, false), (false, true), (true, true)] {
            config.options.vmess = Some(pathchord_policy::TransitVmessOptions {
                global_padding,
                authenticated_length,
            });
            for security in ["none", "zero", "aes-128-cfb"] {
                let credential = TransitCredential::new(BTreeMap::from([
                    ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
                    ("security".into(), security.into()),
                ]));
                assert!(
                    matches!(VmessAdapter::from_config(&config, &credential, Duration::from_secs(1), crate::adapter_registry::native_tls_roots()), Err(TransitError::Unsupported(reason)) if reason.contains("AEAD")),
                    "{security}"
                );
            }
        }
    }

    #[test]
    fn meek_private_url_is_consumed_only_by_meek_transport() {
        let mut config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("vmess-meek-test"),
            source: None,
            protocol: "vmess".into(),
            endpoint: pathchord_policy::Endpoint {
                host: "example.test".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 1,
            options: pathchord_policy::TransitOptions {
                tls: Some(pathchord_policy::TransitTls {
                    enabled: true,
                    truststore: Vec::new(),
                    ..Default::default()
                }),
                transport: Some(pathchord_policy::TransitTransport {
                    kind: "meek".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credential = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
            ("meek_url".into(), "https://example.test/meek".into()),
        ]));
        assert!(
            VmessAdapter::from_config(
                &config,
                &credential,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots()
            )
            .is_ok()
        );
        config.options.transport = None;
        assert!(matches!(
            VmessAdapter::from_config(
                &config,
                &credential,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots()
            ),
            Err(TransitError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn udp_receive_preserves_partial_header_and_packets_when_cancelled() {
        let default = VmessFramingOptions::default();
        let padded = VmessFramingOptions {
            global_padding: true,
            authenticated_length: false,
        };
        let authenticated = VmessFramingOptions {
            global_padding: false,
            authenticated_length: true,
        };
        let both = VmessFramingOptions {
            global_padding: true,
            authenticated_length: true,
        };
        for (kind, framing) in [
            (BodyCipherKind::Aes128Gcm, default),
            (BodyCipherKind::ChaCha20Poly1305, default),
            (BodyCipherKind::Aes128Cfb, default),
            (BodyCipherKind::Plain, default),
            (BodyCipherKind::Aes128Gcm, padded),
            (BodyCipherKind::Aes128Gcm, authenticated),
            (BodyCipherKind::Aes128Gcm, both),
            (BodyCipherKind::ChaCha20Poly1305, padded),
            (BodyCipherKind::ChaCha20Poly1305, authenticated),
            (BodyCipherKind::ChaCha20Poly1305, both),
        ] {
            let sealed = Sealed {
                bytes: Vec::new(),
                req_key: [0x21; 16],
                req_iv: [0x37; 16],
                resp_v: 0x42,
                command: 2,
                legacy: false,
            };
            let (resp_key, resp_iv) = response_keys(&sealed.req_key, &sealed.req_iv);
            let length_key = kdf16(&resp_key, &[b"AEAD Resp Header Len Key"]);
            let length_iv = kdf12(&resp_iv, &[b"AEAD Resp Header Len IV"]);
            let header_key = kdf16(&resp_key, &[b"AEAD Resp Header Key"]);
            let header_iv = kdf12(&resp_iv, &[b"AEAD Resp Header IV"]);
            let encrypted_length = Aes128Gcm::new_from_slice(&length_key)
                .unwrap()
                .encrypt(Nonce::from_slice(&length_iv), &[0, 4][..])
                .unwrap();
            let encrypted_header = Aes128Gcm::new_from_slice(&header_key)
                .unwrap()
                .encrypt(Nonce::from_slice(&header_iv), &[sealed.resp_v, 0, 0, 0][..])
                .unwrap();
            let mut codec = (kind != BodyCipherKind::Aes128Cfb).then(|| {
                RecordCodec::new(
                    kind,
                    &sealed.req_key,
                    &sealed.req_iv,
                    &resp_key,
                    &resp_iv,
                    framing,
                )
            });
            let mut cfb =
                (kind == BodyCipherKind::Aes128Cfb).then(|| CfbStream::new(&resp_key, &resp_iv));
            let mut wire = [encrypted_length, encrypted_header].concat();
            let header_end = wire.len();
            for payload in [b"first response".as_slice(), b"second response"] {
                if let Some(cfb) = cfb.as_mut() {
                    wire.extend_from_slice(&cfb_record(cfb, payload));
                } else {
                    wire.extend_from_slice(&codec.as_mut().unwrap().encode(payload).unwrap());
                }
            }
            let (client, mut server) = tokio::io::duplex(4096);
            let mut datagram = VmessDatagram::new(Box::new(client), sealed, kind, framing);
            let mut start = 0;
            let length_bytes = if framing.authenticated_length { 18 } else { 2 };
            let mut cuts = vec![7, 23, header_end + 1];
            if length_bytes > 2 {
                cuts.push(header_end + length_bytes - 1);
            }
            cuts.push(header_end + length_bytes + 3);
            for end in cuts {
                server.write_all(&wire[start..end]).await.unwrap();
                start = end;
                assert!(
                    tokio::time::timeout(Duration::from_millis(10), datagram.receive())
                        .await
                        .is_err(),
                    "{kind:?}: incomplete response must remain pending"
                );
                datagram.send(b"request while reading").await.unwrap();
            }
            server.write_all(&wire[start..]).await.unwrap();
            assert_eq!(
                datagram.receive().await.unwrap(),
                b"first response",
                "{kind:?}"
            );
            assert_eq!(
                datagram.receive().await.unwrap(),
                b"second response",
                "{kind:?}"
            );
        }
    }

    #[tokio::test]
    async fn udp_receive_preserves_authentication_and_truncation_errors_after_cancellation() {
        for truncated in [false, true] {
            let sealed = Sealed {
                bytes: Vec::new(),
                req_key: [0x21; 16],
                req_iv: [0x37; 16],
                resp_v: 0x42,
                command: 2,
                legacy: false,
            };
            let (key, iv) = response_keys(&sealed.req_key, &sealed.req_iv);
            let mut encoded =
                Aes128Gcm::new_from_slice(&kdf16(&key, &[b"AEAD Resp Header Len Key"]))
                    .unwrap()
                    .encrypt(
                        Nonce::from_slice(&kdf12(&iv, &[b"AEAD Resp Header Len IV"])),
                        &[0, 4][..],
                    )
                    .unwrap();
            encoded[17] ^= 1;
            let (client, mut server) = tokio::io::duplex(128);
            let mut datagram = VmessDatagram::new(
                Box::new(client),
                sealed,
                BodyCipherKind::Aes128Gcm,
                VmessFramingOptions::default(),
            );
            server.write_all(&encoded[..7]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(10), datagram.receive())
                    .await
                    .is_err()
            );
            if !truncated {
                server.write_all(&encoded[7..]).await.unwrap();
            }
            server.shutdown().await.unwrap();
            let expected = if truncated {
                "VMess response header length is truncated"
            } else {
                "VMess response header length authentication failed"
            };
            assert!(
                matches!(datagram.receive().await, Err(TransitError::Protocol(reason)) if reason == expected)
            );
        }
    }

    #[tokio::test]
    async fn udp_cfb_rejects_corrupt_checksum_and_closes_decoder() {
        let sealed = Sealed {
            bytes: Vec::new(),
            req_key: [0x21; 16],
            req_iv: [0x37; 16],
            resp_v: 0x42,
            command: 2,
            legacy: false,
        };
        let (key, iv) = response_keys(&sealed.req_key, &sealed.req_iv);
        let mut response = cfb_record(&mut CfbStream::new(&key, &iv), b"corrupt");
        response[6] ^= 1;
        let (client, mut server) = tokio::io::duplex(128);
        let mut datagram = VmessDatagram::new(
            Box::new(client),
            sealed,
            BodyCipherKind::Aes128Cfb,
            VmessFramingOptions::default(),
        );
        datagram.response_ready = true;
        server.write_all(&response).await.unwrap();
        assert!(matches!(
            datagram.receive().await,
            Err(TransitError::Protocol(reason)) if reason == "VMess CFB response checksum failed"
        ));
        assert!(matches!(
            datagram.receive().await,
            Err(TransitError::Protocol(reason)) if reason == "VMess UDP response stream is invalid"
        ));
    }

    #[tokio::test]
    async fn cancelled_udp_write_cannot_reuse_a_partial_frame_or_nonce() {
        use std::{
            future::Future,
            pin::pin,
            task::{Context, Poll, Waker},
        };
        for kind in [
            BodyCipherKind::Aes128Gcm,
            BodyCipherKind::Aes128Cfb,
            BodyCipherKind::Plain,
        ] {
            let sealed = Sealed {
                bytes: Vec::new(),
                req_key: [0x21; 16],
                req_iv: [0x37; 16],
                resp_v: 0x42,
                command: 2,
                legacy: false,
            };
            let (stream, _peer) = tokio::io::duplex(1);
            let mut datagram = VmessDatagram::new(
                Box::new(stream),
                sealed,
                kind,
                VmessFramingOptions::default(),
            );
            {
                let mut send = pin!(datagram.send(b"partially-written"));
                assert!(matches!(
                    send.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Pending
                ));
            }
            assert!(
                matches!(datagram.send(b"next").await, Err(TransitError::Protocol(reason)) if reason.contains("interrupted"))
            );
        }
    }

    #[tokio::test]
    async fn packetaddr_preserves_bound_ipv4_ipv6_and_rejects_wrong_sources() {
        #[derive(Debug)]
        struct PacketFixture {
            sent: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
            replies: std::collections::VecDeque<Vec<u8>>,
        }
        #[async_trait]
        impl TransitDatagram for PacketFixture {
            async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
                self.sent.lock().unwrap().push(payload.to_vec());
                Ok(())
            }
            async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
                self.replies
                    .pop_front()
                    .ok_or_else(|| protocol("fixture exhausted"))
            }
        }
        for (host, header) in [
            ("192.0.2.1", vec![1, 192, 0, 2, 1, 0, 53]),
            (
                "2001:db8::1",
                vec![
                    2, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53,
                ],
            ),
        ] {
            let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut valid = header.clone();
            valid.extend_from_slice(b"answer");
            let mut wrong = header.clone();
            *wrong.last_mut().unwrap() ^= 1;
            let fixture = PacketFixture {
                sent: Arc::clone(&sent),
                replies: [valid, wrong, vec![1, 0]].into(),
            };
            let mut datagram = PacketAddrDatagram::new(
                Box::new(fixture),
                Endpoint {
                    host: host.into(),
                    port: 53,
                },
                MAX_RECORD,
            )
            .unwrap();
            datagram.send(b"request").await.unwrap();
            assert_eq!(
                sent.lock().unwrap()[0],
                [header, b"request".to_vec()].concat()
            );
            assert_eq!(datagram.receive().await.unwrap(), b"answer");
            assert!(
                matches!(datagram.receive().await, Err(TransitError::Protocol(reason)) if reason.contains("differs"))
            );
            assert!(
                matches!(datagram.receive().await, Err(TransitError::Protocol(reason)) if reason.contains("invalid"))
            );
            assert!(matches!(
                datagram.send(&vec![0; MAX_RECORD]).await,
                Err(TransitError::Unsupported(_))
            ));
        }
    }

    #[tokio::test]
    async fn packetaddr_rejects_domains_before_dial_and_keeps_tcp_eligible() {
        let mut config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("packetaddr-domain"),
            source: None,
            protocol: "vmess".into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port: 9,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 1,
            options: Default::default(),
        };
        config.options.packet_encoding = Some("packetaddr".into());
        let credential = TransitCredential::new(BTreeMap::from([(
            "uuid".into(),
            "6cbf3f72-3417-4922-bde6-67820d041f25".into(),
        )]));
        let adapter = VmessAdapter::from_config(
            &config,
            &credential,
            Duration::from_secs(1),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        let result = adapter
            .connect_udp(ConnectRequest {
                destination: Endpoint {
                    host: "example.test".into(),
                    port: 53,
                },
            })
            .await;
        assert!(
            matches!(result, Err(TransitError::Unsupported(reason)) if reason.contains("IP destination"))
        );
        config.options.packet_encoding = Some("unsupported".into());
        assert!(
            matches!(VmessAdapter::from_config(&config, &credential, Duration::from_secs(1), crate::adapter_registry::native_tls_roots()), Err(TransitError::Unsupported(reason)) if reason.contains("packet encoding"))
        );
    }

    async fn legacy_peer_matrix(binary: PathBuf, sing_box: bool) {
        let uuid = "6cbf3f72-3417-4922-bde6-67820d041f25";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let document = if sing_box {
            json!({"log":{"disabled":true},"inbounds":[{"type":"vmess","listen":"127.0.0.1","listen_port":port,"users":[{"uuid":uuid,"alterId":4}]}],"outbounds":[{"type":"direct"}]})
        } else {
            json!({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vmess","settings":{"clients":[{"id":uuid,"alterId":4}]}}],"outbounds":[{"protocol":"freedom"}]})
        };
        let mut nonce = [0_u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-vmess-peer-{}-{:x}.json",
            std::process::id(),
            u64::from_ne_bytes(nonce)
        ));
        struct ConfigFile(PathBuf);
        impl Drop for ConfigFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let file = ConfigFile(path);
        tokio::fs::write(&file.0, serde_json::to_vec(&document).unwrap())
            .await
            .unwrap();
        let mut command = Command::new(binary);
        command
            .arg("run")
            .arg("-c")
            .arg(&file.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if !sing_box {
            command.env("v2ray.vmess.aead.forced", "false");
        }
        let mut server = command.spawn().unwrap();
        timeout(Duration::from_secs(10), async {
            loop {
                assert!(
                    server.try_wait().unwrap().is_none(),
                    "VMess reference server exited"
                );
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("VMess reference server startup timed out");
        let config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("vmess-legacy-peer"),
            source: None,
            protocol: "vmess".into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 1,
            options: Default::default(),
        };
        for alter_id in ["1", "4"] {
            for (security, padding, authenticated_length) in [
                ("aes-128-gcm", false, false),
                ("chacha20-poly1305", false, false),
                ("aes-128-cfb", false, false),
                ("none", false, false),
                ("zero", false, false),
                ("aes-128-gcm", true, false),
                ("aes-128-gcm", false, true),
                ("aes-128-gcm", true, true),
                ("chacha20-poly1305", true, false),
                ("chacha20-poly1305", false, true),
                ("chacha20-poly1305", true, true),
            ] {
                let credential = TransitCredential::new(BTreeMap::from([
                    ("uuid".into(), uuid.into()),
                    ("alter_id".into(), alter_id.into()),
                    ("security".into(), security.into()),
                ]));
                let mut configured = config.clone();
                configured.options.vmess = Some(pathchord_policy::TransitVmessOptions {
                    global_padding: padding,
                    authenticated_length,
                });
                let adapter = VmessAdapter::from_config(
                    &configured,
                    &credential,
                    Duration::from_secs(5),
                    crate::adapter_registry::native_tls_roots(),
                )
                .unwrap();
                let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = target.local_addr().unwrap();
                let echo = tokio::spawn(async move {
                    let (mut stream, _) = target.accept().await.unwrap();
                    let mut bytes = vec![0; 32_000];
                    stream.read_exact(&mut bytes).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                });
                let mut stream = adapter
                    .connect(ConnectRequest {
                        destination: Endpoint {
                            host: address.ip().to_string(),
                            port: address.port(),
                        },
                    })
                    .await
                    .unwrap();
                let payload: Vec<u8> = (0..32_000).map(|i| (i % 251) as u8).collect();
                stream.write_all(&payload).await.unwrap();
                let mut received = vec![0; payload.len()];
                timeout(Duration::from_secs(5), stream.read_exact(&mut received))
                    .await
                    .unwrap_or_else(|_| panic!("{security} alter_id={alter_id} TCP timed out"))
                    .unwrap_or_else(|error| {
                        panic!("{security} alter_id={alter_id} TCP failed: {error}")
                    });
                assert_eq!(received, payload, "{security} alter_id={alter_id}");
                echo.await.unwrap();

                let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let address = udp.local_addr().unwrap();
                let echo = tokio::spawn(async move {
                    let mut buf = [0; 4096];
                    for _ in 0..2 {
                        let (size, peer) = udp.recv_from(&mut buf).await.unwrap();
                        udp.send_to(&buf[..size], peer).await.unwrap();
                    }
                });
                let mut datagram = adapter
                    .connect_udp(ConnectRequest {
                        destination: Endpoint {
                            host: address.ip().to_string(),
                            port: address.port(),
                        },
                    })
                    .await
                    .unwrap();
                let packet = vec![0x71; if sing_box { 2048 } else { 1024 }];
                for payload in [b"vmess-legacy".as_slice(), packet.as_slice()] {
                    datagram.send(payload).await.unwrap();
                    let received = timeout(Duration::from_secs(5), datagram.receive())
                        .await
                        .unwrap_or_else(|_| panic!("{security} alter_id={alter_id} UDP timed out"))
                        .unwrap_or_else(|error| {
                            panic!("{security} alter_id={alter_id} UDP failed: {error}")
                        });
                    assert_eq!(received, payload, "{security} alter_id={alter_id}");
                }
                datagram.close().await.unwrap();
                echo.await.unwrap();
            }
        }
        if sing_box {
            for encoding in ["xudp", "packetaddr"] {
                let mut configured = config.clone();
                configured.options.packet_encoding = Some(encoding.into());
                let credential = TransitCredential::new(BTreeMap::from([
                    ("uuid".into(), uuid.into()),
                    ("alter_id".into(), "1".into()),
                    ("security".into(), "aes-128-cfb".into()),
                ]));
                let adapter = VmessAdapter::from_config(
                    &configured,
                    &credential,
                    Duration::from_secs(5),
                    crate::adapter_registry::native_tls_roots(),
                )
                .unwrap();
                let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let address = target.local_addr().unwrap();
                let echo = tokio::spawn(async move {
                    let mut packet = [0; 256];
                    let (size, peer) = target.recv_from(&mut packet).await.unwrap();
                    target.send_to(&packet[..size], peer).await.unwrap();
                });
                let mut datagram = adapter
                    .connect_udp(ConnectRequest {
                        destination: Endpoint {
                            host: address.ip().to_string(),
                            port: address.port(),
                        },
                    })
                    .await
                    .unwrap();
                datagram.send(b"legacy-encoded-udp").await.unwrap();
                assert_eq!(
                    timeout(Duration::from_secs(5), datagram.receive())
                        .await
                        .unwrap()
                        .unwrap(),
                    b"legacy-encoded-udp",
                    "{encoding}"
                );
                datagram.close().await.unwrap();
                echo.await.unwrap();
            }
            let wrong = TransitCredential::new(BTreeMap::from([
                ("uuid".into(), "11111111-1111-1111-1111-111111111111".into()),
                ("alter_id".into(), "1".into()),
            ]));
            let adapter = VmessAdapter::from_config(
                &config,
                &wrong,
                Duration::from_secs(5),
                crate::adapter_registry::native_tls_roots(),
            )
            .unwrap();
            let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = target.local_addr().unwrap();
            let mut datagram = adapter
                .connect_udp(ConnectRequest {
                    destination: Endpoint {
                        host: address.ip().to_string(),
                        port: address.port(),
                    },
                })
                .await
                .unwrap();
            let sent = datagram.send(b"must-not-arrive").await;
            if sent.is_ok() {
                assert!(
                    timeout(Duration::from_secs(5), datagram.receive())
                        .await
                        .unwrap()
                        .is_err()
                );
            } else {
                assert!(matches!(sent, Err(TransitError::Protocol(_))));
            }
            let mut packet = [0; 128];
            assert!(
                timeout(Duration::from_millis(100), target.recv_from(&mut packet))
                    .await
                    .is_err()
            );
        }
        server.kill().await.unwrap();
        server.wait().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_vmess_alter_id_interoperates_with_sing_box() {
        timeout(
            Duration::from_secs(60),
            legacy_peer_matrix(
                PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").unwrap()),
                true,
            ),
        )
        .await
        .expect("sing-box legacy VMess matrix timed out");
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_V2FLY pointing to a V2Fly server binary"]
    async fn native_vmess_alter_id_interoperates_with_v2fly() {
        timeout(
            Duration::from_secs(60),
            legacy_peer_matrix(
                PathBuf::from(std::env::var_os("PATHCHORD_TEST_V2FLY").unwrap()),
                false,
            ),
        )
        .await
        .expect("V2Fly legacy VMess matrix timed out");
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_vmess_tcp_interoperates_with_sing_box() {
        let binary =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference engine"));
        let uuid = "6cbf3f72-3417-4922-bde6-67820d041f25";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let inbound = json!({
            "type": "vmess",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"uuid": uuid}]
        });
        let mut config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("vmess-test"),
            source: None,
            protocol: "vmess".into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: Default::default(),
        };
        let body = serde_json::to_vec(&json!({
            "log": {"disabled": true},
            "inbounds": [inbound],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
        }))
        .unwrap();
        let mut server = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg("stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        server.stdin.take().unwrap().write_all(&body).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "reference readiness"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let default = VmessFramingOptions::default();
        let padded = VmessFramingOptions {
            global_padding: true,
            authenticated_length: false,
        };
        let authenticated = VmessFramingOptions {
            global_padding: false,
            authenticated_length: true,
        };
        let both = VmessFramingOptions {
            global_padding: true,
            authenticated_length: true,
        };
        for (security, framing) in [
            ("aes-128-gcm", default),
            ("chacha20-poly1305", default),
            ("none", default),
            ("zero", default),
            ("aes-128-cfb", default),
            ("aes-128-gcm", padded),
            ("aes-128-gcm", authenticated),
            ("aes-128-gcm", both),
            ("chacha20-poly1305", padded),
            ("chacha20-poly1305", authenticated),
            ("chacha20-poly1305", both),
        ] {
            let credentials = TransitCredential::new(BTreeMap::from([
                ("uuid".into(), uuid.into()),
                ("security".into(), security.into()),
            ]));
            let mut configured = config.clone();
            configured.options.vmess = Some(pathchord_policy::TransitVmessOptions {
                global_padding: framing.global_padding,
                authenticated_length: framing.authenticated_length,
            });
            let adapter = VmessAdapter::from_config(
                &configured,
                &credentials,
                Duration::from_secs(3),
                crate::adapter_registry::native_tls_roots(),
            )
            .unwrap();
            let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = target.local_addr().unwrap();
            let expected: Vec<u8> = (0..50_000).map(|index| (index % 251) as u8).collect();
            let expected_len = expected.len();
            let target_task = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut payload = vec![0; expected_len];
                stream.read_exact(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            });
            let mut stream = adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "127.0.0.1".into(),
                        port: target_addr.port(),
                    },
                })
                .await
                .unwrap();
            stream.write_all(&expected).await.unwrap();
            stream.flush().await.unwrap();
            let mut output = vec![0; expected_len];
            tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut output))
                .await
                .unwrap_or_else(|_| panic!("{security} TCP response timed out"))
                .unwrap_or_else(|error| panic!("{security} TCP response failed: {error}"));
            assert_eq!(output, expected, "{security}");
            target_task.await.unwrap();

            let udp_target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_address = udp_target.local_addr().unwrap();
            let udp_task = tokio::spawn(async move {
                let mut payload = [0_u8; 4096];
                for _ in 0..3 {
                    let (length, peer) = udp_target.recv_from(&mut payload).await.unwrap();
                    udp_target.send_to(&payload[..length], peer).await.unwrap();
                }
            });
            let mut datagram = adapter
                .connect_udp(ConnectRequest {
                    destination: Endpoint {
                        host: "127.0.0.1".into(),
                        port: udp_address.port(),
                    },
                })
                .await
                .unwrap();
            let large = vec![0x53; 4096];
            for payload in [b"first".as_slice(), b"second".as_slice(), large.as_slice()] {
                datagram.send(payload).await.unwrap();
                let response = tokio::time::timeout(Duration::from_secs(3), datagram.receive())
                    .await
                    .unwrap_or_else(|_| panic!("{security} UDP response timed out"))
                    .unwrap_or_else(|error| panic!("{security} UDP response failed: {error}"));
                assert_eq!(response, payload, "{security}");
            }
            datagram.close().await.unwrap();
            udp_task.await.unwrap();
        }
        for encoding in ["xudp", "packetaddr"] {
            config.options.packet_encoding = Some(encoding.into());
            let credential = TransitCredential::new(BTreeMap::from([("uuid".into(), uuid.into())]));
            let tcp_adapter = VmessAdapter::from_config(
                &config,
                &credential,
                Duration::from_secs(5),
                crate::adapter_registry::native_tls_roots(),
            )
            .unwrap();
            let tcp_target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_address = tcp_target.local_addr().unwrap();
            let tcp_echo = tokio::spawn(async move {
                let (mut stream, _) = tcp_target.accept().await.unwrap();
                let mut payload = [0; 3];
                stream.read_exact(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            });
            let mut stream = tcp_adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: tcp_address.ip().to_string(),
                        port: tcp_address.port(),
                    },
                })
                .await
                .unwrap();
            stream.write_all(b"tcp").await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0; 3];
            timeout(Duration::from_secs(3), stream.read_exact(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&response, b"tcp");
            tcp_echo.await.unwrap();
            for (security, framing) in [
                ("aes-128-gcm", default),
                ("chacha20-poly1305", default),
                ("aes-128-cfb", default),
                ("none", default),
                ("aes-128-gcm", both),
                ("chacha20-poly1305", both),
            ] {
                config.options.vmess = Some(pathchord_policy::TransitVmessOptions {
                    global_padding: framing.global_padding,
                    authenticated_length: framing.authenticated_length,
                });
                let credential = TransitCredential::new(BTreeMap::from([
                    ("uuid".into(), uuid.into()),
                    ("security".into(), security.into()),
                ]));
                let adapter = VmessAdapter::from_config(
                    &config,
                    &credential,
                    Duration::from_secs(5),
                    crate::adapter_registry::native_tls_roots(),
                )
                .unwrap();
                for host in ["127.0.0.1", "::1"] {
                    let udp = tokio::net::UdpSocket::bind((host, 0)).await.unwrap();
                    let address = udp.local_addr().unwrap();
                    let echo = tokio::spawn(async move {
                        let mut buffer = [0; 8192];
                        for _ in 0..3 {
                            let (size, source) = udp.recv_from(&mut buffer).await.unwrap();
                            udp.send_to(&buffer[..size], source).await.unwrap();
                        }
                    });
                    let mut datagram = adapter
                        .connect_udp(ConnectRequest {
                            destination: Endpoint {
                                host: address.ip().to_string(),
                                port: address.port(),
                            },
                        })
                        .await
                        .unwrap();
                    let large = vec![0x73; 4096];
                    for payload in [b"first".as_slice(), b"second", large.as_slice()] {
                        datagram.send(payload).await.unwrap();
                        assert_eq!(
                            timeout(Duration::from_secs(3), datagram.receive())
                                .await
                                .unwrap()
                                .unwrap(),
                            payload,
                            "{security} {encoding}"
                        );
                    }
                    datagram.close().await.unwrap();
                    echo.await.unwrap();
                }
            }
        }
        config.options.packet_encoding = Some("xudp".into());
        config.options.vmess = None;
        let credential = TransitCredential::new(BTreeMap::from([("uuid".into(), uuid.into())]));
        let adapter = VmessAdapter::from_config(
            &config,
            &credential,
            Duration::from_secs(5),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut packet = [0; 32];
            let (size, source) = udp.recv_from(&mut packet).await.unwrap();
            udp.send_to(&packet[..size], source).await.unwrap();
        });
        let mut datagram = adapter
            .connect_udp(ConnectRequest {
                destination: Endpoint {
                    host: "localhost".into(),
                    port,
                },
            })
            .await
            .unwrap();
        datagram.send(b"domain").await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), datagram.receive())
                .await
                .unwrap()
                .unwrap(),
            b"domain"
        );
        datagram.close().await.unwrap();
        echo.await.unwrap();
        server.kill().await.unwrap();
        server.wait().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_vmess_tls_websocket_and_udp_interoperate_with_sing_box() {
        let binary =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference engine"));
        let uuid = "6cbf3f72-3417-4922-bde6-67820d041f25";
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["vmess.test".into()]).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let document = json!({
            "log": {"disabled": true},
            "inbounds": [{
                "type": "vmess",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"uuid": uuid, "alterId": 4}],
                "tls": {"enabled": true, "certificate": cert.pem(), "key": signing_key.serialize_pem()},
                "transport": {"type": "ws", "path": "/vmess"}
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
        });
        let mut server = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg("stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        server
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&document).unwrap())
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "reference readiness"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("vmess-modern-test"),
            source: None,
            protocol: "vmess".into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: pathchord_policy::TransitOptions {
                tls: Some(pathchord_policy::TransitTls {
                    enabled: true,
                    insecure: true,
                    server_name: Some("vmess.test".into()),
                    alpn: vec!["http/1.1".into()],
                    ..Default::default()
                }),
                transport: Some(pathchord_policy::TransitTransport {
                    kind: "ws".into(),
                    path: Some("/vmess".into()),
                    ..Default::default()
                }),
                udp: Some(true),
                ..Default::default()
            },
        };
        for (security, alter_id) in [
            ("aes-128-gcm", "0"),
            ("aes-128-cfb", "0"),
            ("aes-128-gcm", "1"),
            ("aes-128-cfb", "1"),
        ] {
            let credentials = TransitCredential::new(BTreeMap::from([
                ("uuid".into(), uuid.into()),
                ("security".into(), security.into()),
                ("alter_id".into(), alter_id.into()),
            ]));
            let adapter = VmessAdapter::from_config(
                &config,
                &credentials,
                Duration::from_secs(5),
                crate::adapter_registry::native_tls_roots(),
            )
            .unwrap();
            let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_address = target.local_addr().unwrap();
            let target_task = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut payload = [0_u8; 7];
                stream.read_exact(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            });
            let mut stream = adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "127.0.0.1".into(),
                        port: target_address.port(),
                    },
                })
                .await
                .unwrap();
            stream.write_all(b"modern!").await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = [0_u8; 7];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"modern!");
            target_task.await.unwrap();

            let udp_target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_address = udp_target.local_addr().unwrap();
            let udp_task = tokio::spawn(async move {
                let mut packet = [0_u8; 256];
                let (length, peer) = udp_target.recv_from(&mut packet).await.unwrap();
                udp_target.send_to(&packet[..length], peer).await.unwrap();
            });
            let mut datagram = adapter
                .connect_udp(ConnectRequest {
                    destination: Endpoint {
                        host: "127.0.0.1".into(),
                        port: udp_address.port(),
                    },
                })
                .await
                .unwrap();
            datagram.send(b"vmess-udp").await.unwrap();
            assert_eq!(datagram.receive().await.unwrap(), b"vmess-udp");
            datagram.close().await.unwrap();
            udp_task.await.unwrap();
        }
        server.kill().await.unwrap();
        server.wait().await.unwrap();
    }
}
