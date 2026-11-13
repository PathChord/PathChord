//! Small, pure Rust VMess AEAD TCP client.
//!
//! This module intentionally implements the plain TCP VMess transport only.
//! TLS, WebSocket, mux, and UDP options are rejected by the adapter factory
//! until their native implementations are added.

use std::sync::Arc;
use std::time::Duration;

use aes::cipher::BlockEncrypt;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use pathchord_policy::TransitProxyConfig;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::Zeroize;

use crate::{
    AdapterKind, BoxedTransitConnection, ConnectRequest, Endpoint, TransitAdapter,
    TransitCredential, TransitError, TransitMetadata,
};

const MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const MAX_RECORD: usize = 16_368;

pub(crate) struct VmessAdapter {
    metadata: TransitMetadata,
    cmd_key: [u8; 16],
    transport: crate::native_transport::NativeTransport,
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
        if config.options.udp == Some(true)
            || config.options.tls.as_ref().is_some_and(|tls| tls.enabled)
            || config.options.transport.is_some()
        {
            return Err(unsupported("native VMess supports plain TCP only"));
        }
        crate::adapter_registry::validate_credentials(
            Some(credential),
            &["uuid", "security", "alter_id"],
        )?;
        if credential
            .field("alter_id")
            .is_some_and(|value| value.parse::<u32>().ok().is_none_or(|value| value != 0))
        {
            return Err(unsupported("native VMess requires alter_id 0"));
        }
        let uuid = credential
            .field("uuid")
            .ok_or_else(|| unsupported("VMess UUID is missing"))?;
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| unsupported("VMess UUID is invalid"))?;
        let security = credential.field("security").unwrap_or("aes-128-gcm");
        if !matches!(security, "aes-128-gcm" | "auto") {
            return Err(unsupported("native VMess supports aes-128-gcm only"));
        }
        let transport =
            crate::native_transport::NativeTransport::new(config, credential, tls, timeout)?;
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "vmess".to_owned(),
                },
                labels: config.labels.clone(),
            },
            cmd_key: cmd_key(uuid.as_bytes()),
            transport,
            timeout,
        })
    }

    async fn open(&self, destination: &Endpoint) -> Result<BoxedTransitConnection, TransitError> {
        crate::validate_destination(destination)?;
        timeout(self.timeout, async {
            let stream = self.transport.connect().await?;
            let sealed = seal_header(&self.cmd_key, destination)?;
            let mut stream = stream;
            stream
                .write_all(&sealed.bytes)
                .await
                .map_err(|_| protocol("VMess request header write failed"))?;
            stream
                .flush()
                .await
                .map_err(|_| protocol("VMess request header flush failed"))?;
            Ok(spawn_duplex(stream, sealed))
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
        false
    }
    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        self.open(&request.destination).await
    }
}

struct Sealed {
    bytes: Vec<u8>,
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_v: u8,
}

fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(uuid);
    digest.update(MAGIC);
    digest.finalize().into()
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
    let salt = <Hmac<Sha256> as Mac>::new_from_slice(b"VMess AEAD KDF").expect("valid KDF salt");
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

fn seal_header(cmd_key: &[u8; 16], target: &Endpoint) -> Result<Sealed, TransitError> {
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
    let cipher =
        aes::Aes128::new_from_slice(&auth_key).map_err(|_| protocol("VMess Auth ID key failed"))?;
    cipher.encrypt_block(aes::Block::from_mut_slice(&mut auth));

    let padding = (nonce_bytes[4] & 0x0f) as usize;
    let mut plain = vec![1];
    plain.extend_from_slice(&req_iv);
    plain.extend_from_slice(&req_key);
    plain.extend_from_slice(&[resp_v, 1, ((padding as u8) << 4) | 0x03, 0, 1]);
    plain.extend_from_slice(&target.port.to_be_bytes());
    let host = target.host.as_bytes();
    if host.is_empty() || host.len() > 255 {
        return Err(unsupported("VMess target hostname is invalid"));
    }
    plain.extend_from_slice(&[2, host.len() as u8]);
    plain.extend_from_slice(host);
    plain.extend(std::iter::repeat_n(0, padding));
    plain.extend_from_slice(&fnv1a32(&plain).to_be_bytes());

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
    })
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

fn spawn_duplex(upstream: BoxedTransitConnection, sealed: Sealed) -> BoxedTransitConnection {
    let (client, server) = tokio::io::duplex(32 * 1024);
    let (mut client_read, mut client_write) = tokio::io::split(server);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let write_key = sealed.req_key;
    let write_iv = sealed.req_iv;
    let (resp_key, resp_iv) = response_keys(&sealed.req_key, &sealed.req_iv);
    let resp_v = sealed.resp_v;
    tokio::spawn(async move {
        let cipher = Aes128Gcm::new_from_slice(&write_key).expect("VMess key length");
        let mut buf = vec![0u8; MAX_RECORD];
        let mut counter = 0u16;
        while let Ok(size) = client_read.read(&mut buf).await {
            if size == 0 {
                break;
            }
            let Ok(length) = u16::try_from(size + 16) else {
                break;
            };
            let nonce = record_nonce(&write_iv, counter);
            counter = counter.wrapping_add(1);
            let Ok(encrypted) = cipher.encrypt(Nonce::from_slice(&nonce), &buf[..size]) else {
                break;
            };
            if upstream_write
                .write_all(&length.to_be_bytes())
                .await
                .is_err()
                || upstream_write.write_all(&encrypted).await.is_err()
            {
                break;
            }
        }
        let _ = upstream_write.shutdown().await;
    });
    tokio::spawn(async move {
        let length_key = kdf16(&resp_key, &[b"AEAD Resp Header Len Key"]);
        let length_iv = kdf12(&resp_iv, &[b"AEAD Resp Header Len IV"]);
        let mut encrypted_length = [0u8; 18];
        if upstream_read
            .read_exact(&mut encrypted_length)
            .await
            .is_err()
        {
            let _ = client_write.shutdown().await;
            return;
        }
        let Ok(length_plain) = Aes128Gcm::new_from_slice(&length_key)
            .expect("VMess key")
            .decrypt(
                Nonce::from_slice(&length_iv),
                Payload {
                    msg: &encrypted_length,
                    aad: &[],
                },
            )
        else {
            let _ = client_write.shutdown().await;
            return;
        };
        let header_len = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
        let header_key = kdf16(&resp_key, &[b"AEAD Resp Header Key"]);
        let header_iv = kdf12(&resp_iv, &[b"AEAD Resp Header IV"]);
        let mut header = vec![0u8; header_len + 16];
        if upstream_read.read_exact(&mut header).await.is_err() {
            let _ = client_write.shutdown().await;
            return;
        }
        let Ok(header_plain) = Aes128Gcm::new_from_slice(&header_key)
            .expect("VMess key")
            .decrypt(
                Nonce::from_slice(&header_iv),
                Payload {
                    msg: &header,
                    aad: &[],
                },
            )
        else {
            let _ = client_write.shutdown().await;
            return;
        };
        if header_plain.first().copied() != Some(resp_v) {
            let _ = client_write.shutdown().await;
            return;
        }
        let cipher = Aes128Gcm::new_from_slice(&resp_key).expect("VMess key");
        let mut counter = 0u16;
        loop {
            let mut len = [0u8; 2];
            if upstream_read.read_exact(&mut len).await.is_err() {
                break;
            }
            let size = u16::from_be_bytes(len) as usize;
            if !(16..=MAX_RECORD + 16).contains(&size) {
                break;
            }
            let mut body = vec![0u8; size];
            if upstream_read.read_exact(&mut body).await.is_err() {
                break;
            }
            let nonce = record_nonce(&resp_iv, counter);
            counter = counter.wrapping_add(1);
            let Ok(plain) = cipher.decrypt(Nonce::from_slice(&nonce), body.as_slice()) else {
                break;
            };
            if client_write.write_all(&plain).await.is_err() {
                break;
            }
        }
        let _ = client_write.shutdown().await;
    });
    Box::new(client)
}

fn response_keys(key: &[u8; 16], iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let key_hash: [u8; 32] = Sha256::digest(key).into();
    let iv_hash: [u8; 32] = Sha256::digest(iv).into();
    (
        key_hash[..16].try_into().unwrap(),
        iv_hash[..16].try_into().unwrap(),
    )
}

fn record_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
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
        let config = TransitProxyConfig {
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
        let credentials = TransitCredential::new(BTreeMap::from([("uuid".into(), uuid.into())]));
        let adapter = VmessAdapter::from_config(
            &config,
            &credentials,
            Duration::from_secs(3),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0u8; 6];
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
        stream.write_all(b"native").await.unwrap();
        stream.flush().await.unwrap();
        let mut output = [0u8; 6];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"native");
        target_task.await.unwrap();
        server.kill().await.unwrap();
        server.wait().await.unwrap();
    }
}
