//! Trojan-Go's optional Shadowsocks AEAD stream, without an SS target header.

use std::{
    io,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use shadowsocks::{
    config::ServerType,
    context::{Context, SharedContext},
    crypto::{CipherKind, v1::openssl_bytes_to_key},
    relay::tcprelay::crypto_io::{CryptoRead, CryptoStream, CryptoWrite, StreamType},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::{BoxedTransitConnection, TransitCredential, TransitError};

pub(super) struct Encryption {
    method: CipherKind,
    key: Zeroizing<Vec<u8>>,
    context: SharedContext,
}

impl Encryption {
    pub(super) fn from_credential(
        credential: &TransitCredential,
    ) -> Result<Option<Self>, TransitError> {
        let method = credential.field("trojan_go_ss_method");
        let password = credential.field("trojan_go_ss_password");
        let (method, password) = match (method, password) {
            (None, None) => return Ok(None),
            (Some(method), Some(password)) if !password.is_empty() => (method, password),
            _ => {
                return Err(unsupported(
                    "Trojan-Go Shadowsocks credentials are incomplete",
                ));
            }
        };
        let method = match method {
            "aes-128-gcm" => CipherKind::AES_128_GCM,
            "aes-256-gcm" => CipherKind::AES_256_GCM,
            "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,
            _ => return Err(unsupported("Trojan-Go Shadowsocks method is unsupported")),
        };
        let mut key = Zeroizing::new(vec![0; method.key_len()]);
        openssl_bytes_to_key(password.as_bytes(), &mut key);
        Ok(Some(Self {
            method,
            key,
            context: Context::new_shared(ServerType::Local),
        }))
    }

    pub(super) fn wrap(&self, stream: BoxedTransitConnection) -> BoxedTransitConnection {
        Box::new(EncryptedStream {
            stream: CryptoStream::from_stream(
                &self.context,
                stream,
                StreamType::Client,
                self.method,
                &self.key,
            ),
            context: self.context.clone(),
        })
    }
}

struct EncryptedStream {
    stream: CryptoStream<BoxedTransitConnection>,
    context: SharedContext,
}

impl AsyncRead for EncryptedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Self { stream, context } = &mut *self;
        Pin::new(stream)
            .poll_read_decrypted(cx, context, buf)
            .map_err(Into::into)
    }
}

impl AsyncWrite for EncryptedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream)
            .poll_write_encrypted(cx, buf)
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_shutdown(cx).map_err(Into::into)
    }
}

fn unsupported(message: &'static str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}
