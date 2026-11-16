//! SIP003 simple-obfs HTTP and TLS camouflage for Shadowsocks TCP streams.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, Visitor};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::TransitError;

const MAX_RECORD: usize = 16 * 1024;
const MAX_HTTP_HEADER: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Http,
    Tls,
}

#[derive(Debug, Clone)]
pub(super) struct Config {
    mode: Mode,
    host: String,
    port: u16,
    uri: String,
    method: String,
}

fn unsupported(message: &'static str) -> TransitError {
    TransitError::Unsupported(message.into())
}

struct JsonOptions(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for JsonOptions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OptionsVisitor;
        impl<'de> Visitor<'de> for OptionsVisitor {
            type Value = JsonOptions;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object with unique string options")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if values.insert(key, value).is_some() {
                        return Err(A::Error::custom("duplicate simple-obfs option"));
                    }
                }
                Ok(JsonOptions(values))
            }
        }
        deserializer.deserialize_map(OptionsVisitor)
    }
}

impl Config {
    pub(super) fn parse(
        plugin: Option<&str>,
        options: Option<&str>,
        port: u16,
    ) -> Result<Option<Self>, TransitError> {
        let plugin = plugin.filter(|value| !value.is_empty());
        let Some(plugin) = plugin else {
            return if options.is_some_and(|value| !value.is_empty()) {
                Err(unsupported("Shadowsocks plugin options require a plugin"))
            } else {
                Ok(None)
            };
        };
        if !matches!(plugin, "obfs" | "obfs-local" | "simple-obfs") {
            return Err(unsupported("Shadowsocks plugin is unsupported"));
        }
        let raw = options.unwrap_or("");
        if raw.len() > 8192 {
            return Err(unsupported("simple-obfs options are too large"));
        }
        let mut parsed = if raw.trim_start().starts_with('{') {
            serde_json::from_str::<JsonOptions>(raw)
                .map_err(|_| unsupported("simple-obfs JSON options are invalid or duplicated"))?
                .0
        } else {
            parse_sip003(raw)?
        };
        let mode = match take_alias(&mut parsed, "obfs", "mode")?.as_deref() {
            None if plugin != "obfs" => Mode::Http,
            Some("http") => Mode::Http,
            Some("tls") => Mode::Tls,
            _ => return Err(unsupported("simple-obfs mode is invalid or missing")),
        };
        let host = take_alias(&mut parsed, "obfs-host", "host")?.unwrap_or_else(|| {
            if plugin == "obfs" {
                "bing.com"
            } else {
                "cloudfront.net"
            }
            .to_owned()
        });
        let uri = parsed.remove("obfs-uri");
        let method = parsed.remove("http-method");
        if !parsed.is_empty() {
            return Err(unsupported("simple-obfs option is unsupported"));
        }
        if host.is_empty()
            || host.len() > 253
            || !host.is_ascii()
            || host
                .bytes()
                .any(|byte| byte <= b' ' || byte == 0x7f || b"/\\?#@".contains(&byte))
        {
            return Err(unsupported("simple-obfs host is invalid"));
        }
        if mode == Mode::Tls && (uri.is_some() || method.is_some()) {
            return Err(unsupported("simple-obfs HTTP options require HTTP mode"));
        }
        let uri = uri.unwrap_or_else(|| "/".into());
        if !uri.starts_with('/')
            || uri.len() > 4096
            || !uri.is_ascii()
            || uri
                .bytes()
                .any(|byte| byte <= b' ' || byte == 0x7f || byte == b'#')
        {
            return Err(unsupported("simple-obfs URI is invalid"));
        }
        let method = method.unwrap_or_else(|| "GET".into());
        if method.is_empty()
            || method.len() > 32
            || !method
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(unsupported("simple-obfs HTTP method is invalid"));
        }
        if 256 + host.len() + uri.len() + method.len() > MAX_HTTP_HEADER {
            return Err(unsupported("simple-obfs request header is too large"));
        }
        Ok(Some(Self {
            mode,
            host,
            port,
            uri,
            method,
        }))
    }
}

fn take_alias(
    values: &mut BTreeMap<String, String>,
    first: &str,
    second: &str,
) -> Result<Option<String>, TransitError> {
    match (values.remove(first), values.remove(second)) {
        (Some(_), Some(_)) => Err(unsupported("duplicate simple-obfs option")),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn parse_sip003(raw: &str) -> Result<BTreeMap<String, String>, TransitError> {
    let mut output = BTreeMap::new();
    if raw.is_empty() {
        return Ok(output);
    }
    let mut key = String::new();
    let mut value = String::new();
    let mut in_value = false;
    let mut escaped = false;
    for c in raw.chars() {
        if escaped {
            if in_value {
                value.push(c);
            } else {
                key.push(c);
            }
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '=' && !in_value {
            in_value = true;
            continue;
        }
        if c == ';' {
            if key.is_empty()
                || !in_value
                || output
                    .insert(std::mem::take(&mut key), std::mem::take(&mut value))
                    .is_some()
            {
                return Err(unsupported("simple-obfs options are invalid or duplicated"));
            }
            in_value = false;
        } else if in_value {
            value.push(c);
        } else {
            key.push(c);
        }
    }
    if escaped {
        return Err(unsupported("simple-obfs options contain a trailing escape"));
    }
    if (!key.is_empty() || in_value)
        && (key.is_empty() || !in_value || output.insert(key, value).is_some())
    {
        return Err(unsupported("simple-obfs options are invalid or duplicated"));
    }
    Ok(output)
}

#[derive(Debug)]
enum ReadState {
    HttpHeader(Vec<u8>),
    TlsFirst(Vec<u8>),
    TlsHeader(Vec<u8>),
    TlsPayload(usize),
    Plain,
    Failed,
}

pub(super) struct Stream<S> {
    inner: S,
    config: Config,
    first_write: bool,
    pending: Vec<u8>,
    offset: usize,
    read: ReadState,
    failed: bool,
}

impl<S> Stream<S> {
    pub(super) fn new(inner: S, config: Config) -> Self {
        let read = match config.mode {
            Mode::Http => ReadState::HttpHeader(Vec::new()),
            Mode::Tls => ReadState::TlsFirst(Vec::new()),
        };
        Self {
            inner,
            config,
            first_write: true,
            pending: Vec::new(),
            offset: 0,
            read,
            failed: false,
        }
    }
    fn frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.pending.clear();
        self.offset = 0;
        match (self.config.mode, self.first_write) {
            (Mode::Http, true) => {
                let mut random = [0; 16];
                getrandom::fill(&mut random)
                    .map_err(|_| io::Error::other("simple-obfs randomness failed"))?;
                let host = if self.config.port == 80 {
                    self.config.host.clone()
                } else {
                    format!("{}:{}", self.config.host, self.config.port)
                };
                let header = format!(
                    "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.54.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nContent-Length: {}\r\n\r\n",
                    self.config.method,
                    self.config.uri,
                    host,
                    STANDARD.encode(random),
                    data.len()
                );
                self.pending.extend_from_slice(header.as_bytes());
                self.pending.extend_from_slice(data);
            }
            (Mode::Http, false) => self.pending.extend_from_slice(data),
            (Mode::Tls, true) => self.pending = tls_hello(data, &self.config.host)?,
            (Mode::Tls, false) => {
                self.pending.extend_from_slice(&[0x17, 0x03, 0x03]);
                self.pending
                    .extend_from_slice(&(data.len() as u16).to_be_bytes());
                self.pending.extend_from_slice(data);
            }
        }
        self.first_write = false;
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> Stream<S> {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "simple-obfs stream has failed",
            )));
        }
        while self.offset < self.pending.len() {
            let written = match std::task::ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.offset..])
            ) {
                Ok(written) => written,
                Err(error) => {
                    self.failed = true;
                    return Poll::Ready(Err(error));
                }
            };
            if written == 0 {
                self.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "simple-obfs write failed",
                )));
            }
            self.offset += written;
        }
        self.pending.clear();
        self.offset = 0;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.poll_pending(cx))?;
        let length = data.len().min(MAX_RECORD);
        self.frame(&data[..length])?;
        // Buffer ownership transfers here. Flush or the next write completes it.
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(self.poll_pending(cx))?;
        loop {
            // Retain a terminal failure state unless this branch explicitly
            // restores an incomplete or successfully decoded state.
            let state = std::mem::replace(&mut self.read, ReadState::Failed);
            match state {
                ReadState::Plain => {
                    self.read = ReadState::Plain;
                    return Pin::new(&mut self.inner).poll_read(cx, out);
                }
                ReadState::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "simple-obfs response has failed",
                    )));
                }
                ReadState::HttpHeader(mut header) => {
                    let mut byte = [0];
                    let mut buf = ReadBuf::new(&mut byte);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                        Poll::Pending => {
                            self.read = ReadState::HttpHeader(header);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated simple-obfs HTTP response",
                            )));
                        }
                        Poll::Ready(Ok(())) => header.push(byte[0]),
                    }
                    if header.ends_with(b"\r\n\r\n") {
                        if !header.starts_with(b"HTTP/1.") {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "invalid simple-obfs HTTP response",
                            )));
                        }
                        self.read = ReadState::Plain;
                    } else if header.len() >= MAX_HTTP_HEADER {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "simple-obfs HTTP response is too large",
                        )));
                    } else {
                        self.read = ReadState::HttpHeader(header);
                    }
                }
                ReadState::TlsFirst(mut header) => {
                    let mut byte = [0];
                    let mut buf = ReadBuf::new(&mut byte);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                        Poll::Pending => {
                            self.read = ReadState::TlsFirst(header);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated simple-obfs TLS response",
                            )));
                        }
                        Poll::Ready(Ok(())) => header.push(byte[0]),
                    }
                    if header.len() < 107 {
                        self.read = ReadState::TlsFirst(header);
                        continue;
                    }
                    if header[..5] != [0x16, 0x03, 0x01, 0, 91]
                        || header[96..105] != [0x14, 0x03, 0x03, 0, 1, 1, 0x16, 0x03, 0x03]
                    {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "invalid simple-obfs TLS response",
                        )));
                    }
                    let length = usize::from(u16::from_be_bytes([header[105], header[106]]));
                    if length > MAX_RECORD {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "simple-obfs TLS response is too large",
                        )));
                    }
                    self.read = if length == 0 {
                        ReadState::TlsHeader(Vec::new())
                    } else {
                        ReadState::TlsPayload(length)
                    };
                }
                ReadState::TlsHeader(mut header) => {
                    let mut byte = [0];
                    let mut buf = ReadBuf::new(&mut byte);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                        Poll::Pending => {
                            self.read = ReadState::TlsHeader(header);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if buf.filled().is_empty() && header.is_empty() => {
                            self.read = ReadState::TlsHeader(header);
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated simple-obfs TLS record",
                            )));
                        }
                        Poll::Ready(Ok(())) => header.push(byte[0]),
                    }
                    if header.len() < 5 {
                        self.read = ReadState::TlsHeader(header);
                        continue;
                    }
                    if header[..3] != [0x17, 0x03, 0x03] {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "invalid simple-obfs TLS record",
                        )));
                    }
                    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                    if length > MAX_RECORD {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "simple-obfs TLS record is too large",
                        )));
                    }
                    self.read = if length == 0 {
                        ReadState::TlsHeader(Vec::new())
                    } else {
                        ReadState::TlsPayload(length)
                    };
                }
                ReadState::TlsPayload(remaining) => {
                    let limit = remaining.min(out.remaining());
                    let before = out.filled().len();
                    let mut limited = ReadBuf::new(out.initialize_unfilled_to(limit));
                    match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
                        Poll::Pending => {
                            self.read = ReadState::TlsPayload(remaining);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let count = limited.filled().len();
                            out.advance(count);
                            if count == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::UnexpectedEof,
                                    "truncated simple-obfs TLS payload",
                                )));
                            }
                            self.read = if count == remaining {
                                ReadState::TlsHeader(Vec::new())
                            } else {
                                ReadState::TlsPayload(remaining - count)
                            };
                            debug_assert_eq!(out.filled().len(), before + count);
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
    }
}

fn tls_hello(data: &[u8], host: &str) -> io::Result<Vec<u8>> {
    let mut random = [0; 60];
    getrandom::fill(&mut random).map_err(|_| io::Error::other("simple-obfs randomness failed"))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let len = 212 + data.len() + host.len();
    let mut out = Vec::with_capacity(5 + len);
    out.extend_from_slice(&[0x16, 0x03, 0x01]);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&[1, 0]);
    out.extend_from_slice(&((len - 4) as u16).to_be_bytes());
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&random[..28]);
    out.push(32);
    out.extend_from_slice(&random[28..]);
    out.extend_from_slice(&[
        0, 56, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b,
        0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00,
        0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d,
        0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 1, 0,
    ]);
    out.extend_from_slice(&((79 + data.len() + host.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0x23]);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
    out.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(host.len() as u16).to_be_bytes());
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&[
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00,
        0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01,
        0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04,
        0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16,
        0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
    ]);
    debug_assert_eq!(out.len(), len + 5);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{Config, Stream};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    #[tokio::test]
    async fn malformed_response_never_falls_back_to_plaintext_after_an_error() {
        for mode in ["http", "tls"] {
            let config = Config::parse(Some("obfs-local"), Some(&format!("obfs={mode}")), 443)
                .unwrap()
                .unwrap();
            let (client, mut server) = tokio::io::duplex(1024);
            let mut stream = Stream::new(client, config);
            let mut bad_response = if mode == "http" {
                b"invalid response\r\n\r\n".to_vec()
            } else {
                vec![0; 107]
            };
            bad_response.extend_from_slice(b"must-not-be-exposed");
            server.write_all(&bad_response).await.unwrap();
            let mut out = [0; 64];
            assert!(stream.read(&mut out).await.is_err(), "{mode}");
            assert!(stream.read(&mut out).await.is_err(), "{mode}");
        }
    }

    #[tokio::test]
    async fn partial_write_cancellation_and_half_close_preserve_both_directions() {
        timeout(Duration::from_secs(5), async {
            for mode in ["http", "tls"] {
                let config = Config::parse(Some("obfs-local"), Some(&format!("obfs={mode}")), 443)
                    .unwrap()
                    .unwrap();
                // One byte of capacity forces the first frame to make partial
                // progress before the next write is cancelled.
                let (client, mut server) = tokio::io::duplex(1);
                let mut stream = Stream::new(client, config);
                stream.write_all(b"A").await.unwrap();
                assert!(
                    timeout(Duration::from_millis(20), stream.write(b"B"))
                        .await
                        .is_err()
                );
                let peer = tokio::spawn(async move {
                    let mut wire = Vec::new();
                    server.read_to_end(&mut wire).await.unwrap();
                    if mode == "http" {
                        let end = wire
                            .windows(4)
                            .position(|part| part == b"\r\n\r\n")
                            .unwrap()
                            + 4;
                        assert_eq!(&wire[end..], b"AB");
                        server
                            .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\nreply")
                            .await
                            .unwrap();
                    } else {
                        let end = 5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]));
                        assert_eq!(&wire[138..142], &[0, 0x23, 0, 1]);
                        assert_eq!(wire[142], b'A');
                        assert_eq!(&wire[end..], b"\x17\x03\x03\x00\x01B");
                        let mut response = vec![0; 96];
                        response[..5].copy_from_slice(&[0x16, 0x03, 0x01, 0, 91]);
                        response.extend_from_slice(&[
                            0x14, 0x03, 0x03, 0, 1, 1, 0x16, 0x03, 0x03, 0, 5,
                        ]);
                        response.extend_from_slice(b"reply");
                        server.write_all(&response).await.unwrap();
                    }
                    server.shutdown().await.unwrap();
                });
                stream.write_all(b"B").await.unwrap();
                stream.shutdown().await.unwrap();
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"reply", "{mode}");
                peer.await.unwrap();
            }
        })
        .await
        .expect("short-write and half-close exchange timed out");
    }
}
