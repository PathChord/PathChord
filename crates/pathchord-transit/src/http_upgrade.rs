//! Bounded V2Ray HTTPUpgrade handshake for native byte transports.

use http::header::{HeaderName, HeaderValue};
use pathchord_policy::{TransitProxyConfig, TransitTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{BoxedTransitConnection, TransitError};

const MAX_RESPONSE: usize = 16 * 1024;

pub(crate) struct HttpUpgrade {
    request: Vec<u8>,
}

impl HttpUpgrade {
    pub(crate) fn new(
        node: &TransitProxyConfig,
        options: &TransitTransport,
    ) -> Result<Self, TransitError> {
        if options.service_name.is_some()
            || options.host.len() > 1
            || options.max_early_data.unwrap_or(0) != 0
            || options.early_data_header_name.is_some()
        {
            return Err(unsupported(
                "HTTPUpgrade transport parameters are unsupported",
            ));
        }
        if node
            .options
            .tls
            .as_ref()
            .is_some_and(|tls| tls.enabled && tls.alpn.iter().any(|alpn| alpn != "http/1.1"))
        {
            return Err(unsupported("HTTPUpgrade TLS requires HTTP/1.1 ALPN"));
        }
        let path = options.path.as_deref().unwrap_or("/");
        if !path.starts_with('/')
            || path.contains('#')
            || path.parse::<http::uri::PathAndQuery>().is_err()
        {
            return Err(unsupported("HTTPUpgrade path is invalid"));
        }

        let mut names = std::collections::BTreeSet::new();
        for name in options.headers.keys() {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| unsupported("HTTPUpgrade header name is invalid"))?;
            if !names.insert(name.as_str().to_owned()) {
                return Err(unsupported("HTTPUpgrade has duplicate headers"));
            }
        }

        let header_host = options
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.as_str());
        if let (Some(configured), Some(header)) = (options.host.first(), header_host)
            && configured != header
        {
            return Err(unsupported("HTTPUpgrade Host options conflict"));
        }
        let host = options
            .host
            .first()
            .map(String::as_str)
            .or(header_host)
            .or_else(|| {
                node.options
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.server_name.as_deref())
            })
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                let host = if node.endpoint.host.contains(':') {
                    format!("[{}]", node.endpoint.host)
                } else {
                    node.endpoint.host.clone()
                };
                format!("{host}:{}", node.endpoint.port)
            });
        if host.contains('@') || host.parse::<http::uri::Authority>().is_err() {
            return Err(unsupported("HTTPUpgrade Host is invalid"));
        }
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        )
        .into_bytes();
        for (name, value) in &options.headers {
            let parsed_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| unsupported("HTTPUpgrade header name is invalid"))?;
            HeaderValue::from_str(value)
                .map_err(|_| unsupported("HTTPUpgrade header value is invalid"))?;
            if parsed_name == http::header::HOST {
                continue;
            }
            if parsed_name == http::header::CONNECTION || parsed_name == http::header::UPGRADE {
                return Err(unsupported(
                    "HTTPUpgrade headers conflict with handshake fields",
                ));
            }
            request.extend_from_slice(name.as_bytes());
            request.extend_from_slice(b": ");
            request.extend_from_slice(value.as_bytes());
            request.extend_from_slice(b"\r\n");
        }
        request.extend_from_slice(b"\r\n");
        if request.len() > MAX_RESPONSE {
            return Err(unsupported(
                "HTTPUpgrade request headers exceed the size limit",
            ));
        }
        Ok(Self { request })
    }

    pub(crate) async fn handshake(
        &self,
        stream: &mut BoxedTransitConnection,
    ) -> Result<(), TransitError> {
        stream
            .write_all(&self.request)
            .await
            .map_err(|_| protocol())?;
        stream.flush().await.map_err(|_| protocol())?;
        // Read exactly through the terminator, preserving any coalesced
        // application bytes in the underlying stream.
        let mut response = Vec::with_capacity(512);
        while response.len() < MAX_RESPONSE && !response.ends_with(b"\r\n\r\n") {
            response.push(stream.read_u8().await.map_err(|_| protocol())?);
        }
        if !response.ends_with(b"\r\n\r\n") {
            return Err(protocol());
        }
        validate_response(&response)
    }
}

fn validate_response(response: &[u8]) -> Result<(), TransitError> {
    let response = std::str::from_utf8(response).map_err(|_| protocol())?;
    let mut lines = response.split("\r\n");
    let mut status = lines.next().ok_or_else(protocol)?.split_whitespace();
    if status.next() != Some("HTTP/1.1") || status.next() != Some("101") {
        return Err(protocol());
    }
    let mut connection = false;
    let mut upgrade = false;
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(protocol)?;
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| protocol())?;
        let value = HeaderValue::from_str(value.trim()).map_err(|_| protocol())?;
        let value = value.to_str().map_err(|_| protocol())?;
        let has = |token: &str| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        };
        if name == http::header::CONNECTION {
            connection |= has("upgrade");
        } else if name == http::header::UPGRADE {
            upgrade |= has("websocket");
        }
    }
    if connection && upgrade {
        Ok(())
    } else {
        Err(protocol())
    }
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}

fn protocol() -> TransitError {
    TransitError::Protocol("HTTPUpgrade handshake failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_policy::{Endpoint, TransitOptions, TransitProxyId};

    fn node() -> TransitProxyConfig {
        TransitProxyConfig {
            id: TransitProxyId::new("upgrade-test"),
            source: None,
            protocol: "vless".into(),
            endpoint: Endpoint {
                host: "proxy.test".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: Default::default(),
            tags: Default::default(),
            weight: 1,
            options: TransitOptions::default(),
        }
    }

    #[tokio::test]
    async fn upgrade_preserves_bytes_coalesced_with_the_response() {
        let options = TransitTransport {
            kind: "httpupgrade".into(),
            path: Some("/tunnel?one=2".into()),
            host: vec!["front.test".into()],
            headers: [("X-Fixture".into(), "present".into())].into(),
            ..Default::default()
        };
        let upgrade = HttpUpgrade::new(&node(), &options).unwrap();
        let (io, mut peer) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(peer.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /tunnel?one=2 HTTP/1.1\r\nHost: front.test\r\n"));
            assert!(request.contains("X-Fixture: present\r\n"));
            peer.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\ncoalesced").await.unwrap();
        });
        let mut client: BoxedTransitConnection = Box::new(io);
        upgrade.handshake(&mut client).await.unwrap();
        let mut output = [0; 9];
        client.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"coalesced");
        server.await.unwrap();
    }

    #[test]
    fn rejects_invalid_handshakes_and_unconsumed_parameters() {
        for response in [
            b"HTTP/1.1 403 Forbidden\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\nBad Header: x\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
        ] {
            assert!(validate_response(response).is_err());
        }
        let mut options = TransitTransport {
            kind: "httpupgrade".into(),
            ..Default::default()
        };
        options.max_early_data = Some(1);
        assert!(HttpUpgrade::new(&node(), &options).is_err());
        options.max_early_data = None;
        options.host = vec!["example.test".into()];
        options.headers.insert("host".into(), "other.test".into());
        assert!(HttpUpgrade::new(&node(), &options).is_err());
        options.headers.clear();
        options.path = Some("/tunnel#fragment".into());
        assert!(HttpUpgrade::new(&node(), &options).is_err());
        options.path = None;
        options.host = vec!["user@front.test".into()];
        assert!(HttpUpgrade::new(&node(), &options).is_err());
    }
}
