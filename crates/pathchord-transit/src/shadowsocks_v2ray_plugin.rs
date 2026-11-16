//! Native SIP003 v2ray-plugin WebSocket transport for Shadowsocks TCP.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pathchord_policy::{TransitProxyConfig, TransitTls};
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, Visitor};
use serde_json::Value;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, Request, header};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::{BoxedTransitConnection, TransitError};

use super::shadowsocks_v2ray_mux;

const MAX_OPTIONS: usize = 8192;

fn unsupported(message: &'static str) -> TransitError {
    TransitError::Unsupported(message.into())
}

struct JsonOptions {
    fields: BTreeMap<String, Value>,
    headers: BTreeMap<String, String>,
}

struct UniqueHeaders(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for UniqueHeaders {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HeaderVisitor;
        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = UniqueHeaders;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object of unique string headers")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                let mut names = BTreeSet::new();
                while let Some((name, value)) = map.next_entry::<String, String>()? {
                    if !names.insert(name.to_ascii_lowercase()) {
                        return Err(A::Error::custom("duplicate plugin header"));
                    }
                    values.insert(name, value);
                }
                Ok(UniqueHeaders(values))
            }
        }
        deserializer.deserialize_map(HeaderVisitor)
    }
}

impl<'de> Deserialize<'de> for JsonOptions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OptionsVisitor;
        impl<'de> Visitor<'de> for OptionsVisitor {
            type Value = JsonOptions;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object of unique plugin options")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields = BTreeMap::new();
                let mut headers = BTreeMap::new();
                let mut names = BTreeSet::new();
                while let Some(name) = map.next_key::<String>()? {
                    if !names.insert(name.clone()) {
                        return Err(A::Error::custom("duplicate plugin option"));
                    }
                    if name == "headers" {
                        headers = map.next_value::<UniqueHeaders>()?.0;
                    } else {
                        fields.insert(name, map.next_value::<Value>()?);
                    }
                }
                Ok(JsonOptions { fields, headers })
            }
        }
        deserializer.deserialize_map(OptionsVisitor)
    }
}

fn sip003(raw: &str) -> Result<BTreeMap<String, String>, TransitError> {
    let mut result = BTreeMap::new();
    let mut key = String::new();
    let mut value = String::new();
    let mut in_value = false;
    let mut escaped = false;
    for character in raw.chars() {
        if escaped {
            if in_value {
                value.push(character);
            } else {
                key.push(character);
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '=' && !in_value {
            in_value = true;
        } else if character == ';' {
            if key.is_empty() {
                return Err(unsupported("v2ray-plugin option name is empty"));
            }
            if !in_value {
                value.push('1');
            }
            if result
                .insert(std::mem::take(&mut key), std::mem::take(&mut value))
                .is_some()
            {
                return Err(unsupported("v2ray-plugin option is duplicated"));
            }
            in_value = false;
        } else if in_value {
            value.push(character);
        } else {
            key.push(character);
        }
    }
    if escaped || (key.is_empty() && in_value) {
        return Err(unsupported("v2ray-plugin option escape is invalid"));
    }
    if !key.is_empty() {
        if !in_value {
            value.push('1');
        }
        if result.insert(key, value).is_some() {
            return Err(unsupported("v2ray-plugin option is duplicated"));
        }
    }
    Ok(result)
}

fn text(fields: &mut BTreeMap<String, Value>, name: &str) -> Result<Option<String>, TransitError> {
    fields
        .remove(name)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| unsupported("v2ray-plugin option must be a string"))
        })
        .transpose()
}

fn flag(value: Value) -> Result<bool, TransitError> {
    match value {
        Value::Bool(value) => Ok(value),
        Value::Number(value) if value.as_u64() == Some(0) => Ok(false),
        Value::Number(value) if value.as_u64() == Some(1) => Ok(true),
        Value::String(value) if value.eq_ignore_ascii_case("true") || value == "1" => Ok(true),
        Value::String(value) if value.eq_ignore_ascii_case("false") || value == "0" => Ok(false),
        _ => Err(unsupported("v2ray-plugin boolean option is invalid")),
    }
}

#[derive(Clone)]
pub(super) struct Config {
    request: Request<()>,
    tls: Option<(
        Arc<rustls::ClientConfig>,
        rustls::pki_types::ServerName<'static>,
    )>,
    mux: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2rayPlugin")
            .field("tls", &self.tls.is_some())
            .field("mux", &self.mux)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub(super) fn parse(
        node: &TransitProxyConfig,
        raw: Option<&str>,
    ) -> Result<Self, TransitError> {
        let raw = raw.unwrap_or("");
        if raw.len() > MAX_OPTIONS {
            return Err(unsupported("v2ray-plugin options are too large"));
        }
        let raw = if raw.trim_start().starts_with('"') {
            serde_json::from_str::<String>(raw)
                .map_err(|_| unsupported("v2ray-plugin options are invalid"))?
        } else {
            raw.to_owned()
        };
        let is_json = raw.trim_start().starts_with('{');
        let (mut fields, headers) = if is_json {
            let value = serde_json::from_str::<JsonOptions>(&raw)
                .map_err(|_| unsupported("v2ray-plugin JSON options are invalid or duplicated"))?;
            (value.fields, value.headers)
        } else {
            let fields = sip003(&raw)?
                .into_iter()
                .map(|(key, value)| (key, Value::String(value)))
                .collect();
            (fields, BTreeMap::new())
        };
        let mode = text(&mut fields, "mode")?.unwrap_or_else(|| "websocket".into());
        if mode != "websocket" {
            return Err(unsupported("v2ray-plugin mode is unsupported"));
        }
        let mux = fields.remove("mux").map(flag).transpose()?.unwrap_or(true);
        let tls_enabled = if is_json {
            fields.remove("tls").map(flag).transpose()?.unwrap_or(false)
        } else {
            fields.remove("tls").is_some()
        };
        let insecure = fields.remove("skip-cert-verify").map(flag).transpose()?;
        let pin = text(&mut fields, "fingerprint")?;
        let cert = text(&mut fields, "cert")?;
        let cert_raw = text(&mut fields, "certRaw")?;
        if !tls_enabled
            && (insecure.is_some() || pin.is_some() || cert.is_some() || cert_raw.is_some())
        {
            return Err(unsupported("v2ray-plugin TLS options require TLS"));
        }
        if cert.is_some() && cert_raw.is_some() {
            return Err(unsupported("v2ray-plugin certificate options conflict"));
        }
        let supplied_host = text(&mut fields, "host")?;
        let path = text(&mut fields, "path")?.unwrap_or_else(|| "/".into());
        if !fields.is_empty() {
            return Err(unsupported("v2ray-plugin option is unsupported"));
        }
        if !path.starts_with('/')
            || path.len() > 4096
            || path.contains('#')
            || path.parse::<http::uri::PathAndQuery>().is_err()
        {
            return Err(unsupported("v2ray-plugin WebSocket path is invalid"));
        }
        let endpoint_host = if node.endpoint.host.contains(':') {
            format!("[{}]", node.endpoint.host)
        } else {
            node.endpoint.host.clone()
        };
        let uri = format!(
            "{}://{endpoint_host}:{}{path}",
            if tls_enabled { "wss" } else { "ws" },
            node.endpoint.port
        );
        let mut request = uri
            .into_client_request()
            .map_err(|_| unsupported("v2ray-plugin WebSocket request is invalid"))?;
        let mut configured_host = None;
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| unsupported("v2ray-plugin header name is invalid"))?;
            let value = HeaderValue::from_str(&value)
                .map_err(|_| unsupported("v2ray-plugin header value is invalid"))?;
            if matches!(
                name,
                header::CONNECTION
                    | header::UPGRADE
                    | header::CONTENT_LENGTH
                    | header::TRANSFER_ENCODING
            ) || name.as_str().starts_with("sec-websocket-")
            {
                return Err(unsupported("v2ray-plugin header conflicts with WebSocket"));
            }
            if name == header::HOST {
                configured_host = Some(
                    value
                        .to_str()
                        .map_err(|_| unsupported("v2ray-plugin Host is invalid"))?
                        .to_owned(),
                );
            }
            request.headers_mut().insert(name, value);
        }
        if let (Some(host), Some(header)) = (&supplied_host, &configured_host)
            && host != header
        {
            return Err(unsupported("v2ray-plugin Host options conflict"));
        }
        let host = supplied_host
            .as_deref()
            .or(configured_host.as_deref())
            .unwrap_or(if is_json {
                "bing.com"
            } else {
                "cloudfront.com"
            });
        if host.len() > 253 || host.contains('@') || host.parse::<http::uri::Authority>().is_err() {
            return Err(unsupported("v2ray-plugin Host is invalid"));
        }
        request.headers_mut().insert(
            header::HOST,
            HeaderValue::from_str(host).map_err(|_| unsupported("v2ray-plugin Host is invalid"))?,
        );
        let tls = if tls_enabled {
            let server_name = if supplied_host.is_some() || configured_host.is_some() || is_json {
                host
            } else {
                node.endpoint.host.as_str()
            };
            let mut options = TransitTls {
                enabled: true,
                server_name: Some(server_name.into()),
                insecure: insecure.unwrap_or(false),
                alpn: vec!["http/1.1".into()],
                certificate_sha256: pin,
                ..Default::default()
            };
            if let Some(cert) = cert {
                if !Path::new(&cert).is_absolute() {
                    return Err(unsupported(
                        "v2ray-plugin certificate path must be absolute",
                    ));
                }
                options.truststore.push(cert);
            }
            if let Some(raw) = cert_raw {
                let der = STANDARD
                    .decode(raw)
                    .map_err(|_| unsupported("v2ray-plugin certificate is invalid"))?;
                options.certificate.push(format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    STANDARD.encode(der)
                ));
            }
            let name = crate::tls::server_name(&node.endpoint.host, Some(&options))?;
            let tls = crate::tls::configure(
                crate::adapter_registry::native_tls_roots(),
                Some(&options),
                None,
            )?;
            Some((tls, name))
        } else {
            None
        };
        Ok(Self { request, tls, mux })
    }

    pub(super) async fn wrap(
        &self,
        mut stream: BoxedTransitConnection,
        duration: Duration,
    ) -> Result<BoxedTransitConnection, TransitError> {
        if let Some((tls, name)) = &self.tls {
            stream = Box::new(
                tokio_rustls::TlsConnector::from(Arc::clone(tls))
                    .connect(name.clone(), stream)
                    .await
                    .map_err(|_| {
                        TransitError::Connection("v2ray-plugin TLS handshake failed".into())
                    })?,
            );
        }
        let mut request = self.request.clone();
        request.headers_mut().insert(
            header::SEC_WEBSOCKET_KEY,
            HeaderValue::from_str(&generate_key())
                .map_err(|_| unsupported("v2ray-plugin WebSocket key is invalid"))?,
        );
        let config = WebSocketConfig::default()
            .read_buffer_size(16 * 1024)
            .write_buffer_size(0)
            .max_write_buffer_size(128 * 1024)
            .max_message_size(Some(1024 * 1024))
            .max_frame_size(Some(1024 * 1024));
        let (websocket, _) = tokio::time::timeout(
            duration,
            tokio_tungstenite::client_async_with_config(request, stream, Some(config)),
        )
        .await
        .map_err(|_| TransitError::Connection("v2ray-plugin WebSocket handshake timed out".into()))?
        .map_err(|_| TransitError::Protocol("v2ray-plugin WebSocket handshake failed".into()))?;
        let stream = crate::native_transport::websocket_byte_stream(websocket);
        Ok(if self.mux {
            Box::new(shadowsocks_v2ray_mux::MuxStream::new(stream))
        } else {
            stream
        })
    }
}
