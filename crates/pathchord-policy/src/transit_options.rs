//! Non-secret, typed connection options shared by configuration and imports.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitOptions {
    #[serde(default)]
    pub tls: Option<TransitTls>,
    #[serde(default)]
    pub transport: Option<TransitTransport>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub udp: Option<bool>,
    #[serde(default)]
    pub multiplex: Option<TransitMultiplex>,
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
}

impl std::fmt::Debug for TransitOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransitOptions")
            .field("tls", &self.tls)
            .field("transport", &self.transport)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("udp", &self.udp)
            .field("multiplex", &self.multiplex)
            .field("tcp_fast_open", &self.tcp_fast_open)
            .field("bind_interface", &self.bind_interface)
            .field("routing_mark", &self.routing_mark)
            .field("packet_encoding", &self.packet_encoding)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitTls {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub certificate: Vec<String>,
    #[serde(default)]
    pub client_certificate: Vec<String>,
    /// The private key stays in the credential document, under this field name.
    #[serde(default)]
    pub client_key_field: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub reality: Option<TransitReality>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitReality {
    pub public_key: String,
    pub short_id: String,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitTransport {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub max_early_data: Option<u32>,
    #[serde(default)]
    pub early_data_header_name: Option<String>,
}

impl std::fmt::Debug for TransitTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransitTransport")
            .field("type", &self.kind)
            .field("path", &self.path.as_ref().map(|_| "<redacted>"))
            .field("host", &self.host)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("service_name", &self.service_name)
            .field("max_early_data", &self.max_early_data)
            .field("early_data_header_name", &self.early_data_header_name)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitMultiplex {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default)]
    pub min_streams: Option<u32>,
    #[serde(default)]
    pub max_streams: Option<u32>,
    #[serde(default)]
    pub padding: bool,
}

impl TransitOptions {
    pub fn validate(&self) -> Result<(), &'static str> {
        fn bounded(value: &str, maximum: usize) -> bool {
            value.len() <= maximum && !value.chars().any(char::is_control)
        }
        fn headers(values: &BTreeMap<String, String>) -> bool {
            values.len() <= 128
                && values.iter().all(|(name, value)| {
                    !name.is_empty()
                        && name.len() <= 128
                        && name.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
                        })
                        && bounded(value, 8192)
                        && !matches!(
                            name.to_ascii_lowercase().as_str(),
                            "proxy-authorization" | "authorization"
                        )
                })
        }
        if !headers(&self.headers) {
            return Err("options.headers contains invalid, secret, or excessive fields");
        }
        if let Some(tls) = &self.tls {
            if tls
                .server_name
                .as_ref()
                .is_some_and(|name| name.is_empty() || !bounded(name, 255))
                || tls.alpn.len() > 16
                || tls
                    .alpn
                    .iter()
                    .any(|value| value.is_empty() || !bounded(value, 255))
                || tls.certificate.len() > 16
                || tls.client_certificate.len() > 16
                || tls
                    .certificate
                    .iter()
                    .chain(&tls.client_certificate)
                    .any(|value| value.len() > 65536)
                || tls
                    .client_key_field
                    .as_ref()
                    .is_some_and(|value| value.is_empty() || !bounded(value, 128))
                || tls
                    .fingerprint
                    .as_ref()
                    .is_some_and(|value| value.is_empty() || !bounded(value, 64))
            {
                return Err("options.tls contains invalid or excessive fields");
            }
            if !tls.enabled && tls != &TransitTls::default() {
                return Err("options.tls settings require enabled: true");
            }
            if let Some(reality) = &tls.reality
                && (reality.public_key.is_empty()
                    || !bounded(&reality.public_key, 128)
                    || !bounded(&reality.short_id, 16)
                    || !reality
                        .short_id
                        .bytes()
                        .all(|value| value.is_ascii_hexdigit())
                    || !reality.short_id.len().is_multiple_of(2))
            {
                return Err("options.tls.reality contains invalid fields");
            }
        }
        if let Some(transport) = &self.transport
            && (!matches!(
                transport.kind.as_str(),
                "tcp" | "ws" | "grpc" | "http" | "httpupgrade" | "quic" | "xhttp"
            ) || !headers(&transport.headers)
                || transport.host.len() > 16
                || transport
                    .host
                    .iter()
                    .any(|value| value.is_empty() || !bounded(value, 255))
                || transport
                    .path
                    .as_ref()
                    .is_some_and(|value| !bounded(value, 8192))
                || transport
                    .service_name
                    .as_ref()
                    .is_some_and(|value| !bounded(value, 255))
                || transport.max_early_data.is_some_and(|value| value > 65536)
                || transport
                    .early_data_header_name
                    .as_ref()
                    .is_some_and(|value| !bounded(value, 128)))
        {
            return Err("options.transport contains invalid or excessive fields");
        }
        if self
            .bind_interface
            .as_ref()
            .is_some_and(|value| value.is_empty() || !bounded(value, 128))
            || self
                .packet_encoding
                .as_ref()
                .is_some_and(|value| !matches!(value.as_str(), "xudp" | "packetaddr"))
        {
            return Err("options contains invalid dialer or packet settings");
        }
        if let Some(mux) = &self.multiplex
            && (mux
                .protocol
                .as_ref()
                .is_some_and(|value| !matches!(value.as_str(), "smux" | "yamux" | "h2mux"))
                || [mux.max_connections, mux.min_streams, mux.max_streams]
                    .into_iter()
                    .flatten()
                    .any(|value| value == 0 || value > 65536))
        {
            return Err("options.multiplex contains invalid fields");
        }
        Ok(())
    }
}
