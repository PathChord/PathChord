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
    /// SOCKS or Shadowsocks UDP-over-TCP wire version; absent uses native UDP.
    #[serde(default)]
    pub udp_over_tcp: Option<u8>,
    #[serde(default)]
    pub vmess: Option<TransitVmessOptions>,
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
            .field("udp_over_tcp", &self.udp_over_tcp)
            .field("vmess", &self.vmess)
            .field("multiplex", &self.multiplex)
            .field("tcp_fast_open", &self.tcp_fast_open)
            .field("bind_interface", &self.bind_interface)
            .field("routing_mark", &self.routing_mark)
            .field("packet_encoding", &self.packet_encoding)
            .finish()
    }
}

/// VMess body framing options; the adapter validates them against its cipher.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitVmessOptions {
    #[serde(default)]
    pub global_padding: bool,
    #[serde(default)]
    pub authenticated_length: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitTls {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default = "default_truststore_sources")]
    pub truststore: Vec<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub certificate: Vec<String>,
    /// SHA-256 of a DER-encoded peer certificate, in hexadecimal form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha256: Option<String>,
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

impl Default for TransitTls {
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: None,
            insecure: false,
            truststore: default_truststore_sources(),
            alpn: Vec::new(),
            certificate: Vec::new(),
            certificate_sha256: None,
            client_certificate: Vec::new(),
            client_key_field: None,
            fingerprint: None,
            reality: None,
        }
    }
}

/// Parse a complete SHA-256 certificate pin, with optional colon separators.
#[must_use]
pub fn parse_certificate_sha256(value: &str) -> Option<[u8; 32]> {
    let value = value.trim();
    let mut output = [0; 32];
    if value.len() == 64 {
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            output[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
    } else if value.len() == 95 {
        for (index, pair) in value.split(':').enumerate() {
            if index >= 32 || pair.len() != 2 {
                return None;
            }
            let bytes = pair.as_bytes();
            output[index] = (hex_digit(bytes[0])? << 4) | hex_digit(bytes[1])?;
        }
        if value
            .as_bytes()
            .iter()
            .filter(|byte| **byte == b':')
            .count()
            != 31
        {
            return None;
        }
    } else {
        return None;
    }
    Some(output)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod certificate_pin_tests {
    use super::*;

    #[test]
    fn validates_and_roundtrips_certificate_pin() {
        let encoded = format!(
            "{{\"tls\":{{\"enabled\":true,\"certificateSha256\":\"{}\"}}}}",
            "AB:".repeat(31) + "AB"
        );
        let options: TransitOptions = serde_yaml::from_str(&encoded).unwrap();
        options.validate().unwrap();
        assert_eq!(
            parse_certificate_sha256(
                options
                    .tls
                    .as_ref()
                    .unwrap()
                    .certificate_sha256
                    .as_deref()
                    .unwrap()
            ),
            Some([0xab; 32])
        );
        assert!(
            serde_yaml::to_string(&options)
                .unwrap()
                .contains("certificateSha256")
        );
        for value in ["", "ab:cd", "gg".repeat(32).as_str()] {
            let mut options = options.clone();
            options.tls.as_mut().unwrap().certificate_sha256 = Some(value.into());
            assert!(options.validate().is_err());
        }
    }
}

fn default_truststore_sources() -> Vec<String> {
    vec!["system".to_owned()]
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
                || tls
                    .certificate_sha256
                    .as_deref()
                    .is_some_and(|value| parse_certificate_sha256(value).is_none())
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
            if tls.reality.is_some() && tls.certificate_sha256.is_some() {
                return Err("options.tls certificate pin is not supported with REALITY");
            }
        }
        if let Some(transport) = &self.transport
            && (!matches!(
                transport.kind.as_str(),
                "tcp" | "ws" | "grpc" | "http" | "httpupgrade" | "quic" | "xhttp" | "meek"
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
        if self
            .udp_over_tcp
            .is_some_and(|version| !matches!(version, 1 | 2))
            || self.udp_over_tcp.is_some() && self.udp == Some(false)
        {
            return Err("options.udpOverTcp contains an invalid or conflicting version");
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

#[cfg(test)]
mod udp_over_tcp_tests {
    use super::TransitOptions;

    #[test]
    fn validates_and_roundtrips_supported_versions() {
        for version in [1, 2] {
            let options = TransitOptions {
                udp_over_tcp: Some(version),
                ..Default::default()
            };
            options.validate().unwrap();
            let value = serde_yaml::to_string(&options).unwrap();
            assert!(value.contains(&format!("udpOverTcp: {version}")));
            assert_eq!(
                serde_yaml::from_str::<TransitOptions>(&value).unwrap(),
                options
            );
        }
        for version in [0, 3] {
            assert!(
                TransitOptions {
                    udp_over_tcp: Some(version),
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            TransitOptions {
                udp: Some(false),
                udp_over_tcp: Some(2),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
