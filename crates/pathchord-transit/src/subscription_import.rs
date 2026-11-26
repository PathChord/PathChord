//! Subscription adapters normalize connection semantics before publication.
//!
//! Malformed documents fail atomically. Individual malformed or unsupported
//! nodes remain visible, with sanitized diagnostics, alongside usable nodes.

use base64::Engine as _;
use pathchord_policy::{
    TransitMultiplex, TransitOptions, TransitReality, TransitTls, TransitTransport,
    TransitVmessOptions,
};
use serde_json::{Map, Value};
use url::Url;

use super::*;

const KNOWN_PROTOCOLS: &[&str] = &[
    "direct",
    "http",
    "https",
    "socks5",
    "socks4",
    "socks4a",
    "ss",
    "vmess",
    "vless",
    "trojan",
    "hysteria",
    "hysteria2",
    "tuic",
    "ssh",
    "wireguard",
    "shadowtls",
    "anytls",
    "xtls",
    "snell",
];

#[derive(Default)]
struct Node {
    skip: bool,
    name: String,
    protocol: String,
    host: String,
    port: u16,
    credentials: BTreeMap<String, String>,
    original_sing_box_outbound: Option<String>,
    options: TransitOptions,
    tags: BTreeSet<String>,
    weight: u32,
    invalid: BTreeSet<String>,
    unsupported: BTreeSet<String>,
}

impl Node {
    fn new(index: usize) -> Self {
        Self {
            name: format!("node-{}", index + 1),
            weight: 100,
            ..Self::default()
        }
    }

    fn invalid(index: usize, field: &str) -> Self {
        let mut node = Self::new(index);
        node.invalid.insert(field.to_owned());
        node
    }

    fn finish(
        mut self,
        source: &str,
        config: &SubscriptionConfig,
        index: usize,
        used: &mut BTreeSet<String>,
        available: &BTreeSet<String>,
    ) -> NormalizedNode {
        self.protocol = canonical_protocol(&self.protocol);
        if self.protocol == "xtls" {
            if self.credentials.get("flow").is_none_or(String::is_empty) {
                self.invalid.insert("flow".to_owned());
            }
            self.protocol = "vless".to_owned();
        }
        if self.protocol == "direct" {
            self.host.clear();
            self.port = 1;
        }
        if self.protocol != "direct"
            && validate_node(index, &self.protocol, &self.host, self.port, self.weight).is_err()
        {
            self.invalid.insert("endpoint".to_owned());
        }
        if validate_display_name(index, &self.name).is_err() {
            self.name = format!("node-{}", index + 1);
            self.invalid.insert("name".to_owned());
        }
        if validate_tags(index, &self.tags).is_err() {
            self.tags.clear();
            self.invalid.insert("tags".to_owned());
        }
        let required: &[&str] = match self.protocol.as_str() {
            "ss" if self
                .credentials
                .get("cipher")
                .is_some_and(|cipher| matches!(cipher.as_str(), "none" | "plain")) =>
            {
                &["cipher"]
            }
            "ss" => &["cipher", "password"],
            "vmess" | "vless" | "xtls" => &["uuid"],
            "trojan" | "hysteria2" | "anytls" => &["password"],
            "tuic" => &["uuid", "password"],
            _ => &[],
        };
        for field in required {
            if self.credentials.get(*field).is_none_or(String::is_empty) {
                self.invalid.insert((*field).to_owned());
            }
        }
        if self.protocol == "snell" {
            if !["psk", "userkey"].iter().any(|field| {
                self.credentials
                    .get(*field)
                    .is_some_and(|value| !value.is_empty())
            }) {
                self.invalid.insert("psk_or_userkey".to_owned());
            }
            if self
                .credentials
                .get("version")
                .is_some_and(|version| !matches!(version.as_str(), "4" | "6"))
            {
                self.unsupported.insert("version".to_owned());
            }
        }
        // A Clash HTTP node with tls:true is an HTTPS CONNECT node. Never
        // silently establish a plaintext connection in place of TLS.
        if self.protocol == "http" && self.options.tls.as_ref().is_some_and(|tls| tls.enabled) {
            self.protocol = "https".to_owned();
        }
        if self.protocol == "https" {
            self.options
                .tls
                .get_or_insert_with(TransitTls::default)
                .enabled = true;
        }
        let mut diagnostic = if !self.invalid.is_empty() {
            Some(diagnostic(NodeUnavailableReason::InvalidNode, self.invalid))
        } else if !KNOWN_PROTOCOLS.contains(&self.protocol.as_str()) {
            Some(diagnostic(
                NodeUnavailableReason::UnsupportedProtocol,
                BTreeSet::from(["type".to_owned()]),
            ))
        } else if !self.unsupported.is_empty() {
            Some(diagnostic(
                NodeUnavailableReason::UnsupportedParameters,
                self.unsupported,
            ))
        } else {
            None
        };
        // Invalid endpoints are represented by safe inert values. They are
        // never selectable, and retain no secret-bearing source text.
        if self.host.is_empty() && self.protocol != "direct" {
            self.host = "invalid.invalid".to_owned();
        }
        if self.port == 0 {
            self.port = 1;
        }
        if self.protocol.is_empty() {
            self.protocol = "invalid".to_owned();
        }
        if self.credentials.contains_key("sing_box_outbound") {
            // Preserve unsupported documents privately and expose a generic
            // diagnostic without leaking their values.
            self.credentials.retain(|key, _| key == "sing_box_outbound");
            self.options = TransitOptions::default();
            if diagnostic.is_none() {
                diagnostic = Some(self::diagnostic(
                    NodeUnavailableReason::AdapterUnavailable,
                    BTreeSet::from(["sing_box_outbound".to_owned()]),
                ));
            }
        }
        let state = diagnostic.as_ref().map_or_else(
            || {
                if self.credentials.contains_key("sing_box_outbound") {
                    DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
                } else {
                    adapter_state(&self.protocol, available)
                }
            },
            |d| DynamicNodeState::Unavailable(d.code),
        );
        let mut credential = SubscriptionCredential::new(self.credentials);
        credential.original_sing_box_outbound = self.original_sing_box_outbound;
        NormalizedNode {
            config: TransitProxyConfig {
                id: TransitProxyId::in_namespace(
                    config.id.namespace(),
                    unique_node_id(&config.id, &self.name, index, used),
                ),
                source: Some(TransitSource {
                    source_type: source.to_owned(),
                    subscription: config.id.as_str().to_owned(),
                }),
                protocol: self.protocol,
                endpoint: Endpoint {
                    host: self.host,
                    port: self.port,
                },
                credentials_ref: None,
                labels: BTreeMap::from([
                    ("source.name".to_owned(), self.name),
                    ("source.format".to_owned(), source.to_owned()),
                ]),
                tags: self.tags,
                weight: self.weight.clamp(1, 1_000_000),
                options: self.options,
            },
            credential,
            state,
            diagnostic,
            usage: None,
        }
    }
}

fn diagnostic(code: NodeUnavailableReason, fields: BTreeSet<String>) -> NodeDiagnostic {
    NodeDiagnostic {
        code,
        fields: fields
            .into_iter()
            .take(64)
            .map(|field| {
                if field.len() <= 96
                    && field
                        .bytes()
                        .all(|ch| ch.is_ascii_alphanumeric() || b"._-".contains(&ch))
                {
                    field
                } else {
                    "unknown_parameter".to_owned()
                }
            })
            .collect(),
        message: match code {
            NodeUnavailableReason::InvalidNode => {
                "node contains missing or invalid connection fields"
            }
            NodeUnavailableReason::UnsupportedProtocol => "node protocol is not recognized",
            NodeUnavailableReason::UnsupportedParameters => {
                "node contains unsupported connection parameters"
            }
            NodeUnavailableReason::AdapterUnavailable => "node adapter is unavailable",
        }
        .to_owned(),
    }
}

fn canonical_protocol(protocol: &str) -> String {
    match protocol.to_ascii_lowercase().as_str() {
        "shadowsocks" => "ss".to_owned(),
        "socks" => "socks5".to_owned(),
        "hy2" | "hysteria-2" => "hysteria2".to_owned(),
        value => value.to_owned(),
    }
}

pub(super) fn normalize(
    config: &SubscriptionConfig,
    body: &[u8],
    available: &BTreeSet<String>,
) -> Result<Vec<NormalizedNode>, SubscriptionError> {
    let source = config.source.source_type;
    let (format, nodes) = match source {
        SubscriptionSourceType::Static => return Err(SubscriptionError::StaticSource),
        SubscriptionSourceType::Clash => ("clash", clash(body)?),
        SubscriptionSourceType::Sip008 => ("sip008", sip008(body)?),
        SubscriptionSourceType::Uri => ("uri", uris(body)?),
        SubscriptionSourceType::SingBox => ("sing_box", sing_box(body)?),
        SubscriptionSourceType::Surge => ("surge", lines(body, "surge")?),
        SubscriptionSourceType::Quantumult => ("quantumult", lines(body, "quantumult")?),
        SubscriptionSourceType::Loon => ("loon", lines(body, "loon")?),
        SubscriptionSourceType::Auto => detect(body)?,
    };
    if nodes.len() > MAX_SUBSCRIPTION_NODES {
        return Err(SubscriptionError::TooManyNodes);
    }
    let mut used = BTreeSet::new();
    Ok(nodes
        .into_iter()
        .enumerate()
        .filter_map(|(index, node)| {
            let skip = node.skip;
            // Reserve IDs for non-node entries as older versions did, so
            // duplicate provider names keep their prior stable suffixes.
            let normalized = node.finish(format, config, index, &mut used, available);
            (!skip).then_some(normalized)
        })
        .collect())
}

fn detect(body: &[u8]) -> Result<(&'static str, Vec<Node>), SubscriptionError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| malformed("auto"))?
        .trim_start_matches('\u{feff}')
        .trim();
    if (text.starts_with('{') || text.starts_with('['))
        && let Ok(value) = serde_json::from_str::<Value>(text)
    {
        if value.get("outbounds").is_some() || value.get("endpoints").is_some() {
            return Ok(("sing_box", sing_box(body)?));
        }
        if value.is_array() || value.get("servers").is_some() {
            return Ok(("sip008", sip008(body)?));
        }
        if value.get("proxies").is_some() || value.get("proxy-providers").is_some() {
            return Ok(("clash", clash(body)?));
        }
    }
    const CLASH_KEYS: [&str; 6] = [
        "proxies:",
        "proxy-providers:",
        "'proxies':",
        "'proxy-providers':",
        "\"proxies\":",
        "\"proxy-providers\":",
    ];
    if text.lines().any(|line| {
        CLASH_KEYS
            .iter()
            .any(|key| line.trim_start().starts_with(key))
    }) || (text.starts_with('{') && CLASH_KEYS.iter().any(|key| text.contains(key)))
    {
        return Ok(("clash", clash(body)?));
    }
    if text
        .lines()
        .any(|line| line.trim() == "[Proxy]" || line.trim() == "[proxy]")
    {
        return Ok(("surge", lines(body, "surge")?));
    }
    if text.lines().any(|line| line.trim() == "[server_local]") {
        return Ok(("quantumult", lines(body, "quantumult")?));
    }
    if text.contains("://")
        || decode_base64(text)
            .is_some_and(|decoded| decoded.windows(3).any(|bytes| bytes == b"://"))
    {
        return Ok(("uri", uris(body)?));
    }
    if text
        .lines()
        .any(|line| line.contains('=') && line.contains(','))
    {
        return Ok(("surge", lines(body, "surge")?));
    }
    Err(malformed("auto"))
}

fn malformed(format: &'static str) -> SubscriptionError {
    SubscriptionError::MalformedDocument { format }
}

fn map(value: Value, index: usize) -> Result<Map<String, Value>, Box<Node>> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| Box::new(Node::invalid(index, "node")))
}

fn text(
    fields: &mut Map<String, Value>,
    name: &str,
    invalid: &mut BTreeSet<String>,
) -> Option<String> {
    match fields.remove(name) {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value),
        Some(Value::Number(value)) => Some(value.to_string()),
        Some(_) => {
            invalid.insert(name.to_owned());
            None
        }
    }
}

fn number(
    fields: &mut Map<String, Value>,
    name: &str,
    invalid: &mut BTreeSet<String>,
) -> Option<u64> {
    match text(fields, name, invalid) {
        Some(value) => match value.parse() {
            Ok(value) => Some(value),
            Err(_) => {
                invalid.insert(name.to_owned());
                None
            }
        },
        None => None,
    }
}

fn bounded_number<T: TryFrom<u64>>(
    fields: &mut Map<String, Value>,
    name: &str,
    invalid: &mut BTreeSet<String>,
) -> Option<T> {
    let value = number(fields, name, invalid)?;
    match T::try_from(value) {
        Ok(value) => Some(value),
        Err(_) => {
            invalid.insert(name.to_owned());
            None
        }
    }
}

fn flag(
    fields: &mut Map<String, Value>,
    name: &str,
    invalid: &mut BTreeSet<String>,
) -> Option<bool> {
    match fields.remove(name) {
        None | Some(Value::Null) => None,
        Some(Value::Bool(value)) => Some(value),
        Some(Value::Number(value)) if value.as_u64().is_some_and(|value| value <= 1) => {
            Some(value.as_u64() == Some(1))
        }
        Some(Value::String(value)) => match value.to_ascii_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => {
                invalid.insert(name.to_owned());
                None
            }
        },
        Some(_) => {
            invalid.insert(name.to_owned());
            None
        }
    }
}

fn string_list(
    fields: &mut Map<String, Value>,
    name: &str,
    invalid: &mut BTreeSet<String>,
) -> Vec<String> {
    match fields.remove(name) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(values)) if values.iter().all(Value::is_string) => values
            .into_iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect(),
        Some(_) => {
            invalid.insert(name.to_owned());
            Vec::new()
        }
    }
}

fn header_map(value: Option<Value>, field: &str, node: &mut Node) -> BTreeMap<String, String> {
    let Some(value) = value else {
        return BTreeMap::new();
    };
    let Some(values) = value.as_object() else {
        node.invalid.insert(field.to_owned());
        return BTreeMap::new();
    };
    let mut result = BTreeMap::new();
    for (key, value) in values {
        if matches!(
            key.to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
        ) {
            node.unsupported.insert(format!("{field}.{key}"));
            continue;
        }
        if let Some(value) = value.as_str() {
            result.insert(key.clone(), value.to_owned());
        } else {
            node.invalid.insert(format!("{field}.{key}"));
        }
    }
    result
}

fn credentials(fields: &mut Map<String, Value>, names: &[(&str, &str)], node: &mut Node) {
    for (input, output) in names {
        if let Some(value) = text(fields, input, &mut node.invalid) {
            match node.credentials.entry((*output).to_owned()) {
                std::collections::btree_map::Entry::Occupied(entry) => {
                    if entry.get() != &value {
                        node.invalid.insert((*input).to_owned());
                        node.invalid.insert((*output).to_owned());
                    }
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }
    }
}

fn leftovers(fields: Map<String, Value>, prefix: &str, node: &mut Node) {
    for (field, _) in fields {
        node.unsupported.insert(format!("{prefix}{field}"));
    }
}

fn clash(body: &[u8]) -> Result<Vec<Node>, SubscriptionError> {
    let value: Value = serde_yaml::from_slice(body).map_err(|_| malformed("clash"))?;
    let nodes = match value.get("proxies") {
        Some(Value::Array(nodes)) => nodes.as_slice(),
        None if value
            .get("proxy-providers")
            .and_then(Value::as_object)
            .is_some() =>
        {
            &[]
        }
        _ => return Err(malformed("clash")),
    };
    if nodes.len() > MAX_SUBSCRIPTION_NODES {
        return Err(SubscriptionError::TooManyNodes);
    }
    let mut result: Vec<_> = nodes
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, value)| clash_node(value, index))
        .collect();
    if let Some(providers) = value.get("proxy-providers") {
        let providers = providers.as_object().ok_or_else(|| malformed("clash"))?;
        for name in providers.keys() {
            let mut node = Node::new(result.len());
            node.name = name.to_owned();
            node.protocol = "http".to_owned();
            node.host = "unsupported.invalid".to_owned();
            node.port = 1;
            node.unsupported.insert("proxy-providers".to_owned());
            result.push(node);
        }
    }
    if result.len() > MAX_SUBSCRIPTION_NODES {
        return Err(SubscriptionError::TooManyNodes);
    }
    Ok(result)
}

fn clash_node(value: Value, index: usize) -> Node {
    let mut fields = match map(value, index) {
        Ok(fields) => fields,
        Err(node) => return *node,
    };
    let mut node = Node::new(index);
    node.name = text(&mut fields, "name", &mut node.invalid).unwrap_or(node.name);
    node.protocol =
        canonical_protocol(&text(&mut fields, "type", &mut node.invalid).unwrap_or_default());
    node.host = text(&mut fields, "server", &mut node.invalid).unwrap_or_default();
    node.port = number(&mut fields, "port", &mut node.invalid)
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or_default();
    node.weight = bounded_number::<u32>(&mut fields, "weight", &mut node.invalid).unwrap_or(100);
    node.tags = string_list(&mut fields, "tags", &mut node.invalid)
        .into_iter()
        .collect();
    credentials(
        &mut fields,
        &[
            ("username", "username"),
            ("password", "password"),
            ("cipher", "cipher"),
            ("uuid", "uuid"),
            ("alterId", "alter_id"),
            ("flow", "flow"),
            ("plugin", "plugin"),
            ("obfs", "obfs"),
            ("obfs-password", "obfs_password"),
            ("auth-str", "password"),
            ("auth", "password"),
            ("congestion-controller", "congestion_control"),
            ("udp-relay-mode", "udp_relay_mode"),
            ("up", "up_mbps"),
            ("down", "down_mbps"),
            ("ports", "server_ports"),
            ("mport", "server_ports"),
            ("hop-interval", "hop_interval"),
            ("heartbeat-interval", "heartbeat"),
            ("token", "password"),
            ("psk", "psk"),
            ("userkey", "userkey"),
            ("version", "version"),
        ],
        &mut node,
    );
    if node.protocol == "vmess"
        && let Some(cipher) = node.credentials.remove("cipher")
    {
        node.credentials.insert("security".to_owned(), cipher);
    }
    if matches!(node.protocol.as_str(), "vless" | "xtls")
        && let Some(encryption) = text(&mut fields, "encryption", &mut node.invalid)
        && encryption != "none"
    {
        node.unsupported.insert("encryption".to_owned());
    }
    if let Some(value) = fields.remove("plugin-opts") {
        node.credentials
            .insert("plugin_opts".to_owned(), value.to_string());
    }
    node.options.udp = flag(&mut fields, "udp", &mut node.invalid);
    if matches!(node.protocol.as_str(), "socks5" | "ss") {
        let enabled = flag(&mut fields, "udp-over-tcp", &mut node.invalid);
        let version = bounded_number::<u8>(&mut fields, "udp-over-tcp-version", &mut node.invalid);
        if version.is_some_and(|value| !matches!(value, 1 | 2))
            || version.is_some() && enabled != Some(true)
        {
            node.invalid.insert("udp-over-tcp-version".to_owned());
        } else if enabled == Some(true) {
            node.options.udp_over_tcp = Some(version.unwrap_or(1));
        }
    }
    if node.protocol == "ss" && node.options.udp.is_none() {
        // Mihomo's Shadowsocks `udp` flag defaults to false; an omitted value
        // must not silently enable a capability absent from the source node.
        node.options.udp = Some(false);
    }
    node.options.tcp_fast_open = flag(&mut fields, "tfo", &mut node.invalid);
    node.options.bind_interface = text(&mut fields, "interface-name", &mut node.invalid);
    node.options.routing_mark =
        bounded_number::<u32>(&mut fields, "routing-mark", &mut node.invalid);
    node.options.packet_encoding = text(&mut fields, "packet-encoding", &mut node.invalid);
    let vless_packet_explicit = node
        .options
        .packet_encoding
        .as_ref()
        .is_some_and(|value| !value.is_empty());
    if node.protocol == "vmess" {
        let global_padding =
            flag(&mut fields, "global-padding", &mut node.invalid).unwrap_or(false);
        let authenticated_length =
            flag(&mut fields, "authenticated-length", &mut node.invalid).unwrap_or(false);
        if global_padding || authenticated_length {
            node.options.vmess = Some(TransitVmessOptions {
                global_padding,
                authenticated_length,
            });
        }
    }
    if matches!(node.protocol.as_str(), "vless" | "xtls") {
        node.options.packet_encoding = match node.options.packet_encoding.take().as_deref() {
            None | Some("") => Some("xudp".to_owned()),
            Some("packet") => Some("packetaddr".to_owned()),
            Some(value) => Some(value.to_owned()),
        };
    } else if node.protocol == "vmess" && node.options.packet_encoding.as_deref() == Some("packet")
    {
        node.options.packet_encoding = Some("packetaddr".to_owned());
    }
    let headers = fields.remove("headers");
    node.options.headers = header_map(headers, "headers", &mut node);
    let mut tls = TransitTls {
        enabled: flag(&mut fields, "tls", &mut node.invalid).unwrap_or(matches!(
            node.protocol.as_str(),
            "https" | "trojan" | "hysteria" | "hysteria2" | "tuic" | "anytls"
        )),
        ..TransitTls::default()
    };
    tls.server_name = text(&mut fields, "servername", &mut node.invalid)
        .or_else(|| text(&mut fields, "sni", &mut node.invalid));
    tls.insecure = flag(&mut fields, "skip-cert-verify", &mut node.invalid).unwrap_or_default();
    tls.alpn = string_list(&mut fields, "alpn", &mut node.invalid);
    tls.fingerprint = text(&mut fields, "client-fingerprint", &mut node.invalid);
    tls.certificate_sha256 = text(&mut fields, "fingerprint", &mut node.invalid);
    if tls
        .certificate_sha256
        .as_deref()
        .is_some_and(|value| pathchord_policy::parse_certificate_sha256(value).is_none())
    {
        node.invalid.insert("fingerprint".to_owned());
    }
    tls.certificate = string_list(&mut fields, "certificate", &mut node.invalid);
    if let Some(reality) = fields.remove("reality-opts") {
        if let Some(mut reality) = reality.as_object().cloned() {
            let public_key =
                text(&mut reality, "public-key", &mut node.invalid).unwrap_or_default();
            let short_id = text(&mut reality, "short-id", &mut node.invalid).unwrap_or_default();
            tls.reality = Some(TransitReality {
                public_key,
                short_id,
            });
            leftovers(reality, "reality-opts.", &mut node);
        } else {
            node.invalid.insert("reality-opts".to_owned());
        }
    }
    if tls != TransitTls::default() {
        node.options.tls = Some(tls);
    }
    if let Some(network) = text(&mut fields, "network", &mut node.invalid)
        && network != "tcp"
    {
        node.options.transport = Some(TransitTransport {
            kind: if network == "h2" {
                "http".into()
            } else {
                network
            },
            ..TransitTransport::default()
        });
    }
    for (key, kind) in [
        ("ws-opts", "ws"),
        ("grpc-opts", "grpc"),
        ("http-opts", "http"),
        ("h2-opts", "http"),
        ("http-upgrade-opts", "httpupgrade"),
    ] {
        if let Some(value) = fields.remove(key) {
            if let Some(mut options) = value.as_object().cloned() {
                let mut transport = node.options.transport.take().unwrap_or_default();
                if !transport.kind.is_empty() && transport.kind != kind {
                    node.invalid.insert("network".to_owned());
                }
                transport.kind = kind.to_owned();
                transport.path = text(&mut options, "path", &mut node.invalid);
                transport.host = string_list(&mut options, "host", &mut node.invalid);
                transport.service_name = text(&mut options, "grpc-service-name", &mut node.invalid);
                transport.max_early_data =
                    bounded_number::<u32>(&mut options, "max-early-data", &mut node.invalid);
                transport.early_data_header_name =
                    text(&mut options, "early-data-header-name", &mut node.invalid);
                let headers = options.remove("headers");
                transport.headers = header_map(headers, key, &mut node);
                leftovers(options, &format!("{key}."), &mut node);
                node.options.transport = Some(transport);
            } else {
                node.invalid.insert(key.to_owned());
            }
        }
    }
    if let Some(value) = fields.remove("smux") {
        node.options.multiplex = parse_multiplex(value, true, &mut node);
    }
    if matches!(node.protocol.as_str(), "vless" | "xtls")
        && !vless_packet_explicit
        && node
            .options
            .multiplex
            .as_ref()
            .is_some_and(|mux| mux.enabled)
    {
        node.options.packet_encoding = None;
    }
    // Explicit false options with no effect may be omitted; true values must
    // never vanish when the selected engine cannot represent their semantics.
    for key in ["udp-over-tcp", "disable-sni", "reduce-rtt", "zero-rtt"] {
        if let Some(value) = flag(&mut fields, key, &mut node.invalid)
            && value
        {
            node.unsupported.insert(key.to_owned());
        }
    }
    leftovers(fields, "", &mut node);
    node
}

fn parse_multiplex(value: Value, clash: bool, node: &mut Node) -> Option<TransitMultiplex> {
    let Some(mut fields) = value.as_object().cloned() else {
        node.invalid.insert("multiplex".to_owned());
        return None;
    };
    let result = TransitMultiplex {
        enabled: flag(&mut fields, "enabled", &mut node.invalid).unwrap_or_default(),
        protocol: text(&mut fields, "protocol", &mut node.invalid),
        max_connections: bounded_number::<u32>(
            &mut fields,
            if clash {
                "max-connections"
            } else {
                "max_connections"
            },
            &mut node.invalid,
        ),
        min_streams: bounded_number::<u32>(
            &mut fields,
            if clash { "min-streams" } else { "min_streams" },
            &mut node.invalid,
        ),
        max_streams: bounded_number::<u32>(
            &mut fields,
            if clash { "max-streams" } else { "max_streams" },
            &mut node.invalid,
        ),
        padding: flag(&mut fields, "padding", &mut node.invalid).unwrap_or_default(),
    };
    leftovers(fields, "multiplex.", node);
    Some(result)
}

fn sip008(body: &[u8]) -> Result<Vec<Node>, SubscriptionError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| malformed("sip008"))?;
    if value
        .get("version")
        .is_some_and(|version| version.as_u64() != Some(1))
    {
        return Err(malformed("sip008"));
    }
    let nodes = value
        .as_array()
        .or_else(|| value.get("servers").and_then(Value::as_array))
        .ok_or_else(|| malformed("sip008"))?;
    if nodes.len() > MAX_SUBSCRIPTION_NODES {
        return Err(SubscriptionError::TooManyNodes);
    }
    Ok(nodes
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, value)| {
            let mut fields = match map(value, index) {
                Ok(fields) => fields,
                Err(node) => return *node,
            };
            let mut node = Node::new(index);
            node.protocol = "ss".to_owned();
            node.name = text(&mut fields, "remarks", &mut node.invalid).unwrap_or(node.name);
            node.host = text(&mut fields, "server", &mut node.invalid).unwrap_or_default();
            node.port = bounded_number::<u16>(&mut fields, "server_port", &mut node.invalid)
                .unwrap_or_default();
            credentials(
                &mut fields,
                &[
                    ("method", "cipher"),
                    ("password", "password"),
                    ("plugin", "plugin"),
                    ("plugin_opts", "plugin_opts"),
                ],
                &mut node,
            );
            fields.remove("id");
            leftovers(fields, "", &mut node);
            node
        })
        .collect())
}

fn sing_box(body: &[u8]) -> Result<Vec<Node>, SubscriptionError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| malformed("sing_box"))?;
    let mut nodes = Vec::new();
    let mut found = false;
    for key in ["outbounds", "endpoints"] {
        if let Some(values) = value.get(key) {
            let values = values.as_array().ok_or_else(|| malformed("sing_box"))?;
            found = true;
            if nodes.len().saturating_add(values.len()) > MAX_SUBSCRIPTION_NODES {
                return Err(SubscriptionError::TooManyNodes);
            }
            nodes.extend(values.iter().cloned());
        }
    }
    if !found {
        return Err(malformed("sing_box"));
    }
    Ok(nodes
        .into_iter()
        .enumerate()
        .map(|(index, value)| sing_box_node(value, index))
        .collect())
}

fn sing_box_node(value: Value, index: usize) -> Node {
    let skip = matches!(
        value.get("type").and_then(Value::as_str),
        Some("direct" | "block" | "selector" | "urltest")
    );
    if let Some(mut node) = sing_box_native_node(&value, index) {
        node.original_sing_box_outbound = Some(value.to_string());
        return node;
    }
    let original = value.to_string();
    let mut fields = match map(value, index) {
        Ok(fields) => fields,
        Err(node) => return *node,
    };
    let mut node = Node::new(index);
    node.skip = skip;
    node.protocol =
        canonical_protocol(&text(&mut fields, "type", &mut node.invalid).unwrap_or_default());
    if node.protocol == "socks5" {
        match fields.get("version") {
            Some(Value::String(version)) if version == "4" => node.protocol = "socks4".to_owned(),
            Some(Value::String(version)) if version == "4a" => node.protocol = "socks4a".to_owned(),
            Some(Value::String(version)) if version == "5" => {}
            None => {}
            Some(_) => {
                node.invalid.insert("version".to_owned());
            }
        }
    }
    node.name = text(&mut fields, "tag", &mut node.invalid).unwrap_or(node.name);
    if node.protocol == "wireguard" {
        let first_peer = fields
            .get("peers")
            .and_then(Value::as_array)
            .and_then(|peers| peers.first())
            .and_then(Value::as_object);
        if let Some(peer) = first_peer {
            node.host = peer
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            node.port = peer
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .unwrap_or_default();
        } else {
            // Legacy WireGuard outbounds may still be supplied by a provider;
            // the exact engine validates its version-specific schema.
            node.host = text(&mut fields, "server", &mut node.invalid).unwrap_or_default();
            node.port = bounded_number::<u16>(&mut fields, "server_port", &mut node.invalid)
                .unwrap_or_default();
        }
    } else {
        node.host = text(&mut fields, "server", &mut node.invalid).unwrap_or_default();
        node.port = bounded_number::<u16>(&mut fields, "server_port", &mut node.invalid)
            .unwrap_or_default();
    }
    // Only basic identity, endpoint, and required credential shapes are
    // inspected here. The complete private document is authoritative: new
    // engine-supported TLS/transport fields must not be dropped or rejected
    // by a second, incomplete schema. Engine.prepare performs the exact
    // binary check before this node becomes ready for routing.
    credentials(
        &mut fields,
        &[
            ("username", "username"),
            ("password", "password"),
            ("method", "cipher"),
            ("uuid", "uuid"),
            ("psk", "psk"),
            ("userkey", "userkey"),
            ("version", "version"),
        ],
        &mut node,
    );
    node.credentials
        .insert("sing_box_outbound".to_owned(), original);
    node
}

/// Normalize a strict, representable subset to native adapters. Keep the
/// original private document for every other combination so an unsupported
/// field can never silently turn into a different connection.
fn sing_box_native_node(value: &Value, index: usize) -> Option<Node> {
    let mut fields = value.as_object()?.clone();
    let protocol = canonical_protocol(fields.remove("type")?.as_str()?);
    if !matches!(
        protocol.as_str(),
        "socks5"
            | "http"
            | "https"
            | "ss"
            | "vmess"
            | "vless"
            | "trojan"
            | "anytls"
            | "hysteria2"
            | "tuic"
    ) {
        return None;
    }
    // sing-box's Trojan allows plaintext when TLS is absent, whereas the
    // native adapter requires TLS. Preserve such nodes as unavailable.
    if protocol == "trojan" && !fields.contains_key("tls") {
        return None;
    }
    let mut node = Node::new(index);
    node.protocol = protocol;
    node.name = text(&mut fields, "tag", &mut node.invalid).unwrap_or(node.name);
    node.host = text(&mut fields, "server", &mut node.invalid).unwrap_or_default();
    node.port =
        bounded_number::<u16>(&mut fields, "server_port", &mut node.invalid).unwrap_or_default();

    if node.protocol == "socks5"
        && let Some(version) = text(&mut fields, "version", &mut node.invalid)
        && version != "5"
    {
        return None;
    }
    if matches!(node.protocol.as_str(), "socks5" | "ss")
        && let Some(value) = fields.remove("udp_over_tcp")
    {
        node.options.udp_over_tcp = sing_box_udp_over_tcp(value)?;
    }
    if let Some(network) = fields.remove("network") {
        match network {
            Value::String(network) if network == "tcp" => node.options.udp = Some(false),
            Value::Array(networks) if networks.len() == 1 && networks[0] == "tcp" => {
                node.options.udp = Some(false);
            }
            Value::Array(networks)
                if networks.len() == 2
                    && networks.iter().any(|network| network == "tcp")
                    && networks.iter().any(|network| network == "udp") => {}
            _ => return None,
        }
    }
    let mut credential_fields = vec![];
    match node.protocol.as_str() {
        "socks5" => credential_fields.extend([("username", "username"), ("password", "password")]),
        "http" | "https" => credential_fields.extend([
            ("username", "username"),
            ("password", "password"),
            ("path", "http_path"),
        ]),
        "ss" => credential_fields.extend([
            ("method", "cipher"),
            ("password", "password"),
            ("plugin", "plugin"),
            ("plugin_opts", "plugin_opts"),
        ]),
        "vless" => credential_fields.extend([("uuid", "uuid"), ("flow", "flow")]),
        "vmess" => credential_fields.extend([
            ("uuid", "uuid"),
            ("security", "security"),
            ("alter_id", "alter_id"),
        ]),
        "trojan" | "anytls" => credential_fields.push(("password", "password")),
        "hysteria2" => credential_fields.extend([
            ("password", "password"),
            ("up_mbps", "up_mbps"),
            ("down_mbps", "down_mbps"),
        ]),
        "tuic" => credential_fields.extend([
            ("uuid", "uuid"),
            ("password", "password"),
            ("congestion_control", "congestion_control"),
            ("udp_relay_mode", "udp_relay_mode"),
            ("heartbeat", "heartbeat"),
        ]),
        _ => unreachable!(),
    }
    credentials(&mut fields, &credential_fields, &mut node);
    if node.protocol == "hysteria2" {
        sing_box_hysteria2_hopping(&mut fields, &mut node)?;
    }
    if node.protocol == "tuic" {
        for field in ["zero_rtt_handshake", "udp_over_stream"] {
            if let Some(value) = flag(&mut fields, field, &mut node.invalid) {
                node.credentials.insert(field.to_owned(), value.to_string());
            }
        }
    }
    let vless_packet_implicit = node.protocol == "vless" && !fields.contains_key("packet_encoding");
    if node.protocol == "vless" {
        node.options.packet_encoding = match text(&mut fields, "packet_encoding", &mut node.invalid)
        {
            None => Some("xudp".to_owned()),
            Some(value) if value.is_empty() => {
                if node
                    .credentials
                    .get("flow")
                    .is_some_and(|flow| !flow.is_empty())
                {
                    return None;
                }
                None
            }
            Some(value) => Some(value),
        };
    } else if node.protocol == "vmess" {
        node.options.packet_encoding = text(&mut fields, "packet_encoding", &mut node.invalid)
            .filter(|value| !value.is_empty());
        let global_padding =
            flag(&mut fields, "global_padding", &mut node.invalid).unwrap_or(false);
        let authenticated_length =
            flag(&mut fields, "authenticated_length", &mut node.invalid).unwrap_or(false);
        if global_padding || authenticated_length {
            node.options.vmess = Some(TransitVmessOptions {
                global_padding,
                authenticated_length,
            });
        }
    }
    if let Some(value) = fields.remove("multiplex") {
        node.options.multiplex = parse_multiplex(value, false, &mut node);
    }
    if vless_packet_implicit
        && node
            .options
            .multiplex
            .as_ref()
            .is_some_and(|mux| mux.enabled)
    {
        node.options.packet_encoding = None;
    }
    if let Some(value) = fields.remove("headers") {
        node.options.headers = sing_box_headers(value, "headers", &mut node)?;
    }
    if let Some(value) = fields.remove("tls") {
        let mut tls = value.as_object()?.clone();
        let mut options = TransitTls {
            enabled: flag(&mut tls, "enabled", &mut node.invalid).unwrap_or(false),
            server_name: text(&mut tls, "server_name", &mut node.invalid),
            insecure: flag(&mut tls, "insecure", &mut node.invalid).unwrap_or(false),
            alpn: string_list(&mut tls, "alpn", &mut node.invalid),
            certificate: string_list(&mut tls, "certificate", &mut node.invalid),
            client_certificate: string_list(&mut tls, "client_certificate", &mut node.invalid),
            ..TransitTls::default()
        };
        if let Some(key) = tls.remove("client_key") {
            let mut map = Map::from_iter([("client_key".to_owned(), key)]);
            let key = string_list(&mut map, "client_key", &mut node.invalid).join("\n");
            node.credentials.insert("client_key".to_owned(), key);
            options.client_key_field = Some("client_key".to_owned());
        }
        if let Some(value) = tls.remove("utls") {
            let mut utls = value.as_object()?.clone();
            let enabled = flag(&mut utls, "enabled", &mut node.invalid).unwrap_or(false);
            let fingerprint = text(&mut utls, "fingerprint", &mut node.invalid);
            if !utls.is_empty() || (!enabled && fingerprint.is_some()) {
                return None;
            }
            if enabled {
                options.fingerprint = Some(
                    fingerprint
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| "chrome".to_owned()),
                );
            }
        }
        if let Some(value) = tls.remove("reality") {
            let mut reality = value.as_object()?.clone();
            let enabled = flag(&mut reality, "enabled", &mut node.invalid).unwrap_or(false);
            let public_key =
                text(&mut reality, "public_key", &mut node.invalid).unwrap_or_default();
            let short_id = text(&mut reality, "short_id", &mut node.invalid).unwrap_or_default();
            if !reality.is_empty() || (!enabled && (!public_key.is_empty() || !short_id.is_empty()))
            {
                return None;
            }
            if enabled {
                options.reality = Some(TransitReality {
                    public_key,
                    short_id,
                });
            }
        }
        if !tls.is_empty() {
            return None;
        }
        node.options.tls = Some(options);
    }
    if node.protocol == "vmess"
        && node
            .credentials
            .get("security")
            .is_none_or(|security| security.is_empty() || security == "auto")
    {
        let tls = node.options.tls.as_ref().is_some_and(|tls| tls.enabled);
        node.credentials.insert(
            "security".to_owned(),
            crate::vmess::sing_box_default_security(tls).to_owned(),
        );
    }
    if let Some(value) = fields.remove("transport") {
        let mut transport = value.as_object()?.clone();
        let kind = text(&mut transport, "type", &mut node.invalid).unwrap_or_default();
        let mut options = TransitTransport {
            kind,
            ..TransitTransport::default()
        };
        options.path = text(&mut transport, "path", &mut node.invalid);
        options.host = string_list(&mut transport, "host", &mut node.invalid);
        options.service_name = text(&mut transport, "service_name", &mut node.invalid);
        options.max_early_data =
            bounded_number::<u32>(&mut transport, "max_early_data", &mut node.invalid);
        options.early_data_header_name =
            text(&mut transport, "early_data_header_name", &mut node.invalid);
        if let Some(value) = transport.remove("headers") {
            options.headers = sing_box_headers(value, "transport.headers", &mut node)?;
        }
        if !transport.is_empty() {
            return None;
        }
        node.options.transport = Some(options);
    }
    if node.protocol == "hysteria2"
        && let Some(value) = fields.remove("obfs")
    {
        let mut obfs = value.as_object()?.clone();
        credentials(
            &mut obfs,
            &[
                ("type", "obfs"),
                ("password", "obfs_password"),
                ("min_packet_size", "gecko_min_packet_size"),
                ("max_packet_size", "gecko_max_packet_size"),
            ],
            &mut node,
        );
        if !obfs.is_empty() {
            return None;
        }
    }
    if !fields.is_empty() || !node.invalid.is_empty() || !node.unsupported.is_empty() {
        return None;
    }
    Some(node)
}

fn sing_box_hysteria2_hopping(fields: &mut Map<String, Value>, node: &mut Node) -> Option<()> {
    let ranges = match fields.remove("server_ports") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(range)) => vec![Value::String(range)],
        Some(Value::Array(ranges)) if ranges.len() <= 512 => ranges,
        _ => return None,
    };
    let hop_interval = match fields.remove("hop_interval") {
        None | Some(Value::Null) => None,
        Some(Value::String(interval)) if !ranges.is_empty() => Some(interval),
        _ => return None,
    };
    if ranges.is_empty() {
        return Some(());
    }
    let mut ports = Vec::with_capacity(ranges.len());
    for range in &ranges {
        let (start, end) = range.as_str()?.split_once(':')?;
        let start = start.parse::<u16>().ok()?;
        let end = end.parse::<u16>().ok()?;
        if start == 0 || end < start {
            return None;
        }
        ports.push((start, end));
    }
    ports.sort_unstable();
    if ports.windows(2).any(|pair| pair[0].1 >= pair[1].0) {
        // A port included in more than one upstream range has extra weight.
        // The native adapter samples uniformly from the union.
        return None;
    }
    if node.port == 0 && !fields.contains_key("realm") {
        node.port = ports[0].0;
    }
    let ports = ports
        .into_iter()
        .map(|(start, end)| format!("{start}-{end}"))
        .collect::<Vec<_>>()
        .join(",");
    node.credentials.insert("server_ports".to_owned(), ports);
    if let Some(hop_interval) = hop_interval {
        node.credentials
            .insert("hop_interval".to_owned(), hop_interval);
    }
    Some(())
}

fn sing_box_udp_over_tcp(value: Value) -> Option<Option<u8>> {
    if let Some(enabled) = value.as_bool() {
        return Some(enabled.then_some(2));
    }
    let mut fields = value.as_object()?.clone();
    let enabled = match fields.remove("enabled") {
        Some(value) => value.as_bool()?,
        None => false,
    };
    let version = match fields.remove("version") {
        Some(value) => u8::try_from(value.as_u64()?).ok()?,
        None => 0,
    };
    if !fields.is_empty() || !matches!(version, 0..=2) {
        return None;
    }
    Some(enabled.then_some(if version == 0 { 2 } else { version }))
}

fn sing_box_headers(
    value: Value,
    field: &str,
    node: &mut Node,
) -> Option<BTreeMap<String, String>> {
    let mut headers = value.as_object()?.clone();
    for value in headers.values_mut() {
        if let Value::Array(values) = value {
            if values.len() != 1 || !values[0].is_string() {
                return None;
            }
            *value = values[0].clone();
        }
    }
    Some(header_map(Some(Value::Object(headers)), field, node))
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let compact: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&compact).ok())
}

fn decode_percent(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut input = text.bytes();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let high = (input.next()? as char).to_digit(16)?;
            let low = (input.next()? as char).to_digit(16)?;
            bytes.push((high * 16 + low) as u8);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).ok()
}

fn uris(body: &[u8]) -> Result<Vec<Node>, SubscriptionError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| malformed("uri"))?
        .trim_start_matches('\u{feff}')
        .trim();
    let decoded;
    let text = if text.contains("://") {
        text
    } else {
        decoded = decode_base64(text)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| malformed("uri"))?;
        decoded.trim()
    };
    let lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with(';'))
        .collect();
    if !lines.iter().any(|line| line.contains("://")) {
        return Err(malformed("uri"));
    }
    if lines.len() > MAX_SUBSCRIPTION_NODES {
        return Err(SubscriptionError::TooManyNodes);
    }
    Ok(lines
        .into_iter()
        .enumerate()
        .map(|(index, uri)| uri_node(uri, index))
        .collect())
}

fn uri_node(uri: &str, index: usize) -> Node {
    if let Some(payload) = uri.strip_prefix("vmess://") {
        return vmess_uri(payload, index);
    }
    if let Some(payload) = uri.strip_prefix("ss://") {
        return ss_uri(payload, index);
    }
    let Ok(url) = Url::parse(uri) else {
        return Node::invalid(index, "uri");
    };
    if url.scheme() == "trojan-go" {
        return trojan_go_uri(&url, index);
    }
    let mut node = Node::new(index);
    node.protocol = canonical_protocol(url.scheme());
    node.name = url
        .fragment()
        .and_then(decode_percent)
        .filter(|name| !name.is_empty())
        .unwrap_or(node.name);
    node.host = url
        .host_str()
        .map(|host| host.trim_matches(['[', ']']).to_owned())
        .unwrap_or_default();
    node.port = url.port().unwrap_or(match node.protocol.as_str() {
        "http" => 80,
        "https" | "trojan" | "hysteria2" | "tuic" => 443,
        "socks5" | "socks4" | "socks4a" => 1080,
        _ => 0,
    });
    let Some(username) = decode_percent(url.username()) else {
        return Node::invalid(index, "username");
    };
    let password = url.password().and_then(decode_percent);
    match node.protocol.as_str() {
        "vless" | "xtls" => {
            node.credentials.insert("uuid".to_owned(), username);
        }
        "trojan" => {
            node.credentials.insert("password".to_owned(), username);
        }
        "hysteria" | "hysteria2" => {
            node.credentials.insert(
                "password".to_owned(),
                password.map_or(username.clone(), |password| {
                    format!("{username}:{password}")
                }),
            );
        }
        "tuic" => {
            node.credentials.insert("uuid".to_owned(), username);
            if let Some(password) = password {
                node.credentials.insert("password".to_owned(), password);
            }
        }
        "http" | "https" | "socks5" | "socks4" | "socks4a" => {
            if !username.is_empty() {
                node.credentials.insert("username".to_owned(), username);
            }
            if let Some(password) = password {
                if matches!(node.protocol.as_str(), "socks4" | "socks4a") {
                    node.unsupported.insert("password".to_owned());
                }
                node.credentials.insert("password".to_owned(), password);
            }
        }
        _ => {}
    }
    if !matches!(url.path(), "" | "/") {
        node.unsupported.insert("uri.path".to_owned());
    }
    let mut query = Map::new();
    for (key, value) in url.query_pairs() {
        if query
            .insert(key.to_string(), Value::String(value.to_string()))
            .is_some()
        {
            node.invalid.insert(format!("query.{key}"));
        }
    }
    apply_uri_query(&mut query, &mut node);
    leftovers(query, "query.", &mut node);
    node
}

/// Normalize the Trojan-go share-link syntax without discarding its options.
fn trojan_go_uri(url: &Url, index: usize) -> Node {
    let mut node = Node::new(index);
    node.protocol = "trojan".to_owned();
    node.name = url
        .fragment()
        .and_then(decode_percent)
        .filter(|name| !name.is_empty())
        .unwrap_or(node.name);
    node.host = url
        .host_str()
        .map(|host| host.trim_matches(['[', ']']).to_owned())
        .unwrap_or_default();
    node.port = url.port().unwrap_or(443);
    match decode_percent(url.username()) {
        Some(password) if !password.is_empty() && url.password().is_none() => {
            node.credentials.insert("password".to_owned(), password);
        }
        _ => {
            node.invalid.insert("uri.userinfo".to_owned());
        }
    }
    if !matches!(url.path(), "" | "/") {
        node.unsupported.insert("uri.path".to_owned());
    }
    let mut query = Map::new();
    if url.query().is_some_and(|raw| {
        raw.split('&').any(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            decode_percent(key).is_none() || decode_percent(value).is_none()
        })
    }) {
        node.invalid.insert("query.encoding".to_owned());
    }
    for (key, value) in url.query_pairs() {
        if query
            .insert(key.to_string(), Value::String(value.to_string()))
            .is_some()
        {
            node.invalid.insert(format!("query.{key}"));
        }
    }

    // dae accepts these additional spellings; reject contradictions rather
    // than silently letting a false value override a true one.
    let mut insecure = flag(&mut query, "allow_insecure", &mut node.invalid);
    for alias in ["allowinsecure", "skipVerify"] {
        if let Some(value) = flag(&mut query, alias, &mut node.invalid) {
            if insecure.is_some_and(|previous| previous != value) {
                node.invalid.insert(format!("query.{alias}"));
            } else {
                insecure = Some(value);
            }
        }
    }
    if let Some(value) = insecure {
        query.insert("allow_insecure".to_owned(), Value::Bool(value));
    }
    if let Some(security) = text(&mut query, "security", &mut node.invalid)
        && security != "tls"
    {
        node.unsupported.insert("query.security".to_owned());
    }
    if let Some(encryption) = text(&mut query, "encryption", &mut node.invalid) {
        let encryption = zeroize::Zeroizing::new(encryption);
        if encryption.is_empty() {
            node.invalid.insert("query.encryption".to_owned());
        } else if encryption.as_str() != "none" {
            match encryption
                .strip_prefix("ss;")
                .and_then(|ss| ss.split_once(':'))
            {
                Some((_, "")) => {
                    node.invalid.insert("query.encryption".to_owned());
                }
                Some((method, password))
                    if matches!(
                        method,
                        "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305"
                    ) =>
                {
                    node.credentials
                        .insert("trojan_go_ss_method".to_owned(), method.to_owned());
                    node.credentials
                        .insert("trojan_go_ss_password".to_owned(), password.to_owned());
                }
                _ => {
                    // dae's ss;method;password mode writes an SS target header,
                    // which is a different wire protocol from Trojan-Go's
                    // encrypted stream and is therefore not silently reinterpreted.
                    node.unsupported.insert("query.encryption".to_owned());
                }
            }
        }
    }
    let network = text(&mut query, "type", &mut node.invalid).unwrap_or_default();
    if matches!(network.as_str(), "" | "original" | "tcp")
        && node.credentials.contains_key("trojan_go_ss_method")
    {
        // Trojan-Go's original TLS server performs HTTP request sniffing
        // before handing the stream to its Trojan layer. The first encrypted
        // SS record is arbitrary binary, so small writes can be held or
        // discarded by that peer. WebSocket keeps a real HTTP handshake and
        // does not have this ambiguity; keep the unsafe combination out of
        // the selectable node set.
        node.unsupported.insert("query.encryption".to_owned());
    }
    match network.as_str() {
        "" | "original" | "tcp" => {}
        "ws" | "httpupgrade" => {
            query.insert("type".to_owned(), Value::String(network.clone()));
            if query
                .get("host")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                let host = if node.host.contains(':') {
                    format!("[{}]", node.host)
                } else {
                    node.host.clone()
                };
                query.insert("host".to_owned(), Value::String(host));
            }
            if let Some(path) = text(&mut query, "path", &mut node.invalid) {
                let path = if path.is_empty() {
                    "/".to_owned()
                } else if network == "httpupgrade" && !path.starts_with('/') {
                    format!("/{path}")
                } else {
                    path
                };
                query.insert("path".to_owned(), Value::String(path));
            }
        }
        "grpc" => {
            let path =
                text(&mut query, "path", &mut node.invalid).filter(|value| !value.is_empty());
            let service = text(&mut query, "serviceName", &mut node.invalid)
                .filter(|value| !value.is_empty());
            if path
                .as_ref()
                .zip(service.as_ref())
                .is_some_and(|(a, b)| a != b)
            {
                node.invalid.insert("query.serviceName".to_owned());
            }
            let service = service.or(path).unwrap_or_else(|| "GunService".to_owned());
            // A leading slash selects the explicit gRPC service/method path;
            // preserve slashes in dae's service name and append its Tun method.
            query.insert(
                "serviceName".to_owned(),
                Value::String(format!("/{service}/Tun")),
            );
            query.insert("type".to_owned(), Value::String("grpc".to_owned()));
        }
        _ => {
            node.unsupported.insert("query.type".to_owned());
        }
    }
    apply_uri_query(&mut query, &mut node);
    leftovers(query, "query.", &mut node);
    node
}

fn apply_uri_query(query: &mut Map<String, Value>, node: &mut Node) {
    let security = text(query, "security", &mut node.invalid);
    let mut server_name: Option<String> = None;
    for field in ["sni", "peer", "servername"] {
        if let Some(value) = text(query, field, &mut node.invalid).filter(|value| !value.is_empty())
        {
            if server_name
                .as_ref()
                .is_some_and(|previous| previous != &value)
            {
                node.invalid.insert(format!("query.{field}"));
            } else {
                server_name = Some(value);
            }
        }
    }
    let mut insecure = None;
    for field in ["allowInsecure", "insecure", "allow_insecure"] {
        if let Some(value) = flag(query, field, &mut node.invalid) {
            if insecure.is_some_and(|previous| previous != value) {
                node.invalid.insert(format!("query.{field}"));
            } else {
                insecure = Some(value);
            }
        }
    }
    let certificate_sha256 =
        text(query, "pinSHA256", &mut node.invalid).filter(|value| !value.is_empty());
    if certificate_sha256
        .as_deref()
        .is_some_and(|value| pathchord_policy::parse_certificate_sha256(value).is_none())
    {
        node.invalid.insert("query.pinSHA256".to_owned());
    }
    let mut tls = TransitTls {
        enabled: security
            .as_deref()
            .is_some_and(|security| matches!(security, "tls" | "reality"))
            || matches!(
                node.protocol.as_str(),
                "https" | "trojan" | "hysteria" | "hysteria2" | "tuic"
            ),
        server_name,
        insecure: insecure.unwrap_or_default(),
        alpn: string_list(query, "alpn", &mut node.invalid),
        fingerprint: text(query, "fp", &mut node.invalid),
        certificate_sha256,
        ..TransitTls::default()
    };
    if security.as_deref() == Some("reality") {
        tls.reality = Some(TransitReality {
            public_key: text(query, "pbk", &mut node.invalid).unwrap_or_default(),
            short_id: text(query, "sid", &mut node.invalid).unwrap_or_default(),
        });
    } else if security
        .as_deref()
        .is_some_and(|security| !matches!(security, "none" | "tls"))
    {
        node.unsupported.insert("query.security".to_owned());
    }
    if tls != TransitTls::default() {
        node.options.tls = Some(tls);
    }
    for (field, accepted) in [
        ("headerType", "none"),
        ("quicSecurity", "none"),
        ("pcs", ""),
    ] {
        if let Some(value) = text(query, field, &mut node.invalid)
            && !value.is_empty()
            && value != accepted
        {
            node.unsupported.insert(format!("query.{field}"));
        }
    }
    if let Some(spider_path) = text(query, "spx", &mut node.invalid)
        && !matches!(spider_path.as_str(), "" | "/")
    {
        node.unsupported.insert("query.spx".to_owned());
    }
    let network = text(query, "type", &mut node.invalid)
        .or_else(|| text(query, "network", &mut node.invalid));
    if network
        .as_deref()
        .is_none_or(|value| matches!(value, "tcp" | "none"))
    {
        for field in ["host", "path", "serviceName"] {
            if let Some(value) = text(query, field, &mut node.invalid)
                && !value.is_empty()
            {
                node.unsupported.insert(format!("query.{field}"));
            }
        }
    }
    if let Some(network) = network
        && !matches!(network.as_str(), "tcp" | "none")
    {
        if network == "meek" {
            match text(query, "url", &mut node.invalid) {
                Some(url) if !url.is_empty() => {
                    node.credentials.insert("meek_url".to_owned(), url);
                }
                _ => {
                    node.invalid.insert("query.url".to_owned());
                }
            }
            // Meek's complete URL is private. Unsupported aliases must not
            // publish their potentially secret contents in typed options.
            for field in ["path", "host", "serviceName", "ed", "eh"] {
                if query.remove(field).is_some() {
                    node.unsupported.insert(format!("query.{field}"));
                }
            }
            node.options.transport = Some(TransitTransport {
                kind: network,
                ..TransitTransport::default()
            });
        } else {
            let max_early_data = bounded_number::<u32>(query, "ed", &mut node.invalid);
            let early_data_header_name = text(query, "eh", &mut node.invalid).or_else(|| {
                (network == "ws" && max_early_data.is_some_and(|value| value > 0))
                    .then(|| "Sec-WebSocket-Protocol".to_owned())
            });
            node.options.transport = Some(TransitTransport {
                kind: network,
                path: text(query, "path", &mut node.invalid),
                host: string_list(query, "host", &mut node.invalid),
                service_name: text(query, "serviceName", &mut node.invalid)
                    .filter(|value| !value.is_empty()),
                max_early_data,
                early_data_header_name,
                ..TransitTransport::default()
            });
        }
    }
    credentials(
        query,
        &[
            ("flow", "flow"),
            ("obfs", "obfs"),
            ("obfs-password", "obfs_password"),
            ("upmbps", "up_mbps"),
            ("downmbps", "down_mbps"),
            ("mport", "server_ports"),
            ("congestion_control", "congestion_control"),
            ("udp_relay_mode", "udp_relay_mode"),
        ],
        node,
    );
    node.options.udp = flag(query, "udp", &mut node.invalid);
    node.options.packet_encoding = text(query, "packetEncoding", &mut node.invalid);
    if let Some(encryption) = text(query, "encryption", &mut node.invalid)
        && encryption != "none"
    {
        node.unsupported.insert("query.encryption".to_owned());
    }
    if let Some(mux) = flag(query, "mux", &mut node.invalid) {
        node.options.multiplex = Some(TransitMultiplex {
            enabled: mux,
            ..TransitMultiplex::default()
        });
    }
}

fn ss_uri(payload: &str, index: usize) -> Node {
    let mut node = Node::new(index);
    node.protocol = "ss".to_owned();
    let (payload, fragment) = payload
        .split_once('#')
        .map_or((payload, None), |(payload, fragment)| {
            (payload, Some(fragment))
        });
    node.name = fragment
        .and_then(decode_percent)
        .filter(|name| !name.is_empty())
        .unwrap_or(node.name);
    let decoded;
    let payload = if payload.contains('@') {
        payload
    } else {
        decoded = match decode_base64(payload).and_then(|bytes| String::from_utf8(bytes).ok()) {
            Some(value) => value,
            None => return Node::invalid(index, "ss.userinfo"),
        };
        &decoded
    };
    let Some((userinfo, endpoint)) = payload.rsplit_once('@') else {
        return Node::invalid(index, "ss.userinfo");
    };
    let userinfo = if userinfo.contains(':') || matches!(userinfo, "none" | "plain") {
        decode_percent(userinfo)
    } else {
        decode_base64(userinfo).and_then(|bytes| String::from_utf8(bytes).ok())
    };
    let Some((cipher, password)) = userinfo.as_deref().and_then(|value| {
        value
            .split_once(':')
            .or_else(|| matches!(value, "none" | "plain").then_some((value, "")))
    }) else {
        return Node::invalid(index, "ss.userinfo");
    };
    node.credentials
        .insert("cipher".to_owned(), cipher.to_owned());
    node.credentials
        .insert("password".to_owned(), password.to_owned());
    let Ok(url) = Url::parse(&format!("ss://{endpoint}")) else {
        return Node::invalid(index, "endpoint");
    };
    node.host = url
        .host_str()
        .map(|host| host.trim_matches(['[', ']']).to_owned())
        .unwrap_or_default();
    node.port = url.port().unwrap_or_default();
    if !matches!(url.path(), "" | "/") {
        node.unsupported.insert("uri.path".to_owned());
    }
    for (key, value) in url.query_pairs() {
        if key == "plugin" {
            let (plugin, options) = value.split_once(';').unwrap_or((&value, ""));
            node.credentials
                .insert("plugin".to_owned(), plugin.to_owned());
            if !options.is_empty() {
                node.credentials
                    .insert("plugin_opts".to_owned(), options.to_owned());
            }
        } else {
            node.unsupported.insert(format!("query.{key}"));
        }
    }
    node
}

fn vmess_uri(payload: &str, index: usize) -> Node {
    let Some(decoded) = decode_base64(payload) else {
        return Node::invalid(index, "vmess.payload");
    };
    let Ok(value) = serde_json::from_slice::<Value>(&decoded) else {
        return Node::invalid(index, "vmess.payload");
    };
    let mut fields = match map(value, index) {
        Ok(fields) => fields,
        Err(node) => return *node,
    };
    let mut node = Node::new(index);
    node.protocol = "vmess".to_owned();
    node.name = text(&mut fields, "ps", &mut node.invalid).unwrap_or(node.name);
    node.host = text(&mut fields, "add", &mut node.invalid).unwrap_or_default();
    node.port = bounded_number::<u16>(&mut fields, "port", &mut node.invalid).unwrap_or_default();
    credentials(
        &mut fields,
        &[("id", "uuid"), ("aid", "alter_id"), ("scy", "security")],
        &mut node,
    );
    fields.remove("v");
    let tls = text(&mut fields, "tls", &mut node.invalid).unwrap_or_default();
    if !tls.is_empty() && tls != "none" && tls != "tls" {
        node.unsupported.insert("tls".to_owned());
    }
    let tls = TransitTls {
        enabled: tls == "tls",
        server_name: text(&mut fields, "sni", &mut node.invalid),
        alpn: string_list(&mut fields, "alpn", &mut node.invalid),
        fingerprint: text(&mut fields, "fp", &mut node.invalid),
        insecure: flag(&mut fields, "allowInsecure", &mut node.invalid).unwrap_or_default(),
        ..TransitTls::default()
    };
    if tls != TransitTls::default() {
        node.options.tls = Some(tls);
    }
    let network = text(&mut fields, "net", &mut node.invalid).unwrap_or_else(|| "tcp".to_owned());
    let header_type =
        text(&mut fields, "type", &mut node.invalid).unwrap_or_else(|| "none".to_owned());
    let mut host = string_list(&mut fields, "host", &mut node.invalid);
    let mut path = text(&mut fields, "path", &mut node.invalid);
    if network == "meek" {
        match path.take() {
            Some(url) if !url.is_empty() => {
                node.credentials.insert("meek_url".to_owned(), url);
            }
            _ => {
                node.invalid.insert("path".to_owned());
            }
        }
        if !host.is_empty() || header_type != "none" {
            node.unsupported.insert("meek.options".to_owned());
        }
        host.clear();
    }
    if network != "tcp" && network != "none" {
        let service_name = if network == "grpc" { path.take() } else { None };
        node.options.transport = Some(TransitTransport {
            kind: network,
            path,
            host,
            service_name,
            ..TransitTransport::default()
        });
    } else if header_type != "none" {
        node.unsupported.insert("type".to_owned());
    } else if !host.is_empty() || path.as_ref().is_some_and(|path| !path.is_empty()) {
        node.unsupported.insert("tcp.header".to_owned());
    }
    leftovers(fields, "", &mut node);
    node
}

fn split_csv(line: &str) -> Option<Vec<String>> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quote = None;
    for ch in line.chars() {
        match ch {
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            ',' if quote.is_none() => {
                fields.push(field.trim().to_owned());
                field.clear();
            }
            _ => field.push(ch),
        }
    }
    if quote.is_some() {
        return None;
    }
    fields.push(field.trim().to_owned());
    Some(fields)
}

fn lines(body: &[u8], format: &'static str) -> Result<Vec<Node>, SubscriptionError> {
    let text = std::str::from_utf8(body).map_err(|_| malformed(format))?;
    let has_sections = text.lines().any(|line| line.trim().starts_with('['));
    let mut enabled = !has_sections;
    let mut candidates = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            enabled = matches!(
                line.to_ascii_lowercase().as_str(),
                "[proxy]" | "[server_local]"
            );
            continue;
        }
        if !enabled
            || line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        candidates.push(line);
        if candidates.len() > MAX_SUBSCRIPTION_NODES {
            return Err(SubscriptionError::TooManyNodes);
        }
    }
    if candidates.is_empty() {
        return Err(malformed(format));
    }
    Ok(candidates
        .into_iter()
        .enumerate()
        .map(|(index, line)| line_node(line, format, index))
        .collect())
}

fn line_node(line: &str, format: &str, index: usize) -> Node {
    let Some((left, right)) = line.split_once('=') else {
        return Node::invalid(index, "line");
    };
    let Some(parts) = split_csv(right) else {
        return Node::invalid(index, "line");
    };
    let mut fields = Map::new();
    let mut node = Node::new(index);
    let quantumult = format == "quantumult"
        || matches!(
            left.trim().to_ascii_lowercase().as_str(),
            "shadowsocks" | "trojan" | "vmess" | "http" | "socks5"
        ) && parts.first().is_some_and(|value| value.contains(':'));
    let option_start = if quantumult {
        node.protocol = canonical_protocol(left.trim());
        let Some(endpoint) = parts
            .first()
            .and_then(|endpoint| Url::parse(&format!("node://{endpoint}")).ok())
        else {
            return Node::invalid(index, "endpoint");
        };
        node.host = endpoint
            .host_str()
            .map(|host| host.trim_matches(['[', ']']).to_owned())
            .unwrap_or_default();
        node.port = endpoint.port().unwrap_or_default();
        1
    } else {
        node.name = left.trim().to_owned();
        node.protocol = canonical_protocol(parts.first().map_or("", String::as_str));
        node.host = parts.get(1).cloned().unwrap_or_default();
        node.port = parts
            .get(2)
            .and_then(|value| value.parse().ok())
            .unwrap_or_default();
        if format == "loon" && parts.get(3).is_some_and(|field| !field.contains('=')) {
            let names: &[&str] = match node.protocol.as_str() {
                "ss" => &["cipher", "password"],
                "http" | "https" | "socks5" => &["username", "password"],
                "trojan" | "hysteria2" => &["password"],
                "vmess" | "vless" | "xtls" => &["uuid"],
                _ => &[],
            };
            for (offset, name) in names.iter().enumerate() {
                if let Some(value) = parts.get(3 + offset) {
                    fields.insert((*name).to_owned(), Value::String(value.clone()));
                }
            }
            3 + names.len()
        } else {
            3
        }
    };
    for field in parts.iter().skip(option_start) {
        if let Some((key, value)) = field.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            if fields
                .insert(
                    key.clone(),
                    Value::String(value.trim().trim_matches(['\'', '"']).to_owned()),
                )
                .is_some()
            {
                node.invalid.insert(key);
            }
        } else if !field.is_empty() {
            node.unsupported.insert("positional_parameter".to_owned());
        }
    }
    if let Some(tag) = text(&mut fields, "tag", &mut node.invalid) {
        node.name = tag;
    }
    credentials(
        &mut fields,
        &[
            ("username", "username"),
            ("password", "password"),
            ("uuid", "uuid"),
            ("method", "cipher"),
            ("encrypt-method", "cipher"),
            ("cipher", "cipher"),
            ("alter-id", "alter_id"),
            ("flow", "flow"),
            ("plugin", "plugin"),
            ("plugin-opts", "plugin_opts"),
        ],
        &mut node,
    );
    let obfs = text(&mut fields, "obfs", &mut node.invalid);
    let obfs_host = text(&mut fields, "obfs-host", &mut node.invalid);
    if node.protocol == "ss" {
        if let Some(obfs) = obfs {
            if matches!(obfs.as_str(), "http" | "tls") {
                if node.credentials.contains_key("plugin")
                    || node.credentials.contains_key("plugin_opts")
                {
                    node.invalid.insert("plugin".to_owned());
                }
                node.credentials
                    .insert("plugin".to_owned(), "obfs-local".to_owned());
                let options = match obfs_host {
                    Some(host) => format!("obfs={obfs};obfs-host={host}"),
                    None => format!("obfs={obfs}"),
                };
                node.credentials.insert("plugin_opts".to_owned(), options);
            } else {
                node.unsupported.insert("obfs".to_owned());
            }
        } else if obfs_host.is_some() {
            node.unsupported.insert("obfs-host".to_owned());
        }
    } else if let Some(obfs) = obfs {
        if matches!(obfs.as_str(), "ws" | "wss") {
            node.options.transport = Some(TransitTransport {
                kind: "ws".to_owned(),
                host: obfs_host.into_iter().collect(),
                ..TransitTransport::default()
            });
            if obfs == "wss" {
                fields.insert("tls".to_owned(), Value::Bool(true));
            }
        } else {
            node.unsupported.insert("obfs".to_owned());
        }
    } else if obfs_host.is_some() {
        node.unsupported.insert("obfs-host".to_owned());
    }
    if matches!(node.protocol.as_str(), "vmess" | "vless" | "xtls")
        && !node.credentials.contains_key("uuid")
        && let Some(uuid) = node.credentials.remove("password")
    {
        node.credentials.insert("uuid".to_owned(), uuid);
    }
    let tls = TransitTls {
        enabled: flag(&mut fields, "tls", &mut node.invalid)
            .or_else(|| flag(&mut fields, "over-tls", &mut node.invalid))
            .unwrap_or(matches!(
                node.protocol.as_str(),
                "https" | "trojan" | "hysteria2" | "tuic"
            )),
        insecure: flag(&mut fields, "skip-cert-verify", &mut node.invalid)
            .or_else(|| {
                flag(&mut fields, "tls-verification", &mut node.invalid).map(|verify| !verify)
            })
            .unwrap_or_default(),
        server_name: text(&mut fields, "sni", &mut node.invalid)
            .or_else(|| text(&mut fields, "tls-host", &mut node.invalid)),
        alpn: string_list(&mut fields, "alpn", &mut node.invalid),
        ..TransitTls::default()
    };
    if tls != TransitTls::default() {
        node.options.tls = Some(tls);
    }
    node.options.udp = flag(&mut fields, "udp-relay", &mut node.invalid);
    node.options.tcp_fast_open = flag(&mut fields, "tfo", &mut node.invalid)
        .or_else(|| flag(&mut fields, "fast-open", &mut node.invalid));
    if flag(&mut fields, "ws", &mut node.invalid).unwrap_or_default()
        || node
            .options
            .transport
            .as_ref()
            .is_some_and(|transport| transport.kind == "ws")
    {
        let mut transport = node.options.transport.take().unwrap_or_default();
        transport.kind = "ws".to_owned();
        transport.path = text(&mut fields, "ws-path", &mut node.invalid)
            .or_else(|| text(&mut fields, "obfs-uri", &mut node.invalid));
        node.options.transport = Some(transport);
    }
    leftovers(fields, "", &mut node);
    node
}

#[cfg(test)]
#[path = "subscription_import/tests.rs"]
mod tests;
