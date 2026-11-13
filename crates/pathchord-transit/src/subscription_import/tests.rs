use super::*;
use pathchord_policy::{SubscriptionRefresh, SubscriptionSource};

struct ScriptedFetcher(
    std::sync::Mutex<std::collections::VecDeque<Result<Vec<u8>, SubscriptionError>>>,
);
impl ScriptedFetcher {
    fn new(values: impl IntoIterator<Item = Result<Vec<u8>, SubscriptionError>>) -> Self {
        Self(std::sync::Mutex::new(values.into_iter().collect()))
    }
}
#[async_trait]
impl SubscriptionFetcher for ScriptedFetcher {
    async fn fetch(&self, _: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
        self.0.lock().unwrap().pop_front().expect("scripted fetch")
    }
}
fn temp_directory(label: &str) -> PathBuf {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "pathchord-import-{label}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn config(format: SubscriptionSourceType) -> SubscriptionConfig {
    SubscriptionConfig {
        id: SubscriptionId::new("fixture"),
        enabled: true,
        source: SubscriptionSource {
            source_type: format,
            url: "https://provider.invalid/sub".to_owned(),
            credentials_ref: None,
        },
        refresh: SubscriptionRefresh::default(),
        cache: None,
    }
}

fn imports(format: SubscriptionSourceType, source: &str) -> Vec<NormalizedNode> {
    normalize(
        &config(format),
        source.as_bytes(),
        &KNOWN_PROTOCOLS
            .iter()
            .map(|value| (*value).to_owned())
            .chain(["sing_box_outbound".to_owned()])
            .collect(),
    )
    .unwrap()
}

fn base64(value: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

#[test]
fn clash_tls_http_and_transport_options_are_preserved() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"
proxies:
  - {name: secure-http, type: http, server: proxy.test, port: 443, tls: true, servername: tls.test, skip-cert-verify: true, alpn: [http/1.1], username: user, password: sample-password}
  - name: vless-ws
    type: vless
    server: proxy.test
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    client-fingerprint: chrome
    reality-opts: {public-key: public-test-key, short-id: abcdef}
    network: ws
    ws-opts: {path: /socket, headers: {Host: ws.test}, max-early-data: 1024, early-data-header-name: Sec-WebSocket-Protocol}
    smux: {enabled: true, protocol: h2mux, max-connections: 2}
    udp: false
"#,
    );
    assert_eq!(nodes[0].config.protocol, "https");
    assert_eq!(nodes[0].state, DynamicNodeState::Active);
    let tls = nodes[0].config.options.tls.as_ref().unwrap();
    assert!(tls.enabled && tls.insecure);
    assert_eq!(tls.server_name.as_deref(), Some("tls.test"));
    assert_eq!(tls.alpn, ["http/1.1"]);
    let node = &nodes[1];
    assert!(node.diagnostic.is_none());
    let tls = node.config.options.tls.as_ref().unwrap();
    assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(tls.reality.as_ref().unwrap().short_id, "abcdef");
    let transport = node.config.options.transport.as_ref().unwrap();
    assert_eq!(transport.kind, "ws");
    assert_eq!(transport.path.as_deref(), Some("/socket"));
    assert_eq!(transport.headers["Host"], "ws.test");
    assert_eq!(transport.max_early_data, Some(1024));
    assert_eq!(
        node.config
            .options
            .multiplex
            .as_ref()
            .unwrap()
            .max_connections,
        Some(2)
    );
    assert_eq!(node.config.options.udp, Some(false));
}

#[test]
fn one_bad_or_unknown_node_does_not_discard_good_nodes_or_expose_values() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"
proxies:
  - {name: good, type: socks5, server: proxy.test, port: 1080}
  - {name: newer-option, type: http, server: proxy.test, port: 80, future-password: never-expose-this-value}
  - {name: unknown-protocol, type: future-protocol, server: proxy.test, port: 443}
  - {name: incomplete, type: vless, server: proxy.test, port: 443}
  - not-a-node
"#,
    );
    assert_eq!(nodes.len(), 5);
    assert_eq!(nodes[0].state, DynamicNodeState::Active);
    assert_eq!(
        nodes[1].state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::UnsupportedParameters)
    );
    let diagnostic = nodes[1].diagnostic.as_ref().unwrap();
    assert_eq!(diagnostic.fields, ["future-password"]);
    assert!(!format!("{diagnostic:?}").contains("never-expose"));
    assert_eq!(
        nodes[2].diagnostic.as_ref().unwrap().code,
        NodeUnavailableReason::UnsupportedProtocol
    );
    assert_eq!(nodes[3].diagnostic.as_ref().unwrap().fields, ["uuid"]);
    assert_eq!(
        nodes[4].state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::InvalidNode)
    );
}

#[test]
fn clash_nested_unknown_options_and_external_providers_are_visible() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"
proxy-providers: {other: {type: http, url: 'https://private.invalid/secret'}}
proxies:
  - {name: good, type: socks5, server: proxy.test, port: 1080}
  - {name: unknown-ws, type: vless, server: proxy.test, port: 443, uuid: test-id, network: ws, ws-opts: {path: /ws, future-option: secret-value}}
"#,
    );
    assert_eq!(nodes.len(), 3);
    assert_eq!(nodes[0].state, DynamicNodeState::Active);
    assert_eq!(
        nodes[1].diagnostic.as_ref().unwrap().fields,
        ["ws-opts.future-option"]
    );
    assert_eq!(
        nodes[2].diagnostic.as_ref().unwrap().fields,
        ["proxy-providers"]
    );
    assert!(!format!("{:?}", nodes[2].config).contains("private.invalid"));
}

#[test]
fn sip008_accepts_bare_array_and_versioned_envelope() {
    let node = r#"{"remarks":"SS fixture","server":"proxy.test","server_port":8388,"method":"aes-256-gcm","password":"fixture-password"}"#;
    for text in [
        format!("[{node}]"),
        format!(r#"{{"version":1,"servers":[{node}],"bytes_used":100,"bytes_remaining":200}}"#),
    ] {
        let nodes = imports(SubscriptionSourceType::Sip008, &text);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].state, DynamicNodeState::Active);
        assert_eq!(nodes[0].credential.field("cipher"), Some("aes-256-gcm"));
        assert_eq!(
            nodes[0].credential.field("password"),
            Some("fixture-password")
        );
    }
    assert!(
        normalize(
            &config(SubscriptionSourceType::Sip008),
            br#"{"version":99,"servers":[]}"#,
            &BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn uri_subscription_handles_common_schemes_percent_encoding_and_base64_lists() {
    let ss = format!(
        "ss://{}@proxy.test:8388#SS",
        base64("aes-256-gcm:fixture-password")
    );
    let source = format!(
        r#"{ss}
vless://test-uuid@proxy.test:443?security=reality&sni=tls.test&pbk=public-key&sid=abcd&type=ws&path=%2Fsocket&host=ws.test#VLESS
trojan://secret%3Avalue@proxy.test:443?sni=tls.test#Trojan
hy2://user:secret@proxy.test:443?obfs=salamander&obfs-password=obfs-secret#HY2
tuic://test-uuid:fixture-password@proxy.test:443?congestion_control=bbr&alpn=h3#TUIC
http://user:p%40ss@proxy.test:8080#HTTP
https://user:secret@proxy.test#HTTPS
socks5://user:secret@proxy.test:1080#SOCKS
"#
    );
    for input in [source.clone(), base64(&source)] {
        let nodes = imports(SubscriptionSourceType::Auto, &input);
        assert_eq!(nodes.len(), 8);
        assert!(nodes.iter().all(|node| node.diagnostic.is_none()));
        assert_eq!(
            nodes[1]
                .config
                .options
                .transport
                .as_ref()
                .unwrap()
                .path
                .as_deref(),
            Some("/socket")
        );
        assert_eq!(
            nodes[1]
                .config
                .options
                .tls
                .as_ref()
                .unwrap()
                .reality
                .as_ref()
                .unwrap()
                .public_key,
            "public-key"
        );
        assert_eq!(nodes[2].credential.field("password"), Some("secret:value"));
        assert_eq!(nodes[3].credential.field("password"), Some("user:secret"));
        assert_eq!(nodes[5].credential.field("password"), Some("p@ss"));
        assert_eq!(nodes[6].config.endpoint.port, 443);
    }
}

#[test]
fn ss_legacy_and_sip002_plugins_remain_lossless() {
    let source = format!(
        "ss://{}#Legacy\nss://{}@proxy.test:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dhost.test#SIP002",
        base64("aes-256-gcm:password@proxy.test:8388"),
        base64("aes-256-gcm:password")
    );
    let nodes = imports(SubscriptionSourceType::Uri, &source);
    assert_eq!(nodes.len(), 2);
    assert!(nodes.iter().all(|node| node.diagnostic.is_none()));
    assert_eq!(nodes[1].credential.field("plugin"), Some("obfs-local"));
    assert_eq!(
        nodes[1].credential.field("plugin_opts"),
        Some("obfs=http;obfs-host=host.test")
    );
}

#[test]
fn vmess_json_share_retains_authentication_tls_and_transport() {
    let payload = r#"{"v":"2","ps":"VMess","add":"proxy.test","port":"443","id":"fixture-uuid","aid":"0","scy":"auto","net":"ws","type":"none","host":"ws.test","path":"/ws","tls":"tls","sni":"tls.test","alpn":"h2,http/1.1","fp":"chrome"}"#;
    let nodes = imports(
        SubscriptionSourceType::Uri,
        &format!("vmess://{}", base64(payload)),
    );
    let node = &nodes[0];
    assert!(node.diagnostic.is_none());
    assert_eq!(node.credential.field("uuid"), Some("fixture-uuid"));
    assert_eq!(node.credential.field("alter_id"), Some("0"));
    assert_eq!(
        node.config.options.transport.as_ref().unwrap().host,
        ["ws.test"]
    );
    assert_eq!(
        node.config
            .options
            .tls
            .as_ref()
            .unwrap()
            .server_name
            .as_deref(),
        Some("tls.test")
    );
}

#[test]
fn unknown_uri_options_are_explicit_and_do_not_poison_other_lines() {
    let nodes = imports(
        SubscriptionSourceType::Uri,
        "socks5://proxy.test:1080\nvless://uuid@proxy.test:443?future_secret=do-not-print\nnot-a-uri",
    );
    assert_eq!(nodes[0].state, DynamicNodeState::Active);
    let diagnostic = nodes[1].diagnostic.as_ref().unwrap();
    assert_eq!(diagnostic.fields, ["query.future_secret"]);
    assert!(!format!("{diagnostic:?}").contains("do-not-print"));
    assert_eq!(
        nodes[2].state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::InvalidNode)
    );
}

#[test]
fn sing_box_outbound_keeps_one_authoritative_secret_document() {
    let source = r#"{"outbounds":[{"type":"vless","tag":"vless-ws","server":"proxy.test","server_port":443,"uuid":"fixture-uuid","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"tls.test","insecure":false,"alpn":["h2"],"utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"test-key","short_id":"ab"}},"transport":{"type":"ws","path":"/ws","headers":{"Host":"ws.test"}},"multiplex":{"enabled":true,"protocol":"h2mux","padding":true},"connect_timeout":"10s"}]}"#;
    let nodes = imports(SubscriptionSourceType::SingBox, source);
    let node = &nodes[0];
    assert!(node.diagnostic.is_none());
    let outbound: Value =
        serde_json::from_str(node.credential.field("sing_box_outbound").unwrap()).unwrap();
    assert_eq!(outbound["uuid"], "fixture-uuid");
    assert_eq!(outbound["connect_timeout"], "10s");
    assert_eq!(outbound["tls"]["reality"]["short_id"], "ab");
    assert_eq!(outbound["transport"]["headers"]["Host"], "ws.test");
    assert_eq!(outbound["multiplex"]["padding"], true);
    assert_eq!(node.config.options, TransitOptions::default());
    assert_eq!(node.credential.fields().len(), 1);
    assert!(!format!("{:?}", node.credential).contains("fixture-uuid"));
}

#[test]
fn unknown_sing_box_fields_are_kept_for_exact_engine_validation() {
    let nodes = imports(
        SubscriptionSourceType::SingBox,
        r#"{"outbounds":[{"type":"socks","tag":"good","server":"proxy.test","server_port":1080},{"type":"http","tag":"bad","server":"proxy.test","server_port":80,"tls":{"enabled":true,"future_secret":"secret"}}]}"#,
    );
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].config.protocol, "socks5");
    assert_eq!(nodes[0].state, DynamicNodeState::Active);
    assert!(nodes[1].diagnostic.is_none());
    let raw: Value =
        serde_json::from_str(nodes[1].credential.field("sing_box_outbound").unwrap()).unwrap();
    assert_eq!(raw["tls"]["future_secret"], "secret");
    assert_eq!(nodes[1].config.options, TransitOptions::default());
}

#[test]
fn raw_sing_box_nodes_require_the_engine_even_for_native_protocols() {
    let nodes = normalize(
        &config(SubscriptionSourceType::SingBox),
        br#"{"outbounds":[{"type":"socks","server":"proxy.test","server_port":1080}]}"#,
        &BTreeSet::from(["socks5".to_owned()]),
    )
    .unwrap();
    assert_eq!(
        nodes[0].state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
    );
    assert!(nodes[0].credential.field("sing_box_outbound").is_some());
}

#[test]
fn sing_box_wireguard_endpoints_and_outbounds_are_imported_together_losslessly() {
    let source = r#"{
      "endpoints":[{"type":"wireguard","tag":"wg","system":false,"address":["10.0.0.2/32"],"private_key":"fixture-private-key","peers":[{"address":"wg.test","port":51820,"public_key":"fixture-public-key","allowed_ips":["0.0.0.0/0"]}]}],
      "outbounds":[{"type":"vless","tag":"vless","server":"proxy.test","server_port":443,"uuid":"fixture-uuid","tls":{"enabled":true,"min_version":"1.3","future_engine_flag":true},"transport":{"type":"grpc","service_name":"service","permit_without_stream":true}}]
    }"#;
    let nodes = imports(SubscriptionSourceType::Auto, source);
    assert_eq!(nodes.len(), 2);
    assert!(nodes.iter().all(|node| node.diagnostic.is_none()));
    let wg = nodes
        .iter()
        .find(|node| node.config.protocol == "wireguard")
        .unwrap();
    assert_eq!(wg.config.endpoint.host, "wg.test");
    assert_eq!(wg.config.endpoint.port, 51820);
    let raw: Value =
        serde_json::from_str(wg.credential.field("sing_box_outbound").unwrap()).unwrap();
    assert_eq!(raw["private_key"], "fixture-private-key");
    assert_eq!(raw["peers"][0]["allowed_ips"][0], "0.0.0.0/0");
    let node = nodes
        .iter()
        .find(|node| node.config.protocol == "vless")
        .unwrap();
    let raw: Value =
        serde_json::from_str(node.credential.field("sing_box_outbound").unwrap()).unwrap();
    assert_eq!(raw["tls"]["min_version"], "1.3");
    assert_eq!(raw["tls"]["future_engine_flag"], true);
    assert_eq!(raw["transport"]["permit_without_stream"], true);
    let only_endpoints = r#"{"endpoints":[{"type":"wireguard","system":false,"address":["10.0.0.2/32"],"private_key":"private","peers":[{"address":"wg.test","port":51820,"public_key":"public","allowed_ips":["0.0.0.0/0"]}]}]}"#;
    assert_eq!(
        imports(SubscriptionSourceType::Auto, only_endpoints)[0]
            .config
            .protocol,
        "wireguard"
    );
}

#[test]
fn sing_box_secret_transport_headers_remain_in_the_private_raw_outbound() {
    let nodes = imports(
        SubscriptionSourceType::SingBox,
        r#"{"outbounds":[{"type":"vless","server":"proxy.test","server_port":443,"uuid":"fixture-uuid","transport":{"type":"ws","path":"/ws","headers":{"Authorization":"private-header-value","Host":"ws.test"}}}]}"#,
    );
    let node = &nodes[0];
    assert!(node.diagnostic.is_none());
    let outbound: Value =
        serde_json::from_str(node.credential.field("sing_box_outbound").unwrap()).unwrap();
    assert_eq!(
        outbound["transport"]["headers"]["Authorization"],
        "private-header-value"
    );
    assert_eq!(node.config.options, TransitOptions::default());
    assert!(!format!("{:?}", node.config).contains("private-header-value"));
    assert!(!format!("{:?}", node.credential).contains("private-header-value"));
}

#[test]
fn sing_box_socks_versions_and_snell_documents_align_with_engine_protocols() {
    let nodes = imports(
        SubscriptionSourceType::SingBox,
        r#"{"outbounds":[
      {"type":"socks","tag":"v4","server":"proxy.test","server_port":1080,"version":"4"},
      {"type":"socks","tag":"v4a","server":"proxy.test","server_port":1080,"version":"4a"},
      {"type":"socks","tag":"v5","server":"proxy.test","server_port":1080,"version":"5"},
      {"type":"snell","tag":"snell4","server":"proxy.test","server_port":443,"version":4,"psk":"fixture-psk"},
      {"type":"snell","tag":"snell6","server":"proxy.test","server_port":443,"version":6,"userkey":"fixture-userkey"}
    ]}"#,
    );
    let protocols: Vec<_> = nodes
        .iter()
        .map(|node| node.config.protocol.as_str())
        .collect();
    assert_eq!(protocols, ["socks4", "socks4a", "socks5", "snell", "snell"]);
    assert!(
        nodes
            .iter()
            .all(|node| node.state == DynamicNodeState::Active && node.diagnostic.is_none())
    );
    let raw: Value =
        serde_json::from_str(nodes[3].credential.field("sing_box_outbound").unwrap()).unwrap();
    assert_eq!(raw["version"], 4);
    assert_eq!(raw["psk"], "fixture-psk");
    let raw: Value =
        serde_json::from_str(nodes[4].credential.field("sing_box_outbound").unwrap()).unwrap();
    assert_eq!(raw["version"], 6);
    assert_eq!(raw["userkey"], "fixture-userkey");
    assert_eq!(nodes[4].config.options, TransitOptions::default());
}

#[test]
fn clash_snell_preserves_psk_userkey_and_version_without_ignoring_other_options() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"proxies:
      - {name: v4, type: snell, server: proxy.test, port: 443, version: 4, psk: fixture-psk}
      - {name: v6, type: snell, server: proxy.test, port: 443, version: 6, psk: fixture-psk}
      - {name: key, type: snell, server: proxy.test, port: 443, version: 6, userkey: fixture-userkey}
      - {name: unknown, type: snell, server: proxy.test, port: 443, version: 4, psk: fixture-psk, future-option: true}
    "#,
    );
    assert!(
        nodes[..3]
            .iter()
            .all(|node| node.state == DynamicNodeState::Active)
    );
    assert_eq!(nodes[0].credential.field("psk"), Some("fixture-psk"));
    assert_eq!(nodes[1].credential.field("version"), Some("6"));
    assert_eq!(
        nodes[2].credential.field("userkey"),
        Some("fixture-userkey")
    );
    assert_eq!(
        nodes[3].diagnostic.as_ref().unwrap().fields,
        ["future-option"]
    );
}

#[test]
fn surge_quantumult_and_loon_node_lists_normalize_authentication_and_tls() {
    let fixtures = [
        (
            SubscriptionSourceType::Surge,
            "[General]\nloglevel = info\n[Proxy]\nSecure = http, proxy.test, 443, username=user, password=pass, tls=true, sni=tls.test, skip-cert-verify=true\n[Rule]\nFINAL,DIRECT",
        ),
        (
            SubscriptionSourceType::Quantumult,
            "[server_local]\nhttp=proxy.test:443, username=user, password=pass, over-tls=true, tls-host=tls.test, tls-verification=false, tag=Secure",
        ),
        (
            SubscriptionSourceType::Loon,
            "[Proxy]\nSS = Shadowsocks, proxy.test, 8388, aes-256-gcm, \"fixture-password\"",
        ),
    ];
    for (format, text) in fixtures {
        let nodes = imports(format, text);
        assert_eq!(nodes.len(), 1);
        assert!(nodes[0].diagnostic.is_none(), "{:?}", nodes[0].diagnostic);
        if format != SubscriptionSourceType::Loon {
            assert_eq!(nodes[0].config.protocol, "https");
            assert_eq!(nodes[0].credential.field("username"), Some("user"));
            assert!(nodes[0].config.options.tls.as_ref().unwrap().insecure);
        } else {
            assert_eq!(nodes[0].credential.field("cipher"), Some("aes-256-gcm"));
        }
    }
}

#[test]
fn line_formats_preserve_loon_positional_credentials_and_obfs_plugin_parameters() {
    let nodes = imports(
        SubscriptionSourceType::Loon,
        "[Proxy]\nHTTP = Http, proxy.test, 8080, user, pass\nTrojan = Trojan, proxy.test, 443, fixture-password",
    );
    assert!(nodes.iter().all(|node| node.diagnostic.is_none()));
    assert_eq!(nodes[0].credential.field("username"), Some("user"));
    assert_eq!(nodes[0].credential.field("password"), Some("pass"));
    assert_eq!(
        nodes[1].credential.field("password"),
        Some("fixture-password")
    );
    let nodes = imports(
        SubscriptionSourceType::Quantumult,
        "shadowsocks=proxy.test:8388, method=aes-256-gcm, password=fixture-password, obfs=http, obfs-host=obfs.test, tag=SS",
    );
    assert!(nodes[0].diagnostic.is_none());
    assert_eq!(nodes[0].credential.field("plugin"), Some("obfs-local"));
    assert_eq!(
        nodes[0].credential.field("plugin_opts"),
        Some("obfs=http;obfs-host=obfs.test")
    );
}

#[test]
fn malformed_documents_are_rejected_instead_of_publishing_an_empty_snapshot() {
    for (format, source) in [
        (SubscriptionSourceType::Clash, "not: [closed"),
        (SubscriptionSourceType::Sip008, "{invalid}"),
        (
            SubscriptionSourceType::SingBox,
            r#"{"outbounds":"not-a-list"}"#,
        ),
        (
            SubscriptionSourceType::Auto,
            "not a recognized subscription document",
        ),
        (SubscriptionSourceType::Uri, "not-base64"),
    ] {
        assert!(normalize(&config(format), source.as_bytes(), &BTreeSet::new()).is_err());
    }
}

#[test]
fn auto_detects_each_document_family() {
    for text in [
        "proxies: [{name: test, type: socks5, server: proxy.test, port: 1080}]",
        r#"{"version":1,"servers":[{"server":"proxy.test","server_port":8388,"method":"aes-256-gcm","password":"secret"}]}"#,
        r#"{"outbounds":[{"type":"socks","server":"proxy.test","server_port":1080}]}"#,
        "[Proxy]\nProxy = socks5, proxy.test, 1080",
        "[server_local]\nsocks5=proxy.test:1080, tag=Proxy",
        "socks5://proxy.test:1080",
    ] {
        let nodes = imports(SubscriptionSourceType::Auto, text);
        assert_eq!(nodes.len(), 1);
        assert!(nodes[0].diagnostic.is_none());
    }
}

#[test]
fn secret_http_headers_are_not_published_in_typed_options() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"
proxies:
  - name: secret-header
    type: vless
    server: proxy.test
    port: 443
    uuid: fixture-uuid
    network: ws
    ws-opts:
      headers: {Host: ws.test, Authorization: secret-bearer-value, Cookie: private-cookie}
"#,
    );
    let node = &nodes[0];
    assert_eq!(
        node.state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::UnsupportedParameters)
    );
    assert_eq!(
        node.config
            .options
            .transport
            .as_ref()
            .unwrap()
            .headers
            .len(),
        1
    );
    assert!(!format!("{:?}", node.config).contains("secret-bearer-value"));
    assert!(!format!("{:?}", node.diagnostic).contains("private-cookie"));
}

#[tokio::test]
async fn cache_reloads_do_not_revive_nodes_with_invalid_or_unknown_parameters() {
    use pathchord_policy::SubscriptionCache;
    let directory = temp_directory("diagnostic-cache");
    let mut config = config(SubscriptionSourceType::Clash);
    config.cache = Some(SubscriptionCache {
        path: "provider.snapshot".to_owned(),
        max_age_seconds: 3600,
    });
    let source = b"proxies:\n - {name: good, type: socks5, server: proxy.test, port: 1080}\n - {name: bad, type: http, server: proxy.test, port: 80, unsupported-option: secret-value}\n";
    let available = BTreeSet::from(["http".to_owned(), "socks5".to_owned()]);
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.to_vec())])),
        &directory,
        available.clone(),
    );
    assert!(matches!(
        manager.refresh(&config).await,
        RefreshOutcome::Published { .. }
    ));
    let before = manager.snapshot().clone();
    let mut restored =
        SubscriptionManager::new(Arc::new(ScriptedFetcher::new([])), &directory, available);
    assert!(matches!(
        restored.load_cache(&config).await.unwrap(),
        CacheLoadOutcome::Loaded { .. }
    ));
    assert_eq!(restored.snapshot(), &before);
    assert_eq!(restored.snapshot().selectable_nodes().count(), 1);
    let bad = restored
        .snapshot()
        .nodes
        .values()
        .find(|node| node.config.labels["source.name"] == "bad")
        .unwrap();
    assert_eq!(
        bad.diagnostic.as_ref().unwrap().fields,
        ["unsupported-option"]
    );
    assert_eq!(
        bad.state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::UnsupportedParameters)
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn malformed_document_retains_good_snapshot_but_bad_nodes_publish_independently() {
    let source = b"proxies:\n - {name: good, type: socks5, server: proxy.test, port: 1080}\n - {name: future, type: future-protocol, server: proxy.test, port: 443}\n";
    let mut config = config(SubscriptionSourceType::Auto);
    config.refresh.max_attempts = 1;
    let directory = temp_directory("mixed-validity");
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([
            Ok(source.to_vec()),
            Ok(b"proxies: [not-closed".to_vec()),
        ])),
        &directory,
        BTreeSet::from(["socks5".to_owned()]),
    );
    let RefreshOutcome::Published { diff, .. } = manager.refresh(&config).await else {
        panic!("partial validity should publish");
    };
    assert_eq!(diff.added.len(), 2);
    assert_eq!(diff.unavailable.len(), 1);
    let before = manager.snapshot().clone();
    assert!(matches!(
        manager.refresh(&config).await,
        RefreshOutcome::Retained { .. }
    ));
    assert_eq!(manager.snapshot(), &before);
    std::fs::remove_dir_all(directory).unwrap();
}
