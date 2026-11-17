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
            user_agent: None,
        },
        refresh: SubscriptionRefresh::default(),
        cache: None,
    }
}

async fn prepare_imported_nodes(manager: &mut SubscriptionManager) {
    let registry = crate::AdapterRegistry::for_configs(
        Arc::new(crate::NoTransitCredentials),
        std::time::Duration::from_secs(1),
        manager.snapshot().nodes.values().map(|node| &node.config),
    )
    .unwrap();
    let prepared = manager.snapshot().prepare_adapters(&registry).await;
    manager.commit_prepared_adapters(prepared).unwrap();
}

fn imports(format: SubscriptionSourceType, source: &str) -> Vec<NormalizedNode> {
    normalize(
        &config(format),
        source.as_bytes(),
        &KNOWN_PROTOCOLS
            .iter()
            .map(|value| (*value).to_owned())
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
    assert_eq!(node.config.options.packet_encoding, None);
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
fn clash_h2_transport_alias_is_normalized_with_its_options() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"
proxies:
  - name: h2-node
    type: vless
    server: proxy.test
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: h2
    h2-opts: {host: [front.test], path: /tunnel}
"#,
    );
    assert!(nodes[0].diagnostic.is_none());
    let transport = nodes[0].config.options.transport.as_ref().unwrap();
    assert_eq!(transport.kind, "http");
    assert_eq!(transport.host, ["front.test"]);
    assert_eq!(transport.path.as_deref(), Some("/tunnel"));
}

#[test]
fn meek_share_links_keep_the_full_url_in_private_credentials() {
    let vmess = base64(
        r#"{"v":"2","ps":"vmess-meek","add":"proxy.test","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","scy":"auto","net":"meek","type":"none","host":"","path":"https://front.test/vmess?token=vmess-secret","tls":"tls"}"#,
    );
    let source = format!(
        "vless://11111111-1111-1111-1111-111111111111@proxy.test:443?type=meek&security=tls&url=https%3A%2F%2Ffront.test%2Fvless%3Ftoken%3Dvless-secret\nvmess://{vmess}"
    );
    let nodes = imports(SubscriptionSourceType::Uri, &source);
    assert_eq!(nodes.len(), 2);
    for (node, url) in nodes.iter().zip([
        "https://front.test/vless?token=vless-secret",
        "https://front.test/vmess?token=vmess-secret",
    ]) {
        assert!(node.diagnostic.is_none());
        let transport = node.config.options.transport.as_ref().unwrap();
        assert_eq!(transport.kind, "meek");
        assert!(transport.path.is_none());
        assert!(transport.host.is_empty());
        assert_eq!(node.credential.field("meek_url"), Some(url));
        let public = serde_json::to_string(&node.config).unwrap();
        assert!(!public.contains("secret"));
        assert!(!format!("{:?}", node.credential).contains("secret"));
    }

    let invalid = imports(
        SubscriptionSourceType::Uri,
        "vless://11111111-1111-1111-1111-111111111111@proxy.test:443?type=meek&security=tls&url=https%3A%2F%2Ffront.test&path=private-path-sentinel",
    );
    assert!(invalid[0].diagnostic.is_some());
    assert!(
        !serde_json::to_string(&invalid[0].config)
            .unwrap()
            .contains("private-path-sentinel")
    );
}

#[tokio::test]
async fn vmess_framing_options_survive_import_and_require_a_compatible_cipher() {
    let clash = r#"
proxies:
  - {name: padded, type: vmess, server: proxy.test, port: 443, uuid: 11111111-1111-1111-1111-111111111111, cipher: aes-128-gcm, global-padding: true, authenticated-length: true}
  - {name: invalid, type: vmess, server: proxy.test, port: 443, uuid: 11111111-1111-1111-1111-111111111111, cipher: none, global-padding: true}
"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(clash.as_bytes().to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["vmess".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::Clash))
            .await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let selected: Vec<_> = manager.snapshot().selectable_nodes().collect();
    assert_eq!(selected.len(), 1);
    let framing = selected[0].config.options.vmess.as_ref().unwrap();
    assert!(framing.global_padding && framing.authenticated_length);
    assert!(manager.snapshot().nodes.values().any(|node| {
        node.config.labels["source.name"] == "invalid"
            && matches!(node.state, DynamicNodeState::Unavailable(_))
    }));

    let nodes = imports(
        SubscriptionSourceType::SingBox,
        r#"{"outbounds":[{"type":"vmess","server":"proxy.test","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","security":"aes-128-gcm","global_padding":true,"authenticated_length":true}]}"#,
    );
    let framing = nodes[0].config.options.vmess.as_ref().unwrap();
    assert!(framing.global_padding && framing.authenticated_length);
    assert!(nodes[0].credential.field("sing_box_outbound").is_none());
}

#[tokio::test]
async fn vmess_packet_encodings_are_prepared_from_subscription_forms() {
    let clash = b"proxies:\n - {name: packet, type: vmess, server: proxy.test, port: 443, uuid: 11111111-1111-1111-1111-111111111111, cipher: aes-128-gcm, packet-encoding: packet}\n";
    let sing_box = br#"{"outbounds":[{"type":"vmess","server":"proxy.test","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","security":"aes-128-gcm","packet_encoding":"xudp"}]}"#;
    for (source_type, source, expected) in [
        (
            SubscriptionSourceType::Clash,
            clash.as_slice(),
            "packetaddr",
        ),
        (SubscriptionSourceType::SingBox, sing_box.as_slice(), "xudp"),
    ] {
        let mut manager = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([Ok(source.to_vec())])),
            std::env::temp_dir(),
            BTreeSet::from(["vmess".into()]),
        );
        assert!(matches!(
            manager.refresh(&config(source_type)).await,
            RefreshOutcome::Published { .. }
        ));
        prepare_imported_nodes(&mut manager).await;
        let selected = manager.snapshot().selectable_nodes().next().unwrap();
        assert_eq!(
            selected.config.options.packet_encoding.as_deref(),
            Some(expected)
        );
        assert!(
            manager
                .snapshot()
                .validated_adapter(&selected.config.id)
                .unwrap()
                .supports_udp()
        );
    }
}

#[tokio::test]
async fn vless_packetaddr_is_prepared_and_vision_conflict_is_unavailable() {
    let source = br#"{"outbounds":[
      {"type":"vless","tag":"packet","server":"proxy.test","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","packet_encoding":"packetaddr"},
      {"type":"vless","tag":"vision","server":"proxy.test","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision","packet_encoding":"packetaddr","tls":{"enabled":true}}
    ]}"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["vless".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::SingBox))
            .await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let selected: Vec<_> = manager.snapshot().selectable_nodes().collect();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].config.labels["source.name"], "packet");
    assert_eq!(
        selected[0].config.options.packet_encoding.as_deref(),
        Some("packetaddr")
    );
    assert!(
        manager
            .snapshot()
            .nodes
            .values()
            .any(|node| node.config.labels["source.name"] == "vision"
                && matches!(node.state, DynamicNodeState::Unavailable(_)))
    );
}

#[tokio::test]
async fn vless_mux_uses_its_own_datagrams_without_injecting_default_xudp() {
    let sing_box = br#"{"outbounds":[
      {"type":"vless","tag":"default","server":"proxy.test","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111"},
      {"type":"vless","tag":"mux","server":"proxy.test","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","multiplex":{"enabled":true,"protocol":"h2mux"}},
      {"type":"vless","tag":"explicit","server":"proxy.test","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","packet_encoding":"xudp","multiplex":{"enabled":true,"protocol":"h2mux"}}
    ]}"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(sing_box.to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["vless".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::SingBox))
            .await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let by_name: BTreeMap<_, _> = manager
        .snapshot()
        .nodes
        .values()
        .map(|node| (node.config.labels["source.name"].as_str(), node))
        .collect();
    assert_eq!(
        by_name["default"].config.options.packet_encoding.as_deref(),
        Some("xudp")
    );
    assert_eq!(by_name["mux"].config.options.packet_encoding, None);
    assert_eq!(by_name["mux"].state, DynamicNodeState::Active);
    assert_eq!(
        by_name["explicit"]
            .config
            .options
            .packet_encoding
            .as_deref(),
        Some("xudp")
    );
    assert!(matches!(
        by_name["explicit"].state,
        DynamicNodeState::Unavailable(_)
    ));

    let clash = imports(
        SubscriptionSourceType::Clash,
        r#"
proxies:
  - {name: default, type: vless, server: proxy.test, port: 443, uuid: 11111111-1111-1111-1111-111111111111}
  - {name: mux, type: vless, server: proxy.test, port: 443, uuid: 11111111-1111-1111-1111-111111111111, smux: {enabled: true, protocol: h2mux}}
  - {name: explicit, type: vless, server: proxy.test, port: 443, uuid: 11111111-1111-1111-1111-111111111111, packet-encoding: xudp, smux: {enabled: true, protocol: h2mux}}
"#,
    );
    assert_eq!(
        clash[0].config.options.packet_encoding.as_deref(),
        Some("xudp")
    );
    assert_eq!(clash[1].config.options.packet_encoding, None);
    assert_eq!(
        clash[2].config.options.packet_encoding.as_deref(),
        Some("xudp")
    );
}

#[test]
fn clash_vless_none_encryption_is_accepted() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"
proxies:
  - name: vless-none
    type: vless
    server: proxy.test
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    encryption: none
"#,
    );
    assert_eq!(nodes.len(), 1);
    assert!(nodes[0].diagnostic.is_none());
}

#[test]
fn clash_hysteria2_preserves_certificate_pin_and_equal_hopping_aliases() {
    let pin = "01".repeat(32);
    let document = format!(
        "proxies:\n  - {{name: hy2, type: hysteria2, server: proxy.test, port: 443, password: secret, sni: tls.test, skip-cert-verify: true, fingerprint: '{pin}', ports: '10000-14000', mport: '10000-14000', udp: true}}\n"
    );
    let nodes = imports(SubscriptionSourceType::Clash, &document);
    let node = &nodes[0];
    assert!(node.diagnostic.is_none());
    assert_eq!(node.credential.field("server_ports"), Some("10000-14000"));
    let tls = node.config.options.tls.as_ref().unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("tls.test"));
    assert_eq!(tls.certificate_sha256.as_deref(), Some(pin.as_str()));
    assert!(tls.insecure);
    let conflict = document.replace("mport: '10000-14000'", "mport: '11000-14000'");
    assert!(
        imports(SubscriptionSourceType::Clash, &conflict)[0]
            .diagnostic
            .is_some()
    );
    let malformed = document.replace(&pin, "not-a-sha256");
    assert!(
        imports(SubscriptionSourceType::Clash, &malformed)[0]
            .diagnostic
            .is_some()
    );
}

#[test]
fn clash_xtls_alias_normalizes_to_vless_vision() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"
proxies:
  - name: xtls-alias
    type: xtls
    server: proxy.test
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    encryption: none
    flow: xtls-rprx-vision
"#,
    );
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].config.protocol, "vless");
    assert!(nodes[0].diagnostic.is_none());
}

#[test]
fn xtls_alias_without_flow_is_not_silently_downgraded() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"
proxies:
  - name: incomplete-xtls
    type: xtls
    server: proxy.test
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
"#,
    );
    assert_eq!(nodes[0].config.protocol, "vless");
    assert_eq!(nodes[0].diagnostic.as_ref().unwrap().fields, ["flow"]);
}

#[test]
fn vless_uri_early_data_defaults_to_the_websocket_protocol_header() {
    let nodes = imports(
        SubscriptionSourceType::Uri,
        "vless://11111111-1111-1111-1111-111111111111@proxy.test:443?type=ws&ed=1024&path=%2Fws#early",
    );
    let transport = nodes[0].config.options.transport.as_ref().unwrap();
    assert_eq!(transport.max_early_data, Some(1024));
    assert_eq!(
        transport.early_data_header_name.as_deref(),
        Some("Sec-WebSocket-Protocol")
    );
    assert!(nodes[0].diagnostic.is_none());
}

#[tokio::test]
async fn trojan_go_links_prepare_dae_transport_variants() {
    let source = concat!(
        "trojan-go://pass%3Aword@proxy.test:443?type=original#tcp\n",
        "trojan-go://secret@proxy.test:443?type=ws&host=front.test&path=%2Ftunnel&sni=tls.test&allowinsecure=1#ws\n",
        "trojan-go://secret@proxy.test:443?type=grpc#grpc-default\n",
        "trojan-go://secret@proxy.test:443?type=grpc&path=custom.service#grpc-path\n",
        "trojan-go://secret@proxy.test:443?type=httpupgrade&host=front.test&path=%2Fupgrade#upgrade"
    );
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.as_bytes().to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["trojan".into()]),
    );
    assert!(matches!(
        manager.refresh(&config(SubscriptionSourceType::Auto)).await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let nodes: BTreeMap<_, _> = manager
        .snapshot()
        .selectable_nodes()
        .map(|node| (node.config.labels["source.name"].as_str(), node))
        .collect();
    assert_eq!(nodes.len(), 5);
    assert_eq!(
        nodes["tcp"].credential().field("password"),
        Some("pass:word")
    );
    let ws = nodes["ws"].config.options.transport.as_ref().unwrap();
    assert_eq!(ws.kind, "ws");
    assert_eq!(ws.host, ["front.test"]);
    assert_eq!(ws.path.as_deref(), Some("/tunnel"));
    let tls = nodes["ws"].config.options.tls.as_ref().unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("tls.test"));
    assert!(tls.insecure);
    for (name, service) in [
        ("grpc-default", "/GunService/Tun"),
        ("grpc-path", "/custom.service/Tun"),
    ] {
        let transport = nodes[name].config.options.transport.as_ref().unwrap();
        assert_eq!(transport.kind, "grpc");
        assert_eq!(transport.service_name.as_deref(), Some(service));
        assert!(transport.path.is_none());
    }
    let upgrade = nodes["upgrade"].config.options.transport.as_ref().unwrap();
    assert_eq!(upgrade.kind, "httpupgrade");
    assert_eq!(upgrade.host, ["front.test"]);
    assert_eq!(upgrade.path.as_deref(), Some("/upgrade"));
}

#[tokio::test]
async fn trojan_go_encryption_is_kept_in_private_credentials() {
    let source = concat!(
        "trojan-go://secret@proxy.test?encryption=none#plain\n",
        "trojan-go://secret@proxy.test?type=ws&encryption=ss%3Baes-128-gcm%3Aprivate%3Bvalue#encrypted\n",
        "trojan-go://secret@proxy.test?type=original&encryption=ss%3Baes-128-gcm%3Aprivate%3Bvalue#original-encrypted"
    );
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.as_bytes().to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["trojan".into()]),
    );
    assert!(matches!(
        manager.refresh(&config(SubscriptionSourceType::Auto)).await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let nodes: BTreeMap<_, _> = manager
        .snapshot()
        .selectable_nodes()
        .map(|node| (node.config.labels["source.name"].as_str(), node))
        .collect();
    assert_eq!(nodes.len(), 2);
    assert_eq!(
        nodes["encrypted"].credential().field("trojan_go_ss_method"),
        Some("aes-128-gcm")
    );
    assert_eq!(
        nodes["encrypted"]
            .credential()
            .field("trojan_go_ss_password"),
        Some("private;value")
    );
    assert!(!format!("{:?}", nodes["encrypted"].config).contains("private;value"));
    assert!(manager.snapshot().nodes.values().any(|node| {
        node.config.labels["source.name"] == "original-encrypted"
            && node.state
                == DynamicNodeState::Unavailable(NodeUnavailableReason::UnsupportedParameters)
    }));
}

#[test]
fn trojan_go_keeps_unsupported_or_conflicting_parameters_unavailable() {
    let source = concat!(
        "trojan-go://secret@proxy.test?type=ws&path=%2Fws#valid\n",
        "trojan-go://secret@proxy.test?encryption=ss%3Baes-128-gcm%3Bprivate-sentinel#dae-encrypted\n",
        "trojan-go://secret@proxy.test?encryption=ss%3Bunknown%3Aprivate-sentinel#unknown-cipher\n",
        "trojan-go://secret@proxy.test?encryption=ss%3Baes-128-gcm%3A#empty-password\n",
        "trojan-go://secret@proxy.test?encryption=#empty-encryption\n",
        "trojan-go://secret@proxy.test?type=grpc&path=first&serviceName=second#conflict\n",
        "trojan-go://secret:unescaped@proxy.test#userinfo\n",
        "trojan-go://secret@proxy.test?security=none#downgrade\n",
        "trojan-go://secret@proxy.test?type=unknown#unknown\n",
        "trojan-go://secret@proxy.test?type=ws&path=%ZZ#invalid-percent"
    );
    let nodes = imports(SubscriptionSourceType::Uri, source);
    assert_eq!(nodes.len(), 10);
    assert!(nodes[0].diagnostic.is_none());
    assert_eq!(
        nodes[0].config.options.transport.as_ref().unwrap().host,
        ["proxy.test"]
    );
    for node in &nodes[1..] {
        assert!(node.diagnostic.is_some());
        assert!(!format!("{:?}", node.diagnostic).contains("private-sentinel"));
    }
}

#[test]
fn provider_uri_defaults_and_hysteria_pin_are_preserved() {
    let pin = "ab".repeat(32);
    let input = format!(
        "vless://11111111-1111-1111-1111-111111111111@proxy.test:443?security=reality&sni=decoy.test&servername=decoy.test&pbk=key&sid=ab&spx=%2F&type=tcp&flow=xtls-rprx-vision&fp=chrome&encryption=none#vision\n\
         vless://11111111-1111-1111-1111-111111111111@proxy.test:443?security=tls&sni=tls.test&type=ws&host=front.test&path=%2Fws&fp=ios&headerType=none&quicSecurity=none&pcs=&serviceName=&insecure=0#ws\n\
         hysteria2://password@proxy.test:443?sni=tls.test&insecure=false&pinSHA256={pin}&mport=10000-14000#hy2"
    );
    let nodes = imports(SubscriptionSourceType::Uri, &input);
    assert!(nodes.iter().all(|node| node.diagnostic.is_none()));
    assert_eq!(
        nodes[0]
            .config
            .options
            .tls
            .as_ref()
            .unwrap()
            .server_name
            .as_deref(),
        Some("decoy.test")
    );
    let ws = nodes[1].config.options.transport.as_ref().unwrap();
    assert_eq!(ws.kind, "ws");
    assert_eq!(ws.host, ["front.test"]);
    assert_eq!(ws.service_name, None);
    let hy2 = &nodes[2];
    assert_eq!(hy2.credential.field("server_ports"), Some("10000-14000"));
    assert_eq!(
        hy2.config
            .options
            .tls
            .as_ref()
            .unwrap()
            .certificate_sha256
            .as_deref(),
        Some(pin.as_str())
    );
    let conflict = input.replace("servername=decoy.test", "servername=other.test");
    assert!(
        imports(SubscriptionSourceType::Uri, &conflict)[0]
            .diagnostic
            .is_some()
    );
    let unsupported_spider = input.replace("spx=%2F", "spx=%2Fcustom");
    assert!(
        imports(SubscriptionSourceType::Uri, &unsupported_spider)[0]
            .diagnostic
            .is_some()
    );
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

#[tokio::test]
async fn conflicting_credential_aliases_are_unavailable_without_discarding_valid_siblings() {
    let source = r#"
proxies:
  - {name: conflict, type: trojan, server: proxy.test, port: 443, password: first-private-value, auth: second-private-value}
  - {name: good, type: trojan, server: proxy.test, port: 443, password: valid-private-value}
  - {name: equal, type: trojan, server: proxy.test, port: 443, password: matching-private-value, auth: matching-private-value}
"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.as_bytes().to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["trojan".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::Clash))
            .await,
        RefreshOutcome::Published { .. }
    ));
    assert_eq!(manager.snapshot().selectable_nodes().count(), 0);
    prepare_imported_nodes(&mut manager).await;
    assert_eq!(manager.snapshot().selectable_nodes().count(), 2);
    let conflict = manager
        .snapshot()
        .nodes
        .values()
        .find(|node| {
            node.config
                .labels
                .get("source.name")
                .is_some_and(|name| name == "conflict")
        })
        .unwrap();
    assert_eq!(
        conflict.state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::InvalidNode)
    );
    let diagnostic = conflict.diagnostic.as_ref().unwrap();
    assert_eq!(diagnostic.fields, ["auth", "password"]);
    let exposed = format!("{:?}", manager.snapshot());
    for secret in [
        "first-private-value",
        "second-private-value",
        "valid-private-value",
        "matching-private-value",
    ] {
        assert!(!exposed.contains(secret));
    }
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
fn shadowsocks_none_and_plain_allow_empty_or_missing_password_but_not_empty_cipher() {
    let clash = r#"proxies:
  - {name: none, type: ss, server: proxy.test, port: 8388, cipher: none}
  - {name: plain, type: ss, server: proxy.test, port: 8388, cipher: plain, password: ''}
  - {name: invalid, type: ss, server: proxy.test, port: 8388, cipher: '', password: ''}
  - {name: encrypted, type: ss, server: proxy.test, port: 8388, cipher: aes-256-gcm}
"#;
    let nodes = imports(SubscriptionSourceType::Clash, clash);
    assert!(nodes[..2].iter().all(|node| node.diagnostic.is_none()));
    assert!(nodes[2..].iter().all(|node| node.diagnostic.is_some()));
    let uri = format!(
        "ss://none@proxy.test:8388#none\nss://plain:@proxy.test:8388#plain\nss://{}@proxy.test:8388#missing\nss://{}@proxy.test:8388#empty",
        base64("aes-256-gcm:"),
        base64(":password"),
    );
    let nodes = imports(SubscriptionSourceType::Uri, &uri);
    assert!(nodes[..2].iter().all(|node| node.diagnostic.is_none()));
    assert!(nodes[2..].iter().all(|node| node.diagnostic.is_some()));
}

#[test]
fn clash_shadowsocks_udp_defaults_to_disabled() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        "proxies:\n  - {name: default, type: ss, server: proxy.test, port: 8388, cipher: aes-128-gcm, password: fixture}\n  - {name: udp, type: ss, server: proxy.test, port: 8388, cipher: aes-128-gcm, password: fixture, udp: true}\n",
    );
    assert_eq!(nodes[0].config.options.udp, Some(false));
    assert_eq!(nodes[1].config.options.udp, Some(true));
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
    assert_eq!(
        node.diagnostic.as_ref().unwrap().code,
        NodeUnavailableReason::AdapterUnavailable
    );
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
    assert_eq!(
        nodes[1].diagnostic.as_ref().unwrap().code,
        NodeUnavailableReason::AdapterUnavailable
    );
    let raw: Value =
        serde_json::from_str(nodes[1].credential.field("sing_box_outbound").unwrap()).unwrap();
    assert_eq!(raw["tls"]["future_secret"], "secret");
    assert_eq!(nodes[1].config.options, TransitOptions::default());
}

#[test]
fn sing_box_proxy_chain_options_remain_unavailable_without_a_native_chain_runtime() {
    let nodes = imports(
        SubscriptionSourceType::SingBox,
        r#"{"outbounds":[
          {"type":"socks","tag":"base","server":"proxy.test","server_port":1080},
          {"type":"socks","tag":"detoured","server":"proxy.test","server_port":1081,"detour":"base"},
          {"type":"http","tag":"routed","server":"proxy.test","server_port":8080,"route":{"final":"base"}}
        ]}"#,
    );
    assert_eq!(nodes.len(), 3);
    assert_eq!(nodes[0].state, DynamicNodeState::Active);
    for node in &nodes[1..] {
        assert_eq!(
            node.state,
            DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
        );
        assert!(node.credential.field("sing_box_outbound").is_some());
        assert_eq!(node.config.options, TransitOptions::default());
        assert!(!format!("{:?}", node.credential).contains("proxy.test"));
    }
}

#[test]
fn simple_sing_box_socks_node_uses_the_native_adapter() {
    let nodes = normalize(
        &config(SubscriptionSourceType::SingBox),
        br#"{"outbounds":[{"type":"socks","server":"proxy.test","server_port":1080}]}"#,
        &BTreeSet::from(["socks5".to_owned()]),
    )
    .unwrap();
    assert_eq!(nodes[0].state, DynamicNodeState::Active);
    assert!(nodes[0].credential.field("sing_box_outbound").is_none());
}

#[tokio::test]
async fn sing_box_socks_udp_over_tcp_versions_are_preserved() {
    let nodes = imports(
        SubscriptionSourceType::SingBox,
        r#"{"outbounds":[
          {"type":"socks","tag":"default","server":"proxy.test","server_port":1080,"udp_over_tcp":true},
          {"type":"socks","tag":"v1","server":"proxy.test","server_port":1080,"udp_over_tcp":{"enabled":true,"version":1}},
          {"type":"socks","tag":"v2","server":"proxy.test","server_port":1080,"udp_over_tcp":{"enabled":true,"version":2}},
          {"type":"socks","tag":"disabled","server":"proxy.test","server_port":1080,"udp_over_tcp":{"enabled":false,"version":1}},
          {"type":"socks","tag":"invalid","server":"proxy.test","server_port":1080,"udp_over_tcp":{"enabled":true,"version":3}}
        ]}"#,
    );
    assert_eq!(nodes.len(), 5);
    for (node, expected) in nodes.iter().take(4).zip([Some(2), Some(1), Some(2), None]) {
        assert!(node.diagnostic.is_none());
        assert_eq!(node.config.options.udp_over_tcp, expected);
        assert!(node.credential.field("sing_box_outbound").is_none());
    }
    assert_eq!(
        nodes[4].state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
    );
    assert!(nodes[4].credential.field("sing_box_outbound").is_some());

    let source = br#"{"outbounds":[{"type":"socks","server":"proxy.test","server_port":1080,"udp_over_tcp":{"enabled":true,"version":2}}]}"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["socks5".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::SingBox))
            .await,
        RefreshOutcome::Published { .. }
    ));
    assert_eq!(manager.snapshot().selectable_nodes().count(), 0);
    prepare_imported_nodes(&mut manager).await;
    let node = manager.snapshot().selectable_nodes().next().unwrap();
    assert_eq!(node.config.options.udp_over_tcp, Some(2));
    assert!(
        manager
            .snapshot()
            .validated_adapter(&node.config.id)
            .unwrap()
            .supports_udp()
    );
}

#[tokio::test]
async fn shadowsocks_udp_over_tcp_versions_survive_import_and_preparation() {
    let source = br#"{"outbounds":[
      {"type":"shadowsocks","tag":"v2","server":"proxy.test","server_port":8388,"method":"aes-128-gcm","password":"fixture-password","udp_over_tcp":true},
      {"type":"shadowsocks","tag":"v1","server":"proxy.test","server_port":8388,"method":"aes-128-gcm","password":"fixture-password","udp_over_tcp":{"enabled":true,"version":1}}
    ]}"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["ss".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::SingBox))
            .await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let nodes: Vec<_> = manager.snapshot().selectable_nodes().collect();
    assert_eq!(nodes.len(), 2);
    for node in nodes {
        let expected = if node.config.labels["source.name"] == "v1" {
            1
        } else {
            2
        };
        assert_eq!(node.config.options.udp_over_tcp, Some(expected));
        assert!(
            manager
                .snapshot()
                .validated_adapter(&node.config.id)
                .unwrap()
                .supports_udp()
        );
    }
    let clash = imports(
        SubscriptionSourceType::Clash,
        "proxies:\n - {name: legacy, type: ss, server: proxy.test, port: 8388, cipher: aes-128-gcm, password: fixture, udp: true, udp-over-tcp: true}\n",
    );
    assert!(clash[0].diagnostic.is_none());
    assert_eq!(clash[0].config.options.udp_over_tcp, Some(1));
}

#[tokio::test]
async fn tuic_udp_over_stream_is_prepared_and_conflicts_are_unavailable() {
    let source = br#"{"outbounds":[
      {"type":"tuic","tag":"valid","server":"proxy.test","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","password":"fixture-password","udp_over_stream":true},
      {"type":"tuic","tag":"conflict","server":"proxy.test","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","password":"fixture-password","udp_over_stream":true,"udp_relay_mode":"native"}
    ]}"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["tuic".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::SingBox))
            .await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let nodes: Vec<_> = manager.snapshot().selectable_nodes().collect();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].config.labels["source.name"], "valid");
    assert_eq!(nodes[0].credential.field("udp_over_stream"), Some("true"));
    assert!(
        manager
            .snapshot()
            .validated_adapter(&nodes[0].config.id)
            .unwrap()
            .supports_udp()
    );
    assert!(
        manager
            .snapshot()
            .nodes
            .values()
            .any(|node| node.config.labels["source.name"] == "conflict"
                && matches!(node.state, DynamicNodeState::Unavailable(_)))
    );
}

#[tokio::test]
async fn hysteria2_download_and_upload_rates_are_imported_and_prepared() {
    let source = br#"{"outbounds":[
      {"type":"hysteria2","tag":"down","server":"proxy.test","server_port":443,"password":"fixture-password","down_mbps":7},
      {"type":"hysteria2","tag":"up","server":"proxy.test","server_port":443,"password":"fixture-password","up_mbps":4}
    ]}"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["hysteria2".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::SingBox))
            .await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let nodes: Vec<_> = manager.snapshot().selectable_nodes().collect();
    assert_eq!(nodes.len(), 2);
    let down = nodes
        .iter()
        .find(|node| node.config.labels["source.name"] == "down")
        .unwrap();
    let up = nodes
        .iter()
        .find(|node| node.config.labels["source.name"] == "up")
        .unwrap();
    assert_eq!(down.credential.field("down_mbps"), Some("7"));
    assert_eq!(up.credential.field("up_mbps"), Some("4"));
}

#[tokio::test]
async fn sing_box_gecko_sizes_are_preserved_and_invalid_ranges_are_unavailable() {
    let source = br#"{"outbounds":[
      {"type":"hysteria2","tag":"valid","server":"proxy.test","server_port":443,"password":"fixture","obfs":{"type":"gecko","password":"fixture-obfs","min_packet_size":700,"max_packet_size":2048}},
      {"type":"hysteria2","tag":"invalid","server":"proxy.test","server_port":443,"password":"fixture","obfs":{"type":"gecko","password":"fixture-obfs","min_packet_size":1401,"max_packet_size":1400}},
      {"type":"hysteria2","tag":"wrong-type","server":"proxy.test","server_port":443,"password":"fixture","obfs":{"type":"salamander","password":"fixture-obfs","min_packet_size":700}}
    ]}"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["hysteria2".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::SingBox))
            .await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let nodes: Vec<_> = manager.snapshot().selectable_nodes().collect();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].config.labels["source.name"], "valid");
    assert_eq!(
        nodes[0].credential.field("gecko_min_packet_size"),
        Some("700")
    );
    assert_eq!(
        nodes[0].credential.field("gecko_max_packet_size"),
        Some("2048")
    );
}

#[test]
fn clash_socks_udp_over_tcp_defaults_to_version_one() {
    let nodes = imports(
        SubscriptionSourceType::Clash,
        r#"
proxies:
  - {name: default, type: socks5, server: proxy.test, port: 1080, udp-over-tcp: true}
  - {name: v2, type: socks5, server: proxy.test, port: 1080, udp-over-tcp: true, udp-over-tcp-version: 2}
  - {name: invalid, type: socks5, server: proxy.test, port: 1080, udp-over-tcp-version: 2}
"#,
    );
    assert_eq!(nodes[0].config.options.udp_over_tcp, Some(1));
    assert_eq!(nodes[1].config.options.udp_over_tcp, Some(2));
    assert!(nodes[0].diagnostic.is_none() && nodes[1].diagnostic.is_none());
    assert_eq!(
        nodes[2].state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::InvalidNode)
    );
}

#[tokio::test]
async fn sing_box_http_request_path_stays_private_and_is_prepared() {
    let source = br#"{"outbounds":[{"type":"http","tag":"proxy","server":"proxy.test","server_port":8080,"path":"/tunnel?token=private-path-sentinel"}]}"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(source.to_vec())])),
        std::env::temp_dir(),
        BTreeSet::from(["http".into()]),
    );
    assert!(matches!(
        manager
            .refresh(&config(SubscriptionSourceType::SingBox))
            .await,
        RefreshOutcome::Published { .. }
    ));
    prepare_imported_nodes(&mut manager).await;
    let node = manager.snapshot().selectable_nodes().next().unwrap();
    assert_eq!(
        node.credential.field("http_path"),
        Some("/tunnel?token=private-path-sentinel")
    );
    assert!(
        !serde_json::to_string(&node.config)
            .unwrap()
            .contains("private-path-sentinel")
    );
    assert!(!format!("{:?}", node.credential).contains("private-path-sentinel"));
}

#[test]
fn sing_box_policy_outbounds_do_not_create_nodes_or_direct_bypasses() {
    let nodes = normalize(
        &config(SubscriptionSourceType::SingBox),
        br#"{"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"},{"type":"selector","tag":"pick","outbounds":["node","direct"]},{"type":"urltest","tag":"test","outbounds":["node"]},{"type":"socks","tag":"node","server":"proxy.test","server_port":1080}]}"#,
        &BTreeSet::from(["direct".to_owned(), "socks5".to_owned()]),
    ).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].config.protocol, "socks5");
    assert_eq!(nodes[0].state, DynamicNodeState::Active);
}

#[test]
fn skipped_sing_box_groups_preserve_existing_duplicate_node_ids() {
    let nodes = normalize(
        &config(SubscriptionSourceType::SingBox),
        br#"{"outbounds":[{"type":"selector","tag":"same","outbounds":["same"]},{"type":"socks","tag":"same","server":"proxy.test","server_port":1080},{"type":"socks","tag":"same","server":"proxy.test","server_port":1081}]}"#,
        &BTreeSet::from(["socks5".to_owned()]),
    ).unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].config.id.as_str(), "fixture-same-2");
    assert_eq!(nodes[1].config.id.as_str(), "fixture-same-3");
}

#[test]
fn sing_box_vless_packet_encoding_preserves_default_and_explicit_empty() {
    let nodes = normalize(
        &config(SubscriptionSourceType::SingBox),
        br#"{"outbounds":[
          {"type":"vless","tag":"default","server":"proxy.test","server_port":443,"uuid":"fixture"},
          {"type":"vless","tag":"plain","server":"proxy.test","server_port":443,"uuid":"fixture","packet_encoding":""},
          {"type":"vless","tag":"vision","server":"proxy.test","server_port":443,"uuid":"fixture","flow":"xtls-rprx-vision","packet_encoding":""}
        ]}"#,
        &BTreeSet::from(["vless".to_owned()]),
    ).unwrap();
    assert_eq!(
        nodes[0].config.options.packet_encoding.as_deref(),
        Some("xudp")
    );
    assert_eq!(nodes[1].config.options.packet_encoding, None);
    assert_eq!(
        nodes[2].state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
    );
}

#[test]
fn sing_box_plain_trojan_is_not_silently_upgraded_to_tls() {
    let nodes = normalize(
        &config(SubscriptionSourceType::SingBox),
        br#"{"outbounds":[{"type":"trojan","server":"proxy.test","server_port":443,"password":"fixture"}]}"#,
        &BTreeSet::from(["trojan".to_owned()]),
    ).unwrap();
    assert_eq!(
        nodes[0].state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
    );
}

#[tokio::test]
async fn sing_box_private_fallback_remains_unavailable_after_cache_reload() {
    let directory = temp_directory("sing-box-cache");
    let mut config = config(SubscriptionSourceType::SingBox);
    config.cache = Some(pathchord_policy::SubscriptionCache {
        path: "cache.json".into(),
        max_age_seconds: 3600,
    });
    let available = BTreeSet::from(["socks5".to_owned(), "http".to_owned()]);
    let document = br#"{"outbounds":[{"type":"socks","tag":"native","server":"proxy.test","server_port":1080},{"type":"http","tag":"unknown","server":"proxy.test","server_port":80,"future_option":"secret"}]}"#;
    let mut manager = SubscriptionManager::new(
        Arc::new(ScriptedFetcher::new([Ok(document.to_vec())])),
        &directory,
        available.clone(),
    );
    assert!(matches!(
        manager.refresh(&config).await,
        RefreshOutcome::Published { .. }
    ));
    let mut restored =
        SubscriptionManager::new(Arc::new(ScriptedFetcher::new([])), &directory, available);
    assert!(matches!(
        restored.load_cache(&config).await.unwrap(),
        CacheLoadOutcome::Loaded { .. }
    ));
    assert_eq!(restored.snapshot().selectable_nodes().count(), 0);
    assert!(restored.snapshot().nodes.values().any(|node| {
        node.config.labels["source.name"] == "native" && node.state == DynamicNodeState::Pending
    }));
    prepare_imported_nodes(&mut restored).await;
    let states: BTreeMap<_, _> = restored
        .snapshot()
        .nodes
        .values()
        .map(|node| (node.config.labels["source.name"].as_str(), node.state))
        .collect();
    assert_eq!(states["native"], DynamicNodeState::Active);
    assert_eq!(
        states["unknown"],
        DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn sing_box_native_nodes_preserve_supported_options_and_unknown_siblings() {
    let nodes = normalize(
        &config(SubscriptionSourceType::SingBox),
        br#"{"outbounds":[
          {"type":"vless","tag":"reality","server":"proxy.test","server_port":443,"uuid":"6cbf3f72-3417-4922-bde6-67820d041f25","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"decoy.test","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"fixture-key","short_id":"ab"}}},
          {"type":"vmess","tag":"ws","server":"proxy.test","server_port":443,"uuid":"fixture","security":"aes-128-gcm","transport":{"type":"ws","path":"/ws","headers":{"Host":["host.test"]},"max_early_data":1024,"early_data_header_name":"Sec-WebSocket-Protocol"}},
          {"type":"http","tag":"unknown","server":"proxy.test","server_port":80,"future_secret":"never-print"}
        ]}"#,
        &BTreeSet::from(["vless".to_owned(), "vmess".to_owned(), "http".to_owned()]),
    ).unwrap();
    assert_eq!(nodes[0].state, DynamicNodeState::Active);
    assert_eq!(nodes[0].credential.field("flow"), Some("xtls-rprx-vision"));
    let tls = nodes[0].config.options.tls.as_ref().unwrap();
    assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(tls.reality.as_ref().unwrap().short_id, "ab");
    assert_eq!(nodes[1].state, DynamicNodeState::Active);
    let transport = nodes[1].config.options.transport.as_ref().unwrap();
    assert_eq!(transport.max_early_data, Some(1024));
    assert_eq!(transport.headers["Host"], "host.test");
    assert!(nodes[1].credential.field("sing_box_outbound").is_none());
    assert_eq!(
        nodes[2].state,
        DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
    );
    assert!(nodes[2].credential.field("sing_box_outbound").is_some());
    assert!(!format!("{:?}", nodes[2].credential).contains("never-print"));
}

#[test]
fn sing_box_multiple_header_values_remain_unavailable() {
    let nodes = normalize(
        &config(SubscriptionSourceType::SingBox),
        br#"{"outbounds":[{"type":"vless","server":"proxy.test","server_port":443,"uuid":"fixture","transport":{"type":"ws","headers":{"X-Example":["one","two"]}}}]}"#,
        &BTreeSet::from(["vless".to_owned()]),
    ).unwrap();
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
    assert!(nodes.iter().all(|node| {
        node.diagnostic
            .as_ref()
            .is_some_and(|d| d.code == NodeUnavailableReason::AdapterUnavailable)
    }));
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
    assert_eq!(
        node.diagnostic.as_ref().unwrap().code,
        NodeUnavailableReason::AdapterUnavailable
    );
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
    assert_eq!(nodes[2].state, DynamicNodeState::Active);
    for index in [0, 1, 3, 4] {
        assert_eq!(
            nodes[index].state,
            DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
        );
        assert_eq!(
            nodes[index].diagnostic.as_ref().unwrap().code,
            NodeUnavailableReason::AdapterUnavailable
        );
    }
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
    assert_eq!(restored.snapshot().selectable_nodes().count(), 0);
    prepare_imported_nodes(&mut restored).await;
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
