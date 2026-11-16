//! Exercise a pinned Hysteria2 UDP association across two local UDP relays.
//! Run with PATHCHORD_TEST_SING_BOX pointing to a local sing-box binary.

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitCredential,
    TransitError,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::UdpSocket,
    process::Command,
    task::JoinHandle,
    time::{sleep, timeout},
};

async fn relay(front: Arc<UdpSocket>, server: SocketAddr, count: Arc<AtomicUsize>) {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    backend.connect(server).await.unwrap();
    let mut client = None;
    let mut from_client = [0_u8; 65536];
    let mut from_server = [0_u8; 65536];
    loop {
        tokio::select! {
            incoming = front.recv_from(&mut from_client) => {
                let (length, address) = incoming.unwrap();
                client = Some(address);
                count.fetch_add(1, Ordering::Relaxed);
                backend.send(&from_client[..length]).await.unwrap();
            }
            response = backend.recv(&mut from_server) => {
                let length = response.unwrap();
                if let Some(address) = client { front.send_to(&from_server[..length], address).await.unwrap(); }
            }
        }
    }
}

struct Abort(JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to a local sing-box binary"]
async fn pinned_udp_association_survives_hops_between_two_forwarders() {
    timeout(Duration::from_secs(25), async {
        let binary = PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("local sing-box binary"));
        let rcgen::CertifiedKey {cert, signing_key} = rcgen::generate_simple_self_signed(vec!["hop.test".to_owned()]).unwrap();
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = reservation.local_addr().unwrap();
        drop(reservation);
        let config = serde_json::json!({
            "log":{"disabled":true},
            "inbounds":[{"type":"hysteria2","listen":"127.0.0.1","listen_port":server.port(),"users":[{"password":"test-password"}],"down_mbps":1,"tls":{"enabled":true,"certificate":cert.pem(),"key":signing_key.serialize_pem()}}],
            "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}
        });
        let mut child = Command::new(binary).arg("run").arg("-c").arg("stdin")
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
        child.stdin.take().unwrap().write_all(&serde_json::to_vec(&config).unwrap()).await.unwrap();
        sleep(Duration::from_millis(150)).await;
        assert!(child.try_wait().unwrap().is_none(), "sing-box exited at startup");
        let first = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let second = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let first_count = Arc::new(AtomicUsize::new(0));
        let second_count = Arc::new(AtomicUsize::new(0));
        let _first = Abort(tokio::spawn(relay(Arc::clone(&first),server,Arc::clone(&first_count))));
        let _second = Abort(tokio::spawn(relay(Arc::clone(&second),server,Arc::clone(&second_count))));
        let ports = format!("{},{}", first.local_addr().unwrap().port(), second.local_addr().unwrap().port());
        let pin: String = Sha256::digest(cert.der().as_ref()).iter().map(|byte| format!("{byte:02x}")).collect();
        let config = TransitProxyConfig {
            id:TransitProxyId::new("hy2-hop-test"), source:None, protocol:"hysteria2".into(),
            endpoint:PolicyEndpoint {host:"127.0.0.1".into(), port:server.port()}, credentials_ref:None,
            labels:BTreeMap::new(), tags:BTreeSet::new(), weight:100,
            options:TransitOptions { tls:Some(TransitTls {enabled:true, insecure:true, server_name:Some("hop.test".into()), truststore:Vec::new(), certificate_sha256:Some(pin), ..Default::default()}), ..Default::default() },
        };
        let bbr_credentials=TransitCredential::new(BTreeMap::from([("password".into(),"test-password".into()),("server_ports".into(),ports.clone()),("hop_interval".into(),"50ms".into()),("down_mbps".into(),"2".into())]));
        let credentials=TransitCredential::new(BTreeMap::from([("password".into(),"test-password".into()),("server_ports".into(),ports),("hop_interval".into(),"50ms".into()),("up_mbps".into(),"2".into()),("down_mbps".into(),"2".into())]));
        let base = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider())).with_safe_default_protocol_versions().unwrap().with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth();
        let registry=AdapterRegistry::new(Arc::new(NoTransitCredentials),Duration::from_secs(5),Arc::new(base));
        let adapter=registry.build_with_credential(&config,&credentials).unwrap();
        let target=UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr=target.local_addr().unwrap();
        let echo=tokio::spawn(async move {let mut buf=[0_u8;1024]; loop {let (len,peer)=target.recv_from(&mut buf).await.unwrap(); target.send_to(&buf[..len],peer).await.unwrap();}});
        let _echo=Abort(echo);
        let bbr_adapter=registry.build_with_credential(&config,&bbr_credentials).unwrap();
        let mut bbr_association=bbr_adapter.connect_udp(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(),port:target_addr.port()}}).await.unwrap();
        for index in 0_u8..10 {
            bbr_association.send(&[index;32]).await.unwrap();
            let received=timeout(Duration::from_secs(2),bbr_association.receive()).await.expect("BBR UDP response timed out").unwrap();
            assert_eq!(received,vec![index;32]);
            sleep(Duration::from_millis(50)).await;
        }
        bbr_association.close().await.unwrap();
        first_count.store(0, Ordering::Relaxed);
        second_count.store(0, Ordering::Relaxed);
        let mut association=adapter.connect_udp(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(),port:target_addr.port()}}).await.unwrap();
        for index in 0_u8..60 {
            association.send(&[index;32]).await.unwrap();
            let received=timeout(Duration::from_secs(2),association.receive()).await.expect("UDP response timed out").unwrap();
            assert_eq!(received,vec![index;32]);
            sleep(Duration::from_millis(50)).await;
        }
        assert!(first_count.load(Ordering::Relaxed)>0 && second_count.load(Ordering::Relaxed)>0, "both hop forwarders must receive QUIC packets");
        association.close().await.unwrap();
        let mut invalid_pin = config.clone();
        invalid_pin.options.tls.as_mut().unwrap().certificate_sha256 = Some("00".repeat(32));
        let invalid_adapter = registry.build_with_credential(&invalid_pin, &credentials).unwrap();
        assert!(matches!(invalid_adapter.connect_udp(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(),port:target_addr.port()}}).await, Err(TransitError::Connection(_))), "wrong certificate pin must fail even when insecure is set");
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }).await.expect("bounded Hysteria2 port hopping test");
}
