#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use pathchord_ingress::{
    Actor, GenerationExpectation, LOCAL_API_VERSION, RequestEnvelope, ResponseEnvelope,
    read_object, write_object,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};

const BIN: &str = env!("CARGO_BIN_EXE_pathchord");

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(directory: &Path, socket: &Path, identity: &Path, config: &Path) -> Process {
    Process(
        Command::new(BIN)
            .current_dir(directory)
            .env_remove("PATHCHORD_CONFIG")
            .env_remove("PATHCHORD_CONFIG_DIR")
            .args([
                "--socket",
                socket.to_str().unwrap(),
                "ingress",
                "--ingress-id",
                "entry",
                "--identity",
                identity.to_str().unwrap(),
                "--config",
                config.to_str().unwrap(),
                "--data-dir",
                directory.join("data").to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

async fn wait_socket(path: &Path, process: &mut Process) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            let mut error = String::new();
            std::io::Read::read_to_string(process.0.stderr.as_mut().unwrap(), &mut error).unwrap();
            panic!("ingress exited ({status}): {error}");
        }
        if UnixStream::connect(path).await.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "control socket startup timed out"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn call(
    path: &Path,
    operation: &str,
    request_id: &str,
    generation: Option<u64>,
) -> ResponseEnvelope {
    let mut socket = UnixStream::connect(path).await.unwrap();
    write_object(
        &mut socket,
        &RequestEnvelope {
            api_version: LOCAL_API_VERSION.into(),
            operation: operation.into(),
            request_id: request_id.into(),
            actor: Actor {
                id: "ignored-local-actor".into(),
                capabilities: vec![],
            },
            expected_generation: generation.map(|value| GenerationExpectation {
                scope: "configuration".into(),
                value,
            }),
            body: if operation == "status.get" {
                json!({})
            } else {
                json!({"id": "provider"})
            },
        },
    )
    .await
    .unwrap();
    read_object(&mut socket).await.unwrap()
}

async fn connect(proxy_port: u16) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.ok()?;
    stream
        .write_all(b"CONNECT target.example:443 HTTP/1.1\r\nHost: target.example:443\r\n\r\n")
        .await
        .ok()?;
    let mut header = Vec::new();
    let completed = tokio::time::timeout(Duration::from_secs(3), async {
        while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
            header.push(stream.read_u8().await?);
        }
        std::io::Result::Ok(())
    })
    .await;
    if completed.is_ok_and(|result| result.is_ok()) && header.starts_with(b"HTTP/1.1 200") {
        Some(stream)
    } else {
        None
    }
}

fn configuration(provider: u16, proxy: u16, path: &str) -> String {
    format!(
        r#"apiVersion: pathchord.io/v1
kind: Subscription
metadata: {{name: provider}}
spec:
  source: {{type: clash, url: 'http://127.0.0.1:{provider}/{path}', userAgent: 'PathChord-Test/1'}}
  refresh: {{intervalSeconds: 3600, timeoutSeconds: 2, maxAttempts: 1, backoffSeconds: 1}}
  cache: {{path: provider.snapshot, maxAgeSeconds: 86400}}
---
apiVersion: pathchord.io/v1
kind: ProxyRule
metadata: {{name: ordinary}}
spec: {{order: 10, catchAll: true, select: any}}
---
apiVersion: pathchord.io/v1
kind: Listener
metadata: {{name: local}}
spec: {{type: http, bind: '127.0.0.1:{proxy}', protocols: [tcp], authentication: disabled}}
---
apiVersion: pathchord.io/v1
kind: DNSPolicy
metadata: {{name: default}}
spec: {{defaultRoute: local, local: {{servers: ['127.0.0.1:53']}}}}
---
apiVersion: pathchord.io/v1
kind: FallbackPolicy
metadata: {{name: default}}
spec: {{action: reject}}
"#
    )
}

#[tokio::test]
async fn disabled_and_deleted_subscriptions_stay_unselectable_across_process_restart() {
    tokio::time::timeout(Duration::from_secs(55), async {
        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let relay_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = relay.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
                        match stream.read_u8().await { Ok(byte) => header.push(byte), Err(_) => return }
                    }
                    if stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() { return; }
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider_port = provider.local_addr().unwrap().port();
        let fetches = Arc::new(AtomicUsize::new(0));
        let wrong_agents = Arc::new(AtomicUsize::new(0));
        let fetch_count = Arc::clone(&fetches);
        let wrong_agent_count = Arc::clone(&wrong_agents);
        let provider_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = provider.accept().await.unwrap();
                fetch_count.fetch_add(1, Ordering::SeqCst);
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
                    match stream.read_u8().await { Ok(byte) => header.push(byte), Err(_) => break }
                }
                if !String::from_utf8_lossy(&header).to_ascii_lowercase().contains("\r\nuser-agent: pathchord-test/1\r\n") {
                    wrong_agent_count.fetch_add(1, Ordering::SeqCst);
                }
                let body = format!("proxies: [{{name: relay, type: http, server: 127.0.0.1, port: {relay_port}}}]\n");
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        for operation in ["subscriptions.disable", "subscriptions.delete"] {
            let directory = Directory(std::env::temp_dir().join(format!("pathchord-subscription-{}-{}", std::process::id(), port())));
            std::fs::create_dir_all(&directory.0).unwrap();
            let identity = directory.0.join("identity");
            assert!(Command::new(BIN).args(["keygen", "--output", identity.to_str().unwrap()]).stdout(Stdio::null()).status().unwrap().success());
            let socket = directory.0.join("ingress.sock");
            let config = directory.0.join("config.yaml");
            let proxy_port = port();
            let config_text = configuration(provider_port, proxy_port, "old");
            std::fs::write(&config, &config_text).unwrap();
            assert!(pathchord_policy::KubeConfig::from_yaml(&config_text).is_ok(), "invalid test config: {:?}", pathchord_policy::KubeConfig::from_yaml(&config_text));
            let mut process = start(&directory.0, &socket, &identity, &config);
            wait_socket(&socket, &mut process).await;
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut existing = loop {
                if let Some(stream) = connect(proxy_port).await { break stream; }
                assert!(Instant::now() < deadline, "subscription node did not become selectable");
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            assert!(directory.0.join("data/subscriptions/provider.snapshot").exists());
            let mut serial = 0;
            loop {
                let status = call(&socket, "status.get", "status", None).await;
                let generation = status.result.unwrap()["configuration_generation"].as_u64().unwrap();
                serial += 1;
                let result = call(&socket, operation, &format!("change-{serial}"), Some(generation)).await;
                if result.ok { break; }
                assert!(serial < 5, "mutation failed: {result:?}");
            }
            assert!(connect(proxy_port).await.is_none(), "new flow passed after successful {operation}");
            existing.write_all(b"still-open").await.unwrap();
            let mut reply = [0; 10];
            existing.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"still-open");
            drop(existing);
            drop(process);
            let before_restart = fetches.load(Ordering::SeqCst);
            let mut restarted = start(&directory.0, &socket, &identity, &config);
            wait_socket(&socket, &mut restarted).await;
            assert!(connect(proxy_port).await.is_none(), "old cache revived after restart and {operation}");
            tokio::time::sleep(Duration::from_millis(1200)).await;
            assert!(connect(proxy_port).await.is_none());
            assert_eq!(fetches.load(Ordering::SeqCst), before_restart, "disabled or deleted source was fetched");
            drop(restarted);
            std::fs::write(&config, configuration(provider_port, proxy_port, "new")).unwrap();
            let mut changed = start(&directory.0, &socket, &identity, &config);
            wait_socket(&socket, &mut changed).await;
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                if connect(proxy_port).await.is_some() { break; }
                assert!(Instant::now() < deadline, "changed declaration did not reactivate the source");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(fetches.load(Ordering::SeqCst) > before_restart);
        }
        assert_eq!(wrong_agents.load(Ordering::SeqCst), 0, "custom User-Agent must survive configuration and restart");
        provider_task.abort();
        relay_task.abort();
    }).await.expect("bounded subscription restart test");
}
