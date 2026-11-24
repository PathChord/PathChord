#![cfg(unix)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn binary(name: &str) -> PathBuf {
    let mut path = std::env::current_exe().expect("test executable path");
    for _ in 0..8 {
        path.pop();
        let candidate = path.join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("could not locate role binary {name}");
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Task<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn command_json(arguments: &[&str]) -> Value {
    let output = Command::new(binary("pathchordctl"))
        .args(["-o", "json"])
        .args(arguments)
        .output()
        .expect("run CLI");
    assert!(
        output.status.success(),
        "CLI command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI JSON response")
}

fn assert_private_owner(path: &Path) {
    let metadata = std::fs::metadata(path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), nix::unistd::Uid::effective().as_raw());
}

fn spawn(arguments: &[&str], directory: &Path) -> Process {
    let role_index = arguments
        .iter()
        .position(|argument| matches!(*argument, "ingress" | "egress"))
        .expect("service role");
    let role = arguments[role_index];
    let binary_name = match role {
        "ingress" => "pathchord-ingressd",
        "egress" => "pathchord-egressd",
        other => panic!("unknown service role {other}"),
    };
    let mut command = Command::new(binary(binary_name));
    let service_arguments = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (index != role_index).then_some(*argument))
        .collect::<Vec<_>>();
    command
        .args(service_arguments)
        .current_dir(directory)
        .env_remove("PATHCHORD_CONFIG")
        .env_remove("PATHCHORD_CONFIG_DIR");
    if arguments.contains(&"ingress") {
        command
            .env(
                "PATHCHORD_CONFIG",
                directory.join("ignored-environment.yaml"),
            )
            .env(
                "PATHCHORD_CONFIG_DIR",
                directory.join("ignored-environment.d"),
            );
    }
    Process(
        command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start service"),
    )
}

fn unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_socket(path: &Path, process: &mut Process) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            let mut error = String::new();
            if let Some(mut output) = process.0.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut output, &mut error);
            }
            panic!("service exited during startup ({status}): {error}");
        }
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "service startup timed out");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn separate_cli_processes_enroll_and_forward_http_and_udp_through_a_transit() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = std::env::temp_dir().join(format!("pc-cli-{}-{}", std::process::id(), unused_port()));
        std::fs::create_dir(&directory).unwrap();
        let directory = Directory(directory);
        let ingress_key = directory.0.join("ingress.json");
        let egress_key = directory.0.join("egress.json");
        let ingress_public = command_json(&["keygen", "--identity-file", ingress_key.to_str().unwrap()]);
        let egress_public = command_json(&["keygen", "--identity-file", egress_key.to_str().unwrap()]);
        assert_private_owner(&ingress_key);
        assert_private_owner(&egress_key);
        let egress_port = unused_port();
        let proxy_port = unused_port();
        let egress_socket = directory.0.join("e.sock");
        let ingress_socket = directory.0.join("i.sock");
        let egress_address = format!("127.0.0.1:{egress_port}");
        let egress_config = directory.0.join("egress.yaml");
        std::fs::write(&egress_config, format!(
            "apiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {{name: exit}}\nspec: {{bind: '{egress_address}', identity: egress.key, authorizationDb: auth.db, controlSocket: e.sock}}\n"
        )).unwrap();
        let mut egress = spawn(&["egress", "--config", egress_config.to_str().unwrap(), "--identity", egress_key.to_str().unwrap()], &directory.0);
        wait_for_socket(&egress_socket, &mut egress).await;
        assert_private_owner(&egress_socket);
        let enrolled = command_json(&["--config", egress_config.to_str().unwrap(), "enroll", "add",
            "--ingress-id", "entry", "--public-key", ingress_public["public_key"].as_str().unwrap()]);
        assert_eq!(enrolled["ok"], true);

        for (options, expected) in [
            (vec!["--expected-generation", "0", "--yes"], "GenerationConflict"),
            (vec![], "confirmation declined"),
        ] {
            let output = Command::new(binary("pathchordctl"))
                .args(["--socket", egress_socket.to_str().unwrap(), "enroll", "revoke", "--ingress-id", "entry"])
                .args(options)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains(expected), "{output:?}");
        }

        let transit = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transit_port = transit.local_addr().unwrap().port();
        let transit_task = Task(tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    next = transit.accept() => {
                        let (mut client, _) = next.unwrap();
                        let address = egress_address.clone();
                        tasks.spawn(async move {
                            let mut header = Vec::new();
                            while !header.ends_with(b"\r\n\r\n") {
                                assert!(header.len() < 8192);
                                header.push(client.read_u8().await.unwrap());
                            }
                            assert!(header.starts_with(format!("CONNECT {address} HTTP/1.1").as_bytes()));
                            let mut target = TcpStream::connect(address).await.unwrap();
                            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.unwrap();
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        }));
        let yaml = format!(r#"apiVersion: pathchord.io/v1
kind: Egress
metadata: {{name: exit}}
spec:
  host: 127.0.0.1
  port: {egress_port}
  publicKey: {public}
  capabilities: {{tcp: true, udp: true}}
  transit: {{}}
  trafficPolicyRef: default
---
apiVersion: pathchord.io/v1
kind: TransitProxy
metadata: {{name: relay}}
spec: {{protocol: http, host: 127.0.0.1, port: {transit_port}}}
---
apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata: {{name: default}}
spec: {{scheduler: effectiveCapacityWeighted}}
---
apiVersion: pathchord.io/v1
kind: EgressRule
metadata: {{name: egress-route}}
spec: {{order: 10, catchAll: true, egressRef: exit}}
---
apiVersion: pathchord.io/v1
kind: Listener
metadata: {{name: mixed}}
spec: {{type: mixed, bind: '127.0.0.1:{proxy_port}', protocols: [tcp, udp]}}
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
"#, public = egress_public["public_key"].as_str().unwrap());
        let config_path = directory.0.join("conf.d");
        std::fs::create_dir(&config_path).unwrap();
        for (index, document) in yaml.split("\n---\n").enumerate() {
            std::fs::write(config_path.join(format!("{index:02}.yaml")), document).unwrap();
        }
        std::fs::write(config_path.join("service.yaml"),
            "apiVersion: pathchord.io/v1\nkind: IngressService\nmetadata: {name: local}\nspec: {ingressId: entry, dataDir: ../data, credentialsDir: ../credentials, controlSocket: ../i.sock}\n"
        ).unwrap();
        let mut ingress = spawn(&["ingress", "--config-dir", config_path.to_str().unwrap(), "--identity", ingress_key.to_str().unwrap()], &directory.0);
        wait_for_socket(&ingress_socket, &mut ingress).await;
        assert_private_owner(&ingress_socket);
        assert_eq!(command_json(&["--config-dir", config_path.to_str().unwrap(), "get", "status"])["ok"], true);

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = Task(tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") { header.push(stream.read_u8().await.unwrap()); }
            assert!(header.starts_with(b"GET /smoke HTTP/1.1"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nready").await.unwrap();
        }));
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        client.write_all(format!("GET http://{origin_address}/smoke HTTP/1.1\r\nHost: {origin_address}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"ready"));

        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let udp_task = Task(tokio::spawn(async move {
            let mut data = [0; 128];
            let (count, peer) = target.recv_from(&mut data).await.unwrap();
            target.send_to(&data[..count], peer).await.unwrap();
        }));
        let mut control = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2]; control.read_exact(&mut method).await.unwrap(); assert_eq!(method, [5, 0]);
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut relay = [0; 10]; control.read_exact(&mut relay).await.unwrap(); assert_eq!(&relay[..4], &[5, 0, 0, 1]);
        let relay = std::net::SocketAddr::from(([relay[4], relay[5], relay[6], relay[7]], u16::from_be_bytes([relay[8], relay[9]])));
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1]; packet.extend_from_slice(&target_address.port().to_be_bytes()); packet.extend_from_slice(b"datagram");
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap(); udp.send_to(&packet, relay).await.unwrap();
        let mut data = [0; 128]; let (count, _) = udp.recv_from(&mut data).await.unwrap(); assert_eq!(&data[..count], packet);
        drop(control);
        let replacement = std::fs::read_to_string(&egress_config).unwrap()
            .replace(&format!("127.0.0.1:{egress_port}"), "127.0.0.1:7444");
        std::fs::write(&egress_config, replacement).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let status = command_json(&["--socket", egress_socket.to_str().unwrap(), "get", "status"]);
            assert_eq!(status["result"]["runtime"]["running"], true);
            if status["result"]["runtime"]["configuration"]["state"] == "restart_required" {
                break;
            }
            assert!(Instant::now() < deadline, "Egress did not report a restart requirement: {status}");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        for process in [&mut ingress, &mut egress] {
            assert!(Command::new("kill").args(["-TERM", &process.0.id().to_string()]).status().unwrap().success());
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    assert!(status.success(), "service must complete graceful SIGTERM shutdown: {status}");
                    break;
                }
                assert!(Instant::now() < deadline, "service shutdown timed out");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        assert!(!ingress_socket.exists());
        assert!(!egress_socket.exists());
        drop(transit_task); drop(origin_task); drop(udp_task);
    }).await.expect("bounded two-process CLI smoke test");
}
