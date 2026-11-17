//! Test-only client for protocol peers running in a different QEMU guest.
//!
//! Input contains only generated fixture credentials. The output deliberately
//! contains protocol names and byte counts, never the credential document.

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use pathchord_policy::TransitProxyConfig;
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitCredential,
};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    node: TransitProxyConfig,
    credentials: BTreeMap<String, String>,
    targets: Vec<String>,
    tcp_port: u16,
    udp_port: u16,
    #[serde(default)]
    expect_unavailable: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("expected a probe JSON path")?;
    let input: Probe = serde_json::from_slice(&std::fs::read(path)?)?;
    let registry = AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(10),
        [&input.node],
    )?;
    let built =
        registry.build_with_credential(&input.node, &TransitCredential::new(input.credentials));
    if input.expect_unavailable {
        if built.is_ok() {
            return Err("unsupported fixture unexpectedly became available".into());
        }
        println!(
            "{}",
            serde_json::json!({"protocol": input.node.protocol, "unavailable": true})
        );
        return Ok(());
    }
    let adapter = built?;
    timeout(Duration::from_secs(15), adapter.prepare()).await??;
    let mut tcp_bytes = 0_usize;
    let mut udp_bytes = 0_usize;
    for host in &input.targets {
        let mut stream = timeout(
            Duration::from_secs(15),
            adapter.connect(ConnectRequest {
                destination: Endpoint {
                    host: host.clone(),
                    port: input.tcp_port,
                },
            }),
        )
        .await??;
        // Concurrent read/write avoids filling either direction's TCP window.
        let (mut read, mut write) = tokio::io::split(&mut stream);
        let payload: Vec<u8> = (0..131_071).map(|n| (n % 251) as u8).collect();
        let mut echoed = vec![0; payload.len()];
        timeout(Duration::from_secs(30), async {
            tokio::try_join!(
                async {
                    write.write_all(&payload).await?;
                    write.flush().await
                },
                read.read_exact(&mut echoed)
            )?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| format!("{} TCP {host} round trip timed out", input.node.protocol))??;
        if echoed != payload {
            return Err("cross-machine TCP payload differs".into());
        }
        tcp_bytes += payload.len();
        drop(stream);
        let mut datagram = timeout(
            Duration::from_secs(15),
            adapter.connect_udp(ConnectRequest {
                destination: Endpoint {
                    host: host.clone(),
                    port: input.udp_port,
                },
            }),
        )
        .await??;
        for size in [1, 53, 1200, 4096, 4096] {
            let payload: Vec<u8> = (0..size).map(|n| ((n + size) % 251) as u8).collect();
            timeout(Duration::from_secs(10), datagram.send(&payload)).await??;
            let echoed = timeout(Duration::from_secs(10), datagram.receive()).await??;
            if echoed != payload {
                return Err("cross-machine UDP payload differs".into());
            }
            udp_bytes += payload.len();
        }
        timeout(Duration::from_secs(10), datagram.close()).await??;
    }
    println!(
        "{}",
        serde_json::json!({
            "protocol": input.node.protocol,
            "tcp_bytes": tcp_bytes, "udp_bytes": udp_bytes,
            "targets": input.targets, "ok": true,
        })
    );
    Ok(())
}
