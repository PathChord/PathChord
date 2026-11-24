//! Optional, fail-closed process metadata discovery for accepted sockets.

use std::net::SocketAddr;

use async_trait::async_trait;
use pathchord_policy::{ProcessMetadata, ProcessMetadataRequest};

/// The accepted socket endpoints used for a best-effort process lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessSocketTuple {
    pub source: SocketAddr,
    pub local: SocketAddr,
}

/// Resolves only the listener-requested process facts. `None` means unknown or
/// unavailable and must not be interpreted as an implicit policy match.
#[async_trait]
pub trait ProcessMetadataProvider: std::fmt::Debug + Send + Sync {
    async fn lookup(
        &self,
        socket: ProcessSocketTuple,
        request: ProcessMetadataRequest,
    ) -> Option<ProcessMetadata>;
}

/// Default provider for callers that do not opt into platform discovery.
#[derive(Debug, Default)]
pub struct NoopProcessMetadataProvider;

#[async_trait]
impl ProcessMetadataProvider for NoopProcessMetadataProvider {
    async fn lookup(
        &self,
        _socket: ProcessSocketTuple,
        _request: ProcessMetadataRequest,
    ) -> Option<ProcessMetadata> {
        None
    }
}

/// Explicit provider for platforms where safe process discovery is not
/// available. It reports unknown metadata rather than fabricating a result.
#[derive(Debug, Default)]
pub struct UnavailableProcessMetadataProvider;

#[async_trait]
impl ProcessMetadataProvider for UnavailableProcessMetadataProvider {
    async fn lookup(
        &self,
        _socket: ProcessSocketTuple,
        _request: ProcessMetadataRequest,
    ) -> Option<ProcessMetadata> {
        None
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File};
    use std::io::{self, Read};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::{Path, PathBuf};

    use async_trait::async_trait;
    use pathchord_policy::{ProcessMetadata, ProcessMetadataRequest};

    use super::{ProcessMetadataProvider, ProcessSocketTuple};

    const MAX_PROC_NET_BYTES: usize = 4 * 1024 * 1024;
    const MAX_PROC_STATUS_BYTES: usize = 128 * 1024;
    const MAX_EXECUTABLE_PATH_BYTES: usize = 4096;
    const MAX_PROCESSES: usize = 65_536;
    const MAX_FDS_PER_PROCESS: usize = 65_536;

    /// Linux provider backed only by bounded, read-only procfs operations.
    #[derive(Default)]
    pub struct LinuxProcessMetadataProvider;

    impl std::fmt::Debug for LinuxProcessMetadataProvider {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("LinuxProcessMetadataProvider(..)")
        }
    }

    #[async_trait]
    impl ProcessMetadataProvider for LinuxProcessMetadataProvider {
        async fn lookup(
            &self,
            socket: ProcessSocketTuple,
            request: ProcessMetadataRequest,
        ) -> Option<ProcessMetadata> {
            if request.is_empty() {
                return None;
            }
            tokio::task::spawn_blocking(move || lookup(socket, request))
                .await
                .ok()
                .flatten()
        }
    }

    fn lookup(
        socket: ProcessSocketTuple,
        request: ProcessMetadataRequest,
    ) -> Option<ProcessMetadata> {
        let inode = find_socket_inode(socket)?;
        let process_id = find_process_id(inode)?;
        let root = PathBuf::from("/proc").join(process_id.to_string());
        let executable = request.executable.then(|| read_executable(&root)).flatten();
        let status = (request.user || request.group)
            .then(|| read_bounded(&root.join("status"), MAX_PROC_STATUS_BYTES).ok())
            .flatten();
        let user_id = request
            .user
            .then(|| status.as_deref().and_then(|value| status_id(value, "Uid:")))
            .flatten();
        let group_id = request
            .group
            .then(|| status.as_deref().and_then(|value| status_id(value, "Gid:")))
            .flatten();
        Some(ProcessMetadata {
            process_id: Some(process_id),
            executable,
            user_id,
            group_id,
        })
    }

    fn find_socket_inode(socket: ProcessSocketTuple) -> Option<u64> {
        ["/proc/net/tcp", "/proc/net/tcp6"]
            .into_iter()
            .filter_map(|path| read_bounded(Path::new(path), MAX_PROC_NET_BYTES).ok())
            .flat_map(|table| {
                table
                    .lines()
                    .filter_map(parse_socket_row)
                    .collect::<Vec<_>>()
            })
            .find_map(|(local, source, state, inode)| {
                (state == 1
                    && socket_addresses_equal(local, socket.local)
                    && socket_addresses_equal(source, socket.source))
                .then_some(inode)
            })
    }

    fn parse_socket_row(line: &str) -> Option<(SocketAddr, SocketAddr, u8, u64)> {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let local = parse_socket_address(fields.get(1)?)?;
        let source = parse_socket_address(fields.get(2)?)?;
        let state = u8::from_str_radix(fields.get(3)?, 16).ok()?;
        let inode = fields.get(9)?.parse::<u64>().ok()?;
        Some((local, source, state, inode))
    }

    fn parse_socket_address(value: &str) -> Option<SocketAddr> {
        let (address, port) = value.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let address = match address.len() {
            8 => {
                let value = u32::from_str_radix(address, 16).ok()?;
                IpAddr::V4(Ipv4Addr::from(value.to_le_bytes()))
            }
            32 => {
                let mut bytes = [0_u8; 16];
                for index in 0..4 {
                    let chunk = &address.as_bytes()[index * 8..(index + 1) * 8];
                    let chunk = std::str::from_utf8(chunk).ok()?;
                    let value = u32::from_str_radix(chunk, 16).ok()?;
                    bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => return None,
        };
        Some(SocketAddr::new(address, port))
    }

    fn socket_addresses_equal(left: SocketAddr, right: SocketAddr) -> bool {
        if left.port() != right.port() {
            return false;
        }
        if right.ip().is_unspecified() {
            return left.is_ipv4() == right.is_ipv4();
        }
        canonical_ip(left.ip()) == canonical_ip(right.ip())
    }

    fn canonical_ip(address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            address => address,
        }
    }

    fn find_process_id(inode: u64) -> Option<u32> {
        let current = std::process::id();
        if process_owns_inode(current, inode) {
            return Some(current);
        }
        let mut inspected = 0_usize;
        for entry in fs::read_dir("/proc").ok()?.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(process_id) = name.parse::<u32>() else {
                continue;
            };
            if process_id == current {
                continue;
            }
            inspected = inspected.saturating_add(1);
            if inspected > MAX_PROCESSES {
                return None;
            }
            if process_owns_inode(process_id, inode) {
                return Some(process_id);
            }
        }
        None
    }

    fn process_owns_inode(process_id: u32, inode: u64) -> bool {
        let expected = format!("socket:[{inode}]");
        let directory = PathBuf::from("/proc")
            .join(process_id.to_string())
            .join("fd");
        let Ok(entries) = fs::read_dir(directory) else {
            return false;
        };
        for (index, entry) in entries.flatten().enumerate() {
            if index >= MAX_FDS_PER_PROCESS {
                return false;
            }
            if fs::read_link(entry.path())
                .ok()
                .and_then(|target| target.to_str().map(str::to_owned))
                .as_deref()
                == Some(expected.as_str())
            {
                return true;
            }
        }
        false
    }

    fn read_executable(root: &Path) -> Option<String> {
        let executable = fs::read_link(root.join("exe")).ok()?;
        let value = executable.to_str()?;
        (value.len() <= MAX_EXECUTABLE_PATH_BYTES).then(|| value.to_owned())
    }

    fn status_id(status: &str, key: &str) -> Option<u32> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))?
            .split_ascii_whitespace()
            .next()?
            .parse()
            .ok()
    }

    fn read_bounded(path: &Path, maximum: usize) -> io::Result<String> {
        let mut input = File::open(path)?.take(maximum.saturating_add(1) as u64);
        let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
        input.read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "procfs file exceeds lookup limit",
            ));
        }
        String::from_utf8(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "procfs file is not UTF-8"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use tokio::net::{TcpListener, TcpStream};

        #[test]
        fn parses_procfs_ipv4_and_ipv6_socket_addresses() {
            assert_eq!(
                parse_socket_address("0100007F:1F90"),
                Some("127.0.0.1:8080".parse().unwrap())
            );
            assert_eq!(
                parse_socket_address("00000000000000000000000001000000:0035"),
                Some("[::1]:53".parse().unwrap())
            );
        }

        #[test]
        fn wildcard_listener_matches_a_concrete_local_socket_in_the_same_family() {
            assert!(socket_addresses_equal(
                "127.0.0.1:8080".parse().unwrap(),
                "0.0.0.0:8080".parse().unwrap(),
            ));
            assert!(socket_addresses_equal(
                "[2001:db8::1]:8080".parse().unwrap(),
                "[::]:8080".parse().unwrap(),
            ));
            assert!(!socket_addresses_equal(
                "127.0.0.1:8080".parse().unwrap(),
                "[::]:8080".parse().unwrap(),
            ));
        }

        #[tokio::test]
        async fn loopback_tcp_reports_current_executable_and_numeric_identity() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
            let client = client.unwrap();
            let (server, source) = accepted.unwrap();
            let provider = LinuxProcessMetadataProvider;
            let expected = fs::read_link("/proc/self/exe")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let metadata = provider
                .lookup(
                    ProcessSocketTuple {
                        source,
                        local: server.local_addr().unwrap(),
                    },
                    ProcessMetadataRequest {
                        executable: true,
                        user: true,
                        group: true,
                    },
                )
                .await
                .expect("loopback socket process metadata");

            assert_eq!(metadata.process_id, Some(std::process::id()));
            assert_eq!(metadata.executable.as_deref(), Some(expected.as_str()));
            assert!(metadata.user_id.is_some());
            assert!(metadata.group_id.is_some());
            assert!(!format!("{provider:?}").contains(&expected));
            drop((client, server));
        }

        #[tokio::test]
        async fn missing_socket_and_empty_request_return_unknown() {
            let provider = LinuxProcessMetadataProvider;
            let missing = ProcessSocketTuple {
                source: "192.0.2.10:12345".parse().unwrap(),
                local: "198.51.100.20:54321".parse().unwrap(),
            };
            assert_eq!(
                provider
                    .lookup(
                        missing,
                        ProcessMetadataRequest {
                            executable: true,
                            user: false,
                            group: false,
                        },
                    )
                    .await,
                None
            );
            assert_eq!(
                provider
                    .lookup(missing, ProcessMetadataRequest::default())
                    .await,
                None
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxProcessMetadataProvider;

#[cfg(target_os = "linux")]
pub type SystemProcessMetadataProvider = LinuxProcessMetadataProvider;

#[cfg(not(target_os = "linux"))]
mod native_platform {
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    use async_trait::async_trait;
    use netsock::family::AddressFamilyFlags;
    use netsock::protocol::ProtocolFlags;
    use netsock::socket::ProtocolSocketInfo;
    use pathchord_policy::{ProcessMetadata, ProcessMetadataRequest};

    use super::{ProcessMetadataProvider, ProcessSocketTuple};

    const MAX_PROCESS_NAME_BYTES: usize = 4096;

    /// Non-Linux provider backed by `netsock`'s native socket and process APIs.
    /// It never invokes a shell or parses command output. User and group
    /// identifiers remain unknown when the platform API does not expose them
    /// to an unprivileged process.
    #[derive(Debug, Default)]
    pub struct NativeProcessMetadataProvider;

    #[async_trait]
    impl ProcessMetadataProvider for NativeProcessMetadataProvider {
        async fn lookup(
            &self,
            socket: ProcessSocketTuple,
            request: ProcessMetadataRequest,
        ) -> Option<ProcessMetadata> {
            if request.is_empty() {
                return None;
            }
            tokio::task::spawn_blocking(move || lookup(socket, request))
                .await
                .ok()
                .flatten()
        }
    }

    fn lookup(
        socket: ProcessSocketTuple,
        request: ProcessMetadataRequest,
    ) -> Option<ProcessMetadata> {
        let sockets = netsock::iter_sockets(
            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
            ProtocolFlags::TCP | ProtocolFlags::UDP,
        )
        .ok()?;
        let mut owners = BTreeMap::new();
        for info in sockets.flatten() {
            let matches = match &info.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                    addresses_equal(tcp.local_addr, socket.local.ip())
                        && tcp.local_port == socket.local.port()
                        && addresses_equal(tcp.remote_addr, socket.source.ip())
                        && tcp.remote_port == socket.source.port()
                }
                // A UDP socket has no peer in the native table. Only use it
                // when the local endpoint is unique; otherwise report unknown.
                ProtocolSocketInfo::Udp(udp) => {
                    addresses_equal(udp.local_addr, socket.local.ip())
                        && udp.local_port == socket.local.port()
                }
            };
            if matches {
                for process in info.processes {
                    owners.entry(process.pid).or_insert(process.name);
                }
            }
        }
        let (process_id, executable) = match owners.into_iter().collect::<Vec<_>>().as_slice() {
            [(pid, name)] => (
                Some(*pid),
                request.executable.then(|| {
                    name.chars()
                        .take(MAX_PROCESS_NAME_BYTES)
                        .collect::<String>()
                }),
            ),
            _ => (None, None),
        };
        process_id.map(|process_id| ProcessMetadata {
            process_id: Some(process_id),
            executable,
            user_id: None,
            group_id: None,
        })
    }

    fn addresses_equal(left: IpAddr, right: IpAddr) -> bool {
        if right.is_unspecified() {
            left.is_ipv4() == right.is_ipv4()
        } else {
            left == right
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use native_platform::NativeProcessMetadataProvider;

#[cfg(not(target_os = "linux"))]
pub type SystemProcessMetadataProvider = NativeProcessMetadataProvider;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "freebsd")]
    #[tokio::test]
    async fn native_lookup_reports_the_socket_owner_or_unknown_without_inventing_identity() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
        let _client = client.unwrap();
        let (stream, source) = accepted.unwrap();
        let request = ProcessMetadataRequest {
            executable: true,
            user: true,
            group: true,
        };
        let provider = SystemProcessMetadataProvider::default();
        let metadata = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            provider.lookup(
                ProcessSocketTuple {
                    local: stream.local_addr().unwrap(),
                    source,
                },
                request,
            ),
        )
        .await
        .expect("native socket ownership lookup is bounded");
        if let Some(metadata) = metadata {
            assert_eq!(metadata.process_id, Some(std::process::id()));
            assert!(
                metadata
                    .executable
                    .as_ref()
                    .is_some_and(|name| !name.is_empty() && name.len() <= 4096)
            );
            assert_eq!(metadata.user_id, None);
            assert_eq!(metadata.group_id, None);
        }
        let absent = provider
            .lookup(
                ProcessSocketTuple {
                    local: "127.0.0.1:0".parse().unwrap(),
                    source: "127.0.0.1:0".parse().unwrap(),
                },
                request,
            )
            .await;
        assert_eq!(absent, None);
    }

    #[tokio::test]
    async fn noop_provider_always_returns_unknown() {
        let provider = NoopProcessMetadataProvider;
        assert_eq!(
            provider
                .lookup(
                    ProcessSocketTuple {
                        source: "127.0.0.1:1".parse().unwrap(),
                        local: "127.0.0.1:2".parse().unwrap(),
                    },
                    ProcessMetadataRequest {
                        executable: true,
                        user: true,
                        group: true,
                    },
                )
                .await,
            None
        );
    }
}
