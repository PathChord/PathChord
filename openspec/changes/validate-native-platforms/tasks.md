# Tasks

These pending tasks were carried over from the implementation plan during the
2026-11-14 documentation migration; their presence supplies no completion evidence.

## 1. Windows hosts

- [ ] 1.1 Run native HTTP/CONNECT, SOCKS4/4a/5, Mixed and SOCKS5 UDP tests across authentication, source restrictions, IPv4/IPv6/domain targets, DNS, bounded resources, reload and shutdown; retain commands and results from the Windows host.
- [ ] 1.2 Exercise Named Pipe ACLs, configuration watching, and local management under service and regular-user identities; verify unauthorized access is rejected and accepted changes become visible.
- [ ] 1.3 Exercise WinINet refresh, exact previous-value restoration, and crash/journal recovery for the system-proxy switch; verify restored host settings after shutdown and restart.

## 2. FreeBSD hosts

- [ ] 2.1 Build and run native listener/control tests on FreeBSD, covering HTTP/CONNECT, SOCKS4/4a/5, Mixed, UDP, DNS, authentication, source restrictions and IPv4/IPv6; record execution evidence separately from target linking.
- [ ] 2.2 Verify native dependencies, SQLite and credential/socket permissions, process-metadata fallback, configuration watching, signals, bounded resources and shutdown under the intended service account; retain host results.

## 3. Privileged Linux and evidence

- [ ] 3.1 Run root-level TPROXY/REDIRECT TCP/UDP and real /dev/net/tun IPv4/IPv6 smoke tests; verify protected destinations, owned rules/tables, rollback, restart cleanup and route-journal recovery.
- [ ] 3.2 Run the optional eBPF TC backend checks from the research note on a supported kernel/interface; verify mark ownership, TCP/UDP IPv4/IPv6 forwarding and cleanup while preserving ordinary TPROXY fallback and the TUN contract.
- [ ] 3.3 Record host versions, architectures, repository revisions, commands, outcomes and unresolved failures in openspec/implementation-status.md; verify no target-build or fake-device result is presented as native runtime evidence.
