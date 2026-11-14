# Design

## Context

The existing runtime has portable listener regressions and Windows/FreeBSD target build checks. Native forwarding and host integration remain unverified. See [status](../../implementation-status.md) and the [platform contract](../../specs/platform-and-dns/spec.md).

## Goals / non-goals

Gather reproducible host evidence for existing contracts. Additional FreeBSD transparent interception/TUN support needs its own assessment; do not imply it is enabled by this validation. Wintun distribution remains a separate packaging concern.

## Decisions

Run ordinary listeners before privileged routing/device work. Use this matrix and record host OS, architecture, revision, commands, and results without credentials:

| Platform | Explicit listeners | Local control | Host checks |
| --- | --- | --- | --- |
| Linux | HTTP, SOCKS, Mixed | Unix socket | Cross-machine forwarding; privileged transparent/TUN and optional eBPF smoke. |
| Windows | HTTP, SOCKS, Mixed | Named Pipe | Forwarding, ACLs, watcher, WinINet refresh and system-proxy crash recovery. |
| FreeBSD | HTTP, SOCKS, Mixed | Unix socket | Forwarding, native dependencies, SQLite/socket permissions, watcher and signals. |

For each platform cover authentication, source restrictions, IPv4/IPv6 and domain targets, DNS, bounded TCP/UDP resources, reload, shutdown, and management. Linux route tests must establish rule/table ownership and cleanup; fake devices alone do not qualify. The [dae/eBPF investigation](research/dae-ebpf-transparent-proxy.md) supplies staged kernel checks for the optional backend.

## Risks / trade-offs

- Privileged routing can affect the host → use an isolated test host/network namespace, capture prior state, and verify restoration.
- A successful target build can obscure missing host evidence → record each evidence class separately in status.
