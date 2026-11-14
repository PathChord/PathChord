# PathChord deployment and local operation

**English** | [简体中文](spec.zh-CN.md)

## Purpose

Define service startup, configuration selection, platform prerequisites, explicit identity enrollment, private credentials, protected management, and shutdown behavior for Ingress and Egress.

For setup commands and examples, see the [deployment usage guide](../../../docs/guides/deployment.md).

## Requirements

### Requirement: Independent service processes and explicit proxy operation

Ingress and Egress SHALL run as separate service invocations, each owning its process and local management endpoint. Ordinary explicit HTTP/SOCKS proxy operation SHALL NOT require packet interception or TUN privileges. Listener protocol behavior SHALL follow the [platform contract](../platform-and-dns/spec.md#http-and-socks-listeners).

#### Scenario: Ordinary local proxy setup

- **WHEN** the supplied direct-routing Mixed listener example is used
- **THEN** the listener serves HTTP and SOCKS on `127.0.0.1:7890`, restricted to loopback, without requiring packet interception or TUN privileges.

#### Scenario: Unix local control endpoint defaults

- **WHEN** a regular Unix account starts Ingress without an explicit control socket
- **THEN** the endpoint is `$XDG_RUNTIME_DIR/pathchord/ingress.sock` when that runtime directory is available, otherwise `~/.config/pathchord/ingress.sock`; root and packaged service accounts use `/run/pathchord/ingress.sock` with the runtime directory created before startup.

#### Scenario: Explicit enrollment socket selection

- **WHEN** the enrollment client selects a control endpoint
- **THEN** it defaults to the corresponding local `egress.sock` endpoint and an explicitly supplied socket takes precedence; the endpoint belongs to the Egress service machine.

### Requirement: Explicit configuration-source precedence

Ingress SHALL follow the [configuration source contract](../configuration-schema/spec.md#configuration-sources), selecting command line before environment variables and account defaults. Recursive YAML/YML/JSON files SHALL form one validated resource graph; reload SHALL replace the complete valid graph atomically and retain the old graph on failure. Private credentials, key JSON, and service data SHALL remain outside that resource tree.

#### Scenario: Command line overrides the environment

- **WHEN** `PATHCHORD_CONFIG_DIR` is set and Ingress is started with an explicit `--config` file
- **THEN** the command-line file is the selected configuration source.

#### Scenario: Account configuration defaults

- **WHEN** neither a command-line source nor a configuration environment variable is selected
- **THEN** Ingress loads `~/.config/pathchord` for a regular account or `/etc/pathchord` for root and service accounts.

#### Scenario: Source options conflict

- **WHEN** both `--config`/`-c` and `--config-dir`/`-C` are supplied, or more than one non-empty configuration environment variable is set without a command-line source
- **THEN** source selection fails rather than merging competing configuration sources.

#### Scenario: Reload candidate is invalid

- **WHEN** a changed resource tree does not form a valid complete resource graph
- **THEN** the running service retains the previous graph.

### Requirement: Privileged setup preserves routing ownership

Transparent and TUN operation SHALL follow the [platform contract](../platform-and-dns/spec.md), requiring privileges to create sockets/devices and manage owned routes. Administrator packet-filter rules and host routes SHALL remain distinct from PathChord's journaled policy routes; cleanup SHALL remove only objects still matching the journal. Protected endpoints SHALL bypass interception, and FreeBSD SHALL reject transparent and TUN listeners.

#### Scenario: Transparent route no longer matches its journal

- **WHEN** a policy-routing object no longer matches PathChord's ownership journal during cleanup
- **THEN** PathChord does not remove that object.

#### Scenario: Administrator configures transparent packet delivery

- **WHEN** administrator-owned packet-filter rules send traffic to a Linux TPROXY listener
- **THEN** those rules use the listener's bind address, mark, and policy-routing table; the service requires root or equivalent transparent-socket and network-administration capabilities such as `CAP_NET_ADMIN` and `CAP_NET_RAW`.

#### Scenario: Optional eBPF backend prerequisites

- **WHEN** a Linux listener selects `backend: ebpf`
- **THEN** the build requires `clang`, and operation requires `bpftool`, `tc`, BPF/BTF kernel support, network-administration privileges, an explicitly selected ingress interface, and `allowedSources`; the ordinary TPROXY backend remains an explicit alternative for hosts without those capabilities.

### Requirement: Explicit identities and Egress enrollment

Each service SHALL retain its private identity locally, and key generation SHALL print only the public key. Egress enrollment SHALL bind the Ingress public key, canonical Egress identity, and expected authorization generation. Cross-machine operation SHALL use a reachable Egress address with the explicitly verified key and canonical Egress ID. Changing the Transit transport SHALL preserve end-to-end Noise and enrollment semantics.

#### Scenario: Enrollment after the initial authorization generation

- **WHEN** an operator mutates an authorization database after its initial generation
- **THEN** enrollment uses the observed generation rather than assuming generation 0.

#### Scenario: UDP capability follows the selected route

- **WHEN** UDP uses an authenticated Egress route
- **THEN** it requires the Egress UDP capability and a TCP Transit Path; ordinary third-party UDP routing additionally requires native UDP support from the selected node, as defined by the [Transit adapter contract](../transit-proxies/spec.md#udp-routing-boundaries).

### Requirement: Private credentials and protected service lifecycle

Listener and node secrets SHALL be private JSON documents in `--credentials-dir`, named by opaque `credentialsRef` values, and SHALL NOT be committed. Local control SHALL use Unix ownership/permissions or Windows Named Pipe ACLs. The opt-in Web Gateway SHALL share the [control service](../ingress-control-plane/spec.md) authentication and capability boundary. Services SHALL own task/connection cleanup and report restart-required startup-only changes during reload.

#### Scenario: Required listener credentials meet SOCKS4

- **WHEN** a listener requires a Basic or SOCKS5 credential document containing `username` and `password`, and a client attempts SOCKS4 or SOCKS4a
- **THEN** the listener refuses the connection rather than bypassing required credentials.

#### Scenario: Prometheus retains management authorization

- **WHEN** `/metrics` is requested through the explicitly enabled Web Gateway
- **THEN** the request uses the same bearer authentication, Origin checks, and `metrics:read` capability as management metric queries; a configured `--web-token-file` supplies the bearer token.

#### Scenario: Service shutdown

- **WHEN** a service receives Ctrl-C or, on Unix, SIGTERM
- **THEN** it shuts down its owned tasks and connections.

#### Scenario: Startup-only configuration change

- **WHEN** reload reports that an identity, listener topology, or other startup-only change requires a restart
- **THEN** a service restart is required to apply that change; persistent configuration changes otherwise follow the reload contract.
