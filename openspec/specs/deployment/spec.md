# PathChord deployment and local operation

**English** | [简体中文](spec.zh-CN.md)

## Purpose

Define service startup, configuration selection, platform prerequisites, explicit identity enrollment, private credentials, protected management, and shutdown behavior for Ingress and Egress.

For setup commands and examples, see the [deployment usage guide](../../../docs/guides/deployment.md).

## Requirements

### Requirement: Independent service processes and explicit proxy operation

Ingress and Egress SHALL run as separate service invocations, each using its dedicated role executable, owning its process, and exposing its local management endpoint. `pathchordctl` SHALL be the management client for both endpoints. Ordinary explicit HTTP/SOCKS proxy operation SHALL NOT require packet interception or TUN privileges. Listener protocol behavior SHALL follow the [platform contract](../platform-and-dns/spec.md#http-and-socks-listeners).

#### Scenario: Dedicated service executable selection

- **WHEN** a packaged Ingress or Egress service starts
- **THEN** it invokes `pathchord-ingressd` or `pathchord-egressd` directly and does not select the role through a shared service subcommand.

#### Scenario: Ordinary local proxy setup

- **WHEN** the supplied direct-routing Mixed listener example is used
- **THEN** the listener serves HTTP and SOCKS on `127.0.0.1:7890`, restricted to loopback, without requiring packet interception or TUN privileges.

#### Scenario: Unix local control endpoint defaults

- **WHEN** a regular Unix account starts Ingress without an explicit control socket
- **THEN** the endpoint is `$XDG_RUNTIME_DIR/pathchord/ingress.sock` when that runtime directory is available, otherwise `~/.config/pathchord/ingress.sock`; root and packaged service accounts use `/run/pathchord/ingress.sock` with the runtime directory created before startup. Ingress resources default to `~/.config/pathchord/ingress` or `/etc/pathchord/ingress`.

#### Scenario: Explicit enrollment socket selection

- **WHEN** the enrollment client selects a control endpoint
- **THEN** `pathchordctl enroll` defaults to the corresponding local `egress.sock` endpoint and an explicitly supplied socket takes precedence; the endpoint belongs to the Egress service machine. Egress resources default to `~/.config/pathchord/egress` or `/etc/pathchord/egress`.

### Requirement: Role-specific service artifact boundaries

The Ingress service executable SHALL contain the local listener, Transit Proxy,
subscription, DNS, and transparent/TUN platform behavior it advertises. The
Egress service executable SHALL provide authenticated Path/Session forwarding,
TCP/UDP target connections, authorization, and global resource protection
without requiring Ingress listener, Transit Proxy, subscription, TUN, or eBPF
runtime components.

#### Scenario: Egress starts without Ingress platform privileges

- **WHEN** Egress starts on a host without TUN access and without
  `CAP_NET_ADMIN` or `CAP_NET_RAW`
- **THEN** it can bind its configured Path listener, open its authorization
  store, and admit an explicitly enrolled Ingress Session when ordinary target
  forwarding prerequisites are available.

#### Scenario: Dedicated management client

- **WHEN** an operator invokes `pathchordctl` for status or enrollment
- **THEN** the client connects to the selected local control endpoint without
  starting either service executable and preserves the versioned control
  envelope and generation checks.

### Requirement: Single-role package deployment

Each packaged installation SHALL select exactly one service role and install only its daemon, `pathchordctl`, configuration, and service definitions. Unix packages SHALL use the local non-login `pathchord` account. Opposite-role packages SHALL be mutually exclusive. Role replacement SHALL be explicit, and package lifecycle operations SHALL preserve operator-owned configuration, identities, and authorization data.

#### Scenario: Selected role package payload

- **WHEN** an operator installs an Ingress or Egress role package
- **THEN** it supplies the selected daemon, `pathchordctl`, configuration and service, and contains no daemon, default configuration, or service definition for the other role.

#### Scenario: Opposite role package conflict

- **WHEN** a role package is installed and an operator attempts to install the opposite role
- **THEN** installation is rejected before changing service registration, configuration, private state, or control endpoints; changing roles requires explicit removal and replacement.

#### Scenario: Single-role Unix service identity

- **WHEN** a Unix role package prepares its service identity and private paths
- **THEN** the selected service runs as the local non-login `pathchord` account, only its role directories are created, and private files and control endpoints reject unauthorized local access.

#### Scenario: Role package lifecycle preserves private state

- **WHEN** the selected role package is upgraded, rolled back, or removed
- **THEN** operator configuration, identities and authorization data are retained, the other role is not implicitly enabled, and retained identity data is not automatically reused as another role's identity.

### Requirement: Explicit configuration-source precedence

Ingress SHALL follow the [configuration source contract](../configuration-schema/spec.md#configuration-sources), selecting command line before environment variables and account defaults. Recursive YAML/YML/JSON files SHALL form one validated resource graph; reload SHALL replace the complete valid graph atomically and retain the old graph on failure. Private credentials, key JSON, and service data SHALL remain outside that resource tree.

#### Scenario: Command line overrides the environment

- **WHEN** `PATHCHORD_CONFIG_DIR` is set and Ingress is started with an explicit `--config` file
- **THEN** the command-line file is the selected configuration source.

#### Scenario: Account configuration defaults

- **WHEN** neither a command-line source nor a configuration environment variable is selected
- **THEN** Ingress loads `~/.config/pathchord/ingress` for a regular account or `/etc/pathchord/ingress` for packaged service accounts, while Egress uses the corresponding `egress` directory.

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
