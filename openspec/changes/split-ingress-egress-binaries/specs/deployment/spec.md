# Spec Delta

## MODIFIED Requirements

### Requirement: Independent service processes and explicit proxy operation

Ingress and Egress SHALL run as separate service invocations, each using its dedicated role executable, owning its process, and exposing its local management endpoint. `pathchordctl` SHALL be the management client for both endpoints. Ordinary explicit HTTP/SOCKS proxy operation SHALL NOT require packet interception or TUN privileges. Listener protocol behavior SHALL follow the [platform contract](../../../../specs/platform-and-dns/spec.md#http-and-socks-listeners).

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

## ADDED Requirements

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
