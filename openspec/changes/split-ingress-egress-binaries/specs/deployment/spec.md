# Spec Delta

## MODIFIED Requirements

### Requirement: Independent service processes and explicit proxy operation

Ingress and Egress SHALL run as separate service invocations, each using a
dedicated role executable, owning its process, and exposing its local
management endpoint. Ordinary explicit HTTP/SOCKS proxy operation SHALL NOT
require packet interception or TUN privileges. Listener protocol behavior
SHALL follow the [platform contract](../platform-and-dns/spec.md#http-and-socks-listeners).

#### Scenario: Dedicated service executable selection

- **WHEN** a packaged Ingress or Egress service starts
- **THEN** the service invokes its role-specific executable directly and does
  not select the service role through a shared multi-call service subcommand.

#### Scenario: Ordinary local proxy setup

- **WHEN** the supplied direct-routing Mixed listener example is used
- **THEN** the listener serves HTTP and SOCKS on `127.0.0.1:7890`, restricted to loopback, without requiring packet interception or TUN privileges.

#### Scenario: Unix local control endpoint defaults

- **WHEN** a regular Unix account starts Ingress without an explicit control socket
- **THEN** the endpoint is `$XDG_RUNTIME_DIR/pathchord/ingress.sock` when that runtime directory is available, otherwise `~/.config/pathchord/ingress.sock`; root and packaged service accounts use `/run/pathchord/ingress.sock` with the runtime directory created before startup.

#### Scenario: Explicit enrollment socket selection

- **WHEN** the enrollment client selects a control endpoint
- **THEN** it defaults to the corresponding local `egress.sock` endpoint and an explicitly supplied socket takes precedence; the endpoint belongs to the Egress service machine.

## ADDED Requirements

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

#### Scenario: Ingress-only platform configuration is isolated

- **WHEN** an operator inspects or starts the Egress service package
- **THEN** the package exposes no Egress listener for HTTP, SOCKS, TUN,
  TPROXY, REDIRECT, or eBPF configuration and does not require the files,
  devices, or privileges used only by those Ingress modes.

### Requirement: Dedicated management client

Role service executables SHALL not be the management command dispatcher. A
dedicated management client SHALL send the existing versioned local control
envelopes to the selected Ingress or Egress endpoint and SHALL preserve the
authorization, generation, redaction, and enrollment semantics of the control
plane.

#### Scenario: Query an Ingress service

- **WHEN** an operator invokes the management client for Ingress status
- **THEN** the client connects to the selected Ingress control endpoint and
  returns the structured status response without starting an Ingress service.

#### Scenario: Mutate Egress authorization

- **WHEN** an operator invokes enrollment or authorization management with the
  Egress control endpoint
- **THEN** the client sends the request to Egress, preserves the expected
  authorization generation, and returns the typed response and cleanup result.

### Requirement: Role-specific service state and privilege roots

Ingress and Egress SHALL use separate service data, private identity, control
socket, and credential access roots. A service SHALL have access only to the
role-owned roots required by its configured runtime and SHALL retain the
existing prohibition on committing private credentials.

#### Scenario: Egress service starts with its own state roots

- **WHEN** the Egress service starts from its packaged configuration
- **THEN** its identity, authorization database, control socket, and runtime
  state resolve under the Egress-owned paths and it does not create or mutate
  Ingress listener, subscription, or interception state.

#### Scenario: Role roots are permission-restricted

- **WHEN** a service package prepares its configuration and state directories
- **THEN** the directories and private files use ownership and permissions that
  prevent the other role and unprivileged local actors from reading private
  identity, authorization, credential, or bearer-token data.
