# Spec Delta

## MODIFIED Requirements

### Requirement: Whole-bundle identities and references

Ingress SHALL validate the complete resource graph across all source files,
resolve references by namespace, kind, and name, and reject duplicate
identities without last-file-wins semantics. A complete Ingress configuration
SHALL contain exactly one DNSPolicy and one FallbackPolicy. Egress SHALL use
the role-specific Egress source contract defined below rather than requiring the
Ingress resource graph.

#### Scenario: Duplicate resources are split between files

- **WHEN** two files in a configuration directory declare the same `(namespace, kind, metadata.name)` identity
- **THEN** the complete candidate bundle is rejected rather than selecting the later filename

#### Scenario: Egress does not require Ingress-only resources

- **WHEN** an Egress source contains one valid `EgressService` and no
  `DNSPolicy`, `FallbackPolicy`, Listener, or routing resources
- **THEN** Egress validates and starts from that service source without
  fabricating or requiring Ingress policy resources.

## ADDED Requirements

### Requirement: Role-specific Egress configuration source

An Egress configuration source SHALL contain exactly one `EgressService` in a
single resource file or directory tree and SHALL reject Ingress-only resource
kinds instead of loading the complete Ingress policy graph. The source SHALL
retain the existing `EgressService` field validation, private-path rules, and
namespace identity semantics.

#### Scenario: Egress loads a service-only source

- **WHEN** an Egress source contains exactly one valid `EgressService`
- **THEN** Egress accepts its bind, identity, authorization database, control
  socket, resource limits, DNS mode, and optional Web Gateway settings without
  requiring any Ingress resource.

#### Scenario: Egress source contains an Ingress resource

- **WHEN** an Egress source contains a Listener, TransitProxy, Subscription,
  EgressRule, ProxyRule, DNSPolicy, FallbackPolicy, or geodata resource
- **THEN** source validation fails with a typed diagnostic identifying that the
  resource is outside the Egress configuration contract.

#### Scenario: Egress source contains zero or multiple services

- **WHEN** an Egress source contains no `EgressService`, or contains more than
  one `EgressService` identity in the selected source
- **THEN** Egress refuses startup and does not open its Path listener or mutate
  its authorization database.

#### Scenario: Egress private paths remain outside the resource tree

- **WHEN** an `EgressService` references identity, authorization database,
  control socket, or bearer-token paths
- **THEN** relative paths resolve from the selected Egress source directory,
  private files remain outside the resource documents, and the service applies
  its existing ownership and permission checks before startup.

### Requirement: Egress source precedence and restart boundary

Egress SHALL select an explicit command-line resource source before
`PATHCHORD_CONFIG` or `PATHCHORD_CONFIG_DIR`, then the account default. CLI
field overrides SHALL take precedence over the selected `EgressService`, and
changes to identity, listener bind, authorization storage, control endpoint, or
other startup-only service fields SHALL require an Egress restart.

#### Scenario: Egress command-line source overrides the environment

- **WHEN** both an Egress configuration environment variable and an explicit
  `--config` or `--config-dir` source are supplied
- **THEN** Egress loads only the explicit source and does not merge the
  environment source into it.

#### Scenario: Egress source fails validation

- **WHEN** the selected Egress source is unreadable, malformed, or violates
  the role-specific resource contract
- **THEN** Egress reports a typed configuration failure before binding its
  public Path listener and retains any existing service state.

#### Scenario: Egress startup configuration changes

- **WHEN** a subsequent Egress source changes identity, bind address,
  authorization database, control socket, or another startup-only field
- **THEN** the service reports restart required and does not partially apply the
  changed service configuration to an active runtime.
