# Spec Delta

## MODIFIED Requirements

### Requirement: Egress source precedence and restart boundary

Egress SHALL select an explicit command-line resource source before
`PATHCHORD_CONFIG` or `PATHCHORD_CONFIG_DIR`, then the account default. `EgressService` fields SHALL take precedence over role defaults. Explicit
control socket and temporary identity overrides SHALL take precedence over
resource values. Changes to identity, listener bind, authorization storage, control endpoint, or
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

## ADDED Requirements

### Requirement: Role startup settings in the selected source

The selected source SHALL support authoring startup settings for either role.
Private values SHALL remain in separate files. Omitted private paths SHALL
resolve from the role's directory layout.

#### Scenario: Ingress startup settings are authored with its policy graph

- **WHEN** the selected Ingress bundle declares its service settings
- **THEN** the daemon resolves its identity, state and credential directories,
  control socket, and Web Gateway settings alongside the complete policy graph.

#### Scenario: Minimal Egress resource uses role defaults

- **WHEN** an EgressService declares its name and Path listener and omits
  identity and private paths
- **THEN** the service uses the resource name as its default Egress ID and
  resolves the identity, authorization database, and control socket paths
  from role defaults.
