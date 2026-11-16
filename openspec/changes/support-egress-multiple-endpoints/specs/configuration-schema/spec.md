# Spec Delta

## MODIFIED Requirements

### Requirement: Atomic publication and resilient watching

The complete candidate SHALL pass parsing, validation, normalization, compilation, and required persistence before one immutable generation is published. Invalid candidates SHALL retain the last good bundle; atomic file and root-directory replacement SHALL preserve watching. Changes to an Egress endpoint set, common admission minimum, referenced policy, or resolved policy contents SHALL report restart required and retain the active bundle.

#### Scenario: Atomic replacement contains an invalid candidate

- **WHEN** a watched configuration file is atomically replaced by an invalid resource candidate
- **THEN** the last good bundle remains active and watching continues for subsequent valid replacements

#### Scenario: A referenced policy changes without changing its name

- **WHEN** a reload changes the contents of a TrafficPolicy referenced by an Egress while retaining the same reference name
- **THEN** Ingress reports restart required and retains the active configuration and Session policy snapshots

#### Scenario: Only Transit membership changes

- **WHEN** a subscription or authorized administrator-metadata update changes nodes under an unchanged Egress binding
- **THEN** Ingress publishes the valid dynamic generation and drains removed candidates without requiring a new Egress policy snapshot

#### Scenario: Egress endpoint topology changes

- **WHEN** a candidate adds, removes, reorders, or changes an Egress endpoint or an EgressService bind
- **THEN** the candidate is validated as a complete snapshot, the active runtime remains unchanged, and the reload result reports restart required

## ADDED Requirements

### Requirement: Egress service supports one identity across multiple binds

An EgressService SHALL accept a bounded non-empty normalized list of public Path listener binds. Every bind in one service SHALL use the same Egress ID, private identity, authorization store, and global resource limits.

#### Scenario: Multiple address families use one Egress identity

- **WHEN** an EgressService declares valid IPv4 and IPv6 binds, including different ports
- **THEN** one Egress runtime exposes both listeners and authenticates Paths under the same Egress identity and authorization generation

#### Scenario: Duplicate listener binds are declared

- **WHEN** an EgressService declares the same address and port more than once after normalization
- **THEN** validation rejects the candidate with a field-specific duplicate-bind error

#### Scenario: One listener cannot be bound

- **WHEN** any configured bind cannot be opened during Egress startup or restart
- **THEN** the service does not publish a partial listener set and reports a typed startup failure

### Requirement: Egress service bind forms normalize deterministically

The EgressService schema SHALL accept the existing singular `bind` as a one-element shorthand and a plural `binds` list for multiple listeners. Supplying both forms SHALL be rejected; the normalized form SHALL preserve declared order and contain no duplicate SocketAddr values.

#### Scenario: Existing singular bind is loaded

- **WHEN** an EgressService supplies only `bind`
- **THEN** validation produces the equivalent one-element normalized bind list

#### Scenario: Singular and plural binds conflict

- **WHEN** an EgressService supplies both `bind` and `binds`
- **THEN** validation rejects the resource instead of choosing one form by precedence

### Requirement: Ingress Egress supports bounded endpoint candidates

An Ingress-side Egress SHALL contain a bounded non-empty ordered endpoint list. Each endpoint SHALL contain a valid hostname or IP literal and a port in `1..=65535`; endpoints may use different address families, hostnames, and ports.

#### Scenario: IPv4, IPv6, and named endpoints are configured

- **WHEN** one Egress declares valid candidates for an IPv4 address, an IPv6 address, and a hostname with independently configured ports
- **THEN** the normalized policy retains all candidates under the same Egress resource identity and public key

#### Scenario: An endpoint has an invalid host or port

- **WHEN** an endpoint has an empty/invalid host or a zero/out-of-range port
- **THEN** complete-bundle validation rejects the Egress and retains the previous published snapshot

#### Scenario: Endpoint candidates are duplicated

- **WHEN** two candidates normalize to the same host and port
- **THEN** validation rejects the Egress with a duplicate-endpoint diagnostic

### Requirement: Ingress Egress endpoint forms normalize without changing identity

The Egress schema SHALL accept the existing `address` and `port` pair as a one-element endpoint shorthand and a plural `endpoints` list. Supplying both forms SHALL be rejected, and endpoint normalization SHALL not change the Egress resource name, Egress ID, or public-key binding.

#### Scenario: Existing address and port are loaded

- **WHEN** an Egress supplies only `address` and `port`
- **THEN** validation produces the equivalent one-element normalized endpoint list and preserves existing routing identity

#### Scenario: Singular and plural endpoint forms conflict

- **WHEN** an Egress supplies `address`/`port` together with `endpoints`
- **THEN** validation rejects the resource instead of silently merging or selecting one form

### Requirement: Endpoint collections have bounded canonical values

Normalized `binds` and `endpoints` SHALL contain 1..=32 values, preserve declared order, reject duplicate values, and derive no new identity from an endpoint. Binds use SocketAddr IPv6 brackets; Egress endpoint hosts store IPv6 literals without URI brackets. Endpoint topology is startup-only.

#### Scenario: Endpoint collection exceeds its bound

- **WHEN** `binds` or `endpoints` contains more than 32 entries
- **THEN** complete-bundle validation rejects the candidate with a bounded-size diagnostic

#### Scenario: IPv6 values are normalized

- **WHEN** a bind uses `[2001:db8::10]:8443` and an Egress endpoint uses host `2001:db8::10` with port `8443`
- **THEN** the bind and endpoint are accepted in their respective canonical forms without changing the Egress identity

#### Scenario: Endpoint order changes

- **WHEN** a valid endpoint list is reordered without changing its members
- **THEN** the normalized topology changes and the reload result reports restart required
