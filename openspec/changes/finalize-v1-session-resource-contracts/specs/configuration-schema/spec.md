# Spec Delta

## MODIFIED Requirements

### Requirement: Validated adapter options

Transit Proxy configuration SHALL preserve typed connection options and validate their selected adapter support. TLS-capable adapters SHALL load system roots by default, accept an ordered local PEM/DER truststore source list, and fail the candidate atomically when any configured truststore source is invalid; unknown YAML option fields SHALL be rejected.

#### Scenario: Custom truststore sources are configured

- **WHEN** a TLS node sets truststore sources to `system` and local PEM/DER files
- **THEN** the adapter uses the union of those sources, resolves relative paths from the selected configuration source, and rejects the candidate if any source is unreadable or invalid

#### Scenario: Adapter cannot consume a connection option

- **WHEN** a configured node requires a connection option that its selected adapter does not support
- **THEN** the node is rejected or exposes an explicit diagnostic under the Transit Proxy contract instead of silently discarding the option

### Requirement: Versioned schema conformance

The v1 schema SHALL expose Egress aggregate wire capacity and global inbound target-connection limits while keeping desired Path count, per-Ingress stream quotas, and Path safety ceilings outside the authored Egress policy surface.

#### Scenario: Removed desired-Path fields are authored

- **WHEN** an EgressService contains `recommendedPathCount`, `maxConcurrentPaths`, or `maxStreamsPerIngress`
- **THEN** schema validation rejects the server-owned or retired field instead of treating it as an Ingress Path target

#### Scenario: Author runtime status in a resource

- **WHEN** an administrator supplies a resource containing an authored `status` field
- **THEN** validation rejects the resource and leaves the previously published snapshot active

## ADDED Requirements

### Requirement: Egress resource limits are global

An EgressService SHALL define a global maximum inbound target-connection count and a configured aggregate wire bandwidth cap. The runtime SHALL enforce these as global resource ceilings across all authorized Ingress Sessions.

#### Scenario: Global connection cap is reached

- **WHEN** active target connections plus pending reservations reach the global limit
- **THEN** new target opens return `RESOURCE_LIMIT` while existing target connections remain active

### Requirement: Truststore sources are explicit and bounded

TLS truststore sources SHALL default to `["system"]`. Each additional source SHALL be a local PEM/DER file path; relative paths resolve from the selected configuration source, absolute paths are allowed, symlink targets SHALL be regular files, and an empty list SHALL mean no trust anchors.

#### Scenario: Empty truststore is selected

- **WHEN** a node explicitly configures an empty truststore source list without insecure verification
- **THEN** ordinary certificate validation fails closed and the adapter does not restore system roots implicitly

### Requirement: Egress capacity fields have distinct meanings

The schema SHALL distinguish the configured aggregate wire hard cap from runtime effective capacity and current load. Runtime capacity state SHALL be represented separately from the authored configured cap and SHALL support unknown/provisional/measured/stale values.

#### Scenario: Capacity is not yet measured

- **WHEN** Egress starts without enough fresh measurements
- **THEN** the configured cap remains the hard upper bound, while effective capacity is exposed as provisional or unknown rather than authored as a measured value
