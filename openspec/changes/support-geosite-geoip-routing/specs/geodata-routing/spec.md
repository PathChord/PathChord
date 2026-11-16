# Spec Delta

## MODIFIED Requirements

### Requirement: V2Fly geodata compatibility

Ingress SHALL load operator-provided V2Fly `GeoSiteList` and `GeoIPList` protobuf databases and resolve named sets before publishing the containing configuration generation. It SHALL implement the matching types and attributes defined by the detailed contract.

#### Scenario: Use the upstream Hugging Face set

- **WHEN** a valid domain-list-community database contains the `huggingface` set and a rule references it
- **THEN** `huggingface.co`, `hf.co`, and label-bounded subdomains such as `us.aws.cdn.hf.co` match according to the published set

#### Scenario: Load a V2Fly GeoIP set

- **WHEN** a valid v2fly/geoip database contains an IPv4 or IPv6 CIDR in a referenced set
- **THEN** an available destination address in that CIDR matches the set with its declared inverse-match semantics

### Requirement: Hostname and IP facts remain distinct

Geosite SHALL match the original hostname when one is available. GeoIP SHALL match the original destination IP when one is available. Neither predicate SHALL trigger name resolution or invent an address or hostname.

#### Scenario: IP-only transparent destination

- **WHEN** a transparent flow has an IP destination and no original hostname
- **THEN** geosite predicates do not match that unknown hostname and geoip predicates evaluate the original IP

#### Scenario: Hostname-only explicit destination

- **WHEN** an explicit proxy request has a hostname and no original destination IP
- **THEN** geosite predicates evaluate that hostname and geoip predicates do not match an invented address

### Requirement: Geodata validation is bounded and atomic

Dataset reads, decoded entries, compiled regular expressions, and indexes SHALL have explicit implementation limits. Missing, malformed, unsupported, oversized, or unresolved referenced data SHALL reject the candidate generation and identify the database and set without exposing private paths or unrelated data.

#### Scenario: Invalid replacement database

- **WHEN** a referenced database is replaced by a malformed or oversized file during reload
- **THEN** the candidate fails with a bounded diagnostic and the previously published configuration and geodata generation remain active

#### Scenario: Unknown set or unsupported regular expression

- **WHEN** a rule references a missing set or a selected set contains a regular expression the implementation cannot safely compile
- **THEN** publication fails explicitly rather than silently discarding rules or treating the set as empty

### Requirement: Geodata matching is deterministic

Geodata predicates SHALL use the database snapshot captured with the routing generation and SHALL NOT perform network I/O during matching. Hostnames SHALL be normalized to lowercase and root-domain matches SHALL respect DNS label boundaries; regular expressions retain their explicit case-sensitive semantics.

#### Scenario: Root-domain boundary

- **WHEN** a set contains the root domain `hf.co`
- **THEN** `hf.co` and `us.aws.cdn.hf.co` match, while `nothf.co` does not

#### Scenario: Database changes during a decision

- **WHEN** a new database generation is published while a flow is evaluating ordered rules
- **THEN** that flow completes its entire decision using its captured generation

### Requirement: Detailed geodata contract

Geodata processing SHALL follow the complete [detailed contract](#detailed-contract).

#### Scenario: Apply the detailed contract

- **WHEN** geodata configuration or matching is processed
- **THEN** the schema, limits, and failure semantics below are enforced
