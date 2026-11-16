# Spec Delta

## MODIFIED Requirements

### Requirement: Egress status is global and policy-free

Egress status reports SHALL describe global Egress resource facts aggregated across all configured listener endpoints and SHALL NOT contain routing rules, Egress Transit selectors, TrafficPolicy identity, business-class policy, or Ingress demand metadata. Path-local quality observations SHALL be owned by Ingress and derived from local Path traffic and control feedback.

#### Scenario: Egress reports shared capacity

- **WHEN** an Egress serves multiple Ingress Sessions
- **THEN** its status reports aggregate wire rate, capacity, active target connections, service state, and global admission state without exposing per-rule information

#### Scenario: Egress has multiple listener endpoints

- **WHEN** an Egress serves Paths through multiple configured listeners
- **THEN** capacity, target-connection counts, authorization effects, and admission state are reported once for the Egress and are not multiplied or partitioned by listener

## ADDED Requirements

### Requirement: Local observations identify bounded Egress endpoints

Authorized local operational views SHALL expose a bounded normalized endpoint inventory and the endpoint candidate selected by each Path. Endpoint observations SHALL use stable bounded endpoint ordinals or IDs, retain one of `configured`, `available`, `degraded`, `draining`, `failed`, or `unknown` with typed reasons and bounded counters, and SHALL not become unbounded metric labels.

#### Scenario: Inspect Egress endpoint inventory

- **WHEN** an authorized operator queries the Egress or Session resources
- **THEN** the response reports the configured endpoint count and each endpoint's bounded state, while redacting credentials and secret-bearing configuration

#### Scenario: Inspect a Path's selected endpoint

- **WHEN** an authorized operator queries a ready, draining, or failed Path
- **THEN** the response identifies the normalized endpoint ordinal used by that Path and does not claim that another endpoint was used

#### Scenario: An endpoint has repeated failures

- **WHEN** one endpoint accumulates bounded connection or listener failures
- **THEN** local observations expose its typed failure state and bounded counters without changing the aggregate Egress capacity or inventing a new Egress identity

### Requirement: Endpoint details stay out of wire status and metric labels

Endpoint-specific local observations SHALL not add raw endpoint hostnames, ports, or failure text to Prometheus label sets or the authenticated `STATUS_REPORT` layout. Aggregate Egress health and capacity SHALL remain available through their existing bounded fields.

#### Scenario: Prometheus metrics are rendered

- **WHEN** the metrics endpoint renders an Egress with multiple configured endpoints
- **THEN** it emits only bounded aggregate Egress gauges and does not create one unbounded label value per endpoint hostname or port

#### Scenario: An authenticated peer receives Egress status

- **WHEN** an Ingress receives the authenticated Egress status report over a Path
- **THEN** the report keeps the existing aggregate wire layout and does not disclose the Egress listener inventory

