# Spec Delta

## MODIFIED Requirements

### Requirement: Bounded replication policy

Each admitted Stream or UDP Association SHALL use the selected TrafficPolicy's immutable replication budget, while one negotiated Session cap remains the hard upper bound. A low-budget flow SHALL NOT permanently reduce the independent budget of later flows in the same Session.

#### Scenario: Two flows use different policies

- **WHEN** a low-replication flow and a high-replication flow share a Session
- **THEN** each flow uses its own policy/class budget, and only the Session-wide remaining cap is shared

#### Scenario: Unknown traffic class is configured

- **WHEN** a TransitRule names a class that does not exist in its selected TrafficPolicy
- **THEN** validation rejects the reference instead of admitting the flow under an arbitrary class

## ADDED Requirements

### Requirement: Ingress owns Path target decisions

Ingress SHALL derive target Path counts from matching EgressRule minimums, eligible Transit relationships, directional demand, Path quality, and Egress hard resource ceilings. Egress recommendations SHALL NOT override the Ingress rule decision.

#### Scenario: Egress has no Path recommendation

- **WHEN** Egress reports capacity and admission state without a recommended Path count
- **THEN** Ingress still computes a bounded target for each matching EgressRule from its own policy and runtime observations

### Requirement: Rule-specific Path eligibility is enforced

An EgressRule SHALL count only Paths whose Transit relationship, capabilities, health, and current admission state satisfy the rule's TransitRule set. Namespace membership alone SHALL NOT make a Path eligible for the rule.

#### Scenario: Warmup finds an ineligible Transit

- **WHEN** a ready Transit adapter does not match the selected EgressRule's TransitRule
- **THEN** the adapter is not counted toward that rule's minimum Path requirement and is not selected for its new flow

### Requirement: Resource failure does not fall through silently

When a candidate Egress rejects a pre-admission open with `RESOURCE_LIMIT`, Ingress SHALL try another compliant Egress candidate in the captured generation when one exists. If none succeeds, it SHALL return the typed resource failure without silently selecting direct or an unrelated Proxy rule.

#### Scenario: All candidates are saturated

- **WHEN** every compliant Egress candidate reports a resource limit before Stream admission
- **THEN** the local flow fails with a retryable resource error and no unconfigured fallback is used

### Requirement: Rule demand aggregation is bounded

Ingress SHALL aggregate demand by Session-scoped rule, policy, and class keys using bounded counters and low-frequency windows. It SHALL NOT retain unbounded per-flow demand history or send rule metadata to Egress.

#### Scenario: A Session reconnects

- **WHEN** a new SessionID replaces a failed Session
- **THEN** its demand counters and EWMA start empty while prior values remain only in bounded observations
