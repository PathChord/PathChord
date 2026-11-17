# Configuration delta

## MODIFIED Requirements

### Requirement: Declarative configuration contract

Configuration processing SHALL conform to the complete [detailed contract](#detailed-contract), including its object model, examples, listener references, namespace ownership, and update rules. Desired configuration and read-only runtime status SHALL remain separate.

#### Scenario: Publish validated desired resources

- **WHEN** a configuration bundle is accepted for publication
- **THEN** its complete object graph is validated and converted into a typed immutable snapshot, with runtime observations exposed separately through read-only `status` views

#### Detailed contract

##### Routing and Egress binding

EgressRule actions remain `egressRef`, `egressSelector`, or explicit `mode: none`.
An Egress action emits the captured routing generation and Egress candidates;
the matched rule identity MAY remain diagnostic data, but MUST NOT drive Path
eligibility, scheduling, replication, or autoscaling. Business TCP/UDP support
is checked on the Egress. Ordinary Proxy rules and mandatory explicit fallback
retain their current ordering and failure boundaries.

The selected Egress's `transit` binding is evaluated against same-namespace
Transit nodes and published runtime state. Hard disabled, revoked, unsupported,
or unavailable nodes cannot be admitted by labels. A built-in direct Transit
is usable only when explicitly present in the node graph and admitted by that
binding; no direct route is invented when candidates are unavailable.

`statusRequirements.minUsablePaths` is the sole configured Path minimum for
that Egress. The Session manager bootstraps from valid topology, authorization,
and eligible Transit candidates without requiring an already connected Egress
observation. Business admission waits for authenticated ready Paths, fresh
Egress admission state, and the common minimum. Loss of the last ready Path is
a hard Session failure; falling below the minimum with ready Paths remaining
is a degraded admission condition and does not itself close existing work.

##### Uniform scheduling policy

The Egress's `trafficPolicyRef` resolves to one immutable Session policy.
Streams, UDP Associations, later Path attachments, and Egress-routed DNS use
that same policy and pool. Per-Stream queues and flow control remain bounded
and fairly scheduled; public business-class priority/share and budget
overrides do not exist. The negotiated replication cap is never raised by
opening another flow or attaching another Path.

Subscription and administrator-metadata generations can change eligible nodes
under the fixed binding. Removed relationships stop receiving new Paths and
their existing Paths drain under lifecycle deadlines. Such updates do not
reroute an already admitted target connection to another Egress. The Path
binding, Egress admission minimum, policy reference, and resolved policy
definition require an Ingress restart when changed.

### Requirement: Ordered routing and explicit fallback

Ingress SHALL evaluate effective Egress rules before ordinary Proxy rules and the mandatory global fallback. Egress rules SHALL select an Egress reference or selector, or explicitly enter ordinary Proxy mode with `mode: none`. Egress selection SHALL use the common Path admission state and business protocol capability without flow-specific Transit selection. Unsupported ordinary UDP routes SHALL fail without a direct bypass.

#### Scenario: No effective Egress route is selected

- **WHEN** ordered effective Egress rules do not select an admissible route for a new flow
- **THEN** Ingress evaluates ordinary Proxy rules and then the configured global fallback in that order

#### Scenario: Different rules select the same Egress

- **WHEN** two flows match different Egress rules that select the same Egress
- **THEN** both use that Egress's Session Path pool and TrafficPolicy without deriving different Transit candidates or Path requirements from their rules

### Requirement: Bounded replication policy

Each Session SHALL capture the TrafficPolicy selected by its Egress and share one replication allowance per sending direction, bounded by the negotiated Session cap. All admitted Streams and UDP Associations SHALL use that immutable policy without rule, flow, or business-class budget overrides. Separate Sessions SHALL account independently even when they reference the same TrafficPolicy.

#### Scenario: Two flows use different Egress policies

- **WHEN** two flows select Egresses with different TrafficPolicies
- **THEN** each uses the policy and shared allowance of its own Session, without changing the other Session's budget

#### Scenario: Two flows use different policies

- **WHEN** two flows select Egresses with different TrafficPolicies
- **THEN** each uses the policy and shared allowance of its own Session, without changing the other Session's budget

#### Scenario: Unknown traffic class is configured

- **WHEN** a configuration contains a traffic-class reference or a retired class policy field
- **THEN** validation rejects that field instead of admitting the flow under a default or arbitrary business class

#### Scenario: Several flows share the replication allowance

- **WHEN** Streams and UDP Associations in one Session request optional copies concurrently in the same sending direction
- **THEN** their combined accounting stays within that direction's remaining Session allowance, after required control reservations, without multiplying it by the number of flows

### Requirement: Session maintenance per Egress

Ingress SHALL maintain one Session slot per configured Egress and establish its Paths from the Egress's Transit binding independently of business-flow matches. Live idle Sessions SHALL be reused by subsequent Streams and UDP Associations. Hard Egress failure SHALL destroy the Session and related business connections; recovery SHALL create a fresh Session.

#### Scenario: Egress warms before a business match

- **WHEN** Ingress starts with a valid Egress binding and no business flow has matched a route
- **THEN** it can establish that Egress's initial Paths without synthesizing a target, listener, flow tag, or geodata match

#### Scenario: Egress recovers after hard failure

- **WHEN** an Egress becomes online after its previous Session was destroyed by hard failure
- **THEN** Ingress creates a new Session and Path set instead of resurrecting the old Session

#### Scenario: Only destination-specific routing rules exist

- **WHEN** Ingress starts with a valid Egress binding and no business flow has matched a rule
- **THEN** it can establish that Egress's initial Paths without synthesizing a target, listener, flow tag, or geodata match

### Requirement: Ingress owns Path target decisions

Ingress SHALL derive one target Path count per Session from the Egress minimum, eligible Transit relationships, aggregate directional demand, Path quality, and Egress hard resource ceilings. Neither route identities nor flow matches SHALL define additional Path targets. Egress resource reports SHALL NOT override the Ingress decision.

#### Scenario: Egress has no Path recommendation

- **WHEN** Egress reports capacity and admission state without a recommended Path count
- **THEN** Ingress computes one bounded Session target from its Egress configuration and runtime observations

#### Scenario: A minimum exceeds a negotiated safety ceiling

- **WHEN** the configured minimum cannot be achieved within the Session's hard Path ceiling
- **THEN** Ingress keeps the target within that ceiling and denies new admission while exposing the shortfall instead of creating unbounded Paths

### Requirement: Geodata predicates participate in ordered routing

EgressRule and ProxyRule flow matches SHALL evaluate configured geosite and geoip predicates using the same immutable geodata generation as the rest of the routing decision. These predicates SHALL follow the existing geodata routing contract without changing rule order or implicit fallback behavior, and SHALL NOT select Transit relationships within an Egress.

#### Scenario: Hugging Face redirect uses the same Egress policy

- **WHEN** an explicit proxy flow targets a hostname in a configured `huggingface` geosite set, including a CDN subdomain
- **THEN** the matching Egress rule selects its configured Egress and the flow uses that Egress's common Path pool

#### Scenario: GeoIP predicate receives an original destination address

- **WHEN** an IP-targeted TCP or UDP flow reaches a rule with a matching geoip set
- **THEN** the rule evaluates the original destination IP under its captured generation before selecting an Egress, Proxy, or configured fallback

#### Scenario: Geodata fact is unavailable

- **WHEN** a rule needs a hostname or IP that the listener did not provide
- **THEN** the corresponding geodata predicate does not match and Ingress proceeds through the configured ordered rules and fallback without resolving through another DNS route

## REMOVED Requirements

### Requirement: Rule-specific Path eligibility is enforced

**Reason**: Eligibility belongs to the Egress Session pool; separate flow-specific TransitRule sets are retired.

**Migration**: Move the common Transit conditions to `Egress.spec.transit` and the minimum to `Egress.spec.statusRequirements.minUsablePaths`. Resolve conflicting old rule conditions explicitly.

### Requirement: Rule demand aggregation is bounded

**Reason**: Path demand is aggregated once per Session rather than by rule, policy, and class keys.

**Migration**: Use the bounded Session directional demand contract below; do not retain rule-keyed Path demand or transmit it to Egress.

## ADDED Requirements

### Requirement: Egress Session Path eligibility

All Streams and UDP Associations in one Session SHALL share the Path eligibility defined by its Egress Transit binding, authenticated Path readiness, health, and lifecycle state. The flow's route, target, listener, or business protocol SHALL NOT narrow the Transit set. Egress protocol capability and per-resource flow control SHALL remain enforced.

#### Scenario: Warmup finds an ineligible Transit

- **WHEN** a ready Transit adapter does not satisfy the Egress Transit binding
- **THEN** it is excluded from the Session pool and does not count toward the Egress minimum

#### Scenario: TCP-only Transit carries Egress UDP

- **WHEN** a Transit provides an eligible byte stream and the selected Egress supports UDP
- **THEN** UDP Associations can use the shared Path pool without requiring the Transit to support native UDP

#### Scenario: One Transit carries several Paths

- **WHEN** one eligible Transit relationship carries several independently authenticated Paths
- **THEN** its non-draining `ACTIVE` or `DEGRADED` Paths can satisfy the Egress Path minimum while sharing that relationship's configured weight

### Requirement: Session demand aggregation is bounded

Ingress SHALL aggregate upstream and downstream demand once per Session using bounded counters and low-frequency windows. Route identities, policy IDs, and business classes SHALL NOT partition Path demand. A replacement Session SHALL start with empty counters and observations; no unbounded per-flow demand history or local policy metadata SHALL be sent to Egress.

#### Scenario: A Session reconnects

- **WHEN** a new SessionID replaces a failed Session
- **THEN** its aggregate demand counters and EWMA start empty while prior values remain only in bounded observations

#### Scenario: Many matching rules share an Egress

- **WHEN** many routing rules send traffic to the same Egress
- **THEN** their traffic contributes to the same Session directional demand windows without allocating a separate Path requirement or demand-history entry per rule
