# Runtime observability delta

## ADDED Requirements

### Requirement: Correlated Path termination records

Ingress and Egress SHALL capture one typed local termination record for each admitted Path reaching a terminal state. The record SHALL identify the Session, Path, role, observation time, and observed trigger. Ingress SHALL retain the associated Transit Proxy identity when available.

#### Scenario: A Path exceeds its write deadline

- **WHEN** a local Path write or flush exceeds its deadline and causes termination
- **THEN** the terminating role records `write_timeout` with the elapsed write time and available heartbeat age
- **AND** if the peer also observes termination, it records its own trigger for the same Session and Path IDs

#### Scenario: A carrier closes or stops delivering heartbeats

- **WHEN** carrier EOF, a carrier I/O error, or heartbeat expiry causes a Path to terminate
- **THEN** the service records the corresponding trigger without inferring the peer's reason

#### Scenario: Several triggers race to close a Path

- **WHEN** multiple triggers are observed for the same admitted Path
- **THEN** the service records the trigger accepted by the local lifecycle transition and counts the termination once

### Requirement: Recent Path termination evidence

Both roles SHALL expose bounded recent termination records through authorized structured management queries and the existing event interface. Records SHALL remain queryable independently of live Path and Session inventory, subject to retention limits.

#### Scenario: A failed Session disappears from live inventory

- **WHEN** an authorized operator queries a retained termination after its Session has been removed
- **THEN** the query returns the termination with its correlation fields and original timestamp

#### Scenario: A replay cursor predates retained evidence

- **WHEN** an event client reconnects with a cursor outside the retained replay window
- **THEN** the service follows the existing snapshot recovery contract and signals the replay gap

### Requirement: Bounded Path termination counters

Each role SHALL expose process-lifetime Path termination counters through the authenticated Prometheus endpoint, with a fixed reason label domain.

#### Scenario: Several Paths time out before a scrape

- **WHEN** several admitted Paths terminate after local write timeouts and their entries age out before the next scrape
- **THEN** the `write_timeout` counter includes every observed termination and is independent of recent record retention

### Requirement: Runtime stage diagnostics

Ingress and Egress SHALL publish typed outcomes and timings at the boundaries of listener acceptance, routing, DNS, provider refresh, Transit establishment, Session and Path lifecycle, scheduling, Stream and target I/O, and resource admission for the stages registered by the observation service.

#### Scenario: Establishment fails before Path admission

- **WHEN** an endpoint dial, Transit handshake, Noise authentication, or Session attachment fails before a Path is admitted
- **THEN** the service exposes the failing stage, elapsed time, bounded reason, and available local attempt and endpoint identifiers

#### Scenario: A flow stalls after admission

- **WHEN** a Stream is reset or times out after transferring data
- **THEN** the terminating service exposes its local trigger, available directional byte and progress observations, and related Session and Stream identifiers

#### Scenario: Health and scheduling diverge

- **WHEN** a live Path is excluded from new work, or demand exceeds the effective Path budget
- **THEN** the operator can inspect the eligibility reason, relevant freshness, requested and effective targets, and actual usable counts

### Requirement: Bounded diagnostic capture

Each role SHALL support authorized, time-limited capture of additional stage and scheduler evidence. Capture SHALL use bounded memory and rate budgets, expose drops, and operate independently of forwarding and baseline diagnostics.

#### Scenario: Capture duration expires

- **WHEN** capture reaches its configured expiration
- **THEN** optional sampling stops automatically and capture status reports expiration

#### Scenario: Capture exceeds its sample budget

- **WHEN** capture exceeds its sample budget before expiration
- **THEN** the service reports omitted samples and their coverage status
- **AND** live state, termination counts, and forwarding continue independently

#### Scenario: A diagnostic collector falls behind

- **WHEN** observation publication or replay exceeds its capacity
- **THEN** the API exposes observation degradation and loss counters without blocking runtime I/O

### Requirement: Runtime stage aggregates

Each role SHALL expose aggregate stage outcomes, latency distributions, and observation health through the authenticated Prometheus endpoint using fixed label domains.

#### Scenario: A stage has no authoritative measurement

- **WHEN** a producer cannot observe a stage or an optional field on its platform
- **THEN** the management view marks it unavailable and the exporter omits unsupported series

### Requirement: Diagnostic coverage and restart identity

Each role SHALL identify the running build, process instance, observation generation, and producer coverage in diagnostic responses. History and replay SHALL expose the retained range and distinguish expiration, eviction, producer loss, and process restart when known.

#### Scenario: A process restarts between scrapes

- **WHEN** a service restarts and an operator compares its counters or resumes an older cursor
- **THEN** the process identity changes, the process start time identifies the new counter lifetime, and replay signals a restart gap before delivering deltas

#### Scenario: An empty query has incomplete coverage

- **WHEN** a producer or requested time range has incomplete coverage
- **THEN** the response exposes the known gap even when the filtered record list is empty

### Requirement: Directional progress and backpressure evidence

Runtime diagnostics SHALL identify the producer, direction, and measurement boundary for byte progress, queue depth, flow-control waits, and timing. A terminal Path or stalled Stream SHALL retain the last available observations and their age.

#### Scenario: A Path stops progressing with queued data

- **WHEN** a carrier write times out while PathChord still has queued data
- **THEN** diagnostics distinguish the local pending bytes, the elapsed write and last progress, and any separately available kernel send-queue sample
- **AND** unobserved measurements remain unavailable

#### Scenario: A Stream waits for receive credit

- **WHEN** a Stream stops sending because its Stream or Session window is exhausted
- **THEN** diagnostics identify the limiting window and distinguish the condition from a carrier write timeout
