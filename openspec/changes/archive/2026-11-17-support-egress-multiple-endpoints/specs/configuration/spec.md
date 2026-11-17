# Spec Delta

## ADDED Requirements

### Requirement: Egress Paths select endpoint candidates independently

For one configured Egress, Ingress SHALL maintain one Session Path pool while selecting one normalized endpoint candidate for each Path establishment. Endpoint selection SHALL use a deterministic bounded order and SHALL not create a separate Session, policy, or Egress identity per endpoint.

#### Scenario: One Session uses IPv4 and IPv6 endpoints

- **WHEN** an Egress has ready endpoint candidates in different address families and the Session requires multiple Paths
- **THEN** separate Paths may connect through different candidates while remaining in the same authenticated Session Path pool

#### Scenario: Endpoint candidate order is reused

- **WHEN** a Path establishment starts with an ordered endpoint list
- **THEN** the selection cursor and bounded wraparound preserve the configured candidate order and do not retry one candidate indefinitely

### Requirement: Endpoint failure uses bounded pre-admission failover

Before a Path reaches authenticated readiness, Ingress SHALL try eligible Egress endpoint candidates within the Path connection deadline and a finite attempt bound. If every candidate fails, the Path attempt SHALL return a typed connection failure without selecting Direct, an unrelated Egress, or an ordinary Proxy route.

#### Scenario: The preferred endpoint is unavailable

- **WHEN** the first endpoint candidate fails before Noise admission completes and another candidate remains
- **THEN** Ingress tries the next candidate within the same bounded Path establishment operation

#### Scenario: All endpoint candidates fail

- **WHEN** every candidate fails before Path admission
- **THEN** the Egress Path attempt fails with the normalized Egress/Transit connection error and no target Stream or UDP Association is created

#### Scenario: A candidate is retried after a timeout

- **WHEN** an endpoint attempt reaches its connection deadline
- **THEN** the attempt is counted as failed, its resources are released, and the bounded operation advances or terminates without extending the deadline indefinitely

### Requirement: Established Paths retain endpoint ownership

After a Path reaches readiness, its endpoint candidate SHALL remain associated with that Path until the Path drains or fails. Endpoint failure SHALL affect Paths using that candidate and SHALL not migrate an established Path by silently changing its peer socket.

#### Scenario: One endpoint fails while another Path is ready

- **WHEN** a transport failure closes a Path using one endpoint while another non-draining ready Path uses a different endpoint
- **THEN** the Session remains eligible according to its existing minimum and only the failed Path enters recovery or replacement

#### Scenario: A Path endpoint is drained

- **WHEN** an administrator removes an endpoint from the next static configuration or the endpoint is administratively drained
- **THEN** new Paths exclude it and existing Paths follow the normal Path drain deadline before closure

### Requirement: Hostname candidates preserve family and port semantics

An Egress endpoint hostname SHALL be resolved by the selected Transit Adapter using its configured port; a hostname's IPv4 and IPv6 address results are alternatives for that same port. Different ports SHALL be represented by distinct endpoint candidates rather than inferred from DNS address records.

#### Scenario: One hostname returns A and AAAA records

- **WHEN** a hostname candidate resolves to both IPv4 and IPv6 addresses for port 7443
- **THEN** the adapter may try either family for port 7443 within the bounded connection attempt, while the Egress identity remains unchanged

#### Scenario: IPv4 and IPv6 use different ports

- **WHEN** IPv4 uses port 7443 and IPv6 uses port 8443
- **THEN** Ingress treats them as two explicit candidates and can select either candidate independently for a Path

### Requirement: Endpoint attempts use one static bounded sequence

An Egress Path attempt SHALL start at the per-Egress selection cursor, visit each normalized candidate at most once with wraparound, and use one shared deadline for the sequence. The cursor advances after successful admission or exhaustion; endpoint failover applies only before Path admission.

#### Scenario: A Path sequence reaches a successful candidate

- **WHEN** a candidate succeeds and Noise admission reaches readiness
- **THEN** the Path records that candidate, the cursor advances, and no later Stream or UDP retry changes the Path's transport

#### Scenario: A Path sequence is exhausted

- **WHEN** every candidate fails or times out before readiness
- **THEN** the operation returns the existing typed Path connection failure without extending its deadline or bypassing the Egress Transit binding and TrafficPolicy
