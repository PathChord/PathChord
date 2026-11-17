# Configuration compatibility delta

## MODIFIED Requirements

### Requirement: Bounded ordinary Proxy pre-admission failover

An ordinary Proxy rule SHALL try eligible Transit nodes in stable score and ID order, with at most eight attempts sharing the configured connection timeout and the same policy generation. Once an adapter returns a stream or datagram handle, later failures SHALL NOT trigger replacement or retry.

#### Scenario: The preferred ordinary Transit node fails before admission

- **WHEN** the highest-scoring eligible node fails while opening a new TCP or UDP flow before any application data is admitted
- **THEN** Ingress tries the next eligible node in the compiled order within the bounded limit, without selecting Direct or changing the policy generation
