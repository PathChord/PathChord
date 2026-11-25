# Parallel Path refill delta

## ADDED Requirements

### Requirement: Concurrent refill of an established Path pool

When admission permits and a refill pass finds an established Session below its current Path target, Ingress SHALL attempt to fill the deficit concurrently within the remaining local Path capacity and existing eligibility and retry constraints. Ingress MAY attempt speculative refill and retain successful surplus Paths for ordinary scale-in.

#### Scenario: Several usable Paths are missing

- **WHEN** an established Session falls three Paths below target and has sufficient resources and eligible Transit
- **THEN** Ingress starts at least three concurrent attachment attempts in the refill pass

#### Scenario: The speculative attempt succeeds

- **WHEN** concurrent attempts establish more Paths than the current deficit
- **THEN** Ingress retains the successful Paths within the hard limit and applies ordinary scale-in hysteresis to the surplus
