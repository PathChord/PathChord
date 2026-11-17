# Subscription User-Agent configuration delta

## MODIFIED Requirements

### Requirement: Subscription User-Agent is bounded

A Subscription source SHALL accept an optional `userAgent` field. Its value
SHALL be a nonblank printable ASCII HTTP header value of at most 1024 bytes.
An omitted field SHALL use the default specified by the Transit contract.

#### Scenario: User-Agent contains a line break

- **WHEN** a Subscription declares a User-Agent containing a line break
- **THEN** configuration validation rejects the candidate bundle
