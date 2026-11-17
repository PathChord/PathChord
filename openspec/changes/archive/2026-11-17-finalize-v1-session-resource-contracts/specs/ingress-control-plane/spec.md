# Spec Delta

## ADDED Requirements

### Requirement: Local request stages are time-bounded

The Unix socket and Named Pipe adapters SHALL bound prefix read, envelope read, dispatcher execution, and response write. A timeout SHALL close the connection, release its request permit, publish a sanitized diagnostic, and publish no mutation.

#### Scenario: A client sends a partial length prefix

- **WHEN** a local client stops sending before a complete canonical length prefix arrives
- **THEN** the adapter times out and releases the concurrency slot without blocking later management requests

### Requirement: Local resource exhaustion is typed

The local control service SHALL report `RESOURCE_LIMIT` for bounded request, pending-work, or concurrency exhaustion. It SHALL include a retry hint where the operation is retryable and SHALL NOT silently queue unbounded requests.

#### Scenario: All control request permits are occupied

- **WHEN** a new client exceeds the global control request limit
- **THEN** the service rejects the request with a typed resource-limit response and preserves the existing requests

### Requirement: Runtime resource limits do not create hidden fallback

Ingress SHALL distinguish resource-limit failures from target failures and policy failures. A resource-limit result SHALL not silently switch a flow to direct routing or an unrelated Proxy rule.

#### Scenario: Egress target connection capacity is exhausted

- **WHEN** a pre-admission Egress open returns `RESOURCE_LIMIT`
- **THEN** Ingress tries another compliant Egress candidate in the captured generation when available, otherwise returns the typed retryable error
