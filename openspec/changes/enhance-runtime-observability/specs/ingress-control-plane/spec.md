# Runtime diagnostic control delta

## ADDED Requirements

### Requirement: Role-local diagnostic management

The shared management service SHALL offer authorized queries for live diagnostic state, retained records, and capture status on each service role. Capture start and stop SHALL be role-local, audited operations with a distinct authorization capability and normal generation and idempotency checks.

#### Scenario: Local diagnostics with the Web Gateway disabled

- **WHEN** an authorized operator queries an Ingress or Egress over its local control endpoint
- **THEN** the service returns live state and retained diagnostics under the same schema, redaction, and bounds used by its Web Gateway

#### Scenario: A reader attempts to start capture

- **WHEN** an actor with diagnostic read access lacks capture control capability
- **THEN** the service denies capture activation and preserves the current capture state

#### Scenario: A service restarts with a capture active

- **WHEN** either service restarts during a capture
- **THEN** capture status reports inactive in the new process and prior cursors follow the replay gap contract

### Requirement: Bounded diagnostic export

Each role SHALL support an authorized, versioned diagnostic export containing recent records and live observations, with the scope, producer coverage, observation generations, and truncation status needed to interpret it offline. The export SHALL apply the diagnostic query redaction rules before serialization.

#### Scenario: An export reaches its limit

- **WHEN** an authorized operator exports diagnostics for a time range larger than the response budget
- **THEN** the response reports actual coverage and the truncation reason, and identifies the retained live snapshot generation
