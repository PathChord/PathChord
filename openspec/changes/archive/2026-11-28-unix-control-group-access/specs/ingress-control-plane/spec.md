# Unix control socket group access

## ADDED Requirements

### Requirement: Unix control socket group access

The Unix control server SHALL set its control socket mode to `0660` and keep its lifetime lock owner-only. Packaged Unix services SHALL use `pathchord:pathchord` for the control socket and its runtime directory, and mode `0750` for that directory. Socket access SHALL grant local management privileges through the existing local adapter. Private state directories SHALL remain owner-only.

#### Scenario: A local operator is a service group member

- **WHEN** an operator in the `pathchord` group starts a new login session and runs `pathchordctl` against a packaged Unix service
- **THEN** the operator can connect to the control socket and use local management operations without elevating privileges.

#### Scenario: A local operator is outside the service group

- **WHEN** an unprivileged operator outside the `pathchord` group attempts to connect to the packaged Unix control socket
- **THEN** the operating system denies access.
