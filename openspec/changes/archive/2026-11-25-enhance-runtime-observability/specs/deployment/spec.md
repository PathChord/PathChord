# Runtime diagnostic deployment delta

## ADDED Requirements

### Requirement: Discoverable service diagnostics

The dedicated management client SHALL provide role-aware local commands to inspect live runtime detail and recent diagnostic records, and to start, inspect, and stop an authorized capture. Commands SHALL support the existing human and structured output modes and explicit local endpoint selection.

#### Scenario: Troubleshoot using an installed role package

- **WHEN** an operator uses the installed management client against the Ingress or Egress local endpoint
- **THEN** command help exposes the diagnostic operations and structured output preserves correlation IDs, timing, reason codes, and retention or producer-loss status

#### Scenario: Collect evidence from two hosts

- **WHEN** an operator exports diagnostics with the installed management clients on Ingress and Egress
- **THEN** the structured output identifies the role, running build, process lifetime, time coverage, and shared correlation IDs needed to compare the files offline
