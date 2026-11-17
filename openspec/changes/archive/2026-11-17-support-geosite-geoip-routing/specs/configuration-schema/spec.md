# Spec Delta

## MODIFIED Requirements

### Requirement: Geodata resources and references

The configuration schema SHALL support namespace-scoped geosite and geoip database resources and typed named-set references in flow matches. Validation SHALL resolve every reference against the complete resource graph and reject invalid or ambiguous data before publication.

#### Scenario: Reference an absent database

- **WHEN** a rule refers to a geodata resource or named set absent from its namespace
- **THEN** the candidate configuration is rejected with a diagnostic identifying the field and resource rather than publishing a partial rule

#### Scenario: Existing exact host matches remain valid

- **WHEN** an existing configuration uses only `targetHosts`
- **THEN** it retains its existing exact hostname or IP-literal matching semantics without requiring geodata resources

### Requirement: Geodata updates publish atomically

The loader SHALL read and validate each referenced database as part of the complete candidate and publish geodata and rules in one immutable generation. Replacing a configured database file SHALL trigger a bounded reload, and a failed candidate SHALL retain the previous generation.

#### Scenario: Replace a referenced database

- **WHEN** an operator atomically replaces a referenced geodata file with valid content
- **THEN** Ingress validates the complete candidate and publishes the changed data and rules together as a new generation

#### Scenario: Start with missing geodata

- **WHEN** initial configuration references a missing or unreadable geodata database
- **THEN** startup reports a typed configuration failure and does not silently disable that predicate

### Requirement: Detailed geodata contract

Geodata configuration SHALL follow the complete [detailed contract](../../../../../specs/configuration-schema/spec.md#geodata-databases).

#### Scenario: Apply the detailed contract

- **WHEN** geodata configuration or matching is processed
- **THEN** the schema, limits, and failure semantics in the detailed contract are enforced
