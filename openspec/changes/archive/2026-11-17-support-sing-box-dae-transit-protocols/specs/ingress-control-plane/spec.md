# Subscription User-Agent control delta

## MODIFIED Requirements

### Requirement: Subscription User-Agent persists through control operations

The subscription control API SHALL accept and return the configured User-Agent
and persist it across restart. Legacy subscriptions without the field SHALL
retain their management decisions and use the default User-Agent.

#### Scenario: A managed subscription is restarted

- **WHEN** a client creates a subscription with a valid User-Agent and Ingress restarts
- **THEN** subsequent control reads and refreshes retain that value
