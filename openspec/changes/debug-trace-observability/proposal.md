# Debug and trace observability

## Why

Download failures need correlated evidence from carrier establishment through Stream closure.

## What changes

- Unify both service roles under structured FATAL, ERROR, WARN, INFO, DEBUG, and TRACE output.
- Retain Transit Proxy identity, display name, subscription, protocol, and selected Egress endpoint index with Path evidence.

## Capabilities

### Modified capabilities

- `observability` gains detailed diagnostic output and Path attribution.

## Impact

The runtime diagnostic producer and both service deployments gain detailed logging.
