# Detailed runtime logging delta

## ADDED Requirements

### Requirement: Opt-in detailed runtime logging

Both service roles SHALL share one structured log schema and the ordered FATAL, ERROR, WARN, INFO, DEBUG, and TRACE levels. The startup threshold SHALL default to INFO and accept OFF. TRACE SHALL report frame metadata and flow-control decisions. Logs SHALL exclude credentials, raw peer errors, and payloads. A saturated log sink SHALL count losses without waiting in forwarding code.

#### Scenario: A service uses the INFO threshold

- **WHEN** the service uses the INFO threshold
- **THEN** it emits FATAL, ERROR, WARN, and INFO records using the same schema

#### Scenario: Startup cannot continue

- **WHEN** a startup failure prevents the service from running and FATAL is enabled
- **THEN** the process writes a structured FATAL event with a classified reason before exiting unsuccessfully

#### Scenario: A Stream stalls during a traced download

- **WHEN** TRACE is enabled and flow control blocks a Stream
- **THEN** the local log identifies the Session, Stream, direction, and limiting window

### Requirement: Historical Transit attribution

Ingress SHALL associate Path diagnostics with the Transit Proxy ID, display name, subscription, protocol and selected Egress endpoint index when known.

#### Scenario: A subscription changes after admission

- **WHEN** an admitted Path terminates after its subscription changes
- **THEN** its terminal record retains the metadata captured when the Path was established
