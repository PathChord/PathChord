# PathChord

Adaptive multipath proxy with Ingress, Transit Proxy, and Egress.

PathChord provides ordinary proxy semantics to local applications while maintaining multiple replaceable transit paths between an Ingress and a selected Egress.

## Status

Design phase. The current repository contains the architecture and protocol design baseline; implementation choices are intentionally not frozen yet.

## Terminology

- **Ingress**: local traffic entry point and policy engine.
- **Transit Proxy**: an uncontrolled proxy transport used to reach an Egress.
- **Egress**: a controlled logical network interface and final traffic exit.
- **Session**: shared logical session between one Ingress and one Egress.
- **Path**: a long-lived bidirectional connection carried by one Transit Proxy.
- **Stream**: a logical TCP byte stream carried over one Session.

## Design documents

- [Architecture](docs/architecture.md)
- [Protocol](docs/protocol.md)
- [Configuration model](docs/configuration.md)
- [State machines](docs/state-machines.md)
- [Implementation plan](docs/implementation-plan.md)
- [Technology selection](docs/technology-selection.md)

## Planned commands

```text
pathchord ingress
pathchord egress
pathchord status
pathchord enroll
```
