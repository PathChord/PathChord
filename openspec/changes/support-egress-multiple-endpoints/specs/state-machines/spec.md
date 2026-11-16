# Spec Delta

## MODIFIED Requirements

### Requirement: Draining and terminal Session cleanup

Draining Paths and Sessions SHALL reject new business work while retaining existing work according to their deadlines. Losing the last ready Path, whole-Egress runtime restart or hard failure, or authorization failure SHALL close affected Session resources and retire the old SessionID. Failure or administrative drain of one configured Egress endpoint SHALL only affect Paths using that endpoint while another ready endpoint-backed Path remains eligible.

#### Scenario: Only draining Paths remain

- **WHEN** a Session contains ready draining Paths but no `ACTIVE` or `DEGRADED` Path
- **THEN** existing work may finish while new Streams and UDP Associations are rejected

#### Scenario: Last ready Path disappears

- **WHEN** the Session loses its last ready Path
- **THEN** business resources close, the SessionID is retired, and any later Session uses a new SessionID

#### Scenario: One configured endpoint fails

- **WHEN** a listener or transport endpoint fails while another endpoint-backed Path remains `ACTIVE` or `DEGRADED`
- **THEN** only Paths using the failed endpoint enter failure or replacement, the Session remains alive, and existing business work on healthy Paths is retained

#### Scenario: The whole Egress runtime restarts

- **WHEN** all configured Egress listeners and the shared runtime restart or lose authorization state
- **THEN** the affected Session closes according to the existing endpoint-restart rule and recovery creates a fresh SessionID

## ADDED Requirements

### Requirement: Endpoint failure preserves shared lifecycle ownership

Endpoint-specific Path failure SHALL be processed by the existing Session/Path lifecycle owner. Endpoint selection, listener accept loops, and endpoint health observations SHALL request transitions through that owner and SHALL not mutate Session or Path state directly. A replacement Path SHALL use a new PathID, while a whole Egress runtime restart remains a Session restart.

#### Scenario: A failed endpoint is replaced

- **WHEN** bounded recovery establishes a replacement Path through another configured endpoint
- **THEN** the lifecycle owner records the new Path under the existing Session or a fresh Session as required by the current Session state, with no reuse of a retired PathID

#### Scenario: All endpoint-backed Paths are draining

- **WHEN** every ready Path is associated with an endpoint that is draining or failed
- **THEN** the Session denies new business admission and follows the normal drain or last-ready-Path transition instead of treating a merely configured endpoint as ready

