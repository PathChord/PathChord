# Spec Delta

## ADDED Requirements

### Requirement: AnyTLS v2 session reuse and padding

AnyTLS adapters SHALL implement the official v2 settings, padding negotiation,
heartbeat, Stream lifecycle, and reusable Session behavior while preserving one
active Stream per Session.

#### Scenario: A new Session sends the official preface

- **WHEN** the adapter creates a TLS Session with the node's current padding scheme
- **THEN** it sends padded authentication, version-2 settings with a client identity and padding digest, and the first Stream settings in the order required by AnyTLS v2

#### Scenario: A healthy Stream is closed

- **WHEN** the only active Stream sends or receives a normal FIN and its Session event loop remains healthy
- **THEN** the adapter releases the Stream lease and puts the Session into the node's idle pool

#### Scenario: An idle Session is available

- **WHEN** a TCP or UoT v2 UDP request needs an AnyTLS Session and the node has a healthy idle Session
- **THEN** the adapter leases the newest idle Session, opens one new Stream on it, and creates no new TLS connection

#### Scenario: The idle pool is full

- **WHEN** releasing a healthy Session would exceed the node's idle pool limit
- **THEN** the adapter evicts the oldest idle Session and retains at most eight idle Sessions

#### Scenario: An idle Session expires

- **WHEN** an idle Session has remained unused for 60 seconds
- **THEN** the adapter closes and removes it before it can be leased

#### Scenario: The server updates padding

- **WHEN** the Session receives a valid cmdUpdatePaddingScheme
- **THEN** the adapter validates and atomically publishes the scheme for later Sessions while the current Session continues with its captured scheme

#### Scenario: The server rejects a Stream

- **WHEN** a SYNACK contains an error payload
- **THEN** the current request fails with a sanitized protocol error and the Session is discarded without retrying the request

#### Scenario: A peer closes a Stream

- **WHEN** the Session receives FIN for the active Stream
- **THEN** the Stream becomes read-closed, no reciprocal FIN is sent, and the Session returns to the idle pool only after its writer and event loop remain healthy

#### Scenario: A peer sends ALERT

- **WHEN** the Session receives ALERT
- **THEN** the active Stream and Session fail with a sanitized connection error, the Session is removed from the idle pool, and later requests create a new Session

#### Scenario: A heartbeat is received

- **WHEN** the Session receives cmdHeartRequest with any Stream ID
- **THEN** it replies with an empty cmdHeartResponse carrying that same Stream ID

#### Scenario: A UoT v2 request uses the pool

- **WHEN** a UoT v2 UDP association is opened
- **THEN** it leases or creates an AnyTLS Session using the same pool as TCP, opens one Stream, and sends the UoT v2 request before waiting for successful SYNACK
