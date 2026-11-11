# PathChord State Machines

## Egress relationship

```text
UNKNOWN → CONNECTING → CONNECTED
CONNECTED → DEGRADED
DEGRADED → CONNECTED
CONNECTED/DEGRADED → DRAINING
CONNECTED/DEGRADED/DRAINING → DOWN
DOWN → CONNECTING
```

`CONNECTED` requires at least one authenticated bidirectional Path. `DEGRADED` requires at least one Path but fails current capacity, path-count, or capability requirements. `DOWN` closes all related connections.

## Path

```text
DISCOVERED → PROBING → ACTIVE → DRAINING → CLOSED
PROBING → FAILED
ACTIVE → DEGRADED → ACTIVE
ACTIVE → FAILED → CLOSED
```

A newly probed Path joins immediately at its configured weight; no warm-up phase. Quality degradation reduces allocation quickly. Recovery is stabilized. Scale-in uses draining.

## Stream

```text
NEW → OPENING → OPEN
OPEN → HALF_CLOSED_LOCAL
OPEN → HALF_CLOSED_REMOTE
HALF_CLOSED_* → CLOSED
OPEN → RESET
```

A Stream remains bound to its Egress. It may move among compliant Paths in the Session. If its compliant Path set becomes empty, reset the Stream and close the associated target connection.

## Session

```text
NEW → ATTACHING → ACTIVE
ACTIVE → DRAINING
ACTIVE → CLOSED
DRAINING → CLOSED
```

A Session is shared by one Ingress and one Egress. Either endpoint restart, authorization revocation, or Egress hard failure closes the Session and related target connections. It is not resumed after endpoint restart.
