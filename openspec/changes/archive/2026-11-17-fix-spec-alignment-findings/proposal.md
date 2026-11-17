# Proposal

## Why

The implementation audit at `81ef15c` found sixteen violations of existing
OpenSpec contracts, including service termination after connection-history
exhaustion, unbounded admission, unsafe configuration compilation, and incorrect
protocol and subscription behavior. Fix these executable paths and protect the
failure cases with regression tests before publishing the revision.

## What changes

- Keep Ingress serving when optional connection history reaches its bound and
  reject unauthorized SSE requests before opening a stream.
- Validate every supplied DNS endpoint, preserve namespace-qualified identities
  throughout compilation and runtime consumption, and honor schema defaults,
  unknown-field rejection, and omitted-match catch-all rules.
- Bound Egress admission, isolate malformed Path frames, preserve capability
  negotiation and target error classes, honor drain deadlines, and generate
  random RequestIDs.
- Correct Hysteria2/TUIC UDP option validation, credential-alias conflicts,
  aggregate provider download accounting, and optional usage metadata parsing.
- Record current verification in the implementation-status snapshot and run the
  workspace and documentation quality gates before committing and pushing.

## Capabilities

### New capabilities

None.

### Modified capabilities

None. This change implements the existing configuration, configuration-schema,
protocol, wire-profile, state-machines, transit-proxies, ingress-control-plane,
and observability contracts. `skip_specs: true` applies while those normative
contracts remain unchanged; any necessary contract extension requires deltas
before implementation.

## Impact

Policy parsing and compilation, Path admission and Session runtime, Egress
supervision, Transit import/fetch/adapters, Ingress observations and Web Gateway,
regression tests, and implementation evidence. Existing native-host,
cross-machine, production monitoring, and long-running validation tasks retain
their distinct acceptance evidence.
