# Proposal

## Why

The existing final-state contracts exceed the conservative runtime budgets and available observation producers. Complete the already documented scheduling/accounting and deployed monitoring work while preserving unknown measurements as unknown.

## What changes

Add independent per-policy/class accounting, Egress budget coordination, measured scheduler inputs, missing typed observations, and monitoring/alert/dashboard integration. Keep conservative replication behavior until budget agreement is established.

## Capabilities

### New capabilities

None. This change carries over implementation/validation work for existing contracts.

### Modified capabilities

None. `skip_specs: true` applies while normative behavior is unchanged; add the relevant deltas before any required contract change.

## Impact

Existing protocol, state-machines, configuration, observability and ingress-control-plane contracts; scheduler/control/observation runtime and deployment evidence. If a new wire field or observable semantic change is needed, add the affected spec deltas before implementation.
