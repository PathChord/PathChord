# Unix control group access

## Why

Packaged Unix services need to let trusted local operators use their control socket with ordinary group membership.

## What changes

- Grant local management through ownership of the Unix control socket and membership in its group.
- Prepare packaged runtime directories for group access and keep private state and socket locks owner-only.

## Capabilities

### Modified capabilities

- `ingress-control-plane` defines Unix socket mode and group admission.

## Impact

Unix Ingress and Egress control, Unix role packages, deployment guides, and permission checks.
