# Parallel Path refill

## Why

Serial dials can leave an established Session below its Path target while a slow Transit attempt occupies the next refill opportunity.

## What changes

Fill the current Path deficit with concurrent attempts and one speculative attempt when capacity permits. Retain successful excess Paths for normal scale-in.

## Capabilities

### Modified capabilities

- `state-machines` defines concurrent Path refill and temporary surplus.

## Impact

Ingress Path maintenance and integration tests.
