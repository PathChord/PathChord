# Support hundreds of Session Paths

## Why

The eight-Path implementation limit prevents an Ingress from reaching larger configured baselines even when Egress has capacity.

## What changes

Align Ingress Path-pool planning and Session attachment with a runtime capacity of 256 Paths per Session. Exercise a configured 128-Path pool across a real local Ingress and Egress.

## Impact

Ingress pool planning and the shared Session runtime implement the existing configured-baseline and bounded-resource contracts.
