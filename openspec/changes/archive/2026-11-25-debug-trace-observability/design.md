# Detailed runtime logging design

## Context

The existing diagnostic history provides stable local and authenticated wire identifiers.

## Decisions

Read the service level from PATHCHORD_LOG_LEVEL at startup. Send structured JSON
lines to stderr through a bounded queue and report queue loss. Keep TRACE frame
events out of the baseline history. Record the selected Egress endpoint index
and snapshot source.name from Transit configuration at establishment. Keep
identifiers as structured fields and preserve the existing wire exchange.

INFO is the default threshold. Normal shutdown and fatal exit use the same
schema as queued runtime logs and write synchronously at the lifecycle boundary.
Process identity joins service and runtime logs with diagnostic history.
