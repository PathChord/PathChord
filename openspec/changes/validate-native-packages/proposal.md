# Proposal

## Why

Package recipes and static inspections do not establish installation or service behavior on every supported package host. Validate each native artifact before attaching packages to a release.

## What changes

Build and inspect Debian, Alpine, Arch Linux, FreeBSD and Windows NSIS packages on their native package hosts, then exercise service/configuration, upgrade, rollback and removal behavior.

## Capabilities

### New capabilities

None. This change carries over implementation/validation work for existing contracts.

### Modified capabilities

None. `skip_specs: true` applies while normative behavior is unchanged; add the relevant deltas before any required contract change.

## Impact

Existing deployment contract and packaging recipes; native package-host fixtures and evidence in the status snapshot. This change does not claim native validation from Linux-only recipe checks.
