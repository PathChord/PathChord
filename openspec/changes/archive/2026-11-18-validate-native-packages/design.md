# Design

## Context

The recipes provide mutually exclusive Ingress and Egress packages, a pathchord(1) manual and role-specific configuration. Each package installs only the selected daemon and `pathchordctl`; Unix uses the local non-login `pathchord` account. Host tooling and native-service acceptance are separate from artifact assembly. See the [package guide](../../../../packaging/README.md), [deployment contract](../../../specs/deployment/spec.md) and [status](../../../implementation-status.md).

## Goals / non-goals

Validate every named native target, installed payload and service lifecycle. Do not broaden platform protocol support or release packages merely because a recipe parses.

## Decisions

Run both role profiles for Debian, Alpine, Arch Linux, FreeBSD and NSIS independently with the intended service account and filesystem permissions. Inspect artifact metadata, selected daemon and management client, manual, service definition and default configuration, including absence of the opposite role. Linux/Alpine use /etc/pathchord; the FreeBSD port uses /usr/local/etc/pathchord; the Windows service and installer agree on %ProgramData%\PathChord\config. Preserve loopback defaults, reject opposite-role coexistence before mutation, and verify upgrade/rollback and explicit role replacement do not overwrite private operator state.

Run platform listener/control acceptance with the native-platform change where appropriate, while reporting packaging, target linking and runtime evidence separately. Release attachment follows successful native acceptance rather than this planning artifact.

## Risks / trade-offs

- A valid archive can still install incorrect service paths → inspect installed service commands and execute start/stop under the service identity.
- Upgrade/removal can destroy private state → test with isolated fixtures containing sentinel configuration, identity and authorization data.
