# Tasks

These pending tasks were carried over from the implementation plan during the
2026-11-14 documentation migration; their presence supplies no completion evidence.

## 1. Native artifacts

- [x] 1.1 Build/install each Debian role package on its package host; inspect metadata, selected daemon and management client, pathchord(1), matching systemd unit, service identity and /etc/pathchord template, then verify start/stop, local control and opposite-role rejection.
- [x] 1.2 Build/install each Alpine role package with native tooling; inspect metadata, selected daemon and management client, pathchord(1), matching OpenRC definition and /etc/pathchord template, then verify service lifecycle, local control and opposite-role rejection.
- [x] 1.3 Build/install each Arch Linux role package with native tooling; inspect metadata, selected daemon and management client, compressed manual, matching systemd/sysusers/tmpfiles payload and default template, then verify service behavior and opposite-role rejection.
- [x] 1.4 Build/install each FreeBSD role package using native pkg/ports tooling; inspect metadata, selected daemon and management client, manual, matching rc.d script, /usr/local/etc/pathchord paths and socket permissions, then verify service, local control and opposite-role rejection.
- [ ] 1.5 Build/install each Windows NSIS role artifact with native tooling; inspect selected daemon and management client, manual, matching service definition and %ProgramData%\PathChord\config defaults, then verify installer/service agreement, Named Pipe control and opposite-role rejection.

## 2. Upgrade and release evidence

- [x] 2.1 Exercise each role's upgrade, rollback and uninstall, plus explicit role replacement, on each package host with sentinel operator configuration, identity and authorization state; verify service recovery and preservation of private data.
- [x] 2.2 Record artifact metadata, host/tool versions, repository revision and native results in openspec/implementation-status.md; verify every release candidate has target-specific evidence and unresolved targets remain unverified.
