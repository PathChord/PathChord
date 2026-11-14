# Tasks

These pending tasks were carried over from the implementation plan during the
2026-11-14 documentation migration; their presence supplies no completion evidence.

## 1. Native artifacts

- [ ] 1.1 Build/install the Debian package on its package host; inspect metadata, binary, pathchord(1), systemd units, service identity and /etc/pathchord template, then verify start/stop and local control.
- [ ] 1.2 Build/install the Alpine package with native tooling; inspect metadata, binary, pathchord(1), OpenRC definitions and /etc/pathchord template, then verify service lifecycle and local control.
- [ ] 1.3 Build/install the Arch Linux package with native tooling; inspect metadata, binary, compressed manual, systemd/sysusers/tmpfiles payload and default template, then verify installed service behavior.
- [ ] 1.4 Build/install the FreeBSD package using native pkg/ports tooling; inspect metadata, binary, manual, rc.d script, /usr/local/etc/pathchord paths and socket permissions, then verify service and local control.
- [ ] 1.5 Build/install the Windows NSIS artifact with native tooling; inspect binary, manual, service definitions and %ProgramData%\PathChord\config defaults, then verify installer/service agreement and Named Pipe control.

## 2. Upgrade and release evidence

- [ ] 2.1 Exercise upgrade, rollback and uninstall on each package host with sentinel operator configuration, identity and authorization state; verify service recovery and preservation of private data.
- [ ] 2.2 Record artifact metadata, host/tool versions, repository revision and native results in openspec/implementation-status.md; verify every release candidate has target-specific evidence and unresolved targets remain unverified.
