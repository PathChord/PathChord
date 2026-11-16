# Tasks

## 1. Extract shared foundations

- [ ] 1.1 Add separate Cargo packages for the role service binaries and the
  management client, define the intended dependency graph, and verify with
  `cargo metadata --locked` that the packages have no dependency cycle and that
  the Egress binary package does not depend on `pathchord-ingress`.
- [ ] 1.2 Move configuration source selection, bounded resource-file loading,
  relative-path resolution, and common configuration errors into a shared
  configuration crate; preserve Ingress complete-bundle behavior and verify
  source precedence, directory bounds, and path-resolution unit tests pass.
- [ ] 1.3 Add the role-aware configuration parser that accepts exactly one
  `EgressService`, rejects Ingress-only resource kinds, retains CLI overrides,
  and keeps the explicit CLI-only startup path when no resource source is
  selected; verify focused schema tests cover zero, one, and multiple service
  resources and typed rejection diagnostics.
- [ ] 1.4 Move the local envelope transport, Unix socket/Named Pipe server,
  request deadlines, shared authentication plumbing, and optional Web Gateway
  into a shared control crate with a narrow dispatcher trait; verify existing
  control envelope, timeout, redaction, and Web Gateway authorization tests
  pass without importing either service runtime.

## 2. Create the dedicated executables

- [ ] 2.1 Implement `pathchord-ingressd` argument parsing and startup by
  moving the current Ingress lifecycle behind the shared configuration and
  control foundations; verify `pathchord-ingressd --help` works and the direct
  loopback configuration starts an HTTP/SOCKS listener in its own process.
- [ ] 2.2 Implement `pathchord-egressd` argument parsing and startup around
  `EgressNode`, authorization storage, target forwarding, and Egress control;
  verify it starts without TUN access or `CAP_NET_ADMIN`/`CAP_NET_RAW` and its
  release dependency tree contains no Ingress runtime package or Ingress-only
  platform dependency.
- [ ] 2.3 Refactor the current CLI package into `pathchordctl`, retaining
  status, enrollment, key generation, explicit socket selection, role-aware
  defaults, and Ingress system-proxy operations while removing the unreleased
  `ingress` and `egress` service subcommands; verify parser and local-control
  tests cover both role sockets and expected authorization generations.
- [ ] 2.4 Preserve service shutdown, identity permission checks, control socket
  ownership, and typed error behavior in each new entry point; verify signal
  handling and startup-failure tests show that a failed role startup does not
  open its listener or mutate its durable state.

## 3. Apply role-specific configuration and isolation

- [ ] 3.1 Define and implement separate Ingress and Egress default
  configuration, runtime-state, identity, authorization, credential, and
  control-socket roots while retaining explicit CLI and environment precedence;
  verify path-resolution tests cover regular-user, service-account, and
  explicitly selected sources.
- [ ] 3.2 Update Egress startup/reload handling so service-only configuration
  changes report restart required and never partially replace an active Egress
  runtime; verify invalid, unreadable, and startup-only candidates leave the
  running listener and authorization database unchanged.
- [ ] 3.3 Apply role-specific service users/ACLs and capability/device
  restrictions in the runtime model and package metadata; verify Egress has no
  TUN device access or network-administration capability requirements while
  Ingress retains the documented privileges for transparent/TUN modes.
- [ ] 3.4 Update configuration examples and fixtures to use separate role
  sources, preserve explicit enrollment and independent private identities, and
  remove shared-bundle Egress examples; verify every example parses with the
  role that consumes it.

## 4. Update packaging and documentation

- [ ] 4.1 Update Debian, Alpine, Arch, FreeBSD, and Windows package recipes to
  install `pathchord-ingressd`, `pathchord-egressd`, and `pathchordctl`, and
  start each service executable directly with role-specific roots and sockets;
  verify package inventory and service-definition checks cover every named
  target.
- [ ] 4.2 Update installer/uninstaller behavior, system users, runtime/state
  directories, manpage content, and service restart/rollback procedures for the
  three artifacts; verify shell syntax, Windows script/XML validation, and
  generated package file lists pass where host tooling is available.
- [ ] 4.3 Update `docs/design/architecture.md` and its Chinese counterpart,
  deployment/configuration guides, README command examples, and the affected
  OpenSpec main-spec wording to describe dedicated binaries, role-scoped
  Egress configuration, and the separate management client; verify reciprocal
  language switches, links/anchors, technical examples, and bilingual meaning
  remain aligned.
- [ ] 4.4 Update `openspec/implementation-status.md` with the implemented
  artifact/configuration boundaries and separate local, cross-build, native,
  and deployed validation evidence; verify the snapshot does not claim native
  or deployed checks that were not performed.

## 5. Validate the release boundary

- [ ] 5.1 Add end-to-end local tests that start the dedicated Ingress and
  Egress processes, enroll an Ingress identity through `pathchordctl`, establish
  authenticated Noise/Path Sessions, and exercise TCP plus UDP target
  forwarding; verify process-specific sockets and state roots are used.
- [ ] 5.2 Add negative-path tests for Egress resources containing Listener,
  TransitProxy, Subscription, routing, DNS, fallback, or geodata objects and
  for zero/multiple `EgressService` resources; verify typed validation failures
  occur before public bind or authorization-store mutation.
- [ ] 5.3 Add dependency and artifact checks that compare Egress and Ingress
  release binaries, assert the Egress dependency/symbol surface excludes
  Ingress-only runtime components, and verify all three binaries report the
  same release and protocol revision.
- [ ] 5.4 Run the workspace quality gates
  (`cargo fmt --all -- --check`, `cargo clippy --locked --workspace
  --all-targets -- -D warnings`, and `cargo test --locked --workspace
  --all-targets`) plus focused package and process smoke tests; record native
  host, privileged Linux, cross-platform, provider, and deployed checks
  separately from local evidence.
- [ ] 5.5 Run `openspec validate --all --strict --no-interactive`,
  `git diff --check`, and the repository Markdown heading/link/language-pair
  checks; verify the change's proposal, both capability deltas, design, tasks,
  and updated documentation are internally consistent and ready for archive.
