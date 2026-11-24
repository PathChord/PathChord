# Tasks

## 1. Establish shared configuration resolution

- [x] 1.1 Define one role-aware path model for regular users and service
  accounts, covering resource roots, XDG runtime sockets, state roots, private
  credentials, and permissions. Verify unit tests cover regular, root/service,
  FreeBSD alias, and explicit-path cases.
- [x] 1.2 Reuse the shared resolver in Ingress and Egress startup, remove
  working-directory state defaults, and preserve explicit CLI paths for
  fixtures during migration. Verify daemon startup tests report the same
  effective paths for each role, including startup settings authored in the
  Ingress bundle and defaults for a minimal EgressService.
- [x] 1.3 Make configured `controlSocket` part of effective configuration and
  expose source and field provenance. Verify relative private paths resolve from
  the selected role source and remain outside scanned resource trees.
- [x] 1.4 Define the managed-resource file policy and source fingerprint/lock
  protocol. Verify `managed.yaml` is created under directory sources only and
  single-file sources are rejected by resource edit commands.

## 2. Establish the command and transport model

- [x] 2.1 Replace the single-operation parser with canonical `get`, `describe`,
  and `enroll` command trees, preserve unambiguous `status` and existing
  enrollment aliases, and verify `--help` documents the canonical forms.
- [x] 2.2 Add a role-aware socket candidate builder for Unix XDG, home-config,
  `/run`, and `/var/run` locations plus the existing Windows pipe candidate.
  Verify candidate order, absolute-path filtering, de-duplication, and explicit
  `--socket` bypass with unit tests.
- [x] 2.3 Implement connection attempts across candidates, continuing after
  connection or read-only probe failures and reporting candidate diagnostics.
  Verify stale sockets and lost mutation responses, including that no mutation
  is sent to a second endpoint after a request may have been delivered.

## 3. Implement configuration lifecycle commands

- [x] 3.1 Implement `config init --role ingress|egress` and `config init
  --both`, including templates, directory creation, overwrite protection, and
  an explicit identity-generation prompt. Verify initialization never performs
  remote enrollment and supports non-interactive test fixtures.
- [x] 3.2 Implement `config validate` using the selected source and complete
  resource graph. Verify it reports typed diagnostics without starting a daemon
  or mutating state.
- [x] 3.3 Implement `config paths` with source, provenance, role, resolved
  paths, and permission reporting. Verify private values remain redacted.
- [x] 3.4 Implement `config view` with effective resource and path rendering,
  default redaction, and interactive-terminal-only `--reveal-secrets`. Verify
  reveal is rejected for redirected stdout and JSON/YAML output.
- [x] 3.5 Implement `config create`, `get`, `patch`, and `delete` against
  `managed.yaml`. Verify complete-graph validation, identity-based selection,
  atomic replacement, expected source fingerprints, and no partial writes.
- [x] 3.6 Implement `config adopt <kind>/<name>` and
  `config adopt --all-from <file>` with preview, second confirmation,
  document-preserving source edits, comment retention, and rollback on failure.
  Verify unrelated documents and empty source files remain present. Test
  interrupted commits and recovery before daemon and CLI reads.
- [x] 3.7 Enforce Egress resource boundaries in create, patch, delete, and
  adopt. Verify one `EgressService` is accepted, a second is rejected, the
  last service cannot be deleted, omitted identity and private paths resolve
  from role defaults, and Egress edits do not open the control socket.
- [x] 3.8 Keep Egress authorization mutations on the existing `enroll` control
  operations. Verify resource editing never writes authorization database
  contents and every accepted Egress edit reports `restart required`.

## 4. Implement output modes

- [x] 4.1 Add global `--output`/`-o` parsing with `human` default and explicit
  `json` and `yaml` modes. Give key generation a dedicated identity-file flag
  and update callers. Verify invalid modes fail before any socket request.
- [x] 4.2 Add human status and enrollment views with bounded field rendering,
  detail views, and stable column headings. Verify default stdout is human
  readable and contains no serialized response envelope.
- [x] 4.3 Add JSON and YAML renderers for successful responses and typed errors,
  keeping one document on stdout and diagnostics on stderr. Verify both modes
  round-trip through parsers and preserve response fields.

## 5. Preserve operations and update documentation

- [x] 5.1 Route canonical and compatibility commands through the existing
  request builders, authorization capabilities, and generation preconditions.
  Verify local control integration tests cover Ingress status, Egress enrollment,
  system-proxy operations, and explicit sockets. Verify omitted enrollment
  arguments come from the same endpoint, stale generations fail without retry,
  and revoke and delete require confirmation or explicit `--yes`.
- [x] 5.2 Exercise the two-machine enrollment workflow in a local integration
  fixture. Verify `enroll add` writes the local Egress authorization, Ingress
  `config create` or `config patch` writes the verified peer to managed YAML,
  and the configured Ingress authenticates to Egress after startup or restart.
  Verify each command uses the corresponding local endpoint or config source.
- [x] 5.3 Update deployment and operation guides, README examples, and the
  packaged manpage in English and Simplified Chinese with command grammar,
  unified directory layout, config commands, socket candidate behavior, and
  explicit `-o json|yaml` examples. Verify the enrollment walkthrough uses
  `enroll` on Egress and `config` on Ingress.
- [x] 5.4 Reconcile the deployment and configuration-schema main specs and their
  Chinese counterparts after implementation, preserving requirement/scenario identities and reciprocal
  language switches.

## 6. Validate the change

- [x] 6.1 Add CLI tests for candidate discovery, configuration lifecycle, and
  all output modes, including stale sockets, missing sockets, typed service
  errors, redaction, and non-zero exit codes.
- [x] 6.2 Run focused daemon tests for default path consistency, source
  precedence, relative path resolution, and no working-directory state
  fallback. Verify Ingress dynamic reload and Egress restart-required detection
  remain distinct.
- [x] 6.3 Run resource-edit integration tests for managed YAML creation,
  adoption, comment preservation, stale fingerprint rejection, invalid graph
  rollback, and static-change restart reporting.
- [x] 6.4 Run `cargo fmt --all -- --check`, focused CLI tests, workspace clippy,
  and workspace tests. Record local validation separately from native-platform
  evidence.
- [x] 6.5 Run strict OpenSpec validation, `git diff --check`, and bilingual
  link, heading, and requirement/scenario checks after the main specs and guides
  are synchronized.
