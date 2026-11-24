# Design

## Context

`crates/pathchordctl/src/main.rs` currently chooses one path from
`XDG_RUNTIME_DIR` or `/run/pathchord`, connects once, and renders every
successful response with `serde_json::to_string_pretty`. Ingress and Egress
also resolve defaults independently. Service packaging uses `/run/pathchord`
on Linux and `/var/run/pathchord` on FreeBSD, while regular users may run a
daemon under `$XDG_RUNTIME_DIR/pathchord` or `~/.config/pathchord`. The shared
configuration crate already contains account classification logic that can
guide the client, but the standalone client does not reuse it consistently.

The redesign is an operator-facing CLI change. It does not change the local
control envelope, authorization capabilities, request IDs, generation checks,
or the meaning of status and enrollment operations.

## Goals / Non-Goals

**Goals:**

- Resolve the selected role's socket without requiring an explicit path in the
  common packaged and regular-user layouts.
- Produce concise, human-readable output by default.
- Make JSON and YAML output explicit, deterministic, and suitable for scripts.
- Establish a consistent resource-oriented command grammar and help text.
- Preserve a clear escape hatch through `--socket` and compatibility aliases.
- Give operators one effective-configuration view covering source, role,
  socket, state, credentials, identity, and permissions.

**Non-Goals:**

- Adding remote management, multiple control transports, or a shell server.
- Changing local control authentication, authorization, persistence, or wire
  protocol behavior.
- Guessing arbitrary sockets from the current working directory or recursively
  scanning the filesystem.
- Treating a stale socket path as an active endpoint without a successful
  protocol exchange.

## Decisions

### Role-aware deterministic socket discovery

The shared resolver will first select the role configuration source. An
explicit `--socket` wins. When absent, a configured `controlSocket` is tried
when the role source can be parsed. If the source is unavailable or does not
define one, the resolver tries an ordered list. On Unix it includes absolute
`$XDG_RUNTIME_DIR/pathchord/<role>.sock`,
`$HOME/.config/pathchord/<role>.sock`, `/run/pathchord/<role>.sock`, and
`/var/run/pathchord/<role>.sock` paths when applicable. Root and packaged
service users still get the packaged endpoint in the candidate list. Windows
retains the named-pipe candidate. The list is de-duplicated while preserving
order.

Discovery uses connection attempts and read-only probes to select an endpoint.
A missing or stale endpoint can be skipped during selection. After a mutation
may have been sent, use that endpoint for the operation and report an uncertain
outcome if the response is lost. Typed service errors end the operation.
Explicit `--socket` bypasses discovery. If discovery fails, report the selected
role, candidates checked, and relevant connection or probe failures.

### Resource-oriented command grammar

The canonical read commands are `get status` and `get enrollments`, with
`describe status` and `describe enrollment <ingress-id>` for detail-oriented
views. Mutations use `enroll add`, `enroll enable`, `enroll disable`,
`enroll revoke`, and `enroll delete`. Existing `status` and `enroll` forms stay
as aliases where their argument shape is unambiguous, so existing operator
commands remain usable while help and examples teach the canonical grammar.

Status and system-proxy resources address Ingress by default. Enrollment
commands and their read aliases target the Egress authorization service.
`--socket` overrides the endpoint path for the applicable role.

### Two-machine enrollment workflow

The Egress operator registers the verified Ingress public key using
`enroll add` on the Egress machine. The Ingress operator uses the local
`config create` or `config patch` command to record the independently verified
Egress ID and public key, reachable endpoints, and required Transit and
TrafficPolicy settings in the Ingress `Egress` resource. The existing managed
YAML rules apply, including full graph validation and restart reporting for
topology changes. Each operator runs their command against their local service
or configuration source.

When `--egress-id` or `--expected-generation` is omitted, read the needed
values from Egress status on the selected endpoint. Submit the mutation to
that same endpoint with the observed authorization generation and retain any
explicit arguments. Surface a generation conflict with the server's current
generation so the operator can review before retrying. Require confirmation
for revoke and delete, with explicit `--yes` for unattended use.

### Unified configuration layout and source resolution

Regular-user resources live under `~/.config/pathchord/{ingress,egress}`,
runtime sockets under `$XDG_RUNTIME_DIR/pathchord`, and state under
`~/.local/state/pathchord/{ingress,egress}`. Packaged service accounts use
`/etc/pathchord/{ingress,egress}`, `/run/pathchord`, and
`/var/lib/pathchord/{ingress,egress}` respectively. Private identities,
credential maps, authorization databases, and caches live under the role state
or private-data roots and stay outside scanned resource trees.

Resources remain recursive YAML/YML/JSON graphs. The resolver exposes the
selected source, precedence layer, path base, resolved private paths, and
permissions as one effective configuration model. Resources are primary.
CLI overrides are limited to source selection, socket selection,
logging/debugging, and explicitly temporary identity overrides.

`config init --role ingress|egress` creates one role's directories and minimal
templates. `--both` is available for same-host development. Initialization
asks whether to generate a missing identity and never performs remote
enrollment. `config validate` loads and validates the complete graph,
`config paths` prints path provenance, and `config view` prints the effective
configuration with secrets redacted by default.

`config view --reveal-secrets` is an explicit interactive-terminal operation.
It is rejected when stdout is redirected and cannot be combined with JSON or
YAML output. Private identity material is never included in a structured view.

### Declarative resource editing and adoption

Resource editing is a file operation against a directory source. The resolver
maintains one PathChord-managed `managed.yaml`. `config get` reads resources
and reports their source. Each mutation reads the complete source tree,
applies an identity-based change in memory, validates the complete graph, and
replaces `managed.yaml` atomically. Mutations require a directory source.

`config adopt <kind>/<name>` moves one resource from a user-authored YAML file
into `managed.yaml`. `config adopt --all-from <file>` is the explicit batch
form. Adoption first prints the resources to be added, the source documents to
be removed, and the resulting validation summary. It requires a second
interactive confirmation. The commit writes the new managed file and the
edited source file set as one transaction. Coordinate configuration readers and
writers with a source-level lock and durable recovery record. Recover an
interrupted transaction before the next PathChord read or edit so the daemon
and CLI consume a complete old or new bundle. Ordinary commit errors restore
the prior files before reporting failure.

The source file remains after adoption. Resource documents selected for
adoption are removed, while unrelated documents, comments, and an empty source
file are retained. The implementation must use a document-preserving YAML
editing strategy rather than serializing the entire source tree through a data
model that discards comments.

Resource edits change desired configuration only. Ingress may publish eligible
dynamic changes through its existing `ConfigHotReloader`. Static Ingress
changes and all Egress startup-only changes remain inactive until restart.
Egress's existing watcher only marks `restart_required` and does not apply the
candidate. `pathchordctl` never restarts a daemon as a side effect of editing.

### Egress-side editing boundary

An Egress source contains exactly one `EgressService`, so Egress-side
`config create`, `get`, `patch`, `delete`, and `adopt` operate only on that
resource. Creating a second service is rejected. Deleting the only service is
rejected because it would leave an invalid Egress source. A minimal authored
service contains its `bind` or `binds`; `egressId` may default from
`metadata.name`, while identity, authorization database, and control socket
paths resolve from the standard private and runtime roots. Capacity limits,
remote DNS, and Web Gateway settings remain optional startup fields.

Egress configuration commands operate on local YAML and do not connect to the
Egress control socket. Identity and authorization database fields are path
references only. The client never writes private identity material or edits the
authorization SQLite database through resource commands. Enrollment and
authorization mutations continue through the existing `enroll` operations over
the local control protocol. Every accepted Egress resource edit reports that
the desired file changed and that a restart is required.

### Explicit output selection

Add a global `--output <human|json|yaml>` and short `-o` form. `human` is the
default. Use a dedicated identity-file flag for key generation so the global
output selector has one meaning. JSON and YAML render the same normalized response data and are emitted
only when selected. Human status includes the endpoint role, service identity,
configuration generation, readiness, and bounded listener/session summaries
when present. Human enrollment output uses columns for identity, Egress,
state, generation, and labels, with a detail view for one record. Unknown or
new response fields do not break human rendering and remain available in
structured formats.

Errors remain on stderr with a non-zero exit code. Structured output mode uses a
stable error object when a response is received, while transport errors retain
the discovery diagnostics.

### Shared rendering and request layers

Keep request construction and local transport separate from command dispatch.
Normalize successful `ResponseEnvelope` results into small typed view models for
human rendering and serialize the original response envelope for JSON/YAML to
preserve fields and compatibility. Use a YAML serializer already accepted by
the workspace rather than hand-built YAML.

The effective-configuration resolver is shared by the daemons and
`pathchordctl`. It reports source and field provenance without changing the
local control envelope. Human views use bounded summaries, while structured
views preserve machine-readable field names and diagnostics.

## Risks / Trade-offs

- [Risk] Moving default state out of the working directory changes where
  development data is found. -> `config paths` reports the selected state root,
  and explicit CLI paths remain available for fixtures.
- [Risk] Parsing configuration before socket discovery can fail before a daemon
  with a custom socket is reachable. -> Discovery falls back to standard
  candidates and reports both configuration and transport diagnostics.
- [Risk] Interactive secret reveal can expose credentials on screen. -> It
  requires a terminal, rejects structured output and redirection, and never
  includes private identity material.
- [Risk] Adoption can destroy hand-authored YAML structure or comments. -> Use
  document-preserving edits, preview all removals, require a second
  confirmation, and retain the source file and unrelated documents.
- [Risk] A file edit can race with another editor or daemon reload. -> Lock the
  managed and source files, verify an expected source fingerprint before
  commit, and validate the complete graph again immediately before replacement.

## Migration Plan

Implement the shared path resolver first, then migrate daemon defaults and add
the configuration subcommands and resource adoption flow. Document `get status` and
`-o human|json|yaml` as the canonical interface. Retain current `status` and
enrollment spellings as aliases for one release cycle, and print no unsolicited
warnings that would corrupt structured output. Preserve explicit legacy paths
through CLI overrides while operators move state into the new role roots.
Update packaging manpages and both language deployment guides with the source
precedence, directory layout, candidate socket order, configuration commands,
resource adoption confirmation, restart-required reporting, and explicit
machine-output examples.
