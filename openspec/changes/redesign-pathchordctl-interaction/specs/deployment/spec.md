# Spec Delta

## ADDED Requirements

### Requirement: Dedicated management client

`pathchordctl` SHALL provide a role-aware, resource-oriented local management
interface for Ingress and Egress. Canonical read commands SHALL use `get` and
`describe` forms, enrollment mutations SHALL remain grouped under `enroll`,
and existing documented status and enrollment spellings SHALL remain accepted
as compatibility aliases while the redesigned interface is introduced. The
client SHALL preserve the versioned local control envelope, actor capabilities,
and generation checks.

#### Scenario: Canonical status command

- **WHEN** an operator runs `pathchordctl get status`
- **THEN** the client sends the existing status request to the Ingress endpoint
  selected by socket discovery or an explicit `--socket` and renders the result
  using the selected output mode.

#### Scenario: Compatibility status command

- **WHEN** an operator runs `pathchordctl status`
- **THEN** the client performs the same operation and endpoint selection as
  `pathchordctl get status`.

#### Scenario: Enrollment resource commands

- **WHEN** an operator reads an enrollment or runs an `enroll` mutation
- **THEN** the client addresses the local Egress authorization endpoint,
  preserves the existing authorization operation and generation precondition, and renders
  the response using the selected output mode.

#### Scenario: Enrollment resolves omitted arguments

- **WHEN** an Egress authorization mutation omits its expected generation or
  `enroll add` omits the Egress ID
- **THEN** the client reads the omitted values from the selected Egress
  endpoint and sends the mutation to that endpoint. A generation conflict
  reports the current generation and requires a fresh operator invocation.

#### Scenario: Confirm destructive authorization changes

- **WHEN** an operator requests enrollment revoke or delete
- **THEN** the client requires interactive confirmation or explicit `--yes`
  before sending the mutation.

#### Scenario: Configure an enrolled peer on Ingress

- **WHEN** an Ingress operator uses `config create` or `config patch` to
  configure a peer with a verified Egress ID, public key, and reachable endpoints
- **THEN** the client validates the complete Ingress resource graph, updates
  the local managed `Egress` YAML, and reports restart required for a topology
  change. Egress authorizations remain writable only through Egress management.

### Requirement: Local control endpoint discovery

When `--socket` is absent, `pathchordctl` SHALL try a deterministic,
role-specific list starting with the configured `controlSocket` when available,
followed by standard endpoints. The client SHALL select an endpoint before
sending a mutation. Candidates SHALL be
de-duplicated, Windows named-pipe defaults SHALL remain supported, and an
explicit `--socket` SHALL bypass discovery.

#### Scenario: Packaged runtime socket is found automatically

- **WHEN** the packaged daemon listens at `/run/pathchord/ingress.sock` and no
  explicit socket is supplied
- **THEN** `pathchordctl get status` connects to that endpoint without emitting
  a raw missing-file transport error.

#### Scenario: Standard Unix candidates are searched

- **WHEN** no explicit socket is supplied on Unix
- **THEN** the client checks, in deterministic order, the applicable
  `$XDG_RUNTIME_DIR/pathchord/<role>.sock`, `$HOME/.config/pathchord/<role>.sock`,
  `/run/pathchord/<role>.sock`, and `/var/run/pathchord/<role>.sock` paths,
  removing duplicate paths before attempting connections.

#### Scenario: FreeBSD runtime alias is found automatically

- **WHEN** the daemon listens at `/var/run/pathchord/egress.sock` and no
  explicit socket is supplied
- **THEN** an enrollment command tries that candidate after earlier candidates
  and connects successfully.

#### Scenario: Candidate failure continues discovery

- **WHEN** a candidate cannot connect or pass the read-only discovery probe
- **THEN** the client records the failure and tries the next distinct candidate.

#### Scenario: Mutation response is lost

- **WHEN** a mutation may have been sent and the response cannot be read
- **THEN** the client reports an uncertain outcome without sending that
  mutation to another candidate.

#### Scenario: Discovery failure is actionable

- **WHEN** no candidate completes the request
- **THEN** the client exits unsuccessfully and reports the selected role, every
  candidate checked, and the relevant transport failures on stderr.

### Requirement: Human and structured output modes

`pathchordctl` SHALL accept global `--output <mode>` and `-o <mode>` options
with modes `human`, `json`, and `yaml`. The default mode SHALL be `human`.
Structured JSON and YAML output SHALL be emitted only when explicitly selected,
shall represent the same response data, and SHALL remain valid as a single
machine-readable document on stdout. Human output SHALL be readable in a
terminal and SHALL include the principal status or enrollment fields without
requiring JSON parsing.

#### Scenario: Status defaults to human output

- **WHEN** an operator runs `pathchordctl get status` without `-o`
- **THEN** stdout contains the human-readable status view and is not a JSON or
  YAML serialization of the response envelope.

#### Scenario: JSON output is explicit

- **WHEN** an operator runs `pathchordctl get status -o json`
- **THEN** stdout contains one valid pretty-printed JSON document representing
  the response, and diagnostics remain on stderr.

#### Scenario: YAML output is explicit

- **WHEN** an operator runs `pathchordctl get enrollments --output yaml`
- **THEN** stdout contains one valid YAML document representing the response.

#### Scenario: Structured response error

- **WHEN** the local service returns a typed error and a structured output mode
  was selected
- **THEN** the client exits unsuccessfully and emits a stable structured error
  document in the selected format without mixing human status text into stdout.

### Requirement: Unified role configuration layout

Ingress, Egress, and `pathchordctl` SHALL use one role-aware path model for
configuration resources, runtime sockets, state, and private credentials.

#### Scenario: Regular-user paths

- **WHEN** a regular Unix account uses defaults
- **THEN** resources use `~/.config/pathchord/{ingress,egress}`, sockets use
  `$XDG_RUNTIME_DIR/pathchord`, and role state uses
  `~/.local/state/pathchord/{ingress,egress}`.

#### Scenario: Packaged service paths

- **WHEN** a packaged service account uses defaults
- **THEN** resources use `/etc/pathchord/{ingress,egress}`, sockets use
  `/run/pathchord`, and role state uses `/var/lib/pathchord/{ingress,egress}`.

#### Scenario: No working-directory state fallback

- **WHEN** no explicit state path is supplied
- **THEN** the daemon resolves state from the role path model and does not
  create default state relative to the current working directory.

### Requirement: Configuration lifecycle commands

`pathchordctl` SHALL provide role-aware `config init`, `validate`, `paths`, and
`view` commands for creating, checking, and explaining effective configuration.

#### Scenario: Role initialization

- **WHEN** an operator runs `config init --role ingress` or `--role egress`
- **THEN** the client creates missing role directories and templates, asks
  whether to generate a missing identity, and performs no remote enrollment.

#### Scenario: Development initialization

- **WHEN** an operator runs `config init --both`
- **THEN** the client creates both role layouts for same-host development and
  clearly identifies the result as a development setup.

#### Scenario: Configuration validation

- **WHEN** an operator runs `config validate`
- **THEN** the client validates the complete selected resource graph and
  reports source, resource, path, and field diagnostics without starting a
  daemon.

#### Scenario: Effective paths are inspectable

- **WHEN** an operator runs `config paths`
- **THEN** the client reports each effective path, its source or precedence
  layer, role, and relevant filesystem permission state.

### Requirement: Configuration-first startup overrides

Resources SHALL be the primary startup configuration source. CLI overrides SHALL
be limited to source selection, socket selection, logging/debugging, and
explicitly temporary identity overrides.

#### Scenario: Resource values are effective defaults

- **WHEN** a resource and a matching default are both present
- **THEN** the resource value is used and the effective view identifies its
  resource provenance.

#### Scenario: Temporary identity override

- **WHEN** an operator supplies an explicit temporary identity override
- **THEN** it takes precedence for that invocation and the authored resource is
  not modified.

### Requirement: Effective configuration secret handling

`config view` SHALL redact secrets by default and SHALL restrict secret reveal
to an explicit interactive-terminal operation.

#### Scenario: Default configuration view is redacted

- **WHEN** an operator runs `config view` without a reveal option
- **THEN** secret values and private identity material are omitted or redacted.

#### Scenario: Secret reveal requires an interactive terminal

- **WHEN** an operator requests `config view --reveal-secrets`
- **THEN** the client permits it only when stdout is an interactive terminal,
  rejects JSON/YAML output and redirection, and never emits private identity
  material.

### Requirement: Declarative resource editing

Resource edit commands SHALL update a managed YAML resource file after complete
resource-graph validation and SHALL never directly mutate runtime state.

#### Scenario: Create a managed resource

- **WHEN** an operator runs `config create` for a valid resource against a
  directory source
- **THEN** the client validates the complete candidate, atomically updates
  `managed.yaml`, and reports the file change and restart or reload requirement.

#### Scenario: Patch or delete a resource

- **WHEN** an operator runs `config patch` or `config delete` for a resource
  identity
- **THEN** the client applies the identity-based change to `managed.yaml`,
  rejects unresolved references or duplicates, and leaves all files unchanged
  when validation fails.

#### Scenario: Single-file source is read-only for resource editing

- **WHEN** an operator requests a resource edit while the selected source is a
  single configuration file
- **THEN** the client refuses the edit and instructs the operator to migrate to
  a directory source first.

### Requirement: User-resource adoption

The client SHALL support explicit adoption of user-authored resources into the
managed YAML file while preserving unrelated source content.

#### Scenario: Adopt one resource

- **WHEN** an operator runs `config adopt <kind>/<name>`
- **THEN** the client previews the managed addition and source removal, requires
  a second confirmation, then commits both sides only after full validation.

#### Scenario: Adopt all resources from one file

- **WHEN** an operator runs `config adopt --all-from <file>`
- **THEN** the client previews every selected resource and requires explicit
  confirmation before moving them into `managed.yaml`.

#### Scenario: Adoption preserves source organization

- **WHEN** selected resources are adopted from a user-authored file
- **THEN** only those resource documents are removed, while unrelated
  documents, comments, and an empty source file remain present.

#### Scenario: Adoption failure is atomic

- **WHEN** validation, permission, fingerprint, or replacement checks fail
- **THEN** neither the managed file nor source files are changed and the client
  reports the failed check.

#### Scenario: Interrupted adoption is recovered

- **WHEN** adoption is interrupted while replacing files
- **THEN** the next PathChord configuration load or edit recovers a complete
  pre-adoption or post-adoption bundle before consuming it.

### Requirement: Static configuration activation reporting

Configuration edits SHALL report desired-file changes separately from active
runtime activation and SHALL never restart a daemon implicitly.

#### Scenario: Static Egress edit

- **WHEN** an Egress startup field is changed through a managed resource edit
- **THEN** the file is updated after validation, the active runtime is left
  unchanged, and the result reports `restart required`.

#### Scenario: Ingress dynamic edit

- **WHEN** an eligible dynamic Ingress resource is edited
- **THEN** the existing Ingress reload path may publish it, while static edits
  retain their restart requirement.

#### Scenario: Egress watcher observes an edit

- **WHEN** an Egress source file changes while Egress is running
- **THEN** its watcher marks restart required and does not apply the candidate
  to the active runtime.

### Requirement: Egress resource editing boundary

Egress configuration editing SHALL operate only on the single `EgressService`
resource and SHALL remain separate from Egress authorization control operations.

#### Scenario: Minimal EgressService edit

- **WHEN** an operator creates or patches an Egress source with one
  `EgressService` containing `bind` or `binds`
- **THEN** the client accepts the resource graph, resolves omitted service
  identity and private paths from the role defaults, and reports restart status.

#### Scenario: Second EgressService is rejected

- **WHEN** an operator attempts to create an `EgressService` while the selected
  source already contains one
- **THEN** the edit is rejected and the managed file remains unchanged.

#### Scenario: Last EgressService cannot be deleted

- **WHEN** an operator attempts to delete the only `EgressService` in an Egress
  source
- **THEN** the edit is rejected because the resulting source would be invalid.

#### Scenario: Egress edit does not use control protocol

- **WHEN** an operator edits Egress binds, identity paths, resource limits,
  DNS behavior, or Web settings
- **THEN** the client updates YAML locally without connecting to the Egress
  control socket and reports `restart required`.

#### Scenario: Authorization remains a control operation

- **WHEN** an operator enrolls, enables, disables, revokes, or deletes an
  Ingress authorization
- **THEN** `pathchordctl` uses the existing Egress control operation and does not
  encode the authorization database contents in `EgressService` YAML.
