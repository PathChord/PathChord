# Proposal

## Why

`pathchordctl` currently assumes one default Unix socket path and reports a raw
`No such file or directory` transport error when the daemon uses another
standard runtime location. Its successful responses are always pretty-printed
JSON, and service defaults, private paths, and configuration discovery are not
resolved through one operator-visible model. The command surface also exposes
implementation operations rather than a predictable resource-oriented workflow
familiar to operators of tools such as `kubectl`.

## What Changes

- Redesign `pathchordctl` around resource-oriented commands with stable
  `get`, `describe`, and mutation verbs while retaining explicit compatibility
  aliases for the currently documented operations during the transition.
- Establish one role-aware configuration layout for regular users and service
  accounts, separating authored resources, runtime sockets, state, and private
  credentials with XDG-compatible paths for regular users.
- **BREAKING** Make resources the primary source for startup configuration and limit CLI
  overrides to source selection, socket selection, logging/debugging, and
  explicitly temporary identity overrides.
- Add `pathchordctl config init`, `validate`, `paths`, and `view` commands.
  Initialization creates role-scoped directories and templates, validation
  reports complete-graph diagnostics, and path/view commands expose the
  effective configuration without leaking secrets by default.
- Add declarative resource commands for `config create`, `get`, `patch`, and
  `delete`. These commands update a PathChord-managed `managed.yaml` in a
  directory source after complete-graph validation.
- Add explicit resource adoption from user-authored YAML with
  `config adopt <kind>/<name>` and `config adopt --all-from <file>`. Adoption
  previews both sides, requires a second confirmation, moves the selected
  resources into `managed.yaml`, and removes only those resource documents from
  the source while retaining the source file, remaining resources, and comments.
- Constrain Egress-side resource editing to its single `EgressService` resource.
  Egress configuration edits remain YAML operations, report `restart required`,
  and leave authorization database mutations to the existing `enroll` control
  operations.
- Use `config` resource commands to author the local `Egress` resource on
  Ingress. Reserve `enroll` for local authorization operations on Egress.
  Resolve omitted authorization generations and Egress IDs from the selected
  service and preserve explicit preconditions for scripts.
- **BREAKING** Add a global `--output`/`-o` selector with `human` as the default and explicit
  `json` and `yaml` serializers. Human output is intended for terminals and
  remains stable enough for ordinary operator use, while machine formats are
  selected deliberately.
- Make the client discover an available local control socket for the selected
  role. Explicit `--socket` always wins, a configured `controlSocket` is tried
  before standard candidates, and a failed discovery error lists the locations
  checked and the role being addressed.
- Keep control-envelope authentication, generation preconditions, explicit
  enrollment, and the separate Ingress and Egress endpoints unchanged.
- Update tests, manpages, guides, README examples, and the deployment contract
  to document the new command and output behavior.

## Capabilities

### Modified Capabilities

- `deployment`: local management client endpoint discovery, command interaction,
  and output behavior change.
- `configuration-schema`: authored service settings and Egress startup
  override rules change.

## Impact

The `pathchordctl` binary will gain a command parser, effective-configuration
resolver, socket discovery layer, configuration lifecycle and adoption
commands, resource-oriented renderers, and human-readable status and
enrollment views. Ingress and Egress startup will share path and source-selection
primitives. Ingress file watching and Egress restart detection will retain their
different activation semantics. Egress-side edits will address one
`EgressService` and will not use the Egress control socket.
Existing local control requests and response envelopes remain the wire contract.
Scripts that require structured output must pass `-o json` or `-o yaml`.
Packaging and service socket locations remain supported, including Linux
`/run` and `/var/run` aliases and per-user XDG runtime locations.
