# Design

## Context

See `proposal.md` for the motivation and externally visible scope. The current
workspace already separates most protocol and runtime responsibilities into
`pathchord-ingress` and `pathchord-egress` libraries, but one `pathchord-cli`
binary links both libraries and dispatches the `ingress` and `egress` service
subcommands. Egress startup also reaches into the Ingress crate for resource
loading, local control serving, and the optional Web Gateway.

The deployment and configuration deltas in this change preserve the existing
Noise, Session, Path, authorization, local control envelope, and per-Path
identity contracts. They change the executable and configuration boundaries
around those contracts.

## Goals / Non-Goals

**Goals:**

- Build an Egress service artifact whose dependency closure excludes Ingress
  listener, Transit Proxy, subscription, TUN, transparent-proxy, and eBPF
  runtime code.
- Build an Ingress service artifact with the listener and platform features it
  advertises, without making those features available through Egress.
- Provide one dedicated management client that can address either local
  control endpoint without starting a service.
- Make Egress configuration role-scoped and independent from the Ingress
  policy graph while preserving common schema validation and source precedence
  rules.
- Keep the two services separately permissioned and separately packaged while
  releasing them in one versioned bundle.
- Remove the unreleased multi-call service entry point completely rather than
  maintaining a compatibility wrapper.

**Non-Goals:**

- Changing the authenticated wire profile, Noise handshake, Session/Path
  state machine, Stream or UDP semantics, enrollment protocol, or Egress
  resource accounting.
- Allowing arbitrary independent rolling versions of Ingress and Egress.
- Adding remote management, a new management transport, or new Transit Proxy
  protocols.
- Making Ingress and Egress share private identities, authorization stores,
  runtime databases, listener state, or credential files.

## Decisions

### Separate binary packages enforce the dependency boundary

Create dedicated binary packages for `pathchord-ingressd` and
`pathchord-egressd`, each depending on the corresponding runtime library and
the small set of shared crates. Keep binary targets in separate packages rather
than adding multiple targets to the current all-in-one `pathchord-cli` package;
otherwise Cargo's package dependency graph and feature selection can continue
to compile or link the Ingress dependency closure for Egress.

The existing `pathchord-ingress` and `pathchord-egress` libraries remain the
role runtime libraries. Binary packages own argument parsing, identity loading,
service startup, signal handling, and role-specific error presentation.

### Make the management client a separate executable

Refactor the current CLI package into `pathchordctl`. It retains request
builders, local control transport, `status`, `enroll`, `keygen`, and
Ingress-specific system-proxy commands, but it no longer links either service
runtime. The client accepts an explicit socket and provides role-aware defaults
for Ingress and Egress; enrollment defaults to Egress while status and
system-proxy operations default to Ingress.

Keeping management separate avoids placing authorization mutation code in the
Ingress service or listener/platform code in the Egress service. It also makes
the distinction between starting a service and operating an existing service
explicit in the command surface.

### Extract only the shared control and configuration foundations

Create a shared configuration crate for source selection, bounded file/directory
discovery, path resolution, and resource-document loading. Ingress uses the
existing complete-bundle parser and compiler. Egress uses a role-specific
parser that accepts exactly one `EgressService` and rejects Ingress-only
resources before runtime startup.

Create a shared control crate for the versioned local envelope transport,
Unix socket/Named Pipe server, request deadlines, common authentication
plumbing, and the optional Web Gateway. Ingress-specific observations,
subscriptions, listeners, and system-proxy state remain in the Ingress runtime;
Egress-specific authorization dispatch remains in the Egress runtime. The
shared server depends on a narrow management-dispatch trait rather than either
role's runtime crate.

Do not move protocol or policy behavior into the shared layer merely to reduce
the number of crates. The shared layer is limited to code that both roles must
run to expose their already-defined local control contracts.

### Use separate configuration and state roots

Use role-specific default roots and package layouts, for example:

```text
/etc/pathchord/ingress/
/etc/pathchord/egress/
/var/lib/pathchord-ingress/
/var/lib/pathchord-egress/
/run/pathchord/ingress.sock
/run/pathchord/egress.sock
```

Regular-user defaults use corresponding per-role subdirectories under the
user's configuration and runtime directories. Explicit `--config`,
`--config-dir`, `PATHCHORD_CONFIG`, and `PATHCHORD_CONFIG_DIR` retain their
precedence semantics for the selected role. The Egress source may be omitted
only when all required Egress startup values are supplied explicitly; when a
resource source is selected, it must satisfy the Egress-only contract.

Egress private identity, authorization database, control socket, and optional
Web bearer token remain outside the resource documents. Ingress credentials,
subscription caches, platform journals, and listener state remain under
Ingress-owned roots. Relative paths in each role's resource source resolve
against that source, never against the process working directory.

### Align service privileges with the artifact boundary

The Egress service unit has no TUN device access and no `CAP_NET_ADMIN` or
`CAP_NET_RAW` requirement. Its filesystem policy permits only the Egress
configuration, identity, authorization database, control socket directory, and
required logs/state. The Ingress unit owns listener and platform resources and
receives only the capabilities required by its configured interception mode.

Linux service definitions, Alpine/OpenRC scripts, FreeBSD rc.d scripts, and
Windows service definitions all start the dedicated executable directly. The
package installs separate service users or equivalent ACLs where the platform
supports them; at minimum, the role-owned private roots remain inaccessible to
the other service.

### Release both services as one compatibility unit

The release contains `pathchord-ingressd`, `pathchord-egressd`, and
`pathchordctl` with one version and one protocol revision. Package upgrades
replace the role binaries and client together. The design does not claim
zero-downtime or arbitrary cross-version operation: a restarted service still
invalidates its related Session and Paths, and a protocol revision mismatch
must fail during normal capability negotiation rather than silently downgrade.

## Risks / Trade-offs

- **[Risk]** Existing development configurations put Ingress and Egress
  resources in one directory. **Mitigation:** update all examples, package
  defaults, and validation fixtures before the unreleased 0.1.0 boundary; the
  new role-specific source rejects accidental cross-role resources.
- **[Risk]** Moving local control and configuration code can change socket,
  deadline, redaction, or generation behavior. **Mitigation:** preserve the
  existing control envelope and operation registry, add shared transport
  contract tests, and run the current Ingress and Egress management suites
  against the new binaries.
- **[Risk]** Egress still accidentally links Ingress code through a broad
  shared crate. **Mitigation:** make dependency-tree and release-symbol checks
  explicit acceptance tests; keep Ingress-only dependencies out of the shared
  crate's manifest.
- **[Risk]** Separate artifacts make package recipes and platform service
  definitions easier to drift. **Mitigation:** use one package inventory test
  for Debian, Alpine, Arch, FreeBSD, and Windows and verify each service's
  executable, root paths, socket, and privilege settings.
- **[Risk]** A partial upgrade leaves one role at a different protocol revision.
  **Mitigation:** publish the binaries as one release bundle, record the shared
  revision in package metadata, and test clean upgrade and rollback as a
  bundle.
- **[Risk]** Removing the unreleased multi-call entry point breaks local scripts
  used during development. **Mitigation:** update repository scripts, examples,
  CI, and package checks in the same change; no production compatibility shim
  is required before 0.1.0.

## Migration Plan

1. Add the shared configuration and control crates with contract-preserving
   tests and move the common implementations out of `pathchord-ingress`.
2. Add the two dedicated service binary packages and refactor the current
   runtime startup paths into their role-specific mains.
3. Refactor the management package into `pathchordctl`, remove the old
   `Command::Ingress` and `Command::Egress` service dispatch, and update all
   local callers and fixtures.
4. Add role-specific Egress parsing and source validation, split default
   configuration/state roots, and update resource examples.
5. Update package recipes, service definitions, installers, manpage content,
   guides, and bilingual design/spec documents. Remove references to the
   multi-call service executable.
6. Validate dependency closure, release artifacts, local control operations,
   direct Noise/Path forwarding, platform service definitions, and rollback of
   the complete release bundle.
7. Update `openspec/implementation-status.md` with local build/test evidence
   and clearly separate any native-host or deployed validation that remains.

## Open Questions

None. Binary names, the absence of a compatibility wrapper, the separate
management client, role-scoped Egress configuration, and same-bundle release
policy are fixed by this design and the user's pre-0.1.0 scope.
