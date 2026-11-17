# Proposal

## Why

PathChord currently runs Ingress and Egress as separate service processes but
publishes one multi-call executable that links both roles. This makes the
Egress artifact carry Ingress-only proxy protocols, subscription handling,
transparent interception, TUN/eBPF support, and platform adapters even though
Egress only needs authenticated Path/Session forwarding, target connections,
authorization, and resource protection.

The project has not released 0.1.0, so it can establish a clean artifact and
configuration boundary without preserving the unreleased `pathchord ingress`
and `pathchord egress` service subcommands. The change reduces Egress's build,
runtime, and security surface while retaining the existing wire and control
protocol contracts.

## What Changes

- **BREAKING** Publish dedicated `pathchord-ingressd` and
  `pathchord-egressd` service executables instead of one service executable
  selected by `ingress` and `egress` subcommands.
- Publish a role-neutral `pathchordctl` management client for status,
  enrollment, key generation, and other local control operations. Do not add a
  compatibility wrapper for the unreleased multi-call service entry point.
- Extract configuration-source/schema loading and local control transport
  primitives from the Ingress crate into shared crates that Egress can use
  without linking Ingress listeners or platform interception code.
- **BREAKING** Give Egress a role-specific configuration source containing its
  `EgressService` settings and private service paths; Ingress continues to own
  the complete policy resource graph and its reload behavior.
- Keep Egress authorization, identity, control socket, and target forwarding
  independent from Ingress state, credentials, listener resources, and data
  directories.
- Update Cargo targets, package contents, service definitions, installers,
  documentation, and validation so each service starts its dedicated
  executable with role-specific privileges and paths. A package installs exactly
  one selected role and the management client; opposite-role packages conflict.
- Use the local non-login `pathchord` account for the selected Unix service.
  Ingress clients and Egress hosts are separate devices in the supported
  deployment model; simultaneous packaged roles on one system are outside it.
- Publish the role packages and management client in one versioned release with
  matching wire and control protocol revisions; each installed package upgrades
  its selected daemon and management client together. This change does not
  introduce independent rolling-version compatibility.

## Capabilities

### New Capabilities

<!-- No new capability is introduced; the existing deployment and configuration
     contracts own the changed behavior. -->

### Modified Capabilities

- `deployment`: Service artifacts, role-specific executable ownership,
  management-client invocation, single-role installation, and service privileges
  change.
- `configuration-schema`: Egress configuration sources and the allowed
  Egress-only resource subset change while Ingress retains complete-bundle
  validation.

## Impact

The Rust workspace will gain dedicated binary targets and shared configuration
and control crates. `pathchord-ingress` will retain local listeners,
transparent/TUN platform support, Transit Proxy adapters, subscriptions, DNS,
and policy runtime code. `pathchord-egress` will retain Noise/Path admission,
TCP/UDP target forwarding, authorization storage, and global resource limits
without depending on Ingress runtime modules.

The control socket protocol, authorization operation registry, Noise enrollment,
Session/Path wire behavior, and per-Path trust model remain unchanged. Debian,
Alpine, Arch, FreeBSD, and Windows packaging must install and start only the
selected role binary plus the management client. Existing guides, the English and
Chinese deployment/configuration documents, and the implementation status
snapshot must be updated together with the authoritative capability deltas.
