# Design

## Context

The current `FlowMatch` model contains `targetHosts`; `CompiledMatch` compares hostnames case-insensitively and exactly. The listener target is an enum containing either the original hostname or original IP. DNS is independently routed, and the existing configuration loader publishes a validated generation atomically. Configuration directory discovery scans YAML and JSON resource documents with a 4 MiB combined resource limit, so geodata belongs in external `.dat` files rather than inline resources. See `proposal.md` for the motivation.

## Goals / Non-Goals

**Goals:**

- Consume official V2Fly protobuf releases from domain-list-community and v2fly/geoip without generating their data on the Ingress host.
- Resolve and compile named sets as part of the same policy generation as the rules that reference them, with bounded memory and stable errors.
- Preserve original-target and DNS routing boundaries on every TCP and UDP ingress path.

**Non-Goals:**

- Download, schedule, or authenticate database updates automatically; operators control provisioning, verification and replacement.
- Infer geolocation for a hostname by initiating DNS during rule evaluation, or infer a hostname from an IP.
- Change PathChord's Session or wire protocol, or claim compatibility with arbitrary vendor-specific geodata formats.

## Decisions

### Local V2Fly release databases

Define one namespace-scoped `GeoSiteDatabase` and one `GeoIpDatabase` resource, each pointing to an explicit local `.dat` file. Decode the published `GeoSiteList` and `GeoIPList` structures rather than raw `data/` source files. The upstream build already resolves `include`, selective attributes and affiliations; parsing source files directly would duplicate that logic and risk a different set. Support all four domain types and boolean attribute filtering; reject an unsupported selected pattern or attribute explicitly. A bounded protobuf decoder and a bounded RE2-compatible matcher are appropriate dependencies; verify exact regex compatibility against upstream fixtures and fail unsupported expressions rather than reinterpret them. IP sets support IPv4 and IPv6 CIDR and the `inverse_match` flag.

An operator retrieves a pinned release and its SHA-256 from the upstream source, verifies it, then atomically replaces the configured file. The file is outside the scanned resource tree or uses an unscanned extension. Watching the parent plus file identity handles atomic replacement. Candidate loading reads a bounded complete snapshot before decoding; validate file identity/content consistency so a concurrent writer cannot publish a mixed file. Failed reads, malformed content and unknown references retain the last good generation.

### Explicit typed predicates

Add `targetGeoSites` and `targetGeoIps` to all existing flow-match consumers. Their values are set names with optional geosite `@attribute`. Values in a field are ORed; fields are ANDed as in the existing model. Keep `targetHosts` exact and unchanged. A rule combining hostname and IP fields requires both facts, so separate ordered rules express an OR across those categories. Database resources resolve in the same namespace as the rule and are optional for configurations without references.

The current target representation has only one original fact. A domain request can use geosite; an IP request can use geoip. If a future adapter supplies both original facts, carry both explicitly through the immutable policy context. Do not treat local DNS cache contents, resolver results from another route, or Egress-resolved addresses as the original destination. Missing facts do not match, including inverted GeoIP sets.

### Atomic compiled snapshots and bounded inputs

Load and validate datasets before compiling the whole policy graph. Compile selected domain sets to exact/suffix indexes, bounded substring and regex matchers, and selected IP sets to IPv4/IPv6 prefix indexes. Share immutable indexes within the generation, and capture the generation once for Egress, Transit and Proxy evaluation. Maintain explicit per-file, set, entry, pattern and aggregate compiled-memory ceilings with stable diagnostics. Preserve the old compiled generation when data or rule reload fails, and expose the failure through existing reload observations without leaking absolute private paths.

Startup fails if required data are unavailable. An unchanged configuration with no geodata references remains usable without either file. External-file changes must trigger full graph validation; no background updater can mutate an already published matcher.

## Risks / Trade-offs

- [Large upstream files or adversarial patterns consume memory] → Bound bytes, entries, patterns and aggregate compiled index; reject over-limit candidates and cover hostile fixtures.
- [Regex engines differ from Go's regexp dialect] → Test upstream patterns, explicitly diagnose unsupported syntax and never silently drop a rule.
- [GeoIP users expect hostname resolution] → Document original-IP-only matching and the independent DNS boundary with explicit hostname-only and IP-only examples.
- [A database update changes routing globally] → Atomic generation publication, version/checksum guidance and rollback by replacing the previously verified file.
- [A set can change upstream] → Pin release versions in operator procedures and use deterministic fixture snapshots for tests.

## Migration Plan

Existing rules need no changes. Operators who want geodata add the two database resources and typed predicates, provision verified files, then reload the complete graph. A failed reload preserves the previous rules. Roll back by restoring the previous data file and configuration as one validated generation, or by removing geodata predicates and resources. Main capability specs, their Chinese counterparts, bilingual guides and implementation status are synchronized when implementation is complete.
