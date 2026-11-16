# Proposal

## Why

Routing currently matches `targetHosts` as exact hostnames or IP literals. Service domains and address ranges change, so maintaining every Hugging Face CDN hostname or a country's IP prefixes by hand is fragile and can route a redirect to the wrong fallback.

## What Changes

- Add explicitly configured, local V2Fly-compatible geosite and geoip databases and named set references in flow matches. Use [domain-list-community](https://github.com/v2fly/domain-list-community) and [v2fly/geoip](https://github.com/v2fly/geoip) release artifacts as interoperable reference data.
- Match domain sets against the original hostname and IP sets against an available original destination IP, with explicit, deterministic behavior when the relevant fact is unavailable. Preserve existing exact `targetHosts`, rule ordering, DNS route boundaries, and configuration generation semantics.
- Validate and compile referenced datasets before publishing one immutable configuration generation. Report missing, invalid, unsupported, or unknown data explicitly and retain the last good generation on failed reload.
- Document configuration, offline dataset provisioning and update procedures in both languages, and verify matching and reload behavior with deterministic fixtures and published-format samples.

## Capabilities

### New Capabilities

- `geodata-routing`: Geosite and geoip database formats, bounded loading, named-set compilation, and deterministic hostname/IP matching.

### Modified Capabilities

- `configuration`: Apply geodata predicates in the ordered routing decision without implicit DNS resolution or policy bypass.
- `configuration-schema`: Declare database resources and typed rule references with validation, source-path, namespace, and atomic reload semantics.

## Impact

The policy/configuration model, bundle loader and compiler, all EgressRule/TransitRule/ProxyRule evaluation paths, reload machinery, and user-facing bilingual guides are affected. The implementation may add a protobuf decoder and a bounded regular-expression matcher. Published datasets are operator-managed inputs, not committed credentials or an implicit runtime download; no PathChord wire-format change is required.
