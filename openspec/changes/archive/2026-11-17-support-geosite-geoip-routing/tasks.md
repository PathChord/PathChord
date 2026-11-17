# Tasks

## 1. Data format and matching

- [x] 1.1 Implement bounded V2Fly `GeoSiteList`/`GeoIPList` decoding and structural validation, with deterministic fixtures covering IPv4, IPv6, inverse sets, malformed records, duplicate names and all configured size/entry bounds.
- [x] 1.2 Compile geosite plain, regex, root-domain, full and attribute predicates; test case and label boundaries, trailing dots, unsupported patterns, missing attributes and the Hugging Face/CDN example.
- [x] 1.3 Compile GeoIP prefix indexes and test IPv4/IPv6 family separation, prefix edges, inverse matching and unknown-IP behavior.
- [x] 1.4 Validate representative pinned official domain-list-community and v2fly/geoip release artifacts against the decoder and their published checksums; record source versions and distinguish this interoperability check from deterministic fixtures.

## 2. Configuration and publication

- [x] 2.1 Add namespace-scoped database resources and `targetGeoSites`/`targetGeoIps` to the typed schema, normalization and whole-graph validation; test duplicate resources, invalid fields, cross-namespace references, missing sets and existing exact `targetHosts` compatibility.
- [x] 2.2 Load and compile geodata into the immutable policy generation with bounded diagnostics; test startup failure, candidate rejection and preservation of the last good snapshot on malformed or oversized data.
- [x] 2.3 Watch configured external files and parent directories, including atomic replacement, and rebuild the whole candidate; test concurrent decisions and file replacement never mix generations or lose subsequent updates.

## 3. Routing integration and documentation

- [x] 3.1 Apply predicates to EgressRule, TransitRule and ProxyRule for TCP and UDP; test ordering, AND/OR behavior, explicit fallback, hostname-only and IP-only targets, and prove no DNS lookup is introduced.
- [x] 3.2 Add bilingual configuration and operation examples showing verified local V2Fly files, `huggingface` and GeoIP sets, atomic update and rollback; verify links, technical literals and language parity.
- [x] 3.3 Merge the canonical deltas and full detailed contracts into the main English specifications, synchronize Chinese counterparts and affected bilingual design documents, and update the implementation-status snapshot with actual evidence; run strict OpenSpec and link validation.

## 4. Integration validation

- [x] 4.1 Run `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked --workspace --all-targets`, `openspec validate --all --strict --no-interactive`, and `git diff --check`; record results and ignored tests.
- [x] 4.2 With operator-provided verified datasets and the authorized test Egress, route Hugging Face and its actual redirect through `geosite:huggingface`, download a bounded range with `curl -x`, and separately verify a GeoIP-targeted IP flow; record dataset version and deployed-runtime evidence without secrets.

## Workflow follow-up

- Archive the change after implementation, bilingual synchronization and validation are complete.
