# V2Fly release data interoperability on 2026-11-16

The following public release artifacts were downloaded locally and verified against their corresponding upstream `.sha256sum` files. These are provider interoperability observations, not a substitute for deterministic fixture tests or deployed Ingress evidence.

| Source | Release tag | Artifact | SHA-256 |
|---|---|---|---|
| [domain-list-community](https://github.com/v2fly/domain-list-community/releases/tag/20261116002619) | `20261116002619` | `dlc.dat` | `47561470dfc04cda7dd176b61ca99a34bccddefd1b359fe9535732838c6ea2dc` |
| [v2fly/geoip](https://github.com/v2fly/geoip/releases/tag/202611080027) | `202611080027` | `geoip.dat` | `eedb24b3b9fcba27e06b92c0428dab90d9496083091ae4cf39e11387fd99d0e2` |

Both checksums matched. The checked GeoIP file contained 253 sets and 1,410,686 CIDRs, motivating a bounded limit of 3,000,000 decoded entries. The decoder read both files and compiled the `huggingface` and `private` examples. Each of 1,556 geosite sets and each of 253 GeoIP sets also compiled independently; this does not claim that all sets can be compiled simultaneously under the per-generation aggregate index budget. The geosite example matched `us.aws.cdn.hf.co` and rejected `nothf.co`; the GeoIP private example matched `192.168.1.1` and rejected `8.8.8.8`.

The [V2Fly matcher source](https://github.com/v2fly/v2ray-core/blob/master/common/strmatcher/matchers.go) treats regex expressions as case-sensitive, with regular-expression flags controlling exceptions. The implementation follows that behavior against a normalized lowercase target hostname.

## Authorized runtime check

On 2026-11-16 a locally built Linux Ingress used the two configured subscription sources and the existing `egress-jp-1` runtime. With at least three ready Paths, `targetGeoSites: [geosite:huggingface]` routed both `huggingface.co` and the observed redirect `us.aws.cdn.hf.co` through Egress; a bounded model range returned HTTP 206 and 1,048,576 bytes (SHA-256 `e4122797e4dd166866f6ab8c586650d5cff2175c72535939d039f727c95c04cd`). Some Paths became stale during transfer and were replenished; the download completed. A separate `targetGeoIps: [geoip:au]` request for the original IP `1.1.1.1` returned HTTP 301, with Egress target-open attempts increasing and reporting a successful IP target. Four Paths were observed afterward. Temporary Egress authorizations were removed after each run. This is bounded deployed interoperability evidence, not a soak test or native execution of the Ingress on other operating systems.

A later repeat with an earlier Egress diagnostic binary ended after 640,361 bytes with a TLS unexpected EOF and an Egress Session disappearance; that binary did not expose a terminal reason, so the exact reason was not established. After replacing it with a locally built musl binary containing the subsequent Path fixes and bounded Session-end classification, the same geosite and GeoIP checks both completed: HTTP 206 for the full 1 MiB range and HTTP 301 for `1.1.1.1`. Egress reported one active Path at one intermediate observation and four after recovery; `last_session_end` remained null during the successful test. This single repeat demonstrates recovery in that observed run, not a general uptime guarantee.
