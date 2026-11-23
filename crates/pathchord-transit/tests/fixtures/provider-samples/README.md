# Sanitized provider samples

These excerpts come from a user-supplied HTTPS subscription fetched on
2026-11-23. Node names, endpoints, credentials, transport paths and accounting
values use placeholders. The excerpts retain node options and document
wrappers. Client routing rules, request URLs and headers were omitted.

| User-Agent | Fixture | Excerpt |
| --- | --- | --- |
| `clash.meta` | [clash-meta.yaml](clash-meta.yaml) | Four inline proxies |
| `Shadowsocks` | [sip008.json](sip008.json) | Three SIP008 server records |
| `sing-box` | [sing-box.json](sing-box.json) | Four proxies and two non-proxy outbounds |
| `Mihomo`, `v2rayN` | [uri-base64.txt](uri-base64.txt) | Eight URI records with the original Base64 wrapper and decoded CRLF line endings |
| `Surge` | [surge.conf](surge.conf) | Three lines from the proxy section |
| `Loon` | [loon.conf](loon.conf) | Two lines from the proxy section |

The two Base64 responses matched byte for byte. The provider returned HTTP 403
for Quantumult X. The Clash response contained inline proxies.

The [Clash HTTP provider fixture](clash-http-providers.yaml) follows the
documented Mihomo `proxy-providers` syntax. The scripted fetcher replays
responses for the same origin, a different host, and an HTTPS-to-HTTP origin
change. [Mihomo proxy provider reference](https://wiki.metacubex.one/en/config/proxy-providers/)
