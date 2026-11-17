# sing-box REALITY decoy record boundary

On 2026-11-16, a local REALITY + Vision interoperability test intermittently
timed out before sing-box 1.14.4 sent any TLS handshake bytes to PathChord.
Both Chrome and Edge fingerprints reproduced the timeout. The test decoy had
already received the ClientHello and sent its TLS server flight.

sing-box 1.14.4 uses metacubex/utls 1.8.7 for its REALITY server. Its
[`RealityServer` record parser](https://github.com/MetaCubeX/utls/blob/v1.8.7/reality.go)
recognizes a combined encrypted handshake record only when its complete
record length, including the five-byte TLS header, is greater than 512 bytes.
For a shorter combined record it waits for separate handshake records. A
standard rustls decoy that sends its combined server flight as one 512-byte
encrypted record waits for the client Finished, so the two peers can wait for
one another indefinitely. A 513-byte record takes the combined-record path.

The `sing_box_reality_combined_decoy_flight_boundary` ignored test exercises
both cases with a synthetic TLS decoy and captures only TLS record lengths.
It expects no REALITY handshake response for 512 bytes, and a successful
REALITY + Vision echo for 513 bytes. The regular interoperability fixture uses
a longer synthetic certificate so it tests the protocol independently of this
specific server limitation.

This finding is about the tested sing-box server and decoy combination; it
does not establish whether any particular provider node uses a decoy with
this record layout. Raising the client timeout does not resolve the wait.
