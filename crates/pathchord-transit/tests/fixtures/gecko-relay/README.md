# Gecko relay interoperability fixture

This test-only relay uses the sing-quic version pinned by sing-box 1.14.4 to
decode and encode Gecko packets around a plain Hysteria2 server. It accepts
large UDP datagrams in its own buffer, so the test also covers Gecko padding
sizes above the sing-box QUIC server's receive-buffer limit. It is not a
runtime or release dependency.

From this directory, build the relay and run the optional test from the
workspace root:

```sh
go build -o /tmp/pathchord-gecko-relay .
PATHCHORD_TEST_SING_BOX=/path/to/sing-box \
PATHCHORD_TEST_GECKO_RELAY=/tmp/pathchord-gecko-relay \
  cargo test --locked -p pathchord-transit --lib -- --ignored \
  large_gecko_packets_interoperate_with_independent_go_relay
```
