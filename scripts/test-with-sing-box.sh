#!/bin/sh
set -eu

# The external core is started by the Rust fixtures as the protocol server;
# PathChord's native Transit adapter is always the client under test.

if [ -z "${PATHCHORD_TEST_SING_BOX:-}" ]; then
    echo "PATHCHORD_TEST_SING_BOX must point to an external sing-box test binary" >&2
    exit 2
fi
if [ ! -x "$PATHCHORD_TEST_SING_BOX" ]; then
    echo "PATHCHORD_TEST_SING_BOX is not executable: $PATHCHORD_TEST_SING_BOX" >&2
    exit 2
fi

# The Transit library also contains ignored fixtures for Xray and captured
# uTLS ClientHellos. Select the sing-box peers explicitly, including the
# historical native VLESS/Trojan test whose name does not contain sing_box.
cargo test --locked -p pathchord-transit --lib -- --ignored sing_box "$@"
cargo test --locked -p pathchord-transit --test http_transport_external -- --ignored "$@"
cargo test --locked -p pathchord-transit --test http_upgrade_external -- --ignored "$@"
cargo test --locked -p pathchord-transit --test grpc_external -- --ignored sing_box_ "$@"
cargo test --locked -p pathchord-transit --test websocket_early_external -- --ignored "$@"
cargo test --locked -p pathchord-transit --test quic_external -- --ignored "$@"
cargo test --locked -p pathchord-transit --test hysteria2_hopping_external -- --ignored "$@"
if [ -n "${PATHCHORD_TEST_GECKO_RELAY:-}" ]; then
    cargo test --locked -p pathchord-transit --lib -- --ignored \
        large_gecko_packets_interoperate_with_independent_go_relay "$@"
fi
cargo test --locked -p pathchord-transit --test socks5_uot_external -- --ignored "$@"
cargo test --locked -p pathchord-transit --test shadowsocks_uot_external -- --ignored "$@"
cargo test --locked -p pathchord-transit --test tuic_udp_over_stream_external -- --ignored "$@"
cargo test --locked -p pathchord-transit --test sing_mux_external -- --ignored "$@"
cargo test --locked -p pathchord-transit --test tls_fingerprint_external -- --ignored "$@"
cargo test --locked -p pathchord-transit --test vless_packetaddr_external -- --ignored direct_tls_packetaddr_preserves_tcp_and_udp "$@"
cargo test --locked -p pathchord-transit --test vless_packetaddr_external -- --ignored reality_packetaddr_preserves_tcp_and_udp "$@"
cargo test --locked -p pathchord-transit --test http_connect_external -- --ignored standard_http_connect_auth_and_tls_interoperate_with_sing_box "$@"
exec cargo test --locked -p pathchord-transit --lib -- --ignored \
    rust_vless_and_trojan_interoperate_over_tcp_tls_and_websocket "$@"
