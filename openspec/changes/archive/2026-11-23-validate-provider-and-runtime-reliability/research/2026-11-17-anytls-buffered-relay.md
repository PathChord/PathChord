# AnyTLS buffered frame progress regression

The cross-kernel QEMU matrix on 2026-11-17 found a deterministic AnyTLS timeout
when echoing 131071 TCP bytes through sing-box 1.14.4. Small local AnyTLS
fixtures had used seven bytes and did not expose it. REALITY, Hysteria2 and
TUIC already completed the same TCP payload in that matrix. The QEMU setup
used generated certificates and credentials, independent Alpine 3.24.4 kernels
and a private virtual Ethernet link; no real provider or remote account was
involved.

## Minimal failing loop

`spawn_stream_relay` framed application data and called `write_all` on its
upstream, but did not flush PUSH or HeartResponse frames. An `AsyncWrite` may
accept the final bytes into a buffer. The application-facing duplex buffer is
twice the maximum 65535-byte frame payload, so 131071 bytes crosses both that
buffer boundary and the two-frame boundary. The final frame can remain pending
while both endpoints wait for more traffic.

A non-ignored regression connects the real relay to a bounded Tokio duplex
through a 16 KiB `BufWriter`. A peer decodes and echoes the actual AnyTLS frames;
the client concurrently writes and reads 131071 bytes without closing first.
It failed deterministically in 2.01 seconds before the fix:

```sh
cargo test --locked -p pathchord-transit --lib \
  buffered_relay_flushes_the_tail_after_two_maximum_frames -- --nocapture
```

The relay now flushes every completed data or control frame. The same regression
passes in 0.01 seconds, and the bounded UDP framing test also passes. No wire
format or supported option changed.

## Independent peer and QEMU verification

The existing sing-box test now verifies TCP payloads of 7, 65535, 65536,
131070, 131071 and 262145 bytes on one connection, with concurrent writes and
reads and a five-second deadline per exchange. It retains UDP and target
closure checks. That local peer test passes in 0.38 seconds after the fix;
it also passed before the fix, confirming that localhost TLS timing alone
was insufficient as a regression oracle.

```sh
PATHCHORD_TEST_SING_BOX=/tmp/pathchord-outbound-20261117/sing-box \
  cargo test --locked -p pathchord-transit --lib \
  native_anytls_tcp_and_udp_interoperate_with_sing_box -- --ignored --nocapture
cargo build --locked -p pathchord-transit --example cross_machine_probe \
  --target x86_64-unknown-linux-musl
python3 -B scripts/test-qemu-transit.py \
  --sing-box /tmp/pathchord-outbound-20261117/sing-box \
  --output /data/pathchord-qemu/runs/qemu-anytls-flush-validation-20261117 \
  --protocols anytls --baseline-only
```

The original QEMU case now passes against both IPv4 `192.0.2.11` and IPv6
`fd00:7063::11` peer endpoints. Each endpoint reaches both `127.0.0.1` and `::1`
targets, exchanging 262142 verified TCP bytes and 18892 UDP bytes across those
targets. UDP sizes are 1, 53, 1200, 4096 and repeated 4096 bytes per target.
The same run confirms that the selected unsupported VLESS option and retired
SSR remain unavailable. All four recorded cases pass.

The retained [QEMU report](2026-11-17-anytls-qemu.json) contains the guest image,
kernel, independent boot IDs and executable hashes. The test-only sing-box
SHA-256 is `1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`;
the cross-machine probe SHA-256 is
`f854409dc4ce01747c4269e4ccd05ea5a780ce52a7bca07ce24ee4e4434575b9`.
This subset is baseline virtual-network evidence. The complete protocol matrix
records delayed-network coverage separately.
