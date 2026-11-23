# Cross-kernel native protocol validation

The final 2026-11-17 run passed **22 of 22 cases**: twenty positive native
protocol cases and two explicit-unavailability checks. PathChord's native
Transit adapters ran in one QEMU guest while an independent sing-box 1.14.4
server and echo targets ran in a second guest. Both guests used Alpine 3.24.4
and Linux `6.18.63-0-virt`, with independent kernel boot identities connected
through private socket-backed virtual Ethernet.

The complete run is
`/data/pathchord-qemu/runs/transit-final-fixed-20261117-1702`. Its
[retained JSON](2026-11-17-cross-kernel-protocol-validation.json) contains
topology, image/kernel/revision metadata, executable and source hashes, all
case results and network-log hashes. The unmodified run's `results.json`
SHA-256 is `523543a715e71a62d6fbabc97aaac59ca293fb5359d9dc73889f55aa6ed525df`.
The retained JSON adds the reproducible command and source/log manifests; its
SHA-256 is `1aeca7c5892c7ab6d3b655b79a7eb98d06d1e1cca27a98e32aa0cb804b6d50ca`.

## Exact environment

| Input | Recorded value |
| --- | --- |
| Repository base revision | `9caf37278a61e28c6c5c1669eb793eb2b5ba33df`, plus the recorded working-tree fixes |
| Container source image | `alpine:3.24`, resolved to `sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf` |
| Guest OS | Alpine 3.24.4, Linux `6.18.63-0-virt`, x86_64 |
| Guest kernel SHA-256 | `d2edb145c22bc89e745bebbe130ad34ecd0445c26a88f8b41ac457fdc607f45e` |
| Client kernel boot ID | `aedbc01b-4873-48c9-a680-56aa1a13eafe` |
| Server kernel boot ID | `7802f5e2-a666-4895-9dd9-dc3e6fa499e8` |
| Independent test server | sing-box 1.14.4, SHA-256 `1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a` |
| PathChord musl probe | SHA-256 `0fb2689c453979c25efd10f928558ce8f416bd49d51eb4d08301bcc8c9ab2dba` |

The native [probe](../../../../../crates/pathchord-transit/examples/cross_machine_probe.rs)
calls the product's `AdapterRegistry` and native Transit adapters. It does not
start a compatibility process. The independent sing-box binary and its private
guest loader/libraries are test fixtures; their hashes are recorded separately
and they are not product or Cargo runtime dependencies.

Management uses loopback-only SSH through each guest's independent QEMU user
network. Protocol traffic uses a different interface: client `eth1`
`192.0.2.10` / `fd00:7063::10` to server `eth1`
`192.0.2.11` / `fd00:7063::11`. No host route, firewall, interface or real remote
account is modified. VM roots, images, private generated fixtures, reports and
the fixed probe image live under `/data/pathchord-qemu`. The probe's explicit
guest TMPDIR is `/tmp/pathchord-probe-tmp` inside that isolated VM. Both guests
were closed by their lab context and the generated private fixture directory
and temporary management keys were removed.

## Case matrix

Each row runs against both IPv4 and IPv6 server endpoints. Each endpoint case
then reaches both IPv4 `127.0.0.1` and IPv6 `::1` echo targets in the server
guest. Every combination runs once without injected delay and once with netem
adding **10 ms on each direction's egress interface**, for approximately 20 ms
additional round-trip delay. Captured `tc -s qdisc` inventories show both delay
rules and zero injected drops.

| Native combination | Baseline endpoint cases | Delayed endpoint cases | Result |
| --- | ---: | ---: | --- |
| VLESS REALITY, Chrome profile, `xtls-rprx-vision`, XUDP | 2 | 2 | Passed |
| Hysteria2, TLS authentication, native TCP/UDP | 2 | 2 | Passed |
| TUIC v5, TLS exporter authentication, native TCP/UDP | 2 | 2 | Passed |
| AnyTLS, TLS session and UDP-over-TCP framing | 2 | 2 | Passed |
| VMess AEAD, TLS transport, AES-128-GCM body, TCP/UDP | 2 | 2 | Passed |

For every positive endpoint case, each target exchanges a **131071-byte TCP
payload** with concurrent client writes/reads. Every received byte is checked
against the original. UDP independently verifies payloads of 1, 53, 1200, 4096
and repeated 4096 bytes for each target. Thus every positive endpoint case
accounts for 262142 TCP bytes and 18892 UDP bytes, and the twenty cases account
for **5242840 TCP bytes and 377840 UDP bytes** of verified application payload.
Timeouts, truncated packets and differing payloads fail the run.

Two additional cases must fail adapter construction as unavailable:

- The selected VLESS REALITY/Vision node combined with a gRPC transport
  `{type: grpc, serviceName: fixture}` cannot silently substitute a different
  supported transport.
- Retired SSR cannot become a native adapter or an implicit fallback.

The native adapter matrix is distinct from the separate
[Ingress/Egress process soak](2026-11-17-runtime-reliability.md). This run does
not claim an actual provider-to-Egress Path or a deployed multipath Session.

## Reproduce

The build and probe temporary files are kept on `/data`. Copy the executable
before a run so a later unrelated build cannot replace the tested image.

```sh
mkdir -p /data/pathchord-qemu/probe-build/tmp
env TMPDIR=/data/pathchord-qemu/probe-build/tmp CARGO_BUILD_JOBS=2 \
  cargo build --locked -p pathchord-transit --example cross_machine_probe \
  --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/debug/examples/cross_machine_probe \
  /data/pathchord-qemu/probe-build/cross_machine_probe
chmod 500 /data/pathchord-qemu/probe-build/cross_machine_probe
env TMPDIR=/data/pathchord-qemu/probe-build/tmp \
  python3 -B scripts/test-qemu-transit.py \
  --sing-box /tmp/pathchord-outbound-20261117/sing-box \
  --probe /data/pathchord-qemu/probe-build/cross_machine_probe \
  --cache /data/pathchord-qemu/linux-rootfs \
  --output /data/pathchord-qemu/runs/transit-new-run
```

The final executed command uses output directory
`transit-final-fixed-20261117-1702`, as recorded verbatim in the JSON. Its full
source manifest includes the runner, lab, probe, AnyTLS/VMess/native transport
code and `Cargo.lock`.

## VMess failure and regression loop

A preliminary complete run passed nineteen positive cases, then VMess timed
out on a delayed IPv6 peer while echoing 131071 TCP bytes. An isolated VMess
rerun also timed out in the delayed IPv4 case, so the problem was not confined
to IPv6. It shared the progress defect found earlier in
[AnyTLS](2026-11-17-anytls-buffered-relay.md): the VMess AEAD/CFB relay accepted
application data and wrote records upstream without flushing each completed
record. A partial final record could stay buffered while the peer waited.

A non-ignored regression routes the actual VMess relay through a bounded
`BufWriter`, decodes its genuine AES-GCM and stateful CFB records in a peer,
and requires all 131071 upload bytes to reach that peer without first closing
the application stream:

```sh
cargo test --locked -p pathchord-transit --lib \
  buffered_tcp_upload_flushes_partial_final_records -- --nocapture
```

Before the fix, the AES-GCM case deterministically timed out after two seconds.
The relay now flushes after each AEAD and CFB record. Both codec branches pass
in the native FreeBSD suite, and the original delayed-network VMess cases pass
in the final 22-case QEMU matrix. The test's initial CFB setup incorrectly
constructed the AEAD `RecordCodec`; that test setup was corrected to use the
independent stateful CFB decoder. No protocol layout, supported parameter set,
credential boundary or fallback rule changed.

## Acceptance boundaries and remaining provenance gap

Task 1.3's five existing native protocol families now have cross-kernel TCP/UDP
evidence with the listed combinations and explicit unsupported outcomes.
Task 1.2 has a finite supported/diagnostic-gated scope in the
[acceptance matrix](2026-11-17-acceptance-matrix.md); its broader transport,
cipher, peer and negative-test evidence remains separate from this selected
QEMU cross-product.

Task 1.1 remains open: the repository does not retain provenance-backed,
sanitized real-provider exports for every requested URI/Base64, SIP008,
sing-box, Surge, Quantumult X and Loon family and referenced HTTP-provider case.
The server credentials, certificates and documents in these QEMU fixtures are
generated synthetic inputs. They cannot be relabeled as real-provider sample
evidence. Previously recorded live-provider imports and successes also do not
supply those missing replayable source samples.

This is isolated virtual-network interoperability evidence, including a
controlled delay scenario. It does not establish WAN throughput, arbitrary
provider availability, all upstream option combinations, production deployment
or long-running endurance beyond the separately recorded process soak.
