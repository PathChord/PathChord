# Linux kernel validation on 2026-11-17

This is execution evidence for tasks 3.1 and 3.2. The existing
[platform contract](../../../../specs/platform-and-dns/spec.md) remains authoritative.
The run uses the current working tree, including uncommitted implementation
fixes; the manifests record the base revision, dirty state and executable hashes.

## Environment and isolation

The development host runs Linux `7.2.15-zen1-1-zen` on x86_64. Its installed
module trees are for different kernels, and `nft_tproxy` is neither loaded nor
available for the running kernel. A failed native nft TPROXY rule returned
`ENOENT`; this was an environment failure, not forwarding evidence.

The complete kernel matrix therefore runs inside disposable QEMU/KVM machines
created by `scripts/qemu_lab.py`. The tested machine is Alpine 3.24.4, x86_64,
with Linux `6.18.63-0-virt` and its matching kernel modules. The tools are
iproute2/TC 7.0.0, nftables 1.1.6, and bpftool 7.8.0 with libbpf 1.8.
Signed APKs are fetched over HTTPS into a local cache, hashed, then installed
offline in the temporary guest. The APK download files are removed after
installation to preserve the guest root filesystem's capacity.

Inside that guest the harness creates three network namespaces: a client, the
Ingress router, and an independent TCP/UDP target. Two veth pairs provide IPv4
and IPv6 links. `nsenter --net` selects the network namespace while retaining
the guest's bpffs mount; `ip netns exec` would replace `/sys` in another mount
namespace and hide that mount. All routing, nftables, TUN and TC changes remain
inside this disposable guest and its temporary namespaces. The host's routes,
packet filters and network interfaces are not changed. The harness checks that
its named namespaces have been removed on exit, and QEMU removes the guest
kernel and mount state when the run ends.

## Reproduction and artifacts

```sh
cargo build --locked --release --target x86_64-unknown-linux-musl \
  --bin pathchord-ingressd --bin pathchordctl
python3 scripts/test-qemu-linux-platforms.py
```

An optional `--apk-address <address>` supplies a guest/build-container-only CDN
address mapping while preserving the HTTPS hostname and certificate checks.
The wrapper records exact executable/APK SHA-256 values, the guest boot ID,
commands, versions, service logs, and a JSON matrix report under
`/data/pathchord-qemu/runs/linux-platforms/<run>/`. Packet captures contain only synthetic
namespace test traffic. They are retained with the evidence archive.

The ordinary native-host subset can also run on a suitably provisioned Linux
host:

```sh
sudo -n python3 scripts/test-linux-platforms.py
```

## Interception, devices and routing ownership

The QEMU run at `/data/pathchord-qemu/runs/linux-platforms/20261117-151614` passed all task 3.1
checks before reaching the separate eBPF startup investigation:

- TPROXY TCP and UDP over IPv4 and IPv6, with 16,384-byte TCP exchanges and
  4,096-byte UDP datagrams. The independent target returns the peer address;
  the expected Ingress-side source proves the request passed through the
  proxy rather than being forwarded directly by the kernel.
- REDIRECT TCP over IPv4 and IPv6, including original destination extraction.
  UDP configuration is explicitly rejected, as required by the existing
  TCP-only REDIRECT contract.
- Real `/dev/net/tun` creation and forwarding for IPv4 and IPv6. Each family
  completes 17 TCP exchanges whose target responds only after the client
  half-closes, plus a fragmented 4,096-byte UDP round trip. The device is gone
  after Ingress shutdown.
- Protected DNS-upstream endpoints reject both TCP and UDP interception.
- SIGKILL leaves the actual route journal and kernel objects; a new Ingress
  recovers them, starts and then removes its owned routes on graceful stop.
- A changed route protocol and a changed rule mask each cause an ownership
  conflict. The foreign kernel object and recovery journal survive. After the
  test administrator restores the matching object, recovery succeeds.
- Injecting a failure into the IPv6 route-add command rolls back the earlier
  real kernel mutations. A pre-existing foreign rule is rejected without
  modification.

The nftables test rules activate conntrack defragmentation before matching the
transport port. The REDIRECT and TPROXY packet-filter rules are administrator
fixtures; Ingress owns its documented journaled policy routes separately.

## Implementation repairs exposed by the run

The native route inventory uses numeric iproute2 output because protocol
numbers can otherwise become host-specific names such as `bgp` or `openr`.
Numeric local-route type `2` is accepted. Recovery additionally rejects
changed selectors, masks, flags and route attributes rather than deleting an
object that only partially matches its ownership tuple.

TPROXY's raw `recvmsg` now runs through Tokio `async_io`. Reporting `EAGAIN` as
`WouldBlock` clears readiness; the old loop could repeatedly observe stale
readiness and starve the UDP association and response tasks.

TUN performs bounded IP reassembly before socket admission and fragments
outbound packets to the real device MTU. The bound is at most 16 incomplete
datagrams, 128 fragments per datagram and the IP packet length limit, with a
30-second expiry evaluated on subsequent input. Overlapping fragments are
rejected. This preserves the protected endpoint check before socket creation
and covers IPv6 fragmentation, which the selected smoltcp IP interface does
not implement. smoltcp continues to own TCP/UDP transport state and timers.
A completed TCP bridge no longer closes the smoltcp socket before buffered
response bytes are drained and EOF is observed. A handshake that already
reached `CLOSE-WAIT` can still be admitted and preserve its half-close.

The optional TC backend keeps ELF objects and durable ownership journals in
ordinary private data storage, with program/map pins in bpffs. Cleanup checks
the recorded program ID before deleting a TC filter, preserves other filters
and their shared clsact, and recovers its journal after a process crash.
The classifier recognizes IPv6 fragment headers while preserving nonzero
foreign packet marks. JSON bpftool diagnostics are retained from stdout as
well as stderr.

## TC backend matrix

The final run at `/data/pathchord-qemu/runs/linux-platforms/20261117-161035`
returned zero and passed all 21 result groups, repeating the successful earlier
run at `20261117-160543`. The final run includes the live-pin ownership guard
and IPv6 foreign-mark checks. It covers the interception and ownership matrix
above plus:

- Native TC/eBPF TCP and fragmented 4,096-byte UDP over IPv4 and IPv6, including
  protected endpoint rejection, nftables mark counters and packet captures.
- A pre-existing administrator clsact/filter sets packet mark 19. The PathChord
  classifier preserves that nonzero mark for both IPv4 and IPv6, and the peer
  sees the original client source, proving this traffic bypassed mark 17's proxy route. Cleanup preserves
  the administrator filter and clsact.
- SIGKILL leaves BPF pins and the durable program-ID journal. Restart removes
  only the matching TC filter/pins, attaches a fresh program and forwards TCP/UDP.
  A foreign filter installed after startup retains its shared clsact on shutdown.
- Replacing PathChord's filter with an administrator matchall filter makes both
  shutdown and restart report an ownership conflict while retaining the foreign
  filter and journal. Removing that foreign filter permits bounded recovery.
- A pre-existing occupied TC priority is rejected without deleting its filter.
- Injected bpftool unavailability rolls back owned routes and removes temporary
  pins. Selecting the ordinary TPROXY configuration then forwards TCP/UDP and
  retains protected endpoint checks.

TC's JSON inventory includes both a protocol/chain header and a concrete filter;
its program ID can be nested under `options.prog.id` or appear at `options.id`.
The owner verifies the exact program ID, direct-action flag, handle, protocol and
chain before deletion. Shared clsact detection uses JSON inventory rather than
locale-dependent netlink error text. The final revision also requires the live
bpffs program pin to match the journal ID, preventing a stale numeric ID after
reboot from claiming a different program.

## Evidence limits

This is native execution against a real Linux kernel inside QEMU, plus a
separate native-host TUN/routing subset. It is not Windows or FreeBSD evidence,
a WAN performance result, a production deployment, or validation of every
Linux kernel/interface combination. The final executable hashes and repeat-run result are recorded in the accompanying
[JSON evidence manifest](2026-11-17-linux-kernel-validation.json).
