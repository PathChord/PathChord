# PathChord deployment and local operation
**English** | [简体中文](deployment.zh-CN.md)

This guide walks through local proxy setup, privileged Linux listeners, and explicit Ingress/Egress enrollment. Start with the [configuration guide](configuration.md) to choose resources and routing. Required service behavior is defined by the [deployment specification](../../openspec/specs/deployment/spec.md).

The release provides `pathchord-ingressd`, `pathchord-egressd`, and
`pathchordctl`. Each service executable owns a separate process. The ordinary
examples use explicit proxy listeners and require no
packet interception or TUN privileges. Linux transparent and TUN examples are
provided separately and require the platform privileges and routing setup
described below.

## Configuration directory and overrides

With no explicit configuration option, Ingress loads
`~/.config/pathchord/ingress` for a regular account or
`/etc/pathchord/ingress` for packaged service accounts. An explicit
command-line source overrides environment variables, which override the
account default. For example:

```sh
pathchord-ingressd
PATHCHORD_CONFIG_DIR=/opt/pathchord/ingress pathchord-ingressd
pathchord-ingressd --config-dir /opt/pathchord/ingress
pathchord-ingressd --config /opt/pathchord/single.yaml
```

`PATHCHORD_CONFIG` also accepts a file or directory. Set only one non-empty
configuration environment variable when no command-line source is supplied.
`--config`/`-c` and `--config-dir`/`-C` are mutually exclusive. The exact
account classification and precedence are defined in the
[configuration source contract](../../openspec/specs/configuration-schema/spec.md#configuration-sources).

Split resources into `.yaml`, `.yml`, or `.json` files in the selected tree;
subdirectories are included. All resources form one validated graph, so a
Listener, DNSPolicy, FallbackPolicy, node, and routing rules can live in
different files. Keep private key/credential JSON and `--data-dir` outside
that tree. Reloading additions, modifications, removals, and renames replaces
the complete valid graph atomically; a failed candidate retains the old one.

## Local explicit proxy

Build the executable and run the direct-routing example:

```sh
cargo build --locked --release --bin pathchord-ingressd --bin pathchord-egressd --bin pathchordctl
./target/release/pathchord-ingressd --config examples/ingress-direct.yaml
```

Regular Unix users load resources from `~/.config/pathchord/<role>` and keep
state under `~/.local/state/pathchord/<role>`. The socket defaults to
`$XDG_RUNTIME_DIR/pathchord`, with `~/.config/pathchord` as the fallback.
Service accounts default to `/etc/pathchord/<role>`, `/run/pathchord`, and
`/var/lib/pathchord/<role>`. FreeBSD uses `/var/run` and `/var/db` for its
runtime and state roots. Packages can explicitly select existing service paths.

`pathchordctl` uses an explicit `--socket` first, then the role's configured
`controlSocket`, then the applicable XDG runtime, home configuration,
`/run/pathchord`, and `/var/run/pathchord` candidates. `get status` defaults
to Ingress, and `enroll` addresses Egress authorization. Human-readable output
is the default. Scripts can select `-o json` or `-o yaml`.

The mixed listener binds to `127.0.0.1:7890`. Its unauthenticated example is
restricted to loopback. Applications can select HTTP or SOCKS on that address:

```sh
curl -x http://127.0.0.1:7890 https://example.com
curl -x socks5h://127.0.0.1:7890 https://example.com
```

The direct example sends target traffic directly. The subscription example
uses ordinary third-party Proxy routing and explicitly rejects flows with no
usable matching node. Its provider URL MUST be replaced before use:

```sh
pathchord-ingressd --config examples/ingress-subscriptions.yaml
```

## Packaged service identities and privileges

Install one role per machine: `pathchord-ingressd` on an Ingress client or
`pathchord-egressd` on an Egress host. Each package contains its daemon,
`pathchordctl`, its configuration template and matching service. Installing the
opposite role is rejected before changing the installed service or private
state. To change roles, remove the existing package explicitly and install the
other; upgrade, rollback and removal preserve operator configuration and keys.

Both Unix profiles use the local non-login `pathchord` account. Only the selected
role's private roots are created. State directories use `0700`, and control
locks use `0600`. Configuration directories are `root:pathchord` with mode
`0750`. The runtime directory uses `0750` and the control socket uses `0660`,
both owned by `pathchord:pathchord`. Membership in the `pathchord` group grants
local service administration. On Linux, run `sudo usermod -aG pathchord USER`.
On FreeBSD, run `sudo pw groupmod pathchord -m USER`. Start a new login session
before using `pathchordctl` as the added user.
Ingress credentials live in `/var/lib/pathchord-ingress/credentials`, or
`/var/db/pathchord-ingress/credentials` on FreeBSD, outside the resource tree.

Default systemd services have no capabilities and restrict device access.
Only when configuring transparent/TUN listeners, install
`/usr/share/pathchord/systemd/transparent.conf` as
`/etc/systemd/system/pathchord-ingressd.service.d/transparent.conf` and restart
Ingress. Add the adjacent `ebpf.conf` for eBPF after mounting bpffs and preparing
the required kernel and tools. The [package instructions](../../packaging/README.md#service-isolation-and-optional-ingress-privileges)
describe Alpine OpenRC capability setup. Egress needs no TUN device or
network-administration capability.

Windows installs only the selected service definition and restricts that role's
config, data, credentials and logs to its virtual service account, SYSTEM and
Administrators. Provision native device permissions for the selected Ingress
account before using Windows TUN. Ordinary explicit proxy listeners require no
administrator service account.

## Linux transparent and TUN listeners

The [`ingress-tproxy.yaml`](../../examples/ingress-tproxy.yaml) example starts
Linux TPROXY TCP/UDP interception on `0.0.0.0:15001`, using packet mark `1` and
policy-routing table `100`. The host packet-filter rules that send traffic to
the listener and apply the mark remain administrator-owned; they MUST use the
same bind address, mark, and route table. PathChord owns only the matching
policy-routing objects and removes only objects that still match its journal.
The service requires the privileges needed to create transparent sockets and
manage those routes, such as root or the equivalent `CAP_NET_ADMIN` and
`CAP_NET_RAW` capability set.

The [`ingress-tproxy-ebpf.yaml`](../../examples/ingress-tproxy-ebpf.yaml)
example selects `backend: ebpf` and attaches a small Linux TC classifier to the
administrator-selected `lan0` ingress interface. It marks only TCP/UDP packets
for the existing TPROXY policy route; the transparent listener, original-target
handling, UDP associations, and Path/Session policy remain in userspace. The
eBPF backend requires `clang` at build time and `bpftool`, `tc`, BPF/BTF kernel
support, and privileged network administration at runtime. It is intentionally
interface-bound and requires `allowedSources`; use the ordinary TPROXY backend
when the host cannot provide those capabilities.

The [`ingress-tun.yaml`](../../examples/ingress-tun.yaml) example creates a
`PathChord` TUN interface at `198.18.0.1/30` with MTU 1500 and carries TCP and
UDP packets through the same policy and fallback route. The account running
Ingress needs permission to create and configure the TUN device. Add the
desired host routes to the interface and preserve the documented protected
endpoint bypasses before directing host traffic into it. FreeBSD rejects both
transparent and TUN listeners; TUN support is available on Windows through its
native adapter.

Start either example explicitly so a privileged configuration is never picked
up accidentally from the account default:

```sh
sudo ./target/release/pathchord-ingressd --config examples/ingress-tproxy.yaml
sudo ./target/release/pathchord-ingressd --config examples/ingress-tun.yaml
```

TPROXY and TUN listeners accept IP flows, so routing matches the original IP
address, port, protocol, and available process metadata. Domain-only policy
conditions do not match a flow whose original packet contains no hostname.

Unsupported Transit protocols and parameters remain visible as typed node
diagnostics until their native PathChord adapters are implemented. PathChord
does not start or embed an external proxy process as a compatibility backend.
See the [Transit Proxy contract](../../openspec/specs/transit-proxies/spec.md).

## Ingress and Egress enrollment

Generate a private identity on each corresponding machine. The command prints
only the public key; the private file MUST remain local to its owner:

```sh
pathchordctl keygen --identity-file ingress.key.json
pathchordctl keygen --identity-file egress.key.json
```

Start Egress in its own terminal. The Unix control socket is local to Egress:

```sh
pathchord-egressd --egress-id exit --identity egress.key.json \
  --bind 127.0.0.1:9443 --control-socket /tmp/pathchord-egress.sock
```

`--bind` may be repeated when one Egress process owns several public Path
listeners. The same list can be authored as `spec.binds` in an `EgressService`.
Use one Ingress `Egress` resource with an ordered `spec.endpoints` list for
different IPv4, IPv6, hostname, or port candidates; all entries use the same
verified Egress ID and public key. A single `--bind` and the older
`address`/`port` form remain valid for one-endpoint deployments.

On Egress, enroll the independently verified Ingress public key. The CLI
reads the Egress ID and current authorization generation from the selected
service. Explicit `--egress-id` and `--expected-generation` remain available.
Review a generation conflict before retrying. Revocation and deletion prompt
for confirmation. Use `--yes` for unattended operations.

```sh
pathchordctl --socket /tmp/pathchord-egress.sock enroll add \
  --ingress-id entry --public-key INGRESS_PUBLIC_KEY
```

In `examples/ingress-egress.yaml`, replace `REPLACE_WITH_EGRESS_PUBLIC_KEY`
with the Egress public key. The example contains loopback, IPv6, and hostname
endpoint candidates; keep only reachable candidates for a local deployment or
replace them with the public endpoints exposed by Egress. Cross-machine
deployments MUST set reachable Egress binds/endpoints and keep the same
explicitly verified key and canonical Egress ID. Start Ingress in a separate
terminal:

```sh
pathchordctl -C /path/to/ingress config create -f examples/ingress-egress.yaml
pathchord-ingressd --socket /tmp/pathchord-ingress.sock \
  --ingress-id entry --identity ingress.key.json \
  --config-dir /path/to/ingress
pathchordctl --socket /tmp/pathchord-ingress.sock get status
pathchordctl --socket /tmp/pathchord-egress.sock enroll list
```

The example's `direct-path` is a direct transport to the authenticated Egress.
Replacing it with an HTTP, HTTPS, SOCKS5, or Shadowsocks Transit
changes the transport while preserving the end-to-end Noise and enrollment
contracts. UDP flows through an Egress require its UDP capability and a TCP
Transit Path; ordinary third-party UDP routing additionally requires native
UDP support from the selected node.

## Credentials, management, and shutdown

Listener and node secrets are stored in private JSON files named by opaque
`credentialsRef` values under the selected `--credentials-dir`. A Basic or
SOCKS5 credential document contains `username` and `password`; it MUST NOT be
committed. Required listener authentication refuses SOCKS4/4a.

Unix socket ownership/permissions and Windows Named Pipe ACLs protect local
management. Socket paths are local to their service machine. Windows uses
Named Pipe names for the corresponding control endpoints. The Web Gateway is
opt-in through `--web-bind` and shares the local dispatcher. A configured
`--web-token-file` supplies its bearer token. Prometheus scraping uses the
same authentication, Origin checks, and `metrics:read` capability at `/metrics`.
Path-pool gauges report the requested and effective idle baselines, the current
demand target, and aggregate baseline shortfall across live Sessions. See the
[observability contract](../../openspec/specs/observability/spec.md) for exact
field and metric semantics.

Each service accepts Ctrl-C and, on Unix, SIGTERM shutdown and owns its
task/connection cleanup.
Persistent configuration changes follow the reload contract; identity,
listener topology, and other startup-only settings require a service restart
when the reload response reports that requirement.
