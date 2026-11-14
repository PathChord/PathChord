# PathChord deployment and local operation

**English** | [简体中文](deployment.zh-CN.md)

The `pathchord` executable provides the Ingress and Egress service subcommands
and local management commands. Each service invocation owns a separate
process. The ordinary examples use explicit proxy listeners and require no
packet interception or TUN privileges. Linux transparent and TUN examples are
provided separately and require the platform privileges and routing setup
described below.

## Configuration directory and overrides

With no explicit configuration option, Ingress loads `~/.config/pathchord` for
a regular account or `/etc/pathchord` for root/service accounts. An explicit
command-line source overrides environment variables, which override the
account default. For example:

```sh
pathchord ingress
PATHCHORD_CONFIG_DIR=/opt/pathchord/conf.d pathchord ingress
pathchord ingress --config-dir /opt/pathchord/conf.d
pathchord ingress --config /opt/pathchord/single.yaml
```

`PATHCHORD_CONFIG` also accepts a file or directory. Set only one non-empty
configuration environment variable when no command-line source is supplied.
`--config`/`-c` and `--config-dir`/`-C` are mutually exclusive. The exact
account classification and precedence are defined in the
[configuration source contract](configuration-schema.md#configuration-sources).

Split resources into `.yaml`, `.yml`, or `.json` files in the selected tree;
subdirectories are included. All resources form one validated graph, so a
Listener, DNSPolicy, FallbackPolicy, node, and routing rules can live in
different files. Keep private key/credential JSON and `--data-dir` outside
that tree. Reloading additions, modifications, removals, and renames replaces
the complete valid graph atomically; a failed candidate retains the old one.

## Local explicit proxy

Build the executable and run the direct-routing example:

```sh
cargo build --locked --release -p pathchord-cli
./target/release/pathchord ingress --config examples/ingress-direct.yaml
```

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
pathchord ingress --config examples/ingress-subscriptions.yaml
```

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
sudo ./target/release/pathchord ingress --config examples/ingress-tproxy.yaml
sudo ./target/release/pathchord ingress --config examples/ingress-tun.yaml
```

TPROXY and TUN listeners accept IP flows, so routing matches the original IP
address, port, protocol, and available process metadata. Domain-only policy
conditions do not match a flow whose original packet contains no hostname.

Unsupported Transit protocols and parameters remain visible as typed node
diagnostics until their native PathChord adapters are implemented. PathChord
does not start or embed an external proxy process as a compatibility backend.
See the [Transit Proxy contract](transit-proxies.md).

## Ingress and Egress enrollment

Generate a private identity on each corresponding machine. The command prints
only the public key; the private file MUST remain local to its owner:

```sh
pathchord keygen --output ingress.key.json
pathchord keygen --output egress.key.json
```

Start Egress in its own terminal. The Unix control socket is local to Egress:

```sh
pathchord egress --egress-id exit --identity egress.key.json \
  --bind 127.0.0.1:9443 --control-socket /tmp/pathchord-egress.sock
```

On the Egress machine, explicitly enroll the Ingress public key. Replace
`INGRESS_PUBLIC_KEY` with the public output from the Ingress key generation.
Generation 0 applies to a new authorization database; subsequent mutations
MUST use its observed generation:

```sh
pathchord --socket /tmp/pathchord-egress.sock enroll add \
  --ingress-id entry --egress-id exit --public-key INGRESS_PUBLIC_KEY \
  --expected-generation 0
```

In `examples/ingress-egress.yaml`, replace `REPLACE_WITH_EGRESS_PUBLIC_KEY`
with the Egress public key. The example uses a loopback Egress address;
cross-machine deployments MUST set the reachable Egress bind/address and keep
the same explicitly verified key and canonical Egress ID. Start Ingress in a
separate terminal:

```sh
pathchord --socket /tmp/pathchord-ingress.sock ingress \
  --ingress-id entry --identity ingress.key.json \
  --config examples/ingress-egress.yaml
pathchord --socket /tmp/pathchord-ingress.sock status
pathchord --socket /tmp/pathchord-egress.sock enroll list
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

Each service accepts Ctrl-C shutdown and owns its task/connection cleanup.
Persistent configuration changes follow the reload contract; identity,
listener topology, and other startup-only settings require a service restart
when the reload response reports that requirement.
