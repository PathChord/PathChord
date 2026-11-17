#!/usr/bin/env python3
"""Exercise real Linux interception in disposable network namespaces.

Build first with `cargo build --locked --bin pathchord-ingressd --bin pathchordctl`,
then run `sudo -n python3 scripts/test-linux-platforms.py`. No host routing,
firewall, sysctl or interface is changed. Logs and a JSON report are retained in
--output (otherwise a temporary directory printed at startup).
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

TCP_PORT = 19080
UDP_PORT = 19081
PROTECTED_PORT = 19082
LISTENER_PORT = 15001
MARK = 17
TABLE = 47171


def run(*args, ns=None, check=True, **kwargs):
    command = list(map(str, args))
    if ns:
        # Enter only the network namespace: `ip netns exec` replaces /sys in a
        # new mount namespace and hides the shared bpffs used by the backend.
        command = ["nsenter", "--net=/run/netns/" + ns, "--"] + command
    result = subprocess.run(command, check=False, text=True, capture_output=True,
                            timeout=kwargs.pop("timeout", 15), **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"{command}: {result.stderr.strip()} (exit {result.returncode})")
    return result


def spawn(*args, ns=None, **kwargs):
    command = list(map(str, args))
    if ns:
        command = ["nsenter", "--net=/run/netns/" + ns, "--"] + command
    return subprocess.Popen(command, text=True, **kwargs)


def peer():
    selection = selectors.DefaultSelector()
    for family, address in ((socket.AF_INET, "10.251.12.2"),
                            (socket.AF_INET6, "fd25:12::2")):
        for kind, ports in ((socket.SOCK_STREAM, (TCP_PORT, PROTECTED_PORT)),
                            (socket.SOCK_DGRAM, (UDP_PORT, PROTECTED_PORT))):
            for port in ports:
                sock = socket.socket(family, kind)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((address, port))
                if kind == socket.SOCK_STREAM:
                    sock.listen()
                selection.register(sock, selectors.EVENT_READ, kind)
    print("ready", flush=True)
    while True:
        for key, _ in selection.select():
            sock, kind = key.fileobj, key.data
            if kind == socket.SOCK_DGRAM:
                payload, source = sock.recvfrom(65535)
                sock.sendto(source[0].encode() + b"|" + payload, source)
            else:
                connection, source = sock.accept()
                connection.settimeout(5)
                try:
                    payload = b""
                    while chunk := connection.recv(65536):
                        payload += chunk
                    connection.sendall(source[0].encode() + b"|" + payload)
                except (OSError, TimeoutError):
                    pass
                connection.close()


def client(address, protocol, port, expected):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    length = int(os.environ.get("PATHCHORD_TEST_UDP_BYTES", "4096")) if protocol == "udp" else 16384
    payload = (bytes(range(256)) * ((length + 255) // 256))[:length]
    sock = socket.socket(family, kind)
    sock.settimeout(3)
    if kind == socket.SOCK_DGRAM:
        sock.setsockopt(socket.IPPROTO_IPV6 if family == socket.AF_INET6 else socket.IPPROTO_IP,
                        23 if family == socket.AF_INET6 else 10, 0)
    reply = b""
    try:
        sock.connect((address, port))
        sock.sendall(payload)
        if protocol == "tcp":
            sock.shutdown(socket.SHUT_WR)
            while chunk := sock.recv(65536):
                reply += chunk
        else:
            reply = sock.recv(65535)
    except OSError:
        if expected != "blocked":
            raise
    finally:
        sock.close()
    if expected == "blocked":
        assert not reply, "protected destination unexpectedly forwarded"
    else:
        assert reply == expected.encode() + b"|" + payload, repr(reply[:100])
    print(json.dumps({"address": address, "protocol": protocol,
                      "port": port, "bytes": len(payload), "expected": expected}))


class Harness:
    def __init__(self, options):
        self.options = options
        self.output = Path(options.output or tempfile.mkdtemp(prefix="pathchord-linux-"))
        self.output.mkdir(parents=True, exist_ok=True)
        self.output = self.output.resolve()
        self.names = [f"pcplat-{os.getpid()}-{suffix}" for suffix in ("c", "p", "t")]
        self.client_ns, self.proxy_ns, self.target_ns = self.names
        self.children = []
        self.results = []
        self.script = Path(__file__).resolve()
        self.ingress = Path(options.ingress).resolve()
        self.control = self.ingress.with_name("pathchordctl")
        self.service = None
        self.service_log = None

    def record(self, name, **fields):
        result = {"name": name, "outcome": "passed", **fields}
        self.results.append(result)
        print(json.dumps(result), flush=True)

    def ip(self, *args, ns=None, **kwargs):
        # Route protocols and route types have host-dependent symbolic names.
        if "-json" in args and "-N" not in args:
            args = ("-N", *args)
        return run("ip", *args, ns=ns or self.proxy_ns, **kwargs)

    def setup(self):
        for ns in self.names:
            run("ip", "netns", "add", ns)
            self.ip("link", "set", "lo", "up", ns=ns)
        for a, b, name_a, name_b in ((self.client_ns, self.proxy_ns, "client0", "lan0"),
                                    (self.proxy_ns, self.target_ns, "wan0", "target0")):
            self.ip("link", "add", name_a, "type", "veth", "peer", "name", name_b, ns=a)
            self.ip("link", "set", name_b, "netns", b, ns=a)
        for ns, device, addresses in ((self.client_ns, "client0", ("10.251.11.2/24", "fd25:11::2/64")),
                                      (self.proxy_ns, "lan0", ("10.251.11.1/24", "fd25:11::1/64")),
                                      (self.proxy_ns, "wan0", ("10.251.12.1/24", "fd25:12::1/64")),
                                      (self.target_ns, "target0", ("10.251.12.2/24", "fd25:12::2/64"))):
            self.ip("link", "set", device, "up", ns=ns)
            for address in addresses:
                self.ip("address", "add", address, "dev", device, "nodad", ns=ns)
        for family, gateway in (("-4", "10.251.11.1"), ("-6", "fd25:11::1")):
            self.ip(family, "route", "add", "default", "via", gateway, ns=self.client_ns)
        for family, prefix, gateway in (("-4", "10.251.11.0/24", "10.251.12.1"),
                                        ("-6", "fd25:11::/64", "fd25:12::1")):
            self.ip(family, "route", "add", prefix, "via", gateway, ns=self.target_ns)
        run("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1",
            "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.lan0.rp_filter=0", ns=self.proxy_ns)
        peer_log = open(self.output / "peer.log", "w")
        process = spawn(sys.executable, self.script, "--peer", ns=self.target_ns,
                        stdout=peer_log, stderr=subprocess.STDOUT)
        self.children.append(process)
        self.wait(lambda: (self.output / "peer.log").read_text().startswith("ready"), process)
        if shutil.which("tcpdump"):
            capture_log = open(self.output / "capture.log", "w")
            capture = spawn("tcpdump", "-U", "-n", "-i", "any", "-s", "160", "-w", self.output / "network.pcap", ns=self.proxy_ns,
                            stdout=capture_log, stderr=subprocess.STDOUT)
            self.children.append(capture)
        self.record("isolated topology", namespaces=self.names)

    @staticmethod
    def wait(predicate, process=None, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process and process.poll() is not None:
                raise RuntimeError(f"process exited with {process.returncode}")
            if predicate():
                return
            time.sleep(0.05)
        raise TimeoutError("readiness deadline expired")

    def configure(self, mode, family, label):
        work = self.output / label
        work.mkdir(exist_ok=True)
        address = "10.251.12.2" if family == 4 else "fd25:12::2"
        bind = f"0.0.0.0:{LISTENER_PORT}" if family == 4 else f"[::]:{LISTENER_PORT}"
        spec = {"type": "tproxy" if mode == "ebpf" else mode,
                "platform": "linux", "protocols": ["tcp"] if mode == "redirect" else ["tcp", "udp"],
                "allowedSources": ["10.251.11.0/24", "fd25:11::/64"]}
        if mode == "tun":
            spec.update(interface=f"pctun{family}", address="198.18.0.1/30" if family == 4 else "fd25:18::1/64", mtu=1500)
        else:
            spec["bind"] = bind
        if mode in ("tproxy", "ebpf"):
            spec.update(mark=MARK, routeTable=TABLE)
        if mode == "ebpf":
            spec.update(backend="ebpf", interface="lan0")
        resources = [
            {"apiVersion": "pathchord.io/v1", "kind": "Listener", "metadata": {"name": "smoke"}, "spec": spec},
            {"apiVersion": "pathchord.io/v1", "kind": "DNSPolicy", "metadata": {"name": "dns"},
             "spec": {"defaultRoute": "local", "local": {"servers": [f"{address}:{PROTECTED_PORT}" if family == 4 else f"[{address}]:{PROTECTED_PORT}"]}}},
            {"apiVersion": "pathchord.io/v1", "kind": "FallbackPolicy", "metadata": {"name": "fallback"}, "spec": {"action": "direct"}},
        ]
        config = work / "config.yaml"
        config.write_text("\n---\n".join(json.dumps(value) for value in resources) + "\n")
        return work

    def start(self, work, env=None, failure=False):
        self.service_log = open(work / f"ingress-{time.time_ns()}.log", "w")
        socket_path = work / "ctl.sock"
        socket_path.unlink(missing_ok=True)
        self.service = spawn(self.ingress, "--config", work / "config.yaml", "--data-dir", work / "data",
                             "--credentials-dir", work / "secrets", "--socket", socket_path,
                             ns=self.proxy_ns, stdout=self.service_log, stderr=subprocess.STDOUT, env=env)
        self.children.append(self.service)
        if failure:
            assert self.service.wait(timeout=12) != 0, "invalid startup unexpectedly succeeded"
        else:
            self.wait(socket_path.exists, self.service)
            # Socket existence precedes some asynchronous startup work; management is the barrier.
            self.wait(lambda: run(self.control, "--socket", socket_path, "status", ns=self.proxy_ns,
                                  check=False).returncode == 0, self.service)

    def stop(self, crash=False, check=True):
        if self.service and self.service.poll() is None:
            self.service.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
            try:
                status = self.service.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.service.kill()
                status = self.service.wait(timeout=3)
            if not crash and check:
                assert status == 0, f"shutdown returned {status}"
        self.service = None
        if self.service_log:
            self.service_log.close()

    def rules(self, mode, family):
        run("nft", "delete", "table", "inet", "pcsmoke", ns=self.proxy_ns, check=False)
        ip_match = "ip daddr 10.251.12.2" if family == 4 else "ip6 daddr fd25:12::2"
        if mode == "tun":
            device = f"pctun{family}"
            self.ip(f"-{family}", "route", "add", "default", "dev", device, "table", "47200")
            self.ip(f"-{family}", "rule", "add", "priority", "29000", "iif", "lan0", "lookup", "47200")
            return
        if mode == "redirect":
            rule = f'{ip_match} tcp dport {{ {TCP_PORT}, {PROTECTED_PORT} }} counter redirect to :{LISTENER_PORT}'
            kind = "nat"
            priority = "dstnat"
        else:
            prefix = f"meta mark {MARK} " if mode == "ebpf" else ""
            suffix = "" if mode == "ebpf" else f" meta mark set {MARK}"
            rule = f'{prefix}{ip_match} meta l4proto {{ tcp, udp }} th dport {{ {TCP_PORT}, {UDP_PORT}, {PROTECTED_PORT} }} counter tproxy {"ip" if family == 4 else "ip6"} to :{LISTENER_PORT}{suffix} accept'
            kind, priority = "filter", "mangle"
        config = ('table inet pcsmoke { chain incoming { type ' + kind + ' hook prerouting priority ' + priority +
                  '; policy accept; ct state invalid drop; iifname "lan0" ' + rule + '; }; }\n')
        run("nft", "-f", "-", ns=self.proxy_ns, input=config)

    def probe(self, family, protocol, port=None, expected=None):
        address = "10.251.12.2" if family == 4 else "fd25:12::2"
        expected = expected or ("10.251.12.1" if family == 4 else "fd25:12::1")
        result = run(sys.executable, self.script, "--client", address, protocol,
                     str(port or (TCP_PORT if protocol == "tcp" else UDP_PORT)), expected,
                     ns=self.client_ns, timeout=8)
        return json.loads(result.stdout)

    def clean_slots(self):
        for family in (4, 6):
            rules = json.loads(self.ip("-json", f"-{family}", "rule", "show").stdout)
            assert not any(item.get("priority") == 30000 for item in rules), rules
            routes = self.ip("-json", f"-{family}", "route", "show", "table", str(TABLE), check=False)
            assert routes.returncode != 0 or json.loads(routes.stdout) == [], routes.stdout

    def forwarding(self, mode, family, label=None):
        label = label or f"{mode}-ipv{family}"
        work = self.configure(mode, family, label)
        self.start(work)
        self.rules(mode, family)
        results = [self.probe(family, "tcp")]
        if mode != "redirect":
            results.append(self.probe(family, "udp"))
        if mode == "tun":
            # Responses arrive only after the client half-closes. Repetition
            # exercises task-completion versus buffered-response scheduling.
            for _ in range(16):
                self.probe(family, "tcp")
        results.append(self.probe(family, "tcp", PROTECTED_PORT, "blocked"))
        if mode != "redirect":
            results.append(self.probe(family, "udp", PROTECTED_PORT, "blocked"))
        if mode != "tun":
            listing = run("nft", "list", "table", "inet", "pcsmoke", ns=self.proxy_ns).stdout
            (work / "nft.txt").write_text(listing)
            assert "counter packets 0 bytes 0" not in listing, listing
        self.stop()
        if mode == "ebpf":
            self.ebpf_clean(work)
        if mode == "tun":
            links = json.loads(self.ip("-json", "link", "show").stdout)
            assert not any(link["ifname"] == f"pctun{family}" for link in links)
            self.ip(f"-{family}", "rule", "del", "priority", "29000")
            self.ip(f"-{family}", "route", "flush", "table", "47200")
        else:
            self.clean_slots()
        self.record(label, exchanges=results, tcp_roundtrips=17 if mode == "tun" else 1, cleanup=True)

    def redirect_udp_rejected(self):
        work = self.configure("redirect", 4, "redirect-udp-rejected")
        documents = (work / "config.yaml").read_text().split("\n---\n")
        listener = json.loads(documents[0])
        listener["spec"]["protocols"] = ["tcp", "udp"]
        documents[0] = json.dumps(listener)
        (work / "config.yaml").write_text("\n---\n".join(documents))
        self.start(work, failure=True)
        self.clean_slots()
        self.record("REDIRECT UDP configuration rejected explicitly", cleanup=True)

    def recovery(self):
        work = self.configure("tproxy", 4, "route-recovery")
        self.start(work)
        self.stop(crash=True)
        assert list((work / "data").rglob("*-routing.json")), "missing crash journal"
        assert any(item.get("priority") == 30000 for item in json.loads(self.ip("-json", "-4", "rule", "show").stdout))
        self.start(work)
        self.stop()
        self.clean_slots()
        assert not list((work / "data").rglob("*-routing.json"))
        self.record("route journal crash/restart recovery", cleanup=True)

        self.start(work)
        self.stop(crash=True)
        self.ip("-6", "route", "replace", "table", str(TABLE), "proto", "99", "local", "::/0", "dev", "lo")
        self.start(work, failure=True)
        live = json.loads(self.ip("-json", "-6", "route", "show", "table", str(TABLE)).stdout)
        assert live and str(live[0].get("protocol")) == "99", live
        assert list((work / "data").rglob("*-routing.json")), "conflict discarded recovery journal"
        self.ip("-6", "route", "replace", "table", str(TABLE), "proto", "186", "local", "::/0", "dev", "lo")
        self.start(work)
        self.stop()
        self.clean_slots()
        self.record("changed foreign route survives recovery conflict", cleanup=True)

        self.start(work)
        self.stop(crash=True)
        self.ip("-4", "rule", "del", "priority", "30000")
        self.ip("-4", "rule", "add", "priority", "30000", "fwmark", f"{MARK}/0xff", "lookup", str(TABLE), "protocol", "186")
        self.start(work, failure=True)
        live = json.loads(self.ip("-json", "-4", "rule", "show", "priority", "30000").stdout)
        assert len(live) == 1 and live[0].get("fwmask") == "0xff", live
        assert list((work / "data").rglob("*-routing.json"))
        self.ip("-4", "rule", "del", "priority", "30000")
        self.ip("-4", "rule", "add", "priority", "30000", "fwmark", str(MARK), "lookup", str(TABLE), "protocol", "186")
        self.start(work)
        self.stop()
        self.clean_slots()
        self.record("changed foreign rule mask survives recovery conflict", cleanup=True)

    def rollback(self):
        work = self.configure("tproxy", 4, "route-rollback")
        tools = work / "tools"
        tools.mkdir(exist_ok=True)
        real_ip = shutil.which("ip")
        assert real_ip, "iproute2 is required"
        shim = tools / "ip"
        shim.write_text('#!/bin/sh\nif [ "$1 $2 $3" = "-6 route add" ]; then echo "injected route failure" >&2; exit 1; fi\nexec ' + real_ip + ' "$@"\n')
        shim.chmod(0o755)
        environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"])
        self.start(work, env=environment, failure=True)
        self.clean_slots()
        assert not list((work / "data").rglob("*-routing.json"))
        self.record("kernel route apply failure rolls back previous mutations", cleanup=True)
        self.ip("-4", "rule", "add", "priority", "30000", "fwmark", "99", "lookup", str(TABLE), "protocol", "99")
        self.start(work, failure=True)
        rules = json.loads(self.ip("-json", "-4", "rule", "show", "priority", "30000").stdout)
        assert len(rules) == 1 and str(rules[0].get("protocol")) == "99", rules
        self.ip("-4", "rule", "del", "priority", "30000")
        self.clean_slots()
        self.record("foreign rule rejected without mutation", cleanup=True)

    def ebpf_clean(self, work):
        owner = hashlib.sha256(str((work / "data/platform").resolve()).encode()).hexdigest()[:32]
        assert not Path(f"/sys/fs/bpf/pathchord/{owner}/smoke").exists()
        assert not (work / "data/platform/ebpf/smoke/owner.json").exists()
        assert not json.loads(run("tc", "-json", "filter", "show", "dev", "lan0", "ingress", "pref", "30000", ns=self.proxy_ns).stdout)

    def ebpf_ownership(self):
        work = self.configure("ebpf", 4, "ebpf-ownership")
        run("tc", "qdisc", "add", "dev", "lan0", "clsact", ns=self.proxy_ns)
        run("tc", "filter", "add", "dev", "lan0", "ingress", "pref", "100", "matchall", "action", "skbedit", "mark", "19", ns=self.proxy_ns)
        self.start(work)
        self.rules("ebpf", 4)
        self.probe(4, "tcp", expected="10.251.11.2")
        self.probe(4, "udp", expected="10.251.11.2")
        self.rules("ebpf", 6)
        self.probe(6, "tcp", expected="fd25:11::2")
        self.probe(6, "udp", expected="fd25:11::2")
        self.stop()
        self.ebpf_clean(work)
        foreign = json.loads(run("tc", "-json", "filter", "show", "dev", "lan0", "ingress", "pref", "100", ns=self.proxy_ns).stdout)
        assert foreign and foreign[0]["kind"] == "matchall", foreign
        self.record("eBPF preserves foreign packet marks and shared TC filter", cleanup=True)
        run("tc", "filter", "del", "dev", "lan0", "ingress", "pref", "100", ns=self.proxy_ns)
        run("tc", "qdisc", "del", "dev", "lan0", "clsact", ns=self.proxy_ns)

        self.start(work)
        self.stop(crash=True)
        assert (work / "data/platform/ebpf/smoke/owner.json").exists()
        self.start(work)
        self.rules("ebpf", 4)
        self.probe(4, "tcp")
        self.probe(4, "udp")
        # A later foreign filter must preserve even a clsact created by PathChord.
        run("tc", "filter", "add", "dev", "lan0", "ingress", "pref", "100", "matchall", "action", "pass", ns=self.proxy_ns)
        self.stop()
        self.ebpf_clean(work)
        foreign = json.loads(run("tc", "-json", "filter", "show", "dev", "lan0", "ingress", "pref", "100", ns=self.proxy_ns).stdout)
        assert foreign, foreign
        run("tc", "filter", "del", "dev", "lan0", "ingress", "pref", "100", ns=self.proxy_ns)
        run("tc", "qdisc", "del", "dev", "lan0", "clsact", ns=self.proxy_ns)
        self.record("eBPF crash journal recovers pins and preserves later foreign filter", cleanup=True)

        self.start(work)
        run("tc", "filter", "del", "dev", "lan0", "ingress", "pref", "30000", ns=self.proxy_ns)
        run("tc", "filter", "add", "dev", "lan0", "ingress", "pref", "30000", "matchall", "action", "pass", ns=self.proxy_ns)
        self.stop(check=False)
        foreign = json.loads(run("tc", "-json", "filter", "show", "dev", "lan0", "ingress", "pref", "30000", ns=self.proxy_ns).stdout)
        assert foreign and all(value["kind"] == "matchall" for value in foreign), foreign
        assert (work / "data/platform/ebpf/smoke/owner.json").exists()
        self.start(work, failure=True)
        assert json.loads(run("tc", "-json", "filter", "show", "dev", "lan0", "ingress", "pref", "30000", ns=self.proxy_ns).stdout), "recovery deleted foreign filter"
        run("tc", "filter", "del", "dev", "lan0", "ingress", "pref", "30000", ns=self.proxy_ns)
        self.start(work)
        self.stop()
        self.ebpf_clean(work)
        self.clean_slots()
        self.record("eBPF replacement filter survives shutdown and restart ownership conflict", cleanup=True)

        run("tc", "qdisc", "add", "dev", "lan0", "clsact", ns=self.proxy_ns)
        run("tc", "filter", "add", "dev", "lan0", "ingress", "pref", "30000", "matchall", "action", "pass", ns=self.proxy_ns)
        before = run("tc", "-json", "filter", "show", "dev", "lan0", "ingress", ns=self.proxy_ns).stdout
        self.start(work, failure=True)
        after = run("tc", "-json", "filter", "show", "dev", "lan0", "ingress", ns=self.proxy_ns).stdout
        assert json.loads(before) == json.loads(after), (before, after)
        self.clean_slots()
        run("tc", "qdisc", "del", "dev", "lan0", "clsact", ns=self.proxy_ns)
        self.record("eBPF rejects occupied TC priority without deleting administrator filter", cleanup=True)

        tools = work / "tools"
        tools.mkdir(exist_ok=True)
        shim = tools / "bpftool"
        shim.write_text('#!/bin/sh\n echo "injected missing BPF capability" >&2; exit 1\n')
        shim.chmod(0o755)
        self.start(work, env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"]), failure=True)
        self.clean_slots()
        self.ebpf_clean(work)
        self.forwarding("tproxy", 4, "ordinary-tproxy-after-ebpf-failure")
        self.record("explicit ordinary TPROXY fallback after unavailable eBPF", cleanup=True)

    def execute(self):
        print(f"Linux platform evidence: {self.output}", flush=True)
        complete = False
        try:
            self.setup()
            for mode in self.options.modes:
                for family in (4, 6):
                    self.forwarding(mode, family)
            self.redirect_udp_rejected()
            self.recovery()
            self.rollback()
            if not self.options.skip_ebpf:
                for family in (4, 6):
                    self.forwarding("ebpf", family)
                self.ebpf_ownership()
            complete = True
        finally:
            self.stop(check=False)
            for process in reversed(self.children):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
            for ns in reversed(self.names):
                run("ip", "netns", "del", ns, check=False)
            remaining = run("ip", "netns", "list").stdout
            assert not any(ns in remaining for ns in self.names), remaining
            (self.output / "report.json").write_text(json.dumps({"kernel": os.uname().release,
                "architecture": os.uname().machine, "revision": self.options.revision,
                "outcome": "passed" if complete else "failed", "results": self.results, "namespaces_removed": True}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ingress", default="target/debug/pathchord-ingressd")
    parser.add_argument("--output")
    parser.add_argument("--revision", default="working-tree")
    parser.add_argument("--skip-ebpf", action="store_true")
    parser.add_argument("--modes", nargs="+", choices=("tproxy", "redirect", "tun"), default=("tproxy", "redirect", "tun"))
    parser.add_argument("--peer", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--client", nargs=4, help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.peer:
        peer()
    elif options.client:
        address, protocol, port, expected = options.client
        client(address, protocol, int(port), expected)
    else:
        if os.geteuid() != 0:
            parser.error("run with sudo; all network mutations are isolated in temporary namespaces")
        Harness(options).execute()


if __name__ == "__main__":
    main()
