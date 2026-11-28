#!/usr/bin/env python3
"""Verify native TCP/UDP adapters between two independent QEMU Linux guests.

Requires a static musl cross_machine_probe example and a test-only sing-box
1.14.6 executable. All credentials are generated for this disposable lab.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import time
import uuid

from qemu_lab import DEFAULT_CACHE, Lab, ROOT, digest, new_run_directory, run


ECHO = r"""import asyncio, socket

class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, payload, address): self.transport.sendto(payload, address)

async def tcp(reader, writer):
    try:
        while payload := await reader.read(65536):
            writer.write(payload)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()

async def main():
    loop = asyncio.get_running_loop()
    servers, transports = [], []
    for host in ('127.0.0.1', '::1', '192.0.2.11', 'fd00:7063::11'):
        servers.append(await asyncio.start_server(tcp, host, 28080))
        transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=(host, 28081))
        transports.append(transport)
    print('ECHO_READY', flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
"""


def node(protocol, port, certificate):
    return {
        "id": f"qemu-{protocol}", "source": None, "protocol": protocol,
        "endpoint": {"host": "192.0.2.11", "port": port},
        "credentials_ref": None, "labels": {}, "tags": [], "weight": 100,
        "options": {"udp": True, "tls": {
            "enabled": True, "serverName": "proxy.test", "certificates": [certificate],
        }},
    }


def stage_peer(guest, binary):
    """Keep a dynamically linked reference peer's loader private to the lab."""
    guest.put(binary, "/tmp/sing-box")
    libraries = subprocess.run(["ldd", str(binary)], capture_output=True, text=True, check=False)
    paths = set(re.findall(r"(?:=>\s+|^\s*)(/\S+)", libraries.stdout, re.MULTILINE))
    if not paths:
        return "/tmp/sing-box", {}
    guest.ssh("mkdir -p /tmp/peer-glibc")
    hashes = {}
    loader = None
    for name in sorted(paths):
        source = Path(name)
        guest.put(source.resolve(), f"/tmp/peer-glibc/{source.name}")
        hashes[source.name] = digest(source.resolve())
        if source.name.startswith("ld-linux"):
            loader = source.name
    if loader is None:
        raise RuntimeError("could not identify the reference peer's ELF loader")
    return f"/tmp/peer-glibc/{loader} --library-path /tmp/peer-glibc /tmp/sing-box", hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--probe", type=Path,
                        default=ROOT / "target/x86_64-unknown-linux-musl/debug/examples/cross_machine_probe")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--delay-ms", type=int, default=10)
    parser.add_argument("--protocols", nargs="+", choices=("reality", "hysteria2", "tuic", "anytls", "vmess"),
                        default=["reality", "hysteria2", "tuic", "anytls", "vmess"])
    parser.add_argument("--baseline-only", action="store_true")
    arguments = parser.parse_args()
    for binary in (arguments.sing_box, arguments.probe):
        if not binary.is_file():
            parser.error(f"missing executable: {binary}")
    version = run([str(arguments.sing_box.resolve()), "version"], capture_output=True).stdout
    if "sing-box version 1.14.6" not in version.splitlines():
        parser.error("this matrix is pinned to the test-only sing-box 1.14.6 peer")
    if not 0 <= arguments.delay_ms <= 1000:
        parser.error("delay must be between 0 and 1000 milliseconds")
    output = arguments.output.resolve() if arguments.output else new_run_directory("transit")
    output.mkdir(parents=True, exist_ok=True)
    private = output / "private-fixtures"
    private.mkdir(mode=0o700)
    results = []
    try:
        certificate_path, key_path = private / "cert.pem", private / "key.pem"
        run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=proxy.test", "-addext", "subjectAltName=DNS:proxy.test,DNS:decoy.test",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(key_path), "-out", str(certificate_path),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        certificate = certificate_path.read_text()
        generated = run([str(arguments.sing_box.resolve()), "generate", "reality-keypair"],
                        capture_output=True).stdout
        pair = dict(line.split(": ", 1) for line in generated.splitlines() if ": " in line)
        client_uuid, password, short_id = str(uuid.uuid4()), secrets.token_hex(24), secrets.token_hex(8)
        tls = {"enabled": True, "certificate_path": "/tmp/cert.pem", "key_path": "/tmp/key.pem"}
        inbounds = [
            {"type": "vless", "tag": "reality", "listen": "::", "listen_port": 27443,
             "users": [{"uuid": client_uuid, "flow": "xtls-rprx-vision"}],
             "tls": {"enabled": True, "server_name": "decoy.test", "reality": {
                 "enabled": True,
                 "handshake": {"server": "127.0.0.1", "server_port": 27442},
                 "private_key": pair["PrivateKey"], "short_id": [short_id],
             }}},
            {"type": "hysteria2", "tag": "hysteria2", "listen": "::", "listen_port": 27444,
             "users": [{"password": password}], "tls": tls},
            {"type": "tuic", "tag": "tuic", "listen": "::", "listen_port": 27445,
             "users": [{"uuid": client_uuid, "password": password}],
             "tls": {**tls, "alpn": ["h3"]}},
            {"type": "anytls", "tag": "anytls", "listen": "::", "listen_port": 27446,
             "users": [{"name": "fixture", "password": password}], "tls": tls},
            {"type": "vmess", "tag": "vmess", "listen": "::", "listen_port": 27447,
             "users": [{"uuid": client_uuid, "alterId": 0}], "tls": tls},
        ]
        server_config = private / "sing-box.json"
        server_config.write_text(json.dumps({
            "log": {"level": "warn"}, "inbounds": inbounds,
            "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"},
        }))
        echo_path = private / "echo.py"
        echo_path.write_text(ECHO)
        cases = []
        for protocol, port in (("vless", 27443), ("hysteria2", 27444), ("tuic", 27445),
                               ("anytls", 27446), ("vmess", 27447)):
            config = node(protocol, port, certificate)
            credentials = {"password": password} if protocol in ("anytls", "hysteria2") else {"uuid": client_uuid}
            if protocol == "tuic":
                credentials["password"] = password
                config["options"]["tls"]["alpn"] = ["h3"]
            if protocol == "hysteria2":
                config["options"]["tls"]["alpn"] = ["h3"]
            if protocol == "vless":
                credentials["flow"] = "xtls-rprx-vision"
                config["options"]["tls"].pop("certificates")
                config["options"]["tls"]["serverName"] = "decoy.test"
                config["options"]["tls"]["clientHelloFingerprint"] = "chrome"
                config["options"]["tls"]["reality"] = {
                    "publicKey": pair["PublicKey"], "shortId": short_id,
                }
            cases.append({"node": config, "credentials": credentials,
                          "targets": ["127.0.0.1", "::1"], "tcp_port": 28080, "udp_port": 28081})
        unavailable = copy.deepcopy(cases[0])
        unavailable["node"]["options"]["transport"] = {"type": "grpc", "serviceName": "fixture"}
        unavailable["expect_unavailable"] = True
        unavailable["targets"] = []
        retired = copy.deepcopy(cases[3])
        retired["node"]["protocol"] = "ssr"
        retired["node"]["options"] = {}
        retired["expect_unavailable"] = True
        retired["targets"] = []

        with Lab(arguments.cache, output / "guests") as lab:
            peer_command, peer_libraries = stage_peer(lab.server, arguments.sing_box.resolve())
            for source, destination in (
                (certificate_path, "/tmp/cert.pem"),
                (key_path, "/tmp/key.pem"), (server_config, "/tmp/sing-box.json"), (echo_path, "/tmp/echo.py"),
            ):
                lab.server.put(source, destination)
            lab.server.ssh(f"{peer_command} check -c /tmp/sing-box.json")
            lab.server.ssh("nohup python3 /tmp/echo.py >/tmp/echo.log 2>&1 </dev/null &")
            lab.server.ssh("nohup openssl s_server -accept 127.0.0.1:27442 -cert /tmp/cert.pem "
                           "-key /tmp/key.pem -www -tls1_3 >/tmp/decoy.log 2>&1 </dev/null &")
            lab.server.ssh(f"nohup {peer_command} run -c /tmp/sing-box.json >/tmp/peer.log 2>&1 </dev/null &")
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                ready = lab.server.ssh("grep -q ECHO_READY /tmp/echo.log && "
                                       "ss -lnt | grep -q ':27446'", check=False)
                if ready.returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("QEMU protocol server did not start")
            # Distinguish a broken virtual UDP link from protocol negotiation.
            lab.client.ssh("python3 - <<'PY'\nimport socket\n"
                           "for family, host in ((socket.AF_INET, '192.0.2.11'), "
                           "(socket.AF_INET6, 'fd00:7063::11')):\n"
                           " with socket.socket(family, socket.SOCK_DGRAM) as channel:\n"
                           "  channel.settimeout(3)\n"
                           "  channel.sendto(b'virtual-wire' * 300, (host, 28081))\n"
                           "  assert channel.recv(8192) == b'virtual-wire' * 300\nPY")
            # Strip only a temporary copy; the Cargo artifact remains intact.
            stripped = private / "cross_machine_probe"
            shutil.copyfile(arguments.probe, stripped)
            stripped.chmod(0o755)
            run(["strip", str(stripped)])
            lab.client.put(stripped, "/tmp/cross_machine_probe")
            lab.client.ssh("mkdir -p /tmp/pathchord-probe-tmp; chmod 700 /tmp/pathchord-probe-tmp")
            for phase in (("baseline",) if arguments.baseline_only else ("baseline", "delayed")):
                if phase == "delayed":
                    for guest in (lab.client, lab.server):
                        guest.ssh(f"modprobe sch_netem; tc qdisc add dev eth1 root netem delay {arguments.delay_ms}ms")
                for number, case in enumerate(cases):
                    protocol = "reality" if number == 0 else case["node"]["protocol"]
                    if protocol not in arguments.protocols:
                        continue
                    for address in ("192.0.2.11", "fd00:7063::11"):
                        case["node"]["endpoint"]["host"] = address
                        path = private / "probe.json"
                        path.write_text(json.dumps(case))
                        lab.client.put(path, "/tmp/probe.json")
                        result = lab.client.ssh("env TMPDIR=/tmp/pathchord-probe-tmp /tmp/cross_machine_probe /tmp/probe.json", timeout=180, check=False)
                        if result.returncode:
                            for name in ("peer", "decoy", "echo"):
                                (output / f"{name}.log").write_text(
                                    lab.server.ssh(f"cat /tmp/{name}.log", check=False).stdout)
                            for guest in (lab.client, lab.server):
                                (output / f"{guest.role}-failure-network.txt").write_text(
                                    guest.ssh("ss -lnup; ip -s link show eth1; cat /proc/net/snmp; "
                                              "sysctl net.ipv6.bindv6only", check=False).stdout)
                            raise RuntimeError(f"{protocol} {phase} {address}: {result.stderr[-2000:]}")
                        record = json.loads(result.stdout)
                        record.update({"case": protocol, "phase": phase, "peer_address": address})
                        results.append(record)
                        print(json.dumps(record), flush=True)
            for case in (unavailable, retired):
                path = private / "probe.json"
                path.write_text(json.dumps(case))
                lab.client.put(path, "/tmp/probe.json")
                result = lab.client.ssh("env TMPDIR=/tmp/pathchord-probe-tmp /tmp/cross_machine_probe /tmp/probe.json", timeout=30)
                results.append(json.loads(result.stdout))
            for guest in (lab.client, lab.server):
                (output / f"{guest.role}-network.txt").write_text(
                    guest.ssh("ip -br addr; tc -s qdisc show dev eth1").stdout)
            (output / "peer.log").write_text(lab.server.ssh("cat /tmp/peer.log").stdout)
            topology = json.loads((lab.directory / "topology.json").read_text())
            report = {
                "topology": topology, "peer_version": version.splitlines()[0],
                "peer_sha256": digest(arguments.sing_box), "probe_sha256": digest(arguments.probe),
                "peer_private_libraries_sha256": peer_libraries,
                "delay_ms_per_direction": arguments.delay_ms,
                "guest_probe_tmpdir": "/tmp/pathchord-probe-tmp",
                "cases": results, "ok": True,
            }
            (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"QEMU Transit matrix passed: {len(results)} cases; {output / 'results.json'}")
    finally:
        shutil.rmtree(private, ignore_errors=True)


if __name__ == "__main__":
    main()
