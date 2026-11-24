#!/usr/bin/env python3
"""Run bounded, local process soak checks using only synthetic private fixtures.

Build first with cargo build --locked -p pathchord-ingressd -p pathchord-egressd
-p pathchordctl. No real subscriptions, remote machines, root, or network changes
are needed. JSON output contains measurements and check names, never credentials.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import uuid


SENTINEL = "PRIVATE_RUNTIME_FIXTURE_841d"
MAX_ENVELOPE = 1024 * 1024


class Failure(Exception):
    pass


def check(value, name):
    if not value:
        raise Failure(name)


def emit(**value):
    encoded = json.dumps(value, sort_keys=True)
    check(SENTINEL not in encoded, "output_redaction")
    print(encoded, flush=True)


def wait_for(predicate, name, seconds=12):
    deadline = time.monotonic() + seconds
    while True:
        result = predicate()
        if result:
            return result
        check(time.monotonic() < deadline, name)
        time.sleep(0.05)


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        packet = stream.recv(count - len(data))
        if not packet:
            raise EOFError()
        data.extend(packet)
    return bytes(data)


def header(stream):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        check(len(result) < 8192, "bounded_http_header")
        result.extend(exact(stream, 1))
    return bytes(result)


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def varint(value):
    for width, marker, limit in ((1, 0, 64), (2, 0x4000, 16384), (4, 0x80000000, 2**30)):
        if value < limit:
            return (value | marker).to_bytes(width, "big")
    raise Failure("envelope_too_large")


class Management:
    def __init__(self, path):
        self.path = path

    def request(self, operation, body=None, generation=None, scope="configuration", ok=True):
        request = {"api_version": "1", "operation": operation,
                   "request_id": uuid.uuid4().hex,
                   "actor": {"id": "fixture-owner", "capabilities": []}, "body": body or {}}
        if generation is not None:
            request["expected_generation"] = {"scope": scope, "value": generation}
        payload = json.dumps(request).encode()
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(8)
            stream.connect(str(self.path))
            stream.sendall(varint(len(payload)) + payload)
            first = exact(stream, 1)
            width = 1 << (first[0] >> 6)
            prefix = first + exact(stream, width - 1)
            size = int.from_bytes(prefix, "big") & ((1 << (width * 8 - 2)) - 1)
            check(0 < size <= MAX_ENVELOPE, "bounded_management_reply")
            payload = exact(stream, size)
        check(SENTINEL.encode() not in payload, "management_credential_redaction")
        response = json.loads(payload)
        if ok:
            if not response.get("ok"):
                raise Failure("management_" + operation + ":" + response["error"]["message"])
            return response["result"]
        return response

    def status(self):
        return self.request("status.get")

    def items(self, operation):
        result = self.request(operation, {"page_size": 256})
        check(result.get("next_page_token") is None, "bounded_fixture_inventory")
        return result["items"]

    def subscription(self):
        return self.items("subscriptions.list")[0]

    def mutate_subscription(self, operation, stale=None):
        item = self.subscription()
        generation = self.status()["configuration_generation"] if stale is None else stale
        return self.request(operation, {"id": item["id"], "revision": item["revision"]},
                            generation=generation, ok=stale is None)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


class FixtureServer:
    def __init__(self, handler):
        self.server = Server(("127.0.0.1", 0), handler)
        self.server.fixture = self
        self.address = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        try:
            while packet := self.request.recv(16384):
                self.request.sendall(packet)
        except OSError:
            pass


class Relay(FixtureServer):
    def __init__(self):
        self.lock = threading.Lock()
        self.streams = set()
        self.accepted = 0
        super().__init__(RelayHandler)

    def cut(self):
        with self.lock:
            streams = list(self.streams)
        for stream in streams:
            with contextlib.suppress(OSError):
                stream.shutdown(socket.SHUT_RDWR)


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        fixture = self.server.fixture
        client = self.request
        client.settimeout(8)
        try:
            request = header(client).split(b"\r\n", 1)[0].split()
            check(request[0] == b"CONNECT", "fixture_connect_method")
            host, target_port = request[1].decode().rsplit(":", 1)
            check(host == "127.0.0.1", "fixture_loopback_destination")
            with socket.create_connection((host, int(target_port)), timeout=8) as remote:
                with fixture.lock:
                    fixture.streams.update((client, remote))
                    fixture.accepted += 1
                try:
                    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    while True:
                        ready, _, _ = select.select((client, remote), (), (), 2)
                        for peer in ready:
                            packet = peer.recv(16384)
                            if not packet:
                                return
                            (remote if peer is client else client).sendall(packet)
                finally:
                    with fixture.lock:
                        fixture.streams.difference_update((client, remote))
        except (OSError, EOFError, Failure):
            pass


class Provider(FixtureServer):
    def __init__(self, relay):
        self.relay = relay
        self.mode = "good"
        self.requests = 0
        super().__init__(ProviderHandler)


class ProviderHandler(socketserver.BaseRequestHandler):
    def handle(self):
        fixture = self.server.fixture
        self.request.settimeout(5)
        try:
            header(self.request)
            fixture.requests += 1
            mode = fixture.mode
            if mode == "fetch":
                self.request.sendall(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")
                return
            if mode == "parse":
                body = b"proxies: [invalid: ["
            else:
                body = ("proxies:\n"
                        f"- {{name: relay, type: http, server: 127.0.0.1, port: {fixture.relay.address[1]}, "
                        f"username: fixture, password: {SENTINEL}}}\n"
                        f"- {{name: unsupported, type: ssr, server: 127.0.0.1, port: 1, password: {SENTINEL}}}\n").encode()
            response = (f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
                        "Subscription-Userinfo: upload=100; download=200; total=10000; expire=1900000000\r\n"
                        "PathChord-Traffic-Multiplier: 1.25\r\nConnection: close\r\n\r\n").encode()
            self.request.sendall(response + body)
        except (OSError, EOFError):
            pass


class Dns(socketserver.ThreadingUDPServer):
    daemon_threads = True


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        query, stream = self.request
        if self.server.fail:
            return
        if len(query) < 12:
            return
        response = (query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00"
                    + query[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x7f\x00\x00\x01")
        stream.sendto(response, self.client_address)


class Service:
    def __init__(self, binary, arguments, directory, socket_name):
        self.binary = binary
        self.arguments = arguments
        self.directory = directory
        self.management = Management(directory / socket_name)
        self.process = None
        self.log = None
        self.baseline_rss = None
        self.peak = {"fds": 0, "threads": 0, "rss_kib": 0, "rss_growth_kib": 0}

    def start(self):
        env = dict(os.environ)
        env.pop("PATHCHORD_CONFIG", None)
        env.pop("PATHCHORD_CONFIG_DIR", None)
        env["TOKIO_WORKER_THREADS"] = "2"
        self.log = tempfile.TemporaryFile()
        self.process = subprocess.Popen([str(self.binary), *map(str, self.arguments)],
                                        cwd=self.directory, env=env,
                                        stdout=self.log, stderr=self.log)
        self.baseline_rss = None

        def ready():
            check(self.process.poll() is None, "service_start_" + self.binary.name)
            try:
                return self.management.status()
            except (OSError, EOFError):
                return False

        wait_for(ready, "service_control_ready")

    def sample(self):
        check(self.process.poll() is None, "service_remains_running")
        root = Path("/proc") / str(self.process.pid)
        fields = {}
        for line in (root / "status").read_text().splitlines():
            key, _, value = line.partition(":")
            if key in ("VmRSS", "Threads"):
                fields[key] = int(value.split()[0])
        rss = fields["VmRSS"]
        if self.baseline_rss is None:
            self.baseline_rss = rss
        values = {"fds": len(list((root / "fd").iterdir())), "threads": fields["Threads"],
                  "rss_kib": rss, "rss_growth_kib": max(0, rss - self.baseline_rss)}
        for key, value in values.items():
            self.peak[key] = max(self.peak[key], value)
        check(values["fds"] <= 128, "process_fd_limit")
        check(values["threads"] <= 16, "process_thread_limit")
        check(rss <= 256 * 1024, "process_rss_limit")
        check(values["rss_growth_kib"] <= 64 * 1024, "process_rss_growth_limit")
        return values

    def stop(self):
        if self.process is None:
            return
        process = self.process
        self.process = None
        try:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(3)
                    raise Failure("bounded_service_shutdown") from None
            check(process.returncode == 0, "graceful_service_exit_" + self.binary.name)
            check(not self.management.path.exists(), "control_socket_cleanup")
            self.log.seek(0)
            output = self.log.read(MAX_ENVELOPE + 1)
            check(len(output) <= MAX_ENVELOPE, "bounded_fixture_service_logs")
            check(SENTINEL.encode() not in output, "service_log_credential_redaction")
        finally:
            self.log.close()


def tunnel(proxy, target, timeout=5):
    stream = socket.create_connection(proxy, timeout=timeout)
    try:
        stream.sendall(f"CONNECT 127.0.0.1:{target[1]} HTTP/1.1\r\nHost: 127.0.0.1:{target[1]}\r\n\r\n".encode())
        response = header(stream)
        if not response.startswith(b"HTTP/1.1 200"):
            fields = response.split(b"\r\n", 1)[0].split()
            code = fields[1].decode() if len(fields) >= 2 and fields[1].isdigit() else "invalid"
            raise Failure("proxy_connect_status_" + code)
        return stream
    except BaseException:
        stream.close()
        raise


def exchange(stream):
    payload = bytes(range(256)) * 32
    stream.sendall(payload)
    check(exact(stream, len(payload)) == payload, "echo_payload_integrity")


class Traffic:
    def __init__(self, proxy, target):
        self.proxy = proxy
        self.target = target
        self.stop_event = threading.Event()
        self.successes = 0
        self.failures = 0
        self.corrupt = False
        self.phase = "startup"
        self.errors = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            try:
                with tunnel(self.proxy, self.target, timeout=2) as stream:
                    exchange(stream)
                self.successes += 1
            except Failure as error:
                if str(error) == "echo_payload_integrity":
                    self.corrupt = True
                self.failures += 1
                self.errors.append({"phase": self.phase, "error": str(error)})
            except (OSError, EOFError) as error:
                self.failures += 1
                self.errors.append({"phase": self.phase, "error": type(error).__name__})
            self.errors = self.errors[-16:]
            self.stop_event.wait(0.04)

    def progress(self):
        before = self.successes
        wait_for(lambda: self.successes >= before + 3, "continued_live_traffic")
        check(not self.corrupt, "background_payload_integrity")

    def stop(self):
        self.stop_event.set()
        self.thread.join(8)
        check(not self.thread.is_alive(), "traffic_worker_cleanup")
        check(not self.corrupt, "background_payload_integrity")


def resource_check(management):
    metrics = management.request("metrics.snapshot")
    runtime = metrics["runtime"]
    # The configured two-Path baseline can autoscale up to SessionSlot's
    # current eight-Path safety ceiling for a minimum of one usable Path.
    for key, bound in (("sessions", 1), ("ready_paths", 8), ("streams", 8), ("target_connections", 8)):
        value = runtime.get(key)
        check(value is None or value <= bound, "runtime_bound_" + key)
    check(metrics.get("observed_paths", 0) <= 128, "bounded_path_history")
    for session in management.items("sessions.list"):
        retained = session.get("retained_outbound_bytes", 0)
        check(retained is None or retained <= 4 * 1024 * 1024, "bounded_session_buffering")


def identities(management):
    sessions = {item["session_id"] for item in management.items("sessions.list")
                if item["state"] not in ("closed", "failed")}
    paths = {item["path_id"] for item in management.items("metrics.paths")
             if item["state"] in ("active", "degraded")}
    return sessions, paths


def dns_query(proxy, name, expected):
    transaction = os.urandom(2)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    query = transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
    with socket.create_connection(proxy, timeout=4) as control:
        control.sendall(b"\x05\x01\x00")
        check(exact(control, 2) == b"\x05\x00", "dns_socks_method")
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        relay = exact(control, 10)
        check(relay[:4] == b"\x05\x00\x00\x01", "dns_socks_associate")
        address = (socket.inet_ntoa(relay[4:8]), int.from_bytes(relay[8:], "big"))
        prefix = b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x35"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(4)
            udp.sendto(prefix + query, address)
            response, _ = udp.recvfrom(4096)
        check(response[:10] == prefix, "dns_response_source")
        response = response[10:]
        check(response[:2] == transaction and response[3] & 15 == expected, "dns_response_code")
        check(int.from_bytes(response[6:8], "big") == int(expected == 0), "dns_answer_count")


def resource(kind, name, spec):
    return {"apiVersion": "pathchord.io/v1", "kind": kind,
            "metadata": {"name": name}, "spec": spec}


def write_config(path, documents):
    candidate = path.with_suffix(".candidate")
    candidate.write_text(json.dumps({"apiVersion": "pathchord.io/v1", "kind": "List",
                                    "metadata": {"name": "reliability"}, "items": documents}))
    candidate.replace(path)


def keygen(binary, output):
    result = subprocess.run([str(binary), "-o", "json", "keygen", "--identity-file", str(output)],
                            capture_output=True, check=True, timeout=8)
    return json.loads(result.stdout)["public_key"]


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def enroll(management, ingress_id, key):
    generation = management.status()["authorization_generation"]
    return management.request("authorizations.enroll", {"ingress_id": ingress_id,
                              "egress_id": "exit", "public_key": key},
                              generation=generation, scope="authorization")


def authorizations(management, operation, ingress_id, ok=True):
    generation = management.status()["authorization_generation"]
    return management.request(operation, {"ingress_id": ingress_id}, generation=generation,
                              scope="authorization", ok=ok)


def run(args):
    binaries = {name: (args.binary_dir / name).resolve() for name in
                ("pathchord-ingressd", "pathchord-egressd", "pathchordctl")}
    check(all(path.is_file() and os.access(path, os.X_OK) for path in binaries.values()), "role_binaries_available")
    check(Path("/proc/self/status").is_file(), "linux_process_measurements_available")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pc-reliability-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        images = directory / "binaries"
        images.mkdir(mode=0o700)
        for name, source in binaries.items():
            shutil.copyfile(source, images / name)
            (images / name).chmod(0o500)
        binaries = {name: images / name for name in binaries}
        binary_hashes = {name: file_hash(path) for name, path in binaries.items()}
        emit(event="started", cycles=args.cycles, minimum_soak_seconds=args.duration_seconds,
             binary_sha256=binary_hashes, script_sha256=file_hash(Path(__file__)))
        services, fixtures, traffic = [], [], []
        dns = None
        try:
            echo = FixtureServer(Echo)
            relay, provider_relay = Relay(), Relay()
            provider = Provider(provider_relay)
            fixtures.extend((provider, provider_relay, relay, echo))
            dns = Dns(("127.0.0.1", 0), DnsHandler)
            dns.fail = False
            dns_thread = threading.Thread(target=dns.serve_forever, daemon=True)
            dns_thread.start()
            egress_port, path_port, ordinary_port = port(), port(), port()
            egress_public = keygen(binaries["pathchordctl"], directory / "egress.key")
            key = keygen(binaries["pathchordctl"], directory / "ingress.key")
            ingress_id = "entry-0"
            egress = Service(binaries["pathchord-egressd"], ["--egress-id", "exit", "--identity", directory / "egress.key",
                             "--bind", f"127.0.0.1:{egress_port}", "--authorization-db", directory / "authorization.db",
                             "--control-socket", directory / "e.sock"], directory, "e.sock")
            services.append(egress)
            egress.start()
            enroll(egress.management, ingress_id, key)
            dns_spec = {"defaultRoute": "local", "local": {"servers": [f"127.0.0.1:{dns.server_address[1]}"]},
                        "timeoutSeconds": 1, "maxInflight": 8, "cache": {"enabled": False, "maxEntries": 16}}
            path_config = [
                resource("Egress", "exit", {"host": "127.0.0.1", "port": egress_port, "publicKey": egress_public,
                         "capabilities": {"tcp": True, "udp": True}, "pathPool": {"minUsablePaths": 1, "targetUsablePaths": 2},
                         "transit": {}, "trafficPolicyRef": "default"}),
                resource("TransitProxy", "relay", {"protocol": "http", "host": "127.0.0.1", "port": relay.address[1]}),
                resource("TrafficPolicy", "default", {"scheduler": "effectiveCapacityWeighted"}),
                resource("EgressRule", "all", {"order": 10, "catchAll": True, "egressRef": "exit"}),
                resource("Listener", "explicit", {"type": "mixed", "bind": f"127.0.0.1:{path_port}", "protocols": ["tcp", "udp"]}),
                resource("DNSPolicy", "dns", dns_spec), resource("FallbackPolicy", "fallback", {"action": "reject"})]
            write_config(directory / "path.json", path_config)
            ingress = Service(binaries["pathchord-ingressd"], ["--socket", directory / "i.sock", "--ingress-id", ingress_id,
                              "--identity", directory / "ingress.key", "--config", directory / "path.json",
                              "--data-dir", directory / "path-data"], directory, "i.sock")
            services.append(ingress)
            ingress.start()
            ordinary_config = [
                resource("Subscription", "provider", {"source": {"type": "clash", "url": f"http://127.0.0.1:{provider.address[1]}/?token={SENTINEL}"},
                         "refresh": {"intervalSeconds": 3600, "timeoutSeconds": 1, "maxAttempts": 1, "backoffSeconds": 1},
                         "cache": {"path": "provider.snapshot", "maxAgeSeconds": 86400}}),
                resource("ProxyRule", "all", {"order": 10, "catchAll": True, "select": "any"}),
                resource("ProxyRule", "unused", {"order": 20, "match": {"targetPorts": [1]}, "proxy": "direct"}),
                resource("Listener", "explicit", {"type": "mixed", "bind": f"127.0.0.1:{ordinary_port}", "protocols": ["tcp", "udp"]}),
                resource("DNSPolicy", "dns", dns_spec), resource("FallbackPolicy", "fallback", {"action": "reject"})]
            write_config(directory / "ordinary.json", ordinary_config)
            ordinary = Service(binaries["pathchord-ingressd"], ["--socket", directory / "o.sock", "--config", directory / "ordinary.json",
                               "--data-dir", directory / "ordinary-data"], directory, "o.sock")
            services.append(ordinary)
            ordinary.start()
            path_address, ordinary_address = ("127.0.0.1", path_port), ("127.0.0.1", ordinary_port)
            path_traffic, ordinary_traffic = Traffic(path_address, echo.address), Traffic(ordinary_address, echo.address)
            traffic.extend((path_traffic, ordinary_traffic))
            path_traffic.progress()
            ordinary_traffic.progress()
            soak_started = time.monotonic()
            path_traffic.phase = "stable"
            ordinary_traffic.phase = "stable"
            cache = directory / "ordinary-data/subscriptions/provider.snapshot"
            wait_for(cache.is_file, "provider_cache_created")
            checks = {"provider_fetch": 0, "provider_parse": 0, "dns_failure": 0, "reload": 0,
                      "node_drain": 0, "path_churn": 0, "endpoint_restart": 0, "authorization_revoke": 0}
            old_sessions, old_paths = set(), set()
            interruptions = {"path_churn": 0, "endpoint_restart": 0, "authorization_revoke": 0, "node_drain": 0}
            for cycle in range(args.cycles):
                stage = time.monotonic()
                for service in services:
                    service.sample()
                for service in (ingress, ordinary):
                    resource_check(service.management)
                provider_failures_before = ordinary_traffic.failures
                with tunnel(ordinary_address, echo.address) as live:
                    for fault in ("fetch", "parse"):
                        ordinary_traffic.phase = "provider_" + fault
                        cache_before = hashlib.sha256(cache.read_bytes()).hexdigest()
                        provider.mode = fault
                        ordinary.management.mutate_subscription("subscriptions.refresh")
                        wait_for(lambda: ordinary.management.subscription()["state"] == "failed", "failed_refresh_observed")
                        check(hashlib.sha256(cache.read_bytes()).hexdigest() == cache_before, "failed_refresh_preserves_cache")
                        exchange(live)
                        ordinary_traffic.progress()
                        if ordinary_traffic.failures != provider_failures_before:
                            emit(diagnostic="unexpected_provider_traffic_failure", errors=ordinary_traffic.errors)
                        check(ordinary_traffic.failures == provider_failures_before, "no_provider_traffic_loss_during_" + fault)
                        checks["provider_" + fault] += 1
                    provider.mode = "good"
                    ordinary_traffic.phase = "provider_recovery"
                    ordinary.management.mutate_subscription("subscriptions.refresh")
                    wait_for(lambda: ordinary.management.subscription()["state"] == "enabled", "refresh_recovered")
                    nodes = ordinary.management.items("nodes.list")
                    check(any(item.get("protocol") == "http" for item in nodes), "successful_sibling_remains")
                    check(any(item.get("diagnostic") or item.get("observed", {}).get("diagnostic") for item in nodes), "unsupported_sibling_diagnostic")
                    quota = [item.get("observed", {}).get("quota") for item in nodes]
                    check(any(item and item.get("remaining_bytes") == 9700 for item in quota), "provider_accounting_consistency")
                    dns_query(ordinary_address, f"ok{cycle}.test", 0)
                    ordinary_traffic.phase = "dns_failure"
                    dns.fail = True
                    dns_query(ordinary_address, f"fail{cycle}.test", 2)
                    exchange(live)
                    dns.fail = False
                    dns_query(ordinary_address, f"recover{cycle}.test", 0)
                    if ordinary_traffic.failures != provider_failures_before:
                        emit(diagnostic="unexpected_provider_traffic_failure", errors=ordinary_traffic.errors)
                    check(ordinary_traffic.failures == provider_failures_before, "no_provider_traffic_loss_during_dns_fault")
                    checks["dns_failure"] += 1
                    reload_before = ordinary.management.status()["configuration_reload"]["active_generation"]
                    ordinary_traffic.phase = "invalid_reload"
                    (directory / "ordinary.json").write_text('{"kind": "' + SENTINEL + '", invalid')
                    wait_for(lambda: ordinary.management.status()["configuration_reload"]["state"] == "rejected", "invalid_reload_rejected")
                    check(ordinary.management.status()["configuration_reload"]["active_generation"] == reload_before, "invalid_reload_keeps_generation")
                    exchange(live)
                    ordinary_config[2]["spec"]["match"]["targetPorts"] = [2 if cycle % 2 == 0 else 1]
                    ordinary_traffic.phase = "valid_reload"
                    write_config(directory / "ordinary.json", ordinary_config)
                    def reload_applied():
                        state = ordinary.management.status()["configuration_reload"]
                        return state["state"] == "applied" and state["active_generation"] > reload_before
                    wait_for(reload_applied, "valid_reload_advances_generation")
                    exchange(live)
                    ordinary_traffic.progress()
                    if ordinary_traffic.failures != provider_failures_before:
                        emit(diagnostic="unexpected_provider_traffic_failure", errors=ordinary_traffic.errors,
                             configuration=ordinary.management.status()["configuration_reload"],
                             nodes=[{"state": item["state"], "protocol": item["protocol"]}
                                    for item in ordinary.management.items("nodes.list")])
                    check(ordinary_traffic.failures == provider_failures_before, "no_provider_traffic_loss_during_retained_failures")
                    checks["reload"] += 1
                    drain_failures_before = ordinary_traffic.failures
                    ordinary_traffic.phase = "node_drain"
                    generation = ordinary.management.status()["configuration_generation"]
                    ordinary.management.mutate_subscription("subscriptions.disable")
                    stale = ordinary.management.mutate_subscription("subscriptions.enable", stale=generation)
                    check(not stale["ok"] and stale["error"]["code"] == "GENERATION_CONFLICT", "stale_generation_barrier")
                    before = provider_relay.accepted
                    try:
                        with tunnel(ordinary_address, echo.address):
                            raise Failure("disabled_node_selected")
                    except Failure as error:
                        check(str(error).startswith("proxy_connect_status_"), "disabled_node_selection_rejected")
                    check(provider_relay.accepted == before, "draining_adapter_not_selected")
                    exchange(live)
                    ordinary.management.mutate_subscription("subscriptions.enable")
                    ordinary.management.mutate_subscription("subscriptions.refresh")
                    wait_for(lambda: ordinary.management.subscription()["state"] == "enabled", "subscription_reenabled")
                    checks["node_drain"] += 1
                ordinary_traffic.progress()
                ordinary_traffic.phase = "stable"
                interruptions["node_drain"] += ordinary_traffic.failures - drain_failures_before
                sessions, paths = wait_for(lambda: identities(ingress.management) if ingress.management.status()["ready_paths"] >= 1 else None, "paths_ready")
                check(not sessions.intersection(old_sessions), "retired_session_identity_not_reused")
                check(not paths.intersection(old_paths), "retired_path_identity_not_reused")
                old_sessions.update(sessions)
                old_paths.update(paths)
                path_failures_before = path_traffic.failures
                path_traffic.phase = "path_churn"
                relay.cut()
                path_traffic.progress()
                wait_for(lambda: identities(ingress.management)[1].difference(paths), "replacement_path_identity")
                interruptions["path_churn"] += path_traffic.failures - path_failures_before
                checks["path_churn"] += 1
                before_restart_sessions, churn_paths = identities(ingress.management)
                old_sessions.update(before_restart_sessions)
                old_paths.update(churn_paths)
                path_failures_before = path_traffic.failures
                path_traffic.phase = "endpoint_restart"
                with tunnel(path_address, echo.address) as live:
                    exchange(live)
                    egress.stop()
                    try:
                        closed = live.recv(1) == b""
                    except (ConnectionResetError, BrokenPipeError):
                        closed = True
                    check(closed, "endpoint_restart_closes_old_stream")
                    egress.start()
                path_traffic.progress()
                interruptions["endpoint_restart"] += path_traffic.failures - path_failures_before
                wait_for(lambda: identities(ingress.management)[0] and not identities(ingress.management)[0].intersection(before_restart_sessions), "endpoint_restart_session_identity")
                checks["endpoint_restart"] += 1
                before_revoke_sessions, restart_paths = identities(ingress.management)
                old_sessions.update(before_revoke_sessions)
                old_paths.update(restart_paths)
                path_failures_before = path_traffic.failures
                path_traffic.phase = "authorization_revoke"
                with tunnel(path_address, echo.address) as live:
                    exchange(live)
                    authorizations(egress.management, "authorizations.revoke", ingress_id)
                    wait_for(lambda: all(egress.management.status()["runtime"][key] == 0 for key in
                                        ("active_paths", "active_sessions", "active_streams", "active_target_connections")), "revocation_resource_cleanup")
                    response = authorizations(egress.management, "authorizations.enable", ingress_id, ok=False)
                    check(not response["ok"], "revocation_is_terminal")
                    try:
                        closed = live.recv(1) == b""
                    except (ConnectionResetError, BrokenPipeError):
                        closed = True
                    check(closed, "revocation_closes_live_stream")
                ingress.stop()
                authorizations(egress.management, "authorizations.delete", ingress_id)
                ingress_id = f"entry-{cycle + 1}"
                (directory / "ingress.key").unlink()
                key = keygen(binaries["pathchordctl"], directory / "ingress.key")
                enroll(egress.management, ingress_id, key)
                ingress.arguments[3] = ingress_id
                ingress.start()
                path_traffic.progress()
                path_traffic.phase = "stable"
                wait_for(lambda: ingress.management.status()["ready_paths"] >= 1, "fresh_identity_path_ready")
                fresh_sessions, fresh_paths = identities(ingress.management)
                check(fresh_sessions and not fresh_sessions.intersection(old_sessions), "fresh_identity_new_session")
                check(fresh_paths and not fresh_paths.intersection(old_paths), "fresh_identity_new_paths")
                interruptions["authorization_revoke"] += path_traffic.failures - path_failures_before
                checks["authorization_revoke"] += 1
                for service in services:
                    service.sample()
                emit(cycle=cycle + 1, seconds=round(time.monotonic() - stage, 2), checks=checks,
                     traffic={"path": path_traffic.successes, "provider": ordinary_traffic.successes})
                # Spread the complete fault matrix across the requested soak time.
                deadline = soak_started + args.duration_seconds * (cycle + 1) / args.cycles
                stable_failures = (path_traffic.failures, ordinary_traffic.failures)
                while time.monotonic() < deadline:
                    time.sleep(min(1, max(0, deadline - time.monotonic())))
                    for service in services:
                        service.sample()
                    resource_check(ingress.management)
                    resource_check(ordinary.management)
                    check((path_traffic.failures, ordinary_traffic.failures) == stable_failures, "no_uninjected_traffic_failure")
            soak_seconds = time.monotonic() - soak_started
            for worker in traffic:
                worker.stop()
            traffic.clear()
            for service in (ingress, ordinary):
                wait_for(lambda service=service: service.management.status()["streams"] == 0, "stream_resources_quiesce")
            wait_for(lambda: all(egress.management.status()["runtime"][key] == 0 for key in
                                ("active_streams", "active_target_connections")), "target_resources_quiesce")
            for service in reversed(services):
                service.stop()
            emit(result="passed", elapsed_seconds=round(time.monotonic() - started, 2), cycles=args.cycles,
                 soak_seconds=round(soak_seconds, 2),
                 checks=checks, process_peaks={"egress": egress.peak, "path_ingress": ingress.peak, "provider_ingress": ordinary.peak},
                 traffic={"path_success": path_traffic.successes, "path_interruptions": path_traffic.failures,
                          "provider_success": ordinary_traffic.successes, "provider_interruptions": ordinary_traffic.failures},
                 expected_fault_interruptions=interruptions,
                 provider_requests=provider.requests,
                 binary_sha256=binary_hashes,
                 limits={"fds": 128, "threads": 16, "rss_mib": 256, "rss_growth_mib": 64,
                         "sessions": 1, "ready_paths": 8, "streams": 8, "session_retained_bytes": 4194304},
                 evidence="local_process_synthetic_fixtures")
        finally:
            for worker in traffic:
                worker.stop()
            for service in reversed(services):
                with contextlib.suppress(Failure):
                    service.stop()
            for fixture in fixtures:
                fixture.close()
            if dns is not None:
                dns.shutdown()
                dns.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, default=Path("target/debug"))
    parser.add_argument("--duration-seconds", type=float, default=300)
    parser.add_argument("--cycles", type=int, default=12)
    args = parser.parse_args()
    if args.cycles < 1 or args.duration_seconds < 0:
        parser.error("cycles must be positive and duration must be nonnegative")
    try:
        run(args)
        return 0
    except Failure as error:
        emit(result="failed", check=str(error))
    except Exception as error:
        emit(result="failed", check="unexpected_" + type(error).__name__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
