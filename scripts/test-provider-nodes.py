#!/usr/bin/env python3
"""Exercise each Clash node through isolated PathChord and Mihomo processes.

Inputs: PATHCHORD_PROVIDER_1, PATHCHORD_PROVIDER_2, and, for TCP,
PATHCHORD_TEST_TARGET_URL. --network udp probes STUN on port 3478 by default.
Optional: PATHCHORD_TEST_BINARY, PATHCHORD_TEST_MIHOMO, PATHCHORD_TEST_JOBS,
PATHCHORD_TEST_TIMEOUT, PATHCHORD_TEST_USER_AGENT. Never enable process logging.
Requires Linux memfd, /dev/shm, Python 3 and PyYAML. --self-test uses no providers.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import copy
import io
import ipaddress
import json
import os
import select
import shutil
import secrets
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

MAX_BYTES = 4 * 1024 * 1024
MAX_NODES = 10_000
MAX_PROVIDER_DEPTH = 3
MAX_PROVIDERS = 32
PROTOCOLS = {"ss", "shadowsocks", "vmess", "vless", "xtls", "trojan", "hysteria2", "hy2", "tuic", "anytls", "socks5", "http", "https", "wireguard", "hysteria", "snell"}
CLIENT_PROFILES = {"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"}
PRINT_LOCK = threading.Lock()
STUN_COOKIE = b"\x21\x12\xa4\x42"


class SafeFailure(Exception):
    def __init__(self, category):
        self.category = category


def emit(value):
    with PRINT_LOCK:
        print(json.dumps(value, ensure_ascii=True, separators=(",", ":")), flush=True)


def public_protocol(node):
    value = node.get("type") if isinstance(node, dict) else None
    return value.lower() if isinstance(value, str) and value.lower() in PROTOCOLS else "other"


def fingerprint_category(node):
    profile = node.get("client-fingerprint") if isinstance(node, dict) else None
    if isinstance(profile, str) and profile.lower() in CLIENT_PROFILES:
        return profile.lower()
    if profile is not None:
        return "other-client-profile"
    pin = node.get("fingerprint") if isinstance(node, dict) else None
    return "certificate-pin" if pin else "none"


def fetch(url, user_agent, budget):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise SafeFailure("source_url_invalid")
    request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "*/*"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def expired(_signal, _frame):
        raise TimeoutError()
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 20)
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read(min(MAX_BYTES, budget[0]) + 1)
    except TimeoutError:
        raise SafeFailure("source_timeout") from None
    except Exception:
        raise SafeFailure("source_fetch_failed") from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    budget[0] -= len(body)
    if budget[0] < 0 or len(body) > MAX_BYTES:
        raise SafeFailure("source_too_large")
    return body


def parse_nodes(body):
    try:
        document = yaml.safe_load(body)
    except Exception:
        raise SafeFailure("source_format_invalid") from None
    if not isinstance(document, dict):
        raise SafeFailure("source_format_invalid")
    nodes = document.get("proxies", [])
    providers = document.get("proxy-providers", {})
    if not isinstance(nodes, list) or not isinstance(providers, dict):
        raise SafeFailure("source_format_invalid")
    return nodes, providers


def load_provider(url, user_agent):
    budget = [MAX_BYTES]
    nodes = []
    errors = []
    queue = [(url, 0, frozenset())]
    references = 0
    while queue:
        current, depth, ancestors = queue.pop(0)
        if current in ancestors or depth > MAX_PROVIDER_DEPTH or len(ancestors) >= MAX_PROVIDERS:
            errors.append("provider_reference_limit")
            continue
        try:
            added, refs = parse_nodes(fetch(current, user_agent, budget))
        except SafeFailure as error:
            errors.append(error.category)
            continue
        nodes.extend(added)
        if len(nodes) > MAX_NODES:
            raise SafeFailure("source_too_many_nodes")
        for ref in refs.values():
            references += 1
            if not isinstance(ref, dict) or ref.get("type") != "http" or not isinstance(ref.get("url"), str):
                errors.append("provider_reference_unsupported")
                continue
            if references > MAX_PROVIDERS:
                errors.append("provider_reference_limit")
                continue
            queue.append((ref["url"], depth + 1, ancestors | {current}))
    return nodes, errors


class PrivateSubscription:
    def __init__(self, node):
        safe_node = copy.deepcopy(node)
        safe_node["name"] = "fixture-node"
        self.payload = yaml.safe_dump({"proxies": [safe_node]}, allow_unicode=True).encode()
        self.token = secrets.token_urlsafe(32)
        self.fetched = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(2)

            def do_GET(self):
                if self.path != "/" + owner.token:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/yaml")
                self.send_header("Content-Length", str(len(owner.payload)))
                self.end_headers()
                self.wfile.write(owner.payload)
                owner.fetched.set()

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.payload = b""

    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/{self.token}"


def reserve_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def clean_env(cwd):
    return {"PATH": os.defpath, "HOME": cwd, "TMPDIR": cwd, "LANG": "C.UTF-8"}


def varint(value):
    if value < 64:
        return bytes([value])
    if value < 16384:
        return (value | 0x4000).to_bytes(2, "big")
    return (value | 0x80000000).to_bytes(4, "big")


def receive_exact(sock, length, deadline=None):
    data = bytearray()
    while len(data) < length:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            sock.settimeout(remaining)
        block = sock.recv(length - len(data))
        if not block:
            raise EOFError()
        data.extend(block)
    return bytes(data)


def list_nodes(path):
    request = {"api_version": "1", "operation": "nodes.list", "request_id": "audit", "actor": {"id": "local", "capabilities": []}, "expected_generation": None, "body": {}}
    raw = json.dumps(request, separators=(",", ":")).encode()
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(1)
        sock.connect(str(path))
        sock.sendall(varint(len(raw)) + raw)
        first = receive_exact(sock, 1)[0]
        width = 1 << (first >> 6)
        prefix = bytes([first]) + receive_exact(sock, width - 1)
        size = int.from_bytes(prefix, "big") & ((1 << (width * 8 - 2)) - 1)
        if size > 1024 * 1024:
            raise SafeFailure("control_oversize")
        response = json.loads(receive_exact(sock, size))
    if not response.get("ok"):
        raise SafeFailure("control_rejected")
    return response.get("result", {}).get("items", [])


def wait_ready(process, port, control, fetched, deadline, ready_file=None):
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SafeFailure("startup_exit")
        if control is not None and fetched.is_set():
            try:
                nodes = list_nodes(control)
                if nodes:
                    diagnostic = nodes[0].get("observed", {}).get("diagnostic")
                    if diagnostic:
                        raise SafeFailure("node_unavailable")
                    return
            except SafeFailure as error:
                if error.category == "node_unavailable":
                    raise
            except Exception:
                pass
        elif control is None:
            if ready_file is not None:
                if ready_file.is_file():
                    return
                time.sleep(0.1)
                continue
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return
            except OSError:
                pass
        time.sleep(0.1)
    raise SafeFailure("startup_timeout")


def check_target(proxy_port, target, deadline, cafile=None):
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise SafeFailure("target_url_invalid")
    port = parsed.port or 443
    authority = f"[{parsed.hostname}]:{port}" if ":" in parsed.hostname else f"{parsed.hostname}:{port}"
    stage = "connect"
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=max(0.1, deadline - time.monotonic())) as sock:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
            response = bytearray()
            while not response.endswith(b"\r\n\r\n") and len(response) < 16384:
                response.extend(receive_exact(sock, 1, deadline))
            line = bytes(response).split(b"\r\n", 1)[0].split()
            if len(line) < 2 or line[1] != b"200":
                raise SafeFailure("proxy_connect_rejected")
            stage = "tls"
            context = ssl.create_default_context(cafile=cafile)
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as secure:
                secure.settimeout(max(0.1, deadline - time.monotonic()))
                stage = "http"
                path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                secure.sendall(f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: PathChord-audit/1\r\nConnection: close\r\n\r\n".encode("ascii"))
                header = bytearray()
                while not header.endswith(b"\r\n\r\n") and len(header) < 32768:
                    header.extend(receive_exact(secure, 1, deadline))
                if not header.endswith(b"\r\n\r\n"):
                    raise SafeFailure("target_http_invalid")
                line = bytes(header).split(b"\r\n", 1)[0].split()
                if len(line) < 2 or line[0] not in (b"HTTP/1.0", b"HTTP/1.1") or len(line[1]) != 3 or not line[1].isdigit():
                    raise SafeFailure("target_http_invalid")
                code = int(line[1])
                if not 100 <= code <= 599:
                    raise SafeFailure("target_http_invalid")
                return (200 <= code < 300), code, "http_response"
    except SafeFailure:
        raise
    except (TimeoutError, socket.timeout):
        raise SafeFailure(stage + "_timeout") from None
    except ssl.SSLError:
        raise SafeFailure("target_tls_failed") from None
    except Exception:
        raise SafeFailure(stage + "_failed") from None


def udp_capability(node):
    if not isinstance(node, dict):
        return False, "node_invalid"
    protocol = node.get("type")
    if not isinstance(protocol, str) or protocol.lower() not in PROTOCOLS:
        return False, "udp_unsupported"
    protocol = protocol.lower()
    if protocol in ("http", "https"):
        return False, "udp_unsupported"
    if "udp" not in node:
        return (True, None) if protocol in ("hysteria", "hysteria2", "hy2", "tuic") else (False, "udp_disabled")
    value = node["udp"]
    if isinstance(value, bool):
        enabled = value
    elif isinstance(value, int) and value in (0, 1):
        enabled = bool(value)
    elif isinstance(value, str) and value.lower() in ("true", "false", "0", "1"):
        enabled = value.lower() in ("true", "1")
    else:
        return False, "udp_invalid"
    return (True, None) if enabled else (False, "udp_disabled")


def resolve_stun(host, port):
    if not host or not 1 <= port <= 65535 or port == 53:
        raise SafeFailure("stun_target_invalid")

    def expired(_signal, _frame):
        raise TimeoutError()

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 5)
    try:
        addresses = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        return str(ipaddress.IPv4Address(addresses[0][4][0])), port
    except Exception:
        raise SafeFailure("stun_resolve_failed") from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def socks_relay_address(sock, deadline):
    header = receive_exact(sock, 4, deadline)
    if header[:3] != b"\x05\x00\x00":
        raise SafeFailure("udp_associate_failed")
    if header[3] == 1:
        address = ipaddress.ip_address(receive_exact(sock, 4, deadline))
    elif header[3] == 4:
        address = ipaddress.ip_address(receive_exact(sock, 16, deadline))
    elif header[3] == 3:
        length = receive_exact(sock, 1, deadline)[0]
        domain = receive_exact(sock, length, deadline)
        if domain.lower() != b"localhost":
            raise SafeFailure("udp_relay_invalid")
        address = ipaddress.ip_address("127.0.0.1")
    else:
        raise SafeFailure("udp_relay_invalid")
    port = int.from_bytes(receive_exact(sock, 2, deadline), "big")
    if not port or not (address.is_loopback or address.is_unspecified):
        raise SafeFailure("udp_relay_invalid")
    if address.is_unspecified:
        address = ipaddress.ip_address("127.0.0.1" if address.version == 4 else "::1")
    return address, port


def decode_socks_datagram(packet):
    if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
        raise SafeFailure("udp_response_invalid")
    atyp = packet[3]
    offset = 4
    if atyp == 1:
        width = 4
    elif atyp == 4:
        width = 16
    elif atyp == 3 and len(packet) > offset:
        width = packet[offset]
        offset += 1
        if not width:
            raise SafeFailure("udp_response_invalid")
    else:
        raise SafeFailure("udp_response_invalid")
    if len(packet) < offset + width + 2:
        raise SafeFailure("udp_response_invalid")
    address = packet[offset:offset + width]
    if atyp in (1, 4):
        address = str(ipaddress.ip_address(address))
    else:
        try:
            address = address.decode("ascii").lower()
        except UnicodeDecodeError:
            raise SafeFailure("udp_response_invalid") from None
    offset += width
    port = int.from_bytes(packet[offset:offset + 2], "big")
    return address, port, packet[offset + 2:]


def validate_stun_response(response, transaction):
    if len(response) < 20 or response[:2] != b"\x01\x01" or response[4:8] != STUN_COOKIE:
        raise SafeFailure("stun_response_invalid")
    length = int.from_bytes(response[2:4], "big")
    if length % 4 or len(response) != 20 + length:
        raise SafeFailure("stun_response_invalid")
    if response[8:20] != transaction:
        raise SafeFailure("stun_transaction_mismatch")
    offset = 20
    mapped = False
    while offset < len(response):
        if offset + 4 > len(response):
            raise SafeFailure("stun_response_invalid")
        attribute = int.from_bytes(response[offset:offset + 2], "big")
        size = int.from_bytes(response[offset + 2:offset + 4], "big")
        start = offset + 4
        offset = start + (size + 3) // 4 * 4
        if offset > len(response):
            raise SafeFailure("stun_response_invalid")
        if attribute == 0x0020:
            value = response[start:start + size]
            if not (len(value) in (8, 20) and value[0] == 0 and
                    ((value[1] == 1 and len(value) == 8) or (value[1] == 2 and len(value) == 20)) and
                    int.from_bytes(value[2:4], "big") ^ 0x2112):
                raise SafeFailure("stun_response_invalid")
            mapped = True
    if not mapped:
        raise SafeFailure("stun_response_invalid")


def check_stun(proxy_port, target, deadline):
    try:
        if not 1 <= target[1] <= 65535 or target[1] == 53:
            raise SafeFailure("stun_target_invalid")
        ipaddress.IPv4Address(target[0])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=remaining) as control:
            control.sendall(b"\x05\x01\x00")
            if receive_exact(control, 2, deadline) != b"\x05\x00":
                raise SafeFailure("udp_socks_auth")
            control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            address, port = socks_relay_address(control, deadline)
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            with socket.socket(family, socket.SOCK_DGRAM) as datagram:
                datagram.bind(("127.0.0.1" if address.version == 4 else "::1", 0))
                datagram.connect((str(address), port))
                transaction = secrets.token_bytes(12)
                request = b"\x00\x01\x00\x00" + STUN_COOKIE + transaction
                packet = b"\x00\x00\x00\x01" + ipaddress.IPv4Address(target[0]).packed + target[1].to_bytes(2, "big") + request
                datagram.send(packet)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                datagram.settimeout(remaining)
                response = datagram.recv(65535)
                source, source_port, body = decode_socks_datagram(response)
                if (source, source_port) != target:
                    raise SafeFailure("udp_source_mismatch")
                validate_stun_response(body, transaction)
                return True, None, "stun_response"
    except SafeFailure:
        raise
    except (TimeoutError, socket.timeout):
        raise SafeFailure("udp_timeout") from None
    except Exception:
        raise SafeFailure("udp_failed") from None


def process_context(command, cwd, pass_fds=()):
    return subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=clean_env(cwd), pass_fds=pass_fds, start_new_session=True)


def terminate(process):
    if process is None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=2)


def run_engine(engine, node, target, binary, timeout_seconds, cafile=None, network="tcp", temp_paths=None):
    if not isinstance(node, dict):
        return False, None, "node_invalid"
    deadline = time.monotonic() + timeout_seconds
    process = None
    source = None
    fd = None
    try:
        with contextlib.ExitStack() as cleanup:
            temp = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="pc-provider-audit-", dir="/dev/shm"))
            if temp_paths is not None:
                temp_paths.append(Path(temp))
            os.chmod(temp, 0o700)
            port = reserve_port()
            if engine == "pathchord":
                source = PrivateSubscription(node)
                cleanup.callback(source.close)
                listener_type = "mixed" if network == "udp" else "http"
                protocols = "tcp, udp" if network == "udp" else "tcp"
                config = f'''apiVersion: pathchord.io/v1\nkind: Subscription\nmetadata: {{name: fixture}}\nspec:\n  source: {{type: clash, url: '{source.url()}'}}\n  refresh: {{intervalSeconds: 3600, timeoutSeconds: 2, maxAttempts: 1, backoffSeconds: 1}}\n---\napiVersion: pathchord.io/v1\nkind: ProxyRule\nmetadata: {{name: ordinary}}\nspec: {{order: 10, catchAll: true, select: any}}\n---\napiVersion: pathchord.io/v1\nkind: Listener\nmetadata: {{name: local}}\nspec: {{type: {listener_type}, bind: '127.0.0.1:{port}', protocols: [{protocols}], authentication: disabled}}\n---\napiVersion: pathchord.io/v1\nkind: DNSPolicy\nmetadata: {{name: dns}}\nspec: {{defaultRoute: local, local: {{servers: ['9.9.9.9:53']}}}}\n---\napiVersion: pathchord.io/v1\nkind: FallbackPolicy\nmetadata: {{name: fallback}}\nspec: {{action: reject}}\n'''
                config_path = Path(temp) / "config.yaml"
                config_path.write_text(config)
                config_path.chmod(0o600)
                control = Path(temp) / "control.sock"
                process = process_context([binary, "--socket", str(control), "ingress", "--config", str(config_path), "--data-dir", str(Path(temp) / "data"), "--credentials-dir", str(Path(temp) / "secrets")], temp)
                cleanup.callback(terminate, process)
                wait_ready(process, port, control, source.fetched, min(deadline, time.monotonic() + 8))
            else:
                config = {"mixed-port": port, "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "silent", "profile": {"store-selected": False, "store-fake-ip": False}, "proxies": [dict(copy.deepcopy(node), name="fixture-node")], "rules": ["MATCH,fixture-node"]}
                fd = os.memfd_create("provider-audit", flags=0)
                cleanup.callback(os.close, fd)
                os.write(fd, yaml.safe_dump(config, allow_unicode=True).encode())
                os.lseek(fd, 0, os.SEEK_SET)
                ready_file = Path(temp) / "mihomo-ready"
                process = process_context([binary, "-d", temp, "-f", f"/proc/self/fd/{fd}", "--post-up", 'touch "$TMPDIR/mihomo-ready"'], temp, (fd,))
                cleanup.callback(terminate, process)
                wait_ready(process, port, None, None, min(deadline, time.monotonic() + 8), ready_file)
            if time.monotonic() >= deadline:
                raise SafeFailure("request_timeout")
            return check_stun(port, target, deadline) if network == "udp" else check_target(port, target, deadline, cafile)
    except SafeFailure as error:
        return False, None, error.category
    except Exception:
        return False, None, "local_error"


def run_node(provider, index, node, args, target):
    for engine, binary in (("pathchord", args.pathchord), ("mihomo", args.mihomo)):
        eligible, reason = udp_capability(node) if args.network == "udp" else (True, None)
        ok, status, category = (run_engine(engine, node, target, binary, args.timeout, network=args.network)
                                if eligible else (None, None, reason))
        row = {"provider": provider, "index": index, "protocol": public_protocol(node), "fingerprint": fingerprint_category(node), "engine": engine, "ok": ok, "http_status": status, "result": category}
        if args.network == "udp":
            row["network"] = "udp"
        emit(row)
        yield ok


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--pathchord", default=os.getenv("PATHCHORD_TEST_BINARY", "target/debug/pathchord"))
    parser.add_argument("--mihomo", default=os.getenv("PATHCHORD_TEST_MIHOMO", "/tmp/mihomo-1.19.34"))
    parser.add_argument("--jobs", type=int, default=int(os.getenv("PATHCHORD_TEST_JOBS", "3")))
    parser.add_argument("--timeout", type=int, default=int(os.getenv("PATHCHORD_TEST_TIMEOUT", "25")))
    parser.add_argument("--network", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--stun-host", default="stun.cloudflare.com")
    parser.add_argument("--stun-port", type=int, default=3478)
    args = parser.parse_args()
    if args.self_test:
        return self_test(args)
    if not 1 <= args.jobs <= 8 or not 5 <= args.timeout <= 120 or not hasattr(os, "memfd_create") or not os.path.isdir("/dev/shm"):
        emit({"error": "invalid_local_configuration"})
        return 2
    args.pathchord = str(Path(args.pathchord).resolve())
    args.mihomo = str(Path(args.mihomo).resolve())
    if not all(os.path.isfile(binary) and os.access(binary, os.X_OK) for binary in (args.pathchord, args.mihomo)):
        emit({"error": "binary_unavailable"})
        return 2
    target = os.getenv("PATHCHORD_TEST_TARGET_URL")
    urls = [os.getenv("PATHCHORD_PROVIDER_1"), os.getenv("PATHCHORD_PROVIDER_2")]
    if not all(urls) or (args.network == "tcp" and not target):
        emit({"error": "missing_required_environment"})
        return 2
    if args.network == "tcp":
        try:
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise ValueError()
            _ = parsed.port
        except Exception:
            emit({"error": "target_url_invalid"})
            return 2
    else:
        try:
            target = resolve_stun(args.stun_host, args.stun_port)
        except SafeFailure as error:
            emit({"error": error.category})
            return 2
    user_agent = os.getenv("PATHCHORD_TEST_USER_AGENT", "clash.meta")
    if not user_agent or len(user_agent) > 1024 or any(ord(c) < 32 or ord(c) > 126 for c in user_agent):
        emit({"error": "invalid_user_agent"})
        return 2
    work = []
    source_errors = 0
    for provider, url in enumerate(urls, 1):
        try:
            nodes, errors = load_provider(url, user_agent)
            for error in errors:
                emit({"provider": provider, "error": error})
                source_errors += 1
            work.extend((provider, index, node) for index, node in enumerate(nodes, 1))
        except SafeFailure as error:
            emit({"provider": provider, "error": error.category})
            return 2
    success, failure, skipped = 0, source_errors, 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(lambda p=p, i=i, n=n: list(run_node(p, i, n, args, target))) for p, i, n in work]
        for future in concurrent.futures.as_completed(futures):
            try:
                for ok in future.result():
                    if ok is None:
                        skipped += 1
                    else:
                        success += bool(ok)
                        failure += not ok
            except Exception:
                failure += 1
                emit({"error": "local_error"})
    summary = {"nodes": len(work), "success": success, "failure": failure}
    if args.network == "udp":
        summary["skipped"] = skipped
    emit({"summary": summary})
    return 0 if not failure and work and (args.network == "tcp" or success) else 1


def self_test(args):
    args.pathchord = str(Path(args.pathchord).resolve())
    args.mihomo = str(Path(args.mihomo).resolve())
    if not all(os.path.isfile(binary) and os.access(binary, os.X_OK) for binary in (args.pathchord, args.mihomo)):
        emit({"error": "self_test_binary_unavailable"})
        return 2
    if not shutil.which("openssl"):
        emit({"error": "self_test_openssl_unavailable"})
        return 2
    sentinel = "PRIVATE_SENTINEL_4c7f"
    temp_paths = []
    servers = []
    threads = []
    try:
        with tempfile.TemporaryDirectory(prefix="pc-provider-selftest-", dir="/dev/shm") as temp:
            os.chmod(temp, 0o700)
            key, cert = str(Path(temp) / "key.pem"), str(Path(temp) / "cert.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=clean_env(temp), check=True, timeout=10)

            class Target(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")

                def log_message(self, *_args):
                    pass

            target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            target.socket = tls.wrap_socket(target.socket, server_side=True)
            target.daemon_threads = True
            servers.append(target)
            thread = threading.Thread(target=target.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)

            class Proxy(socketserver.StreamRequestHandler):
                def handle(self):
                    self.connection.settimeout(5)
                    request = self.rfile.readline(16384)
                    if not request.startswith(b"CONNECT "):
                        return
                    while self.rfile.readline(16384) not in (b"\r\n", b""):
                        pass
                    with socket.create_connection(("127.0.0.1", target.server_port), timeout=5) as remote:
                        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        self.wfile.flush()
                        peers = (self.connection, remote)
                        while True:
                            ready, _, _ = select.select(peers, [], [], 5)
                            if not ready:
                                return
                            for peer in ready:
                                data = peer.recv(65536)
                                if not data:
                                    return
                                (remote if peer is self.connection else self.connection).sendall(data)

            class Server(socketserver.ThreadingTCPServer):
                allow_reuse_address = True
                daemon_threads = True

            proxy = Server(("127.0.0.1", 0), Proxy)
            servers.append(proxy)
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
            node = {"name": sentinel, "type": "http", "server": "127.0.0.1", "port": proxy.server_address[1], "username": sentinel, "password": sentinel}
            target_url = f"https://127.0.0.1:{target.server_port}/self-test"
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                for engine, binary in (("pathchord", args.pathchord), ("mihomo", args.mihomo)):
                    ok, status, category = run_engine(engine, node, target_url, binary, 15, cert, temp_paths=temp_paths)
                    emit({"provider": 1, "index": 1, "protocol": public_protocol(node), "fingerprint": fingerprint_category(node), "engine": engine, "ok": ok, "http_status": status, "result": category})
                    if not ok or status != 200:
                        raise SafeFailure("self_test_" + engine + "_failed")
                malicious = {"type": sentinel, "client-fingerprint": sentinel}
                emit({"protocol": public_protocol(malicious), "fingerprint": fingerprint_category(malicious)})
            if sentinel in captured.getvalue() or target_url in captured.getvalue():
                raise SafeFailure("self_test_redaction_failed")

            class ConnectOnly(socketserver.StreamRequestHandler):
                def handle(self):
                    self.rfile.readline(16384)
                    while self.rfile.readline(16384) not in (b"\r\n", b""):
                        pass
                    self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    self.wfile.flush()

            dead_proxy = Server(("127.0.0.1", 0), ConnectOnly)
            servers.append(dead_proxy)
            thread = threading.Thread(target=dead_proxy.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
            try:
                check_target(dead_proxy.server_address[1], target_url, time.monotonic() + 3, cert)
                raise SafeFailure("self_test_false_connect_success")
            except SafeFailure as error:
                if error.category == "self_test_false_connect_success":
                    raise

            class StunTarget(socketserver.BaseRequestHandler):
                def handle(self):
                    data, udp = self.request
                    if len(data) != 20 or data[:8] != b"\x00\x01\x00\x00" + STUN_COOKIE:
                        return
                    self.server.requests += 1
                    transaction = data[8:20]
                    if self.server.mode == "wrong_transaction":
                        transaction = bytes([transaction[0] ^ 1]) + transaction[1:]
                    address = int(ipaddress.IPv4Address(self.client_address[0])) ^ int.from_bytes(STUN_COOKIE, "big")
                    value = b"\x00\x01" + (self.client_address[1] ^ 0x2112).to_bytes(2, "big") + address.to_bytes(4, "big")
                    attribute = b"\x00\x20\x00\x08" + value
                    if self.server.mode == "wrong_attribute":
                        attribute = attribute[:2] + b"\x00\x10" + attribute[4:]
                    elif self.server.mode == "missing_mapped":
                        attribute = b"\x00\x21" + attribute[2:]
                    size = 16 if self.server.mode == "wrong_length" else len(attribute)
                    response = b"\x01\x01" + size.to_bytes(2, "big") + STUN_COOKIE + transaction + attribute
                    udp.sendto(response, self.client_address)

            class StunServer(socketserver.ThreadingUDPServer):
                daemon_threads = True
                mode = "normal"
                requests = 0

            stun = StunServer(("127.0.0.1", 0), StunTarget)
            servers.append(stun)
            thread = threading.Thread(target=stun.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
            stun_target = ("127.0.0.1", stun.server_address[1])

            class SocksUdpProxy(socketserver.BaseRequestHandler):
                def handle(self):
                    try:
                        control = self.request
                        control.settimeout(5)
                        greeting = receive_exact(control, 2)
                        if greeting[0] != 5 or b"\x00" not in receive_exact(control, greeting[1]):
                            return
                        control.sendall(b"\x05\x00")
                        request = receive_exact(control, 4)
                        if request[:3] != b"\x05\x03\x00":
                            return
                        if request[3] == 1:
                            receive_exact(control, 4)
                        elif request[3] == 4:
                            receive_exact(control, 16)
                        elif request[3] == 3:
                            receive_exact(control, receive_exact(control, 1)[0])
                        else:
                            return
                        receive_exact(control, 2)
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                            relay.bind(("127.0.0.1", 0))
                            control.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + relay.getsockname()[1].to_bytes(2, "big"))
                            client = None
                            while True:
                                ready, _, _ = select.select((control, relay), [], [], 5)
                                if not ready or (control in ready and not control.recv(1)):
                                    return
                                if relay not in ready:
                                    continue
                                packet, sender = relay.recvfrom(65535)
                                if sender == stun_target and client is not None:
                                    source = socket.inet_aton(stun_target[0])
                                    header = b"\x00\x00\x00\x01" + source + stun_target[1].to_bytes(2, "big")
                                    if self.server.fragment:
                                        header = header[:2] + b"\x01" + header[3:]
                                    relay.sendto(header + packet, client)
                                else:
                                    host, port, body = decode_socks_datagram(packet)
                                    if (host, port) != stun_target:
                                        return
                                    self.server.forwarded += 1
                                    client = sender
                                    relay.sendto(body, stun_target)
                    except Exception:
                        return

            udp_proxy = Server(("127.0.0.1", 0), SocksUdpProxy)
            udp_proxy.forwarded = 0
            udp_proxy.fragment = False
            servers.append(udp_proxy)
            thread = threading.Thread(target=udp_proxy.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
            udp_node = {"name": sentinel, "type": "socks5", "server": "127.0.0.1", "port": udp_proxy.server_address[1], "udp": True}
            for engine, binary in (("pathchord", args.pathchord), ("mihomo", args.mihomo)):
                before_forwarded = udp_proxy.forwarded
                before_requests = stun.requests
                ok, status, category = run_engine(engine, udp_node, stun_target, binary, 15, network="udp", temp_paths=temp_paths)
                if not ok or status is not None or category != "stun_response" or udp_proxy.forwarded <= before_forwarded or stun.requests <= before_requests:
                    raise SafeFailure("self_test_" + engine + "_udp_failed")
            for mode, expected in (("wrong_transaction", "stun_transaction_mismatch"),
                                   ("wrong_length", "stun_response_invalid"),
                                   ("wrong_attribute", "stun_response_invalid"),
                                   ("missing_mapped", "stun_response_invalid")):
                stun.mode = mode
                try:
                    check_stun(udp_proxy.server_address[1], stun_target, time.monotonic() + 3)
                    raise SafeFailure("self_test_false_udp_success")
                except SafeFailure as error:
                    if error.category != expected:
                        raise
            stun.mode = "normal"
            udp_proxy.fragment = True
            try:
                check_stun(udp_proxy.server_address[1], stun_target, time.monotonic() + 3)
                raise SafeFailure("self_test_false_udp_success")
            except SafeFailure as error:
                if error.category != "udp_response_invalid":
                    raise
            udp_proxy.fragment = False
            for value, expected in (({"type": "ss"}, (False, "udp_disabled")),
                                    ({"type": "ss", "udp": True}, (True, None)),
                                    ({"type": "hysteria2"}, (True, None)),
                                    ({"type": "tuic", "udp": False}, (False, "udp_disabled")),
                                    ({"type": "ss", "udp": "invalid"}, (False, "udp_invalid"))):
                if udp_capability(value) != expected:
                    raise SafeFailure("self_test_udp_capability_failed")
            test_args = copy.copy(args)
            test_args.network = "udp"
            with contextlib.redirect_stdout(captured):
                skipped = list(run_node(1, 1, {"type": "ss", "name": sentinel}, test_args, stun_target))
            if skipped != [None, None] or sentinel in captured.getvalue():
                raise SafeFailure("self_test_udp_skip_failed")
            try:
                resolve_stun("127.0.0.1", 53)
                raise SafeFailure("self_test_dns_port_accepted")
            except SafeFailure as error:
                if error.category != "stun_target_invalid":
                    raise
            source = PrivateSubscription({"type": "ss", "name": sentinel, "server": "127.0.0.1", "port": 1, "password": sentinel})
            try:
                env = dict(clean_env(temp), PATHCHORD_PROVIDER_1=source.url(), PATHCHORD_PROVIDER_2=source.url())
                cli = [sys.executable, "-B", str(Path(__file__).resolve()), "--network", "udp", "--stun-host", "127.0.0.1", "--stun-port", str(stun_target[1]), "--pathchord", args.pathchord, "--mihomo", args.mihomo]
                result = subprocess.run(cli, capture_output=True, text=True, env=env, timeout=10)
                lines = [json.loads(line) for line in result.stdout.splitlines()]
                if (result.returncode != 1 or result.stderr or sentinel in result.stdout or source.url() in result.stdout or
                        len(lines) != 5 or lines[-1] != {"summary": {"nodes": 2, "success": 0, "failure": 0, "skipped": 4}} or
                        any(row.get("result") != "udp_disabled" or row.get("ok") is not None for row in lines[:-1])):
                    raise SafeFailure("self_test_udp_summary_failed")
            finally:
                source.close()
        if len(temp_paths) != 4 or any(path.exists() for path in temp_paths):
            raise SafeFailure("self_test_cleanup_failed")
        emit({"self_test": "passed", "engines": ["pathchord", "mihomo"], "checks": ["http_response", "redaction", "cleanup", "connect_only_rejected", "stun_udp", "stun_bad_transaction_rejected", "stun_bad_length_rejected", "stun_bad_attributes_rejected", "fragment_rejected", "udp_disabled_skipped", "udp_summary", "dns_port_rejected"]})
        return 0
    except SafeFailure as error:
        emit({"error": error.category})
        return 1
    except Exception:
        emit({"error": "self_test_failed"})
        return 1
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == "__main__":
    def stop(_signal, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, stop)
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        emit({"error": "interrupted"})
        raise SystemExit(130)
    except Exception:
        emit({"error": "local_error"})
        raise SystemExit(2)
