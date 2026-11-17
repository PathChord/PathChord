#!/usr/bin/env python3
"""Run the privileged Linux matrix inside a disposable QEMU Linux machine.

Build x86_64 musl Ingress/control binaries first. The guest's matching kernel
modules, namespaces and private bpffs keep privileged network operations away
from the development host. See test-linux-platforms.py for the actual matrix.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import time

from qemu_lab import DEFAULT_CACHE, Lab, QEMU_ROOT, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, default=ROOT / "target/x86_64-unknown-linux-musl/release")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path, default=QEMU_ROOT / "runs/linux-platforms")
    parser.add_argument("--udp-bytes", type=int, default=4096)
    parser.add_argument("--apk-address", help="Optional guest-only HTTPS CDN address override")
    options = parser.parse_args()
    output = options.output.resolve() / time.strftime("%Y%m%d-%H%M%S")
    output.mkdir(parents=True)
    binaries = [options.binary_dir.resolve() / name for name in ("pathchord-ingressd", "pathchordctl")]
    for binary in binaries:
        if not binary.is_file():
            parser.error(f"missing musl executable {binary}")
    # Snapshot the actual uploaded executables: other workspace builds may
    # replace a target artifact while this guest matrix is running.
    binary_snapshot = output / "binaries"
    binary_snapshot.mkdir()
    for binary in binaries:
        shutil.copy2(binary, binary_snapshot / binary.name)
    binaries = [binary_snapshot / binary.name for binary in binaries]
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                              capture_output=True, check=True).stdout.strip()
    # Fetch through the same verified HTTPS repositories as the base image,
    # then install offline. A transient guest DNS/TLS failure cannot turn into
    # a missing-package result or require an insecure APK download.
    apk_cache = options.cache.resolve() / "linux-platform-apks"
    apk_cache.mkdir(parents=True, exist_ok=True)
    if not (apk_cache / "packages.json").exists():
        command = ["docker", "run", "--rm", "--network", "host"]
        if options.apk_address:
            command.extend(["--add-host", "dl-cdn.alpinelinux.org:" + options.apk_address])
        command.extend(["--mount", f"type=bind,src={apk_cache},dst=/packages", "alpine:3.24", "sh", "-ec",
                        "apk update && apk fetch --recursive --output /packages nftables bpftool tcpdump"])
        with (output / "apk-fetch.log").open("w") as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
        package_digests = {}
        for package in sorted(apk_cache.glob("*.apk")):
            with package.open("rb") as source:
                package_digests[package.name] = hashlib.file_digest(source, "sha256").hexdigest()
        (apk_cache / "packages.json").write_text(json.dumps(package_digests, indent=2) + "\n")
    expected_packages = json.loads((apk_cache / "packages.json").read_text())
    if {package.name for package in apk_cache.glob("*.apk")} != set(expected_packages):
        raise RuntimeError("the cached APK inventory no longer matches its manifest")
    for name, expected in expected_packages.items():
        with (apk_cache / name).open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != expected:
                raise RuntimeError(f"cached APK digest mismatch: {name}")
    with Lab(cache=options.cache, output=output / "lab") as lab:
        guest = lab.server
        guest.ssh("mkdir -p /tmp/platform-apks")
        for package in sorted(apk_cache.glob("*.apk")):
            guest.put(package, "/tmp/platform-apks/" + package.name)
        setup = guest.ssh("apk add --no-network --force-non-repository /tmp/platform-apks/*.apk && rm -rf /tmp/platform-apks && "
                          "modprobe nft_tproxy && modprobe nft_redir && modprobe cls_bpf && "
                          "modprobe sch_ingress && modprobe tun && mkdir -p /sys/fs/bpf && "
                          "mount -t bpf bpf /sys/fs/bpf", timeout=120)
        (output / "guest-setup.log").write_text(setup.stdout + setup.stderr)
        versions = guest.ssh("uname -a; cat /etc/alpine-release; ip -Version; tc -Version; nft --version; bpftool version")
        (output / "guest-versions.txt").write_text(versions.stdout + versions.stderr)
        for binary in binaries:
            guest.put(binary, "/tmp/" + binary.name)
        guest.put(ROOT / "scripts/test-linux-platforms.py", "/tmp/test-linux-platforms.py")
        command = (f"PATHCHORD_TEST_UDP_BYTES={options.udp_bytes} python3 /tmp/test-linux-platforms.py --ingress /tmp/pathchord-ingressd "
                   "--output /tmp/platform-evidence --revision " + shlex.quote(revision))
        result = guest.ssh(command, check=False, timeout=300)
        (output / "matrix.log").write_text(result.stdout + result.stderr)
        archive = guest.ssh("tar -C /tmp/platform-evidence -czf - . | base64", check=False)
        if archive.returncode == 0:
            archive_path = output / "guest-evidence.tar.gz"
            archive_path.write_bytes(base64.b64decode(archive.stdout))
            with tarfile.open(archive_path) as contents:
                contents.extractall(output / "evidence", filter="data")
        manifest = {
            "revision": revision, "dirty_worktree": bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                text=True, capture_output=True, check=True).stdout),
            "command": command, "guest": json.loads(guest.ssh(
                "python3 -c 'import json,os,pathlib;print(json.dumps({\"kernel\":os.uname().release,"
                "\"architecture\":os.uname().machine,\"boot_id\":pathlib.Path(\"/proc/sys/kernel/random/boot_id\").read_text().strip()}))'").stdout),
            "binaries": {binary.name: hashlib.file_digest(binary.open("rb"), "sha256").hexdigest() for binary in binaries},
            "apk_sha256": json.loads((apk_cache / "packages.json").read_text()),
            "returncode": result.returncode,
        }
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(result.stdout, end="")
        print(result.stderr, end="")
        print(f"QEMU Linux evidence: {output}")
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
