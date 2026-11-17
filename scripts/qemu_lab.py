#!/usr/bin/env python3
"""Disposable, independent Linux guests connected by a private Ethernet link.

The guest root filesystem is assembled with Alpine's native package manager.
QEMU user networking exposes only a loopback SSH management port. A separate
socket-backed pair of virtio NICs carries the traffic under test; it never
changes the host's interfaces, routes, firewall, or libvirt configuration.
"""

from __future__ import annotations

import argparse
import atexit
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parent.parent
QEMU_ROOT = Path(os.environ.get("PATHCHORD_QEMU_ROOT", "/data/pathchord-qemu")).expanduser()
QEMU_RUNS = QEMU_ROOT / "runs"
DEFAULT_CACHE = QEMU_ROOT / "linux-rootfs"
PACKAGES = (
    "linux-virt", "openssh", "python3", "curl", "iproute2", "iproute2-tc",
    "openssl", "cpio", "ca-certificates", "openrc", "apk-tools", "shadow",
)


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def pack_initramfs(source: Path, destination: Path):
    with destination.open("wb") as output:
        listing = subprocess.Popen(["find", ".", "-print0"], cwd=source, stdout=subprocess.PIPE)
        packing = subprocess.Popen(["cpio", "--null", "-o", "-H", "newc", "--owner", "0:0"],
                                   cwd=source, stdin=listing.stdout, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
        listing.stdout.close()
        compressor = ["pigz", "-1", "-p", "4"] if shutil.which("pigz") else ["gzip", "-1"]
        compressing = subprocess.Popen(compressor, stdin=packing.stdout, stdout=output)
        packing.stdout.close()
        for process in (compressing, packing, listing):
            if process.wait():
                raise RuntimeError("could not assemble the guest initramfs")


def new_run_directory(prefix: str) -> Path:
    QEMU_RUNS.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f"{prefix}-", dir=QEMU_RUNS))


def prepare(cache: Path, image: str = "alpine:3.24") -> None:
    """Cache a rootfs, including its matching kernel and loadable modules."""
    cache.mkdir(parents=True, exist_ok=True)
    rootfs = cache / "rootfs"
    if (cache / "rootfs.json").is_file() and (rootfs / "boot/vmlinuz-virt").is_file():
        return
    name = f"pathchord-qemu-prepare-{uuid.uuid4().hex[:10]}"
    archive = cache / "rootfs.tar"
    network = ["--network", "host"]
    if resolver := os.environ.get("PATHCHORD_QEMU_DNS"):
        network.extend(["--dns", resolver])
    if mirror_address := os.environ.get("PATHCHORD_QEMU_APK_ADDRESS"):
        # Keep HTTPS hostname/certificate checks when a build network needs an
        # explicit address for Alpine's CDN. No host resolver files are edited.
        network.extend(["--add-host", f"dl-cdn.alpinelinux.org:{mirror_address}"])
    with (cache / "prepare.log").open("w") as log:
        try:
            # Host networking avoids dependence on Docker's embedded DNS. This
            # container only installs guest packages; it does not manage host networking.
            run([
                "docker", "run", *network, "--name", name, image,
                "sh", "-ec", "apk add --no-cache " + " ".join(PACKAGES),
            ], stdout=log, stderr=subprocess.STDOUT)
            run(["docker", "export", "--output", str(archive), name])
        finally:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
    rootfs.mkdir(exist_ok=True)
    run(["bsdtar", "--no-same-owner", "-xf", str(archive), "-C", str(rootfs)])
    archive.unlink()
    image_id = run(["docker", "image", "inspect", "--format", "{{.Id}}", image],
                   capture_output=True).stdout.strip()
    (cache / "rootfs.json").write_text(json.dumps({
        "image": image, "image_id": image_id, "packages": PACKAGES,
        "alpine": (rootfs / "etc/alpine-release").read_text().strip(),
        "kernel_sha256": digest(rootfs / "boot/vmlinuz-virt"),
    }, indent=2) + "\n")


INIT = r"""#!/bin/sh
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /run/sshd /tmp /root/.ssh
chmod 1777 /tmp
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /run
mkdir -p /run/sshd
modprobe virtio_net
ip link set lo up
ip link set eth0 up
udhcpc -i eth0 -q -t 10 -T 1
role=server
for argument in $(cat /proc/cmdline); do
    case "$argument" in pc_role=*) role=${argument#pc_role=};; esac
done
case "$role" in client) number=10;; server) number=11;; *) exit 1;; esac
ip link set eth1 up
ip addr add "192.0.2.$number/24" dev eth1
ip -6 addr add "fd00:7063::$number/64" dev eth1 nodad
hostname "pathchord-$role"
ssh-keygen -A
/usr/sbin/sshd -e
echo "PATHCHORD_QEMU_READY role=$role kernel=$(uname -r)"
exec python3 -c 'import os; exec("while True:\n try: os.waitpid(-1, 0)\n except ChildProcessError: __import__(\"time\").sleep(1)")'
"""


class Guest:
    def __init__(self, lab: "Lab", role: str, link: int, listen: bool):
        self.lab, self.role = lab, role
        self.connect_timeout = 2
        self.port = free_port()
        self.log = (lab.directory / f"{role}-console.log").open("w")
        acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        command = [
            "qemu-system-x86_64", "-accel", acceleration, "-m", "1024", "-smp", "2",
            "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
            "-kernel", str(lab.cache / "rootfs/boot/vmlinuz-virt"),
            "-initrd", str(lab.directory / "guest.cpio.gz"),
            "-append", f"console=ttyS0 rdinit=/init net.ifnames=0 pc_role={role} panic=-1",
            "-netdev", f"user,id=management,hostfwd=tcp:127.0.0.1:{self.port}-:22",
            "-device", "virtio-net-pci,netdev=management",
            "-netdev", f"socket,id=wire,{'listen' if listen else 'connect'}=127.0.0.1:{link}",
            "-device", "virtio-net-pci,netdev=wire",
        ]
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=subprocess.STDOUT)

    def ssh(self, command: str, *, check=True, timeout=120, input=None):
        result = subprocess.run([
            "ssh", "-i", str(self.lab.directory / "identity"), "-p", str(self.port),
            "-o", "BatchMode=yes", "-o", f"ConnectTimeout={self.connect_timeout}", "-o", "LogLevel=ERROR",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "root@127.0.0.1", command,
        ], input=input, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"{self.role} command failed ({result.returncode}): "
                               f"{result.stdout[-2000:]}{result.stderr[-2000:]}")
        return result

    def ready(self):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"{self.role} guest exited; see {self.log.name}")
            try:
                if self.ssh("true", check=False, timeout=self.connect_timeout + 2).returncode == 0:
                    return
            except subprocess.TimeoutExpired:
                pass
            time.sleep(0.25)
        raise TimeoutError(f"{self.role} guest did not become ready; see {self.log.name}")

    def put(self, source: Path, destination: str):
        # Stream through SSH instead of granting a guest access to a host share.
        with source.open("rb") as data:
            command = [
                "ssh", "-i", str(self.lab.directory / "identity"), "-p", str(self.port),
                "-o", "BatchMode=yes", "-o", f"ConnectTimeout={self.connect_timeout}",
                "-o", "LogLevel=ERROR", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "root@127.0.0.1",
                f"cat > {shlex.quote(destination)} && chmod {source.stat().st_mode & 0o777:o} "
                f"{shlex.quote(destination)}",
            ]
            subprocess.run(command, stdin=data, stdout=subprocess.DEVNULL, check=True, timeout=120)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


class Lab:
    def __init__(self, cache=DEFAULT_CACHE, output=None):
        self.cache = Path(cache).resolve()
        self.directory = Path(output).resolve() if output else new_run_directory("linux")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.guests: list[Guest] = []
        atexit.register(self.close)

    def __enter__(self):
        prepare(self.cache)
        # Reuse the large, immutable base. Linux accepts concatenated compressed
        # cpio archives, so each lab only needs a tiny SSH/configuration overlay.
        base = self.cache / "base.cpio.gz"
        with (self.cache / "base.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if not base.is_file():
                candidate = self.cache / "base.cpio.gz.tmp"
                pack_initramfs(self.cache / "rootfs", candidate)
                candidate.replace(base)
        stage = self.directory / "rootfs"
        stage.mkdir()
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.directory / "identity")])
        authorized = stage / "root/.ssh"
        authorized.mkdir(parents=True, exist_ok=True)
        authorized.chmod(0o700)
        shutil.copyfile(self.directory / "identity.pub", authorized / "authorized_keys")
        (authorized / "authorized_keys").chmod(0o600)
        shadow = stage / "etc/shadow"
        shadow.parent.mkdir(parents=True, exist_ok=True)
        shadow.write_text("\n".join(
            ":".join([fields[0], "", *fields[2:]]) if fields[0] == "root" else ":".join(fields)
            for fields in (line.split(":") for line in (self.cache / "rootfs/etc/shadow").read_text().splitlines())
        ) + "\n")
        ssh_config = stage / "etc/ssh/sshd_config"
        ssh_config.parent.mkdir(parents=True, exist_ok=True)
        ssh_config.write_text("PermitRootLogin prohibit-password\nPasswordAuthentication no\n"
                              "KbdInteractiveAuthentication no\nUsePAM no\nPidFile /run/sshd.pid\n")
        (stage / "init").write_text(INIT)
        (stage / "init").chmod(0o755)
        overlay = self.directory / "overlay.cpio.gz"
        pack_initramfs(stage, overlay)
        with (self.directory / "guest.cpio.gz").open("wb") as output:
            for part in (base, overlay):
                with part.open("rb") as source:
                    shutil.copyfileobj(source, output)
        overlay.unlink()
        shutil.rmtree(stage)
        link = free_port()
        self.server = Guest(self, "server", link, True)
        self.guests.append(self.server)
        # Waiting for SSH also ensures the socket-backed Ethernet listener exists.
        self.server.ready()
        self.client = Guest(self, "client", link, False)
        self.guests.append(self.client)
        self.client.ready()
        self.client.ssh("ping -c 2 -W 2 192.0.2.11 && ping -6 -c 2 -W 2 fd00:7063::11")
        metadata = json.loads((self.cache / "rootfs.json").read_text())
        metadata.update({
            "topology": "client QEMU eth1 <-> private socket Ethernet <-> server QEMU eth1",
            "client": self.client.ssh("uname -srmo; cat /proc/sys/kernel/random/boot_id").stdout.splitlines(),
            "server": self.server.ssh("uname -srmo; cat /proc/sys/kernel/random/boot_id").stdout.splitlines(),
            "management": "loopback-only SSH via independent QEMU user networks",
            "revision": run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True).stdout.strip(),
        })
        if metadata["client"][-1] == metadata["server"][-1]:
            raise RuntimeError("guests do not have independent kernel boot identities")
        (self.directory / "topology.json").write_text(json.dumps(metadata, indent=2) + "\n")
        return self

    def close(self):
        for guest in reversed(self.guests):
            guest.close()
        self.guests.clear()
        # This key only controls these disposable guests and is never an artifact.
        for path in (self.directory / "identity", self.directory / "identity.pub",
                     self.directory / "guest.cpio.gz"):
            path.unlink(missing_ok=True)

    def __exit__(self, *_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "smoke"))
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "prepare":
        prepare(arguments.cache)
        print(arguments.cache / "rootfs.json")
    else:
        with Lab(arguments.cache, arguments.output) as lab:
            print((lab.directory / "topology.json").read_text())


if __name__ == "__main__":
    main()
