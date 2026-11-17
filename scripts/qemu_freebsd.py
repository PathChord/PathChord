#!/usr/bin/env python3
"""Disposable FreeBSD native-validation guest using the official cloud image."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

from qemu_lab import Guest, QEMU_ROOT, ROOT, digest, free_port, new_run_directory, run


IMAGE_NAME = "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
IMAGE_BASE_URL = "https://mirrors.cernet.edu.cn/FreeBSD/releases/VM-IMAGES"
IMAGE_DIRECTORY = "15.1-RELEASE/amd64/Latest"
DEFAULT_CACHE = QEMU_ROOT / "freebsd" / "cache"


def prepare(cache: Path, image_base_url: str = IMAGE_BASE_URL):
    cache.mkdir(parents=True, exist_ok=True)
    image_url = image_base_url.rstrip("/") + "/" + IMAGE_DIRECTORY + "/"
    checksum = cache / "CHECKSUM.SHA256"
    if not checksum.is_file():
        run(["curl", "--fail", "--location", "--silent", "--show-error", "--max-time", "60",
             image_url + "CHECKSUM.SHA256", "--output", str(checksum)])
    archive = cache / IMAGE_NAME
    if not archive.is_file():
        run(["curl", "--fail", "--location", "--silent", "--show-error", "--retry", "2",
             image_url + IMAGE_NAME, "--output", str(archive)])
        (cache / "image-source.json").write_text(json.dumps({"url": image_url + IMAGE_NAME}) + "\n")
    entry = next(line for line in checksum.read_text().splitlines() if IMAGE_NAME in line)
    expected = re.search(r"[0-9a-fA-F]{64}", entry).group(0).lower()
    if digest(archive) != expected:
        raise RuntimeError("FreeBSD image does not match the official SHA-256 checksum")
    image = cache / IMAGE_NAME.removesuffix(".xz")
    if not image.is_file():
        run(["xz", "--decompress", "--keep", str(archive)])
    return image


class FreeBsdLab:
    def __init__(self, output, cache=DEFAULT_CACHE, image_base_url=IMAGE_BASE_URL):
        self.directory, self.cache = Path(output).resolve(), Path(cache).resolve()
        self.image_base_url = image_base_url
        self.directory.mkdir(parents=True, exist_ok=True)
        self.guests = []
        atexit.register(self.close)

    def __enter__(self):
        image = prepare(self.cache, self.image_base_url)
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.directory / "identity")])
        public = (self.directory / "identity.pub").read_text().strip()
        userdata = {
            "hostname": "pathchord-freebsd", "disable_root": False, "ssh_pwauth": False,
            "package_update": False, "package_upgrade": False,
            "ssh_authorized_keys": [public],
            "users": [{"name": "root", "lock_passwd": False, "ssh_authorized_keys": [public]}],
            "write_files": [
                # Pin the official image under test. Its default first-boot pkg
                # upgrade otherwise changes the base OS before SSH is available.
                {"path": "/etc/rc.conf.d/firstboot_pkg_upgrade", "permissions": "0644",
                 "content": 'firstboot_pkg_upgrade_enable="NO"\n'},
            ],
            # FreeBSD nuageinit accepts shell strings here; the Linux cloud-init
            # argv-list form aborts provisioning before authorized_keys is installed.
            "runcmd": ["sysrc sshd_enable=YES; printf '\\nPermitRootLogin prohibit-password\\n' "
                       ">> /etc/ssh/sshd_config; service sshd restart"],
        }
        (self.directory / "user-data").write_text("#cloud-config\n" + json.dumps(userdata) + "\n")
        (self.directory / "meta-data").write_text(json.dumps({
            "instance-id": "pathchord-" + uuid.uuid4().hex,
            "local-hostname": "pathchord-freebsd",
        }) + "\n")
        run(["xorriso", "-as", "mkisofs", "-quiet", "-V", "cidata", "-J", "-r",
             "-o", str(self.directory / "seed.iso"),
             str(self.directory / "user-data"), str(self.directory / "meta-data")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        disk = self.directory / "guest.qcow2"
        run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(disk)])
        guest = Guest.__new__(Guest)
        guest.lab, guest.role, guest.port = self, "freebsd", free_port()
        guest.connect_timeout = 10
        guest.log = (self.directory / "console.log").open("w")
        guest.process = subprocess.Popen([
            "qemu-system-x86_64", "-accel", "kvm", "-m", "2048", "-smp", "2",
            "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
            "-drive", f"file={disk},format=qcow2,if=virtio",
            "-cdrom", str(self.directory / "seed.iso"),
            "-netdev", f"user,id=management,hostfwd=tcp:127.0.0.1:{guest.port}-:22",
            "-device", "virtio-net-pci,netdev=management",
        ], stdin=subprocess.DEVNULL, stdout=guest.log, stderr=subprocess.STDOUT)
        self.guests.append(guest)
        guest.ready()
        self.guest = guest
        metadata = {
            "image": IMAGE_NAME, "requested_image_base_url": self.image_base_url,
            "source": json.loads((self.cache / "image-source.json").read_text())
            if (self.cache / "image-source.json").is_file() else {"url": None, "origin": "pre-existing verified cache"},
            "image_archive_sha256": digest(self.cache / IMAGE_NAME),
            "host": guest.ssh("freebsd-version -ku; uname -m; sysctl -n kern.boot_id", check=False).stdout.splitlines(),
            "management": "loopback-only SSH via QEMU user network",
            "revision": run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True).stdout.strip(),
        }
        (self.directory / "topology.json").write_text(json.dumps(metadata, indent=2) + "\n")
        return self

    def close(self):
        for guest in reversed(self.guests):
            guest.close()
        self.guests.clear()
        for name in ("identity", "identity.pub", "user-data", "meta-data", "seed.iso"):
            (self.directory / name).unlink(missing_ok=True)

    def __exit__(self, *_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--image-base-url", default=IMAGE_BASE_URL,
                        help="VM-IMAGES mirror root (defaults to the CERNET mirror)")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--command", default="freebsd-version -ku; uname -a")
    arguments = parser.parse_args()
    output = arguments.output or new_run_directory("freebsd-smoke")
    with FreeBsdLab(output, arguments.cache, arguments.image_base_url) as lab:
        print(lab.guest.ssh(arguments.command, timeout=600).stdout)
        print(lab.directory / "topology.json")


if __name__ == "__main__":
    main()
