#!/usr/bin/env python3
"""Cross-build against an exported FreeBSD SDK, then execute on native QEMU.

The official FreeBSD image and all guest mutations are owned by FreeBsdLab.
Cross compilation uses one consistent target sysroot/compiler/linker toolchain.
No host routes, accounts or installed packages are changed.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import time
import uuid

from qemu_freebsd import DEFAULT_CACHE, FreeBsdLab, IMAGE_BASE_URL
from qemu_lab import QEMU_ROOT, ROOT, digest, new_run_directory, run


TARGET = "x86_64-unknown-freebsd"
ROLES = ("pathchord-ingressd", "pathchord-egressd", "pathchordctl")


def ssh_arguments(guest, command):
    return ["ssh", "-i", str(guest.lab.directory / "identity"), "-p", str(guest.port),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "root@127.0.0.1", command]


def guest_command(guest, command, *, check=True, timeout=120):
    result = subprocess.run(ssh_arguments(guest, command), capture_output=True,
                            text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"FreeBSD command failed ({result.returncode}): "
                           + (result.stdout + result.stderr)[-3000:])
    return result


def export_sdk(lab, build_root, output):
    sdk = build_root / "sysroot"
    manifest = build_root / "sdk.json"
    if manifest.is_file() and (sdk / "usr/include/sys/types.h").is_file():
        metadata = json.loads(manifest.read_text())
        if digest(build_root / "sdk.tar.gz") != metadata["archive_sha256"]:
            raise RuntimeError("the cached FreeBSD SDK archive checksum changed")
        return sdk, metadata
    build_root.mkdir(parents=True, exist_ok=True)
    archive = build_root / "sdk.tar.gz"
    candidate = archive.with_suffix(".candidate")
    with candidate.open("wb") as destination, (output / "sdk-export.log").open("w") as errors:
        # Debug symbols and the guest's compiler are not target link inputs.
        # Excluding those large trees keeps SDK export bounded and reproducible.
        command = ("set -o pipefail; tar -cf - --exclude=usr/lib/debug "
                   "--exclude=usr/lib/clang -C / usr/include usr/lib lib libexec | gzip -1")
        run(ssh_arguments(lab.guest, command),
            stdout=destination, stderr=errors, timeout=300)
    candidate.replace(archive)
    sdk.mkdir(exist_ok=True)
    run(["bsdtar", "--no-same-owner", "-xf", str(archive), "-C", str(sdk)])
    # SDK libraries may use absolute /lib symlinks. Keep every lookup inside
    # this sysroot rather than following such links into the Linux host.
    rewritten = 0
    for path in sdk.rglob("*"):
        if path.is_symlink():
            target = os.readlink(path)
            if target.startswith("/"):
                path.unlink()
                path.symlink_to(os.path.relpath(sdk / target.lstrip("/"), path.parent))
                rewritten += 1
    metadata = {
        "target": TARGET, "sysroot": str(sdk), "archive_sha256": digest(archive),
        "guest": json.loads((lab.directory / "topology.json").read_text()),
        "rewritten_absolute_symlinks": rewritten,
        "paths": ["usr/include", "usr/lib", "lib", "libexec"],
        "excluded_paths": ["usr/lib/debug", "usr/lib/clang"],
    }
    manifest.write_text(json.dumps(metadata, indent=2) + "\n")
    return sdk, metadata


def toolchain(build_root, sdk):
    directory = build_root / "toolchain"
    directory.mkdir(parents=True, exist_ok=True)
    temporary = build_root / "tmp"
    temporary.mkdir(mode=0o700, exist_ok=True)
    programs = {}
    for name in ("clang", "clang++", "ld.lld", "llvm-ar"):
        program = shutil.which(name)
        if program is None:
            raise RuntimeError(f"missing cross-build tool: {name}")
        # Preserve clang++'s invocation name: it selects the C++ driver mode
        # even when the installation symlinks it to the clang executable.
        programs[name] = str(Path(program).absolute())
    common = ["--target=x86_64-unknown-freebsd15.1", f"--sysroot={sdk}", f"-B{sdk / 'usr/lib'}"]
    commands = {
        "cc": [programs["clang"], *common],
        "cxx": [programs["clang++"], *common, "-stdlib=libc++"],
        "ar": [programs["llvm-ar"]],
        "linker": [programs["clang"], *common, "-fuse-ld=lld",
                   f"-L{sdk / 'usr/lib'}", f"-L{sdk / 'lib'}"],
    }
    for name, command in commands.items():
        wrapper = directory / name
        wrapper.write_text("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
        wrapper.chmod(0o755)
    versions = {name: run([path, "--version"], capture_output=True).stdout.splitlines()[0]
                for name, path in programs.items()}
    env = dict(os.environ)
    env.update({
        "CC_x86_64_unknown_freebsd": str(directory / "cc"),
        "CXX_x86_64_unknown_freebsd": str(directory / "cxx"),
        "AR_x86_64_unknown_freebsd": str(directory / "ar"),
        "CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER": str(directory / "linker"),
        "CARGO_TARGET_DIR": str(build_root / "target"),
        "TMPDIR": str(temporary),
        "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
    })
    (build_root / "toolchain.json").write_text(json.dumps({
        "programs": programs, "versions": versions, "commands": commands,
        "environment": {key: value for key, value in env.items()
                        if key.startswith(("CC_", "CXX_", "AR_", "CARGO_TARGET_X86_64_UNKNOWN_FREEBSD"))
                        or key in ("CARGO_TARGET_DIR", "TMPDIR", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG")},
    }, indent=2) + "\n")
    return directory, env, versions


def compiler_smoke(lab, build_root, tools, output):
    source = build_root / "compiler-smoke.c"
    source.write_text('#include <stdio.h>\n#include <pthread.h>\n'
                      'int main(void) { pthread_rwlock_t lock; '
                      'if (pthread_rwlock_init(&lock, 0)) return 1; '
                      'pthread_rwlock_destroy(&lock); puts("FreeBSD native SDK smoke passed"); return 0; }\n')
    binary = build_root / "compiler-smoke"
    with (output / "compiler-smoke-build.log").open("w") as log:
        run([str(tools / "linker"), "-pthread", str(source), "-o", str(binary)],
            stdout=log, stderr=subprocess.STDOUT)
    lab.guest.put(binary, "/tmp/pathchord-compiler-smoke")
    result = guest_command(lab.guest, "/tmp/pathchord-compiler-smoke")
    (output / "compiler-smoke-native.log").write_text(result.stdout)
    print(result.stdout.strip(), flush=True)


def build(env, jobs, output):
    command = ["cargo", "build", "--locked", "--workspace", "--all-targets", "--target", TARGET,
               "--jobs", str(jobs), "--message-format=json-render-diagnostics"]
    artifacts = []
    errors = []
    with (output / "cargo-messages.jsonl").open("w") as messages, (output / "cargo-build.log").open("w") as log:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                   stderr=log, text=True)
        for line in process.stdout:
            messages.write(line)
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("reason") == "compiler-artifact" and message.get("executable"):
                artifacts.append({
                    "path": message["executable"], "name": message["target"]["name"],
                    "kind": message["target"]["kind"], "test": message["profile"]["test"],
                    "package": message["package_id"],
                })
            if message.get("reason") == "compiler-message" and message["message"]["level"] == "error":
                errors.append(message["message"].get("rendered", message["message"]["message"]))
        status = process.wait()
    if status:
        details = "\n".join(errors[-3:]) or (output / "cargo-build.log").read_text()[-6000:]
        raise RuntimeError("FreeBSD target build failed:\n" + details)
    unique = {artifact["path"]: artifact for artifact in artifacts}
    artifacts = list(unique.values())
    (output / "artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
    return artifacts


def native_tests(lab, artifacts, output, threads, targets, test_filter, repetitions):
    root = "/tmp/pc-tests"
    staging = output / "native-artifacts.tar.gz"
    tests = [artifact for artifact in artifacts if artifact["test"]
             and (not targets or artifact["name"] in targets)]
    if not tests:
        raise RuntimeError("no native test artifact matched the selected targets")
    roles = [artifact for artifact in artifacts if not artifact["test"] and artifact["name"] in ROLES]
    if {item["name"] for item in roles} != set(ROLES):
        raise RuntimeError("cross build did not emit all three role binaries")
    with tarfile.open(staging, "w:gz", compresslevel=1) as archive:
        for artifact in [*roles, *tests]:
            path = Path(artifact["path"])
            archive.add(path, arcname="bin/" + path.name, recursive=False)
    lab.guest.put(staging, "/tmp/pathchord-native-artifacts.tar.gz")
    guest_command(lab.guest,
        "pw usershow pathchord >/dev/null 2>&1 || pw useradd pathchord -d /var/empty -s /usr/sbin/nologin -w no; "
        f"mkdir -p {root}/home {root}/tmp; tar -xzf /tmp/pathchord-native-artifacts.tar.gz -C {root}; "
        f"chown -R pathchord:pathchord {root}; chmod 700 {root} {root}/home {root}/tmp"
    )
    account = guest_command(lab.guest, "id pathchord; pw usershow pathchord").stdout
    (output / "service-account.txt").write_text(account)
    dependencies = guest_command(lab.guest, "ldd " + " ".join(f"{root}/bin/{name}" for name in ROLES)).stdout
    (output / "native-dependencies.txt").write_text(dependencies)
    results = []
    for artifact in tests * repetitions:
        path = Path(artifact["path"])
        command = (f"umask 077; cd {root}; env HOME={root}/home TMPDIR={root}/tmp "
                   "PATH=/bin:/sbin:/usr/bin:/usr/sbin "
                   f"{root}/bin/{shlex.quote(path.name)} --test-threads={threads}")
        if test_filter:
            command += " --exact " + shlex.quote(test_filter)
        result = guest_command(lab.guest, "su -m pathchord -c " + shlex.quote(command), check=False, timeout=240)
        attempt = sum(item["executable"] == path.name for item in results) + 1
        suffix = f"-{attempt}" if repetitions > 1 else ""
        (output / (path.name + suffix + ".log")).write_text(result.stdout + result.stderr)
        matches = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", result.stdout)
        verdict, passed, failed, ignored = matches[-1] if matches else ("error", 0, 0, 0)
        record = {"test": artifact["name"], "executable": path.name, "sha256": digest(path),
                  "passed": int(passed), "failed": int(failed), "ignored": int(ignored),
                  "verdict": verdict, "returncode": result.returncode, "attempt": attempt,
                  "filter": test_filter}
        if test_filter and record["passed"] + record["failed"] + record["ignored"] == 0:
            record["verdict"] = "unmatched_filter"
        results.append(record)
        print(json.dumps(record), flush=True)
    sockets = guest_command(lab.guest, f"find {root}/tmp -type s -print").stdout
    (output / "remaining-test-sockets.txt").write_text(sockets)
    metadata = guest_command(lab.guest, "freebsd-version -ku; uname -a; sysctl -n kern.proc.pid.$$.uid", check=False).stdout
    (output / "native-host.txt").write_text(metadata)
    return results, [{"role": item["name"], "sha256": digest(Path(item["path"]))} for item in roles]


def native_service_check(lab, output):
    script = output / "native-service-check.sh"
    script.write_text(r'''#!/bin/sh
set -eu
umask 077
root=/tmp/pc-tests
work=$root/service
mkdir -p "$work"
chmod 700 "$work"
cd "$work"
export HOME=$root/home TMPDIR=$root/tmp PATH=$root/bin:/bin:/sbin:/usr/bin:/usr/sbin
test "$(id -un)" = pathchord
test "$(id -u)" != 0
pathchordctl keygen --output identity > public.json
pathchord-egressd --egress-id native-check --identity "$work/identity" \
  --authorization-db "$work/authorizations.db" --control-socket "$work/control.sock" \
  --bind 127.0.0.1:37443 > service.log 2>&1 &
daemon_pid=$!
trap 'kill -TERM "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true' EXIT HUP INT TERM
attempt=0
until test -S control.sock; do
  kill -0 "$daemon_pid"
  attempt=$((attempt + 1))
  test "$attempt" -lt 100
  sleep 0.05
done
pathchordctl --socket "$work/control.sock" status > status.json
for file in identity authorizations.db control.sock; do
  test "$(stat -f %Lp "$file")" = 600
  test "$(stat -f %Su "$file")" = pathchord
  printf '%s mode=%s owner=%s\n' "$file" "$(stat -f %Lp "$file")" "$(stat -f %Su "$file")"
done
head -c 15 authorizations.db | grep -q 'SQLite format 3'
kill -TERM "$daemon_pid"
wait "$daemon_pid"
trap - EXIT HUP INT TERM
test ! -e control.sock
printf 'sqlite_native=true private_files=true sigterm_exit=0 socket_removed=true\n'
''')
    script.chmod(0o755)
    lab.guest.put(script, "/tmp/pc-native-service-check.sh")
    result = guest_command(lab.guest, "su -m pathchord -c 'sh /tmp/pc-native-service-check.sh'", check=False)
    (output / "native-service-permissions-signals.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        error = guest_command(lab.guest, "cat /tmp/pc-tests/service/service.log", check=False).stdout
        raise RuntimeError("native service permission/signal checks failed: " + result.stderr + error[-2000:])
    expected = "sqlite_native=true private_files=true sigterm_exit=0 socket_removed=true"
    if expected not in result.stdout:
        raise RuntimeError("native service permission/signal checks omitted their completion marker")
    return {"ok": True, "service_account": "pathchord", "umask": "0077",
            "identity_mode": "0600", "sqlite_mode": "0600", "control_socket_mode": "0600",
            "sigterm_exit": 0, "control_socket_removed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--build-root", type=Path, default=QEMU_ROOT / "freebsd-build")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--image-base-url", default=IMAGE_BASE_URL)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--test-threads", type=int, default=2)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--reuse-artifacts", type=Path)
    parser.add_argument("--test-target", action="append", default=[])
    parser.add_argument("--test-filter")
    parser.add_argument("--repetitions", type=int, default=1)
    arguments = parser.parse_args()
    output = arguments.output.resolve() if arguments.output else new_run_directory("freebsd-platforms")
    build_root = arguments.build_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build_root.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with FreeBsdLab(output / "guest", arguments.cache, arguments.image_base_url) as lab:
        sdk, sdk_metadata = export_sdk(lab, build_root, output)
        tools, env, versions = toolchain(build_root, sdk)
        compiler_smoke(lab, build_root, tools, output)
        if arguments.prepare_only:
            print(build_root / "sdk.json")
            return
        artifacts = (json.loads(arguments.reuse_artifacts.read_text()) if arguments.reuse_artifacts
                     else build(env, arguments.jobs, output))
        tests, binaries = native_tests(lab, artifacts, output, arguments.test_threads,
                                       arguments.test_target, arguments.test_filter, arguments.repetitions)
        service_check = native_service_check(lab, output)
        passed = all(item["returncode"] == 0 and item["verdict"] == "ok" for item in tests)
        report = {"ok": passed, "topology": json.loads((lab.directory / "topology.json").read_text()),
                  "sdk": sdk_metadata, "toolchain": versions, "binaries": binaries, "tests": tests,
                  "elapsed_seconds": round(time.monotonic() - started, 2),
                  "source_revision": run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True).stdout.strip(),
                  "service_account": "pathchord", "profile_debug_info": False,
                  "native_service": service_check,
                  "passed": sum(item["passed"] for item in tests),
                  "ignored": sum(item["ignored"] for item in tests)}
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        if not passed:
            raise RuntimeError(f"native FreeBSD tests reported failures; see {output / 'results.json'}")
        print(f"Native FreeBSD platform checks passed: {report['passed']} tests; {output / 'results.json'}")


if __name__ == "__main__":
    main()
