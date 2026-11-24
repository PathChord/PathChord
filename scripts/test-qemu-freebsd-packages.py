#!/usr/bin/env python3
"""Build role packages with native pkg and verify their rc.d and state lifecycle."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import time

from qemu_freebsd import FreeBsdLab
from qemu_lab import QEMU_ROOT, ROOT, new_run_directory


SCRIPT = r'''set -eu
role="$1"
case "$role" in ingress) other=egress;; egress) other=ingress;; *) exit 2;; esac
name="pathchord-${role}d"
other_name="pathchord-${other}d"
older="/tmp/package-lab/out/$name-0.1.0.pkg"
newer="/tmp/package-lab/out/$name-0.1.1.pkg"
opposite="/tmp/package-lab/out/$other_name-0.1.0.pkg"
ASSUME_ALWAYS_YES=yes
export ASSUME_ALWAYS_YES
pkg add "$older"
[ -x "/usr/local/bin/$name" ]
[ ! -e "/usr/local/bin/$other_name" ]
[ -x /usr/local/bin/pathchordctl ]
[ ! -e "/usr/local/etc/rc.d/$other_name" ]
pkg info -l "$name"
getent passwd pathchord
[ "$(stat -f '%Su:%Sg:%Lp' "/var/db/pathchord-$role")" = 'pathchord:pathchord:700' ]
[ "$(stat -f '%Su:%Sg:%Lp' "/usr/local/etc/pathchord/$role")" = 'root:pathchord:750' ]
[ "$(stat -f '%Su:%Sg:%Lp' /var/run/pathchord)" = 'pathchord:pathchord:700' ]
[ -f /usr/local/share/man/man1/pathchord.1 ]
state="/var/db/pathchord-$role"
config="/usr/local/etc/pathchord/$role/$role.yaml"
printf '\n# operator-lifecycle-sentinel\n' >> "$config"
pathchordctl -o json keygen --identity-file "$state/lifecycle.key.json" >/dev/null
printf authorization-state-fixture > "$state/lifecycle.authorizations.db"
chown pathchord:pathchord "$state"/lifecycle*
chmod 0600 "$state"/lifecycle*
sha256 "$state"/lifecycle* > "/tmp/$role-sentinel.sha256"
verify_state() {
    sha256 "$state"/lifecycle* > /tmp/pathchord-current.sha256
    if ! cmp "/tmp/$role-sentinel.sha256" /tmp/pathchord-current.sha256; then
        echo 'private sentinel content changed during package operation' >&2
        exit 1
    fi
    if ! grep -q '^# operator-lifecycle-sentinel$' "$config"; then
        echo 'operator configuration sentinel was lost during package operation' >&2
        exit 1
    fi
    if [ "$role" = egress ] && [ -e /tmp/pathchord-actual-egress.sha256 ]; then
        sha256 "$state/egress.key.json" "$state/authorizations.db" > /tmp/pathchord-actual-current.sha256
        cmp /tmp/pathchord-actual-egress.sha256 /tmp/pathchord-actual-current.sha256
    fi
}
if pkg add "$opposite" > /tmp/pathchord-conflict.log 2>&1; then
    echo 'opposite role installed unexpectedly' >&2
    exit 1
fi
verify_state
[ -x "/usr/local/bin/$name" ]
[ ! -e "/usr/local/bin/$other_name" ]
if [ "$role" = egress ]; then
    pathchordctl -o json keygen --identity-file "$state/egress.key.json" >/dev/null
    chown pathchord:pathchord "$state/egress.key.json"
fi
service "$name" onestart
ready() {
    endpoint="/var/run/pathchord/$role.sock"
    is_ready=false
    for attempt in $(seq 1 200); do
        if [ -S "$endpoint" ] && pathchordctl --socket "$endpoint" status >/dev/null 2>&1; then is_ready=true; break; fi
        sleep 0.05
    done
    if [ "$is_ready" != true ]; then service "$name" onestatus || true; cat "$state/service.log"; tail -40 /var/log/messages; exit 1; fi
    env SHELL=/bin/sh su -m pathchord -c "pathchordctl --socket $endpoint status"
    [ "$(stat -f '%Su:%Sg:%Lp' "$endpoint")" = 'pathchord:pathchord:600' ]
    if [ "$role" = egress ] && [ -e "$state/native-enrollment.fixture" ]; then
        pathchordctl -o json --socket "$endpoint" enroll get --ingress-id lifecycle-fixture > /tmp/pathchord-enrollment.json
        grep -q lifecycle-fixture /tmp/pathchord-enrollment.json
        grep -q native-upgrade /tmp/pathchord-enrollment.json
        grep -Fq -e "$(cat "$state/native-enrollment.fixture")" /tmp/pathchord-enrollment.json
    fi
    service "$name" onestatus
    pid=$(cat "/var/run/pathchord/pathchord_${role}d.pid")
    [ "$(ps -o uid= -p "$pid" | tr -d ' ')" = "$(id -u pathchord)" ]
    ps -o user,group,pid,command -p "$pid"
}
ready
conflict_before=$(cat "/var/run/pathchord/pathchord_${role}d.pid")
if pkg add "$opposite" > /tmp/pathchord-active-conflict.log 2>&1; then
    echo 'opposite role replaced an active service unexpectedly' >&2
    exit 1
fi
[ "$(cat "/var/run/pathchord/pathchord_${role}d.pid")" = "$conflict_before" ]
verify_state
ready
if [ "$role" = egress ]; then
    public=$(pathchordctl -o json keygen --identity-file "$state/native-ingress.key.json" | sed -n 's/.*"public_key": "\([^" ]*\)".*/\1/p')
    pathchordctl --socket "$endpoint" enroll add --ingress-id lifecycle-fixture --egress-id egress \
        --public-key "$public" --expected-generation 0 --label sentinel=native-upgrade
    printf '%s\n' "$public" > "$state/native-enrollment.fixture"
    chmod 0600 "$state/native-enrollment.fixture"
    ready
fi
before=$(cat "/var/run/pathchord/pathchord_${role}d.pid")
pkg add -f "$newer"
# Package scripts run under pkg's process reaper. Recover the service only
# after the package operation has completely returned to the package host.
service "$name" onestart
ready
[ "$(cat "/var/run/pathchord/pathchord_${role}d.pid")" != "$before" ]
verify_state
before=$(cat "/var/run/pathchord/pathchord_${role}d.pid")
pkg add -f "$older"
service "$name" onestart
ready
[ "$(cat "/var/run/pathchord/pathchord_${role}d.pid")" != "$before" ]
verify_state
service "$name" onestop
[ ! -S "/var/run/pathchord/$role.sock" ]
if [ "$role" = egress ]; then
    sha256 "$state/egress.key.json" "$state/authorizations.db" > /tmp/pathchord-actual-egress.sha256
fi
service "$name" onestart
ready
pkg delete "$name"
[ ! -S "/var/run/pathchord/$role.sock" ]
verify_state
pkg add "$opposite"
[ -x "/usr/local/bin/$other_name" ]
[ ! -e "/usr/local/bin/$name" ]
verify_state
pkg delete "$other_name"
printf '%s\n' "$role: native payload/conflict/account/control/active upgrade/rollback/stop/removal/replacement passed"
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, help='FreeBSD x86_64 role artifacts')
    parser.add_argument('--artifacts', type=Path, help='reuse native role packages from a previous build')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--strip', default='llvm-strip', help='host tool used on fixture copies only')
    args = parser.parse_args()
    if not args.bin_dir and not args.artifacts:
        parser.error('supply --bin-dir or --artifacts')
    QEMU_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='freebsd-package-input-', dir=QEMU_ROOT) as temporary:
        temporary = Path(temporary)
        bins = temporary / 'bins'
        bins.mkdir()
        if args.bin_dir:
            for name in ('pathchord-ingressd', 'pathchord-egressd', 'pathchordctl'):
                subprocess.run([args.strip, '--strip-debug', '-o', str(bins / name), str(args.bin_dir / name)], check=True)
                (bins / name).chmod(0o755)
        archive = temporary / 'inputs.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name in ('packaging', 'LICENSE', 'Cargo.toml'):
                tar.add(ROOT / name, arcname=name)
            tar.add(bins, arcname='bins')
            if args.artifacts:
                tar.add(args.artifacts, arcname='out')
        with FreeBsdLab(args.output or new_run_directory('freebsd-packages')) as lab:
            guest = lab.guest
            def run(label, command, timeout=240):
                preflight_failures = []
                for attempt in range(3):
                    result = guest.ssh(command, check=False, timeout=timeout)
                    if result.returncode == 255 and 'during banner exchange' in result.stderr and attempt < 2:
                        preflight_failures.append(result.stderr)
                        time.sleep(0.5)
                        continue
                    break
                logfile = lab.directory / (label + '.log')
                logfile.write_text(''.join(preflight_failures) + result.stdout + result.stderr)
                if result.returncode:
                    raise RuntimeError(f'{label} failed; see {logfile}\n' + result.stdout[-2000:] + result.stderr[-2000:])
                print(label + ': passed', flush=True)
                return result.stdout
            guest.put(archive, '/tmp/inputs.tar.gz')
            run('prepare', 'env ASSUME_ALWAYS_YES=yes pkg bootstrap; mkdir -p /tmp/package-lab; '
                'tar -xzf /tmp/inputs.tar.gz -C /tmp/package-lab; pkg -v; freebsd-version -ku', timeout=600)
            if not args.artifacts:
                for role in ('ingress', 'egress'):
                    for version in ('0.1.0', '0.1.1'):
                        command = (f'COMPRESSION_LEVEL=1 COMPRESSION_THREADS=1 PATHCHORD_ROLE={role} PATHCHORD_VERSION={version} '
                                   f'PATHCHORD_DAEMON_BINARY=/tmp/package-lab/bins/pathchord-{role}d '
                                   'PATHCHORDCTL_BINARY=/tmp/package-lab/bins/pathchordctl '
                                   'sh /tmp/package-lab/packaging/freebsd/build.sh /tmp/package-lab/out')
                        run(f'build-{role}-{version}', command)
            run('archive-artifacts', 'tar -czf /tmp/package-artifacts.tar.gz -C /tmp/package-lab/out .')
            bundle = lab.directory / 'package-artifacts.tar.gz'
            with bundle.open('wb') as target:
                subprocess.run(['ssh', '-i', str(lab.directory / 'identity'), '-p', str(guest.port),
                                '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'LogLevel=ERROR',
                                '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                                'root@127.0.0.1', 'cat /tmp/package-artifacts.tar.gz'], stdout=target, check=True)
            artifacts = lab.directory / 'artifacts'
            artifacts.mkdir()
            with tarfile.open(bundle) as tar:
                tar.extractall(artifacts, filter='data')
            script = temporary / 'lifecycle.sh'
            script.write_text(SCRIPT)
            guest.put(script, '/tmp/lifecycle.sh')
            for role in ('ingress', 'egress'):
                run(role + '-lifecycle', 'sh /tmp/lifecycle.sh ' + role)
            metadata = json.loads((lab.directory / 'topology.json').read_text())
            metadata['package_host'] = run('inventory', 'pkg -v; freebsd-version -ku; sha256 /tmp/package-lab/out/*.pkg').splitlines()
            metadata['validation'] = ['native pkg build for both role profiles', 'selected payload and opposite-role rejection',
                                      'local non-login account and private roots', 'rc.d start/owner control/active upgrade/rollback/stop',
                                      'uninstall and explicit replacement preserve private state',
                                      'opposite-role rejection preserves running service PID',
                                      'real enrollment survives upgrade and rollback',
                                      'actual Egress identity and SQLite hashes survive uninstall and replacement']
            with archive.open('rb') as data:
                metadata['input_archive_sha256'] = hashlib.file_digest(data, 'sha256').hexdigest()
            (lab.directory / 'package-evidence.json').write_text(json.dumps(metadata, indent=2) + '\n')
            print(lab.directory / 'package-evidence.json')


if __name__ == '__main__':
    main()
