#!/usr/bin/env python3
"""Boot a disposable native systemd package host using systemd-nspawn.

Only the exported image filesystem is installed or changed. The guest has a
private PID/mount/network namespace, no host mounts and no external network.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def descendants(pid):
    try:
        children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
    except FileNotFoundError:
        return []
    result = []
    for child in children:
        child = int(child)
        result.append(child)
        result.extend(descendants(child))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--role', choices=('ingress', 'egress'), required=True)
    parser.add_argument('--opposite', type=Path, required=True)
    parser.add_argument('--older', type=Path, required=True)
    parser.add_argument('--newer', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rootfs = output / 'rootfs'
    rootfs.mkdir()
    name = 'pathchord-package-' + uuid.uuid4().hex[:10]
    container = run(['docker', 'create', '--name', name, args.image], capture_output=True).stdout.strip()
    archive = output / 'rootfs.tar'
    process = None
    console = (output / 'systemd-console.log').open('w')
    init = None
    try:
        run(['docker', 'export', '--output', str(archive), container])
        run(['sudo', '-n', 'bsdtar', '-xf', str(archive), '-C', str(rootfs)])
        run(['sudo', '-n', 'chown', 'root:root', str(rootfs)])
        archive.unlink()
        fixture = rootfs / 'opt/pathchord-package-fixture'
        run(['sudo', '-n', 'mkdir', '-p', str(fixture)])
        for source in (args.older, args.newer, args.opposite, ROOT / 'scripts/test-linux-package-lifecycle.sh', ROOT / 'scripts/test-native-role-service.sh'):
            run(['sudo', '-n', 'cp', str(source.resolve()), str(fixture / source.name)])
        process = subprocess.Popen(['sudo', '-n', 'systemd-nspawn', '--quiet', '--boot', '--register=no',
                                    '--settings=no', '--private-network', '--machine', name,
                                    '--capability=CAP_BPF,CAP_PERFMON,CAP_NET_ADMIN,CAP_NET_RAW,CAP_NET_BIND_SERVICE',
                                    '--directory', str(rootfs)],
                                   stdin=subprocess.DEVNULL, stdout=console, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('systemd-nspawn exited; see systemd-console.log')
            for pid in descendants(process.pid):
                try:
                    if Path(f'/proc/{pid}/comm').read_text().strip() == 'systemd':
                        init = pid
                        break
                except FileNotFoundError:
                    pass
            if init:
                break
            time.sleep(0.1)
        if not init:
            raise RuntimeError('no isolated systemd init process; see console')

        def guest(label, command, timeout=120):
            enter = ['sudo', '-n', 'nsenter', '--target', str(init), '--mount', '--uts',
                     '--ipc', '--net', '--pid', '--cgroup', '--root', '--wd', '/bin/sh', '-ec']
            try:
                result = subprocess.run(enter + ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH; ' + command], capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired as error:
                text = lambda value: value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
                (output / (label + '.log')).write_text(text(error.stdout) + text(error.stderr))
                diagnostic = subprocess.run(enter + ['systemctl list-jobs --no-pager; systemctl --failed --no-pager; journalctl -u pathchord-ingressd -u pathchord-egressd --no-pager -n 50'],
                                            capture_output=True, text=True, timeout=15)
                (output / (label + '-diagnostic.log')).write_text(diagnostic.stdout + diagnostic.stderr)
                raise
            (output / (label + '.log')).write_text(result.stdout + result.stderr)
            if result.returncode:
                diagnostic = subprocess.run(enter + ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH; systemctl --failed --no-pager; journalctl -u pathchord-ingressd -u pathchord-egressd --no-pager -n 60'],
                                            capture_output=True, text=True, timeout=15)
                (output / (label + '-diagnostic.log')).write_text(diagnostic.stdout + diagnostic.stderr)
                raise RuntimeError(f'{label} failed; see {output / (label + ".log")}\n' + result.stdout[-1500:] + result.stderr[-1500:])
            print(label + ': passed', flush=True)
            return result.stdout
        guest('boot', 'for attempt in $(seq 1 200); do state=$(systemctl is-system-running 2>/dev/null || true); case "$state" in running|degraded) exit 0;; esac; sleep 0.1; done; systemctl --failed; exit 1')
        guest('prepare-host', 'systemctl mask --runtime systemd-networkd-wait-online.service NetworkManager-wait-online.service; systemctl start network-online.target')
        fixture = '/opt/pathchord-package-fixture/'
        arguments = ' '.join(shlex.quote(value) for value in (args.role, fixture + args.older.name,
                                                               fixture + args.newer.name, fixture + args.opposite.name))
        guest('lifecycle', 'rm -f /usr/sbin/policy-rc.d; PATHCHORD_DISPOSABLE_PACKAGE_HOST=1 sh ' +
              fixture + 'test-linux-package-lifecycle.sh ' + arguments)
        guest('services', 'PATHCHORD_DISPOSABLE_PACKAGE_HOST=1 sh ' + fixture +
              'test-native-role-service.sh ' + arguments)
        metadata = {
            'image': args.image, 'role': args.role,
            'host': guest('inventory', 'cat /etc/os-release; systemctl --version; uname -srmo').splitlines(),
            'revision': run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True).stdout.strip(),
            'artifact_sha256': guest('artifact-hashes', 'sha256sum ' + ' '.join(
                shlex.quote(fixture + path.name) for path in (args.older, args.newer, args.opposite))).splitlines(),
            'validation': ['native package lifecycle', 'native systemd start/control/upgrade/rollback/stop',
                           'single-role payload and opposite-role rejection', 'shared local service account',
                           'private devices and role-specific capability sets'] +
                          (['privileged Path listener', 'enrolled authorization survives upgrade/rollback']
                           if args.role == 'egress' else []),
        }
        (output / 'package-evidence.json').write_text(json.dumps(metadata, indent=2) + '\n')
        guest('shutdown', 'systemctl poweroff', timeout=30)
    finally:
        if process is not None and process.poll() is None:
            subprocess.run(['sudo', '-n', 'kill', '-s', 'RTMIN+4', str(init)] if init else ['sudo', '-n', 'kill', '-TERM', str(process.pid)], check=False)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                for pid in list(reversed(descendants(process.pid))) + [process.pid]:
                    subprocess.run(['sudo', '-n', 'kill', '-KILL', str(pid)], check=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                process.wait(timeout=20)
        console.close()
        subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rootfs.is_dir():
            run(['sudo', '-n', 'rm', '-rf', str(rootfs)])
        archive.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
