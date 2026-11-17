#!/usr/bin/env python3
"""Build both role APK profiles and test each on its own disposable native host."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile

from qemu_lab import Lab, QEMU_ROOT, ROOT, new_run_directory


def download(guest, source, destination):
    with destination.open('wb') as output:
        subprocess.run(['ssh', '-i', str(guest.lab.directory / 'identity'), '-p', str(guest.port),
                        '-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', '-o', 'StrictHostKeyChecking=no',
                        '-o', 'UserKnownHostsFile=/dev/null', 'root@127.0.0.1',
                        'cat ' + shlex.quote(source)], stdout=output, check=True, timeout=120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, help='current x86_64 musl role binaries')
    parser.add_argument('--artifacts', type=Path, help='reuse signed role APKs and their public key from a prior run')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--apk-address', default='146.75.114.132',
                        help='guest-only CDN address; TLS hostname verification remains enabled')
    args = parser.parse_args()
    if not args.bin_dir and not args.artifacts:
        parser.error('supply --bin-dir or --artifacts')
    output = args.output or new_run_directory('alpine-packages')
    QEMU_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='pathchord-apk-input-', dir=QEMU_ROOT) as temporary:
        archive = Path(temporary) / 'inputs.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name in ('packaging', 'LICENSE', 'Cargo.toml'):
                tar.add(ROOT / name, arcname=name)
            for name in ('test-linux-package-lifecycle.sh', 'test-native-role-service.sh'):
                tar.add(ROOT / 'scripts' / name, arcname=name)
            if args.bin_dir:
                for name in ('pathchord-ingressd', 'pathchord-egressd', 'pathchordctl'):
                    tar.add(args.bin_dir / name, arcname='bins/' + name)
            if args.artifacts:
                tar.add(args.artifacts, arcname='out')
        with Lab(output=output) as lab:
            def run(guest, label, command, timeout=240):
                result = guest.ssh(command, check=False, timeout=timeout)
                logfile = lab.directory / (label + '.log')
                logfile.write_text(result.stdout + result.stderr)
                if result.returncode:
                    raise RuntimeError(f'{label} failed; see {logfile}\n' + result.stdout[-1800:] + result.stderr[-1800:])
                print(label + ': passed', flush=True)
                return result.stdout
            builder = lab.server
            builder.put(archive, '/tmp/inputs.tar.gz')
            if args.artifacts:
                run(builder, 'prepare-reused-artifacts', 'mkdir -p /tmp/package-lab; '
                    'tar -xzf /tmp/inputs.tar.gz -C /tmp/package-lab; '
                    'cp /tmp/package-lab/out/*.pub /etc/apk/keys/; '
                    'tar -czf /tmp/artifacts.tar.gz -C /tmp/package-lab/out .')
            else:
                run(builder, 'prepare-builder', 'printf "\\n' + args.apk_address + ' dl-cdn.alpinelinux.org\\n" >> /etc/hosts; '
                    'chmod 1777 /tmp; apk add --no-cache abuild fakeroot tar xz; '
                    'adduser -D packager; addgroup packager abuild; '
                    'mkdir -p /tmp/package-lab; tar -xzf /tmp/inputs.tar.gz -C /tmp/package-lab; '
                    'rm /tmp/inputs.tar.gz; chown -R packager:packager /tmp/package-lab; '
                    "su -s /bin/sh - packager -c 'abuild-keygen -a -n'; "
                    'cp /home/packager/.abuild/*.pub /etc/apk/keys/')
                for role in ('ingress', 'egress'):
                    for version in ('0.1.0', '0.1.1'):
                        command = (f'PATHCHORD_ROLE={role} PATHCHORD_VERSION={version} '
                                   f'PATHCHORD_DAEMON_BINARY=/tmp/package-lab/bins/pathchord-{role}d '
                                   'PATHCHORDCTL_BINARY=/tmp/package-lab/bins/pathchordctl '
                                   'sh /tmp/package-lab/packaging/alpine/build.sh /tmp/package-lab/out')
                        run(builder, f'build-{role}-{version}', 'su -s /bin/sh - packager -c ' + shlex.quote(command))
                run(builder, 'artifact-inventory', 'cp /home/packager/.abuild/*.pub /tmp/package-lab/out/; '
                    'tar -czf /tmp/artifacts.tar.gz -C /tmp/package-lab/out .; '
                    'sha256sum /tmp/package-lab/out/*.apk; apk info -v abuild apk-tools openrc')
            artifacts = lab.directory / 'artifacts'
            artifacts.mkdir()
            bundle = lab.directory / 'artifacts.tar.gz'
            download(builder, '/tmp/artifacts.tar.gz', bundle)
            with tarfile.open(bundle) as tar:
                tar.extractall(artifacts, filter='data')
            client = lab.client
            client.put(archive, '/tmp/inputs.tar.gz')
            client.put(bundle, '/tmp/artifacts.tar.gz')
            run(client, 'prepare-second-host', 'mkdir -p /tmp/package-lab/out; '
                'tar -xzf /tmp/inputs.tar.gz -C /tmp/package-lab; '
                'tar -xzf /tmp/artifacts.tar.gz -C /tmp/package-lab/out; '
                'cp /tmp/package-lab/out/*.pub /etc/apk/keys/; chmod 1777 /tmp')
            results = {}
            for role, guest in (('ingress', builder), ('egress', client)):
                other = 'egress' if role == 'ingress' else 'ingress'
                arguments = (f'{role} /tmp/package-lab/out/pathchord-{role}d-0.1.0-r0.apk '
                             f'/tmp/package-lab/out/pathchord-{role}d-0.1.1-r0.apk '
                             f'/tmp/package-lab/out/pathchord-{other}d-0.1.0-r0.apk')
                run(guest, role + '-lifecycle', 'PATHCHORD_DISPOSABLE_PACKAGE_HOST=1 sh '
                    '/tmp/package-lab/test-linux-package-lifecycle.sh ' + arguments)
                run(guest, role + '-services', 'PATHCHORD_DISPOSABLE_PACKAGE_HOST=1 sh '
                    '/tmp/package-lab/test-native-role-service.sh ' + arguments)
                results[role] = run(guest, role + '-inventory', 'uname -srmo; cat /etc/alpine-release; '
                                    'apk info -v apk-tools openrc; id pathchord').splitlines()
            metadata = json.loads((lab.directory / 'topology.json').read_text())
            metadata['roles'] = results
            with archive.open('rb') as data:
                metadata['input_archive_sha256'] = hashlib.file_digest(data, 'sha256').hexdigest()
            metadata['artifacts'] = {}
            for artifact in sorted(artifacts.glob('*.apk')):
                with artifact.open('rb') as data:
                    metadata['artifacts'][artifact.name] = hashlib.file_digest(data, 'sha256').hexdigest()
            metadata['validation'] = ['both signed APK role profiles' if args.artifacts else 'both native signed APK role profiles', 'selected payload and opposite-role conflict',
                                      'shared local account and private roots', 'upgrade/rollback/removal and explicit role replacement',
                                      'OpenRC start/owner control/active upgrade/rollback/stop']
            (lab.directory / 'package-evidence.json').write_text(json.dumps(metadata, indent=2) + '\n')
            print('Alpine evidence: ' + str(lab.directory / 'package-evidence.json'))


if __name__ == '__main__':
    main()
