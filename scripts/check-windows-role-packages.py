#!/usr/bin/env python3
"""Compile both NSIS branches with synthetic PE inputs and inspect their payloads.

This is a packaging syntax/inventory check. It does not execute Windows services
or validate production binaries. Native Windows acceptance remains separate.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='pathchord-nsis-check-') as temporary:
        output = arguments.output.resolve() if arguments.output else Path(temporary)
        output.mkdir(parents=True, exist_ok=True)
        source = output / 'fixture.c'
        source.write_text('int main(void) { return 0; }\n')
        fixture = output / 'fixture.exe'
        subprocess.run(['x86_64-w64-mingw32-gcc', '-Os', str(source), '-o', str(fixture)], check=True)
        for role in ('ingress', 'egress'):
            other = 'egress' if role == 'ingress' else 'ingress'
            installer = output / (role + '-syntax-fixture.exe')
            command = ['makensis', '-WX', '-V2', '-DAPP_ROLE=' + role, '-DAPP_VERSION=0.1.0',
                       '-DDAEMON_BINARY_PATH=' + str(fixture), '-DCTL_BINARY_PATH=' + str(fixture),
                       '-DOUTPUT_PATH=' + str(installer), str(ROOT / 'packaging/windows/pathchord.nsi')]
            compiled = subprocess.run(command, check=True, capture_output=True, text=True)
            (output / (role + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
            listing = subprocess.check_output(['7z', 'l', str(installer)], text=True)
            (output / (role + '-inventory.txt')).write_text(listing)
            for required in (f'pathchord-{role}d.exe', f'pathchord-{role}d.xml', f'{role}.yaml', 'pathchordctl.exe'):
                if required not in listing:
                    raise AssertionError('missing selected payload: ' + required)
            for forbidden in (f'pathchord-{other}d.exe', f'pathchord-{other}d.xml', f'{other}.yaml'):
                if forbidden in listing:
                    raise AssertionError('opposite-role payload: ' + forbidden)
            print(role + ': NSIS syntax and payload branch passed with synthetic PE inputs')
        missing = subprocess.run(['makensis', '-V2', '-DDAEMON_BINARY_PATH=' + str(fixture),
                                  '-DCTL_BINARY_PATH=' + str(fixture),
                                  str(ROOT / 'packaging/windows/pathchord.nsi')], capture_output=True, text=True)
        if missing.returncode == 0:
            raise AssertionError('NSIS accepted an omitted role')


if __name__ == '__main__':
    main()
