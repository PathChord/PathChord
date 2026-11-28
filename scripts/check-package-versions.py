#!/usr/bin/env python3
"""Exercise package version resolution from a checkout and standalone source recipes."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def check(command, directory, expected, **environment):
    env = dict(os.environ, PATHCHORD_VERSION='', PATHCHORD_ROLE='ingress')
    env.pop('VERSION', None)
    env.update(environment)
    result = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True)
    if expected is None:
        if result.returncode == 0:
            raise AssertionError(f'{command} accepted an invalid or missing version')
    elif result.returncode or result.stdout.strip() != expected:
        raise AssertionError(f'{command}: {result.stdout}{result.stderr}')


def main():
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        checkout = directory / 'checkout with spaces'
        packaging = checkout / 'packaging'
        shutil.copytree(ROOT / 'packaging', packaging)
        manifest = checkout / 'Cargo.toml'
        commands = [[packaging / 'version.sh'], ['make', '-s', '-C', packaging, 'version']]
        if shutil.which('pwsh'):
            commands.append(['pwsh', '-NoProfile', '-File', packaging / 'windows/version.ps1'])
        for quote in ('"', "'"):
            manifest.write_text(
                '[package]\nversion = "8.0.0"\n[workspace.package] # release\n'
                f'version = {quote}2.3.4{quote} # workspace version\n'
            )
            for command in commands:
                check(command, directory, '2.3.4')
                check(command, directory, '4.5.6', PATHCHORD_VERSION='4.5.6')
                check(command, directory, None, PATHCHORD_VERSION='../invalid')
        check(['make', '-s', '-C', packaging, 'version', 'VERSION=5.6.7'], directory,
              '5.6.7', PATHCHORD_VERSION='4.5.6')

        for recipe, shell in [('arch/PKGBUILD', 'bash'), ('alpine/APKBUILD', 'sh')]:
            for location in (packaging / recipe, directory / Path(recipe).name):
                standalone = location.parent == directory
                if standalone:
                    shutil.copyfile(packaging / recipe, location)
                command = [shell, '-ec', '. "$1"; printf "%s %s\\n" "$pkgver" "$pkgname"', shell, location]
                for role in ('ingress', 'egress'):
                    env = dict(APKBUILD=str(location), PATHCHORD_ROLE=role)
                    check(command, directory, None if standalone else f'2.3.4 pathchord-{role}d', **env)
                    check(command, directory, f'4.5.6 pathchord-{role}d', PATHCHORD_VERSION='4.5.6', **env)
                    check(command, directory, None, PATHCHORD_VERSION='../invalid', **env)


if __name__ == '__main__':
    main()
