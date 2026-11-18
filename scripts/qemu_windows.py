#!/usr/bin/env python3
"""Install and manage an isolated Windows validation guest entirely under /data.

The installation ISO is read-only. Disks, firmware, TPM state, credentials,
seed media and logs are private files under the selected /data directory.
No host shares, bridges or host route changes are required.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import time
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ROOT = Path('/data/pathchord-qemu/windows/base')
FIRMWARE = Path('/usr/share/edk2/x64')


def run(command, **kwargs):
    return subprocess.run([str(value) for value in command], check=True, **kwargs)


def directory(path):
    result = Path(path).expanduser().resolve()
    if not result.is_relative_to('/data'):
        raise ValueError('Windows VM state and output must be under /data')
    result.mkdir(parents=True, exist_ok=True)
    result.chmod(0o700)
    return result


def read_state(root):
    return json.loads((root / 'guest.json').read_text())


def write_state(root, state):
    (root / 'guest.json').write_text(json.dumps(state, indent=2) + '\n')


def prepare(args):
    root = directory(args.root)
    iso = args.iso.expanduser().resolve(strict=True)
    openssh = args.openssh.expanduser().resolve(strict=True)
    if (root / 'guest.json').exists() or (root / 'disk.qcow2').exists():
        raise FileExistsError('Guest already prepared; use start or a new /data directory')
    seed = directory(root / 'seed')
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', root / 'identity'])
    shutil.copyfile(root / 'identity.pub', seed / 'authorized_keys')
    shutil.copyfile(openssh, seed / 'OpenSSH-Win64.zip')
    shutil.copyfile(ROOT / 'scripts/windows-bootstrap.ps1', seed / 'bootstrap.ps1')
    password = (args.password_file.read_text().strip()
                if args.password_file else 'Pc!' + secrets.token_urlsafe(24))
    if not password:
        raise ValueError('The local lab account requires a nonempty password')
    account = {'username': 'pcadmin', 'password': password}
    (root / 'account.json').write_text(json.dumps(account) + '\n')
    (root / 'account.json').chmod(0o600)
    component = ('processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" '
                 'language="neutral" versionScope="nonSxS"')
    command = ("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
               '"$v=(Get-CimInstance Win32_LogicalDisk | Where-Object VolumeName -eq '
               "'PCSEED').DeviceID; &amp; ($v+'\\bootstrap.ps1')\"")
    answer = fr'''<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
<settings pass="windowsPE">
  <component name="Microsoft-Windows-International-Core-WinPE" {component}>
    <SetupUILanguage><UILanguage>zh-CN</UILanguage></SetupUILanguage>
    <InputLocale>0409:00000409</InputLocale><SystemLocale>zh-CN</SystemLocale><UILanguage>zh-CN</UILanguage><UserLocale>en-US</UserLocale>
  </component>
  <component name="Microsoft-Windows-Setup" {component}>
    <DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
      <CreatePartitions>
        <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
        <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
        <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
      </CreatePartitions>
      <ModifyPartitions>
        <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Label>System</Label><Format>FAT32</Format></ModifyPartition>
        <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Label>Windows</Label><Letter>C</Letter><Format>NTFS</Format></ModifyPartition>
      </ModifyPartitions>
    </Disk><WillShowUI>OnError</WillShowUI></DiskConfiguration>
    <ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>{args.index}</Value></MetaData></InstallFrom><InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo><WillShowUI>OnError</WillShowUI></OSImage></ImageInstall>
    <UserData><AcceptEula>true</AcceptEula><FullName>PathChord Lab</FullName><Organization>PathChord</Organization><ProductKey><Key>VK7JG-NPHTM-C97JM-9MPGT-3V66T</Key><WillShowUI>Never</WillShowUI></ProductKey></UserData>
    <DynamicUpdate><Enable>false</Enable><WillShowUI>Never</WillShowUI></DynamicUpdate>
  </component>
</settings>
<settings pass="specialize">
  <component name="Microsoft-Windows-Shell-Setup" {component}><ComputerName>PC-WIN11</ComputerName><TimeZone>China Standard Time</TimeZone></component>
</settings>
<settings pass="oobeSystem">
  <component name="Microsoft-Windows-International-Core" {component}><InputLocale>0409:00000409</InputLocale><SystemLocale>zh-CN</SystemLocale><UILanguage>zh-CN</UILanguage><UserLocale>en-US</UserLocale></component>
  <component name="Microsoft-Windows-Shell-Setup" {component}>
    <OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
    <UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>pcadmin</Name><DisplayName>PathChord Lab</DisplayName><Group>Administrators</Group><Password><Value>{escape(password)}</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>
    <AutoLogon><Username>pcadmin</Username><Password><Value>{escape(password)}</Value><PlainText>true</PlainText></Password><Enabled>true</Enabled><LogonCount>1</LogonCount></AutoLogon>
    <FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><Description>Initialize isolated test management</Description><CommandLine>{command}</CommandLine><RequiresUserInput>false</RequiresUserInput></SynchronousCommand></FirstLogonCommands>
  </component>
</settings></unattend>
'''
    (seed / 'Autounattend.xml').write_text(answer)
    (seed / 'Autounattend.xml').chmod(0o600)
    run(['xorriso', '-as', 'mkisofs', '-quiet', '-V', 'PCSEED', '-J', '-r',
         '-o', root / 'seed.iso', seed], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / 'seed.iso').chmod(0o600)
    run(['qemu-img', 'create', '-q', '-f', 'qcow2', root / 'disk.qcow2', args.disk_size])
    shutil.copyfile(FIRMWARE / 'OVMF_VARS.4m.fd', root / 'OVMF_VARS.fd')
    # Microsoft Windows Secure Boot keys are required by the Windows 11 installer.
    run(['virt-fw-vars', '-i', root / 'OVMF_VARS.fd', '--enroll-microsoft', '--microsoft-db', 'win11', '--secure-boot', '-o', root / 'OVMF_VARS.secure.fd'])
    shutil.move(root / 'OVMF_VARS.secure.fd', root / 'OVMF_VARS.fd')
    directory(root / 'tpm')
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        ssh_port = server.getsockname()[1]
    state = {'iso': str(iso), 'index': args.index, 'memory_mib': args.memory,
             'cpus': args.cpus, 'ssh_port': ssh_port, 'username': 'pcadmin',
             'disk': str(root / 'disk.qcow2'), 'installed': False,
             'management': 'loopback-only SSH, QMP and VNC; restricted QEMU user network',
             'firmware': str(FIRMWARE / 'OVMF_CODE.secboot.4m.fd')}
    write_state(root, state)
    print(json.dumps({'prepared': str(root), 'ssh_port': ssh_port, 'disk': state['disk']}))


def alive(root):
    try:
        pid = int((root / 'qemu.pid').read_text())
        command = Path(f'/proc/{pid}/cmdline').read_bytes()
        return b'qemu-system' in command and str(root / 'qmp.sock').encode() in command
    except (OSError, ValueError):
        return False


def start(args):
    root = directory(args.root)
    if alive(root):
        raise RuntimeError('This Windows guest is already running')
    state = read_state(root)
    (root / 'qmp.sock').unlink(missing_ok=True)
    (root / 'tpm.sock').unlink(missing_ok=True)
    run(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={root / "tpm"}',
         '--ctrl', f'type=unixio,path={root / "tpm.sock"},terminate',
         '--log', f'file={root / "tpm.log"}', '--pid', f'file={root / "tpm.pid"}', '--daemon'])
    command = [
        'qemu-system-x86_64', '-name', 'pathchord-windows-validation',
        '-machine', 'q35,accel=kvm', '-cpu', 'host', '-m', str(state['memory_mib']),
        '-smp', str(state['cpus']), '-nodefaults', '-device', 'VGA',
        '-device', 'qemu-xhci', '-device', 'usb-kbd', '-device', 'usb-tablet',
        '-drive', f'if=pflash,format=raw,readonly=on,file={state["firmware"]}',
        '-drive', f'if=pflash,format=raw,file={root / "OVMF_VARS.fd"}',
        '-chardev', f'socket,id=chrtpm,path={root / "tpm.sock"}',
        '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm', '-device', 'tpm-crb,tpmdev=tpm0',
        '-drive', f'file={state["disk"]},format=qcow2,if=none,id=disk,cache=writeback,discard=unmap',
        '-device', 'ide-hd,drive=disk,bus=ide.0',
        '-netdev', f'user,id=management,restrict=on,hostfwd=tcp:127.0.0.1:{state["ssh_port"]}-:22',
        '-device', 'e1000e,netdev=management', '-rtc', 'base=localtime',
        '-display', 'none', '-vnc', f'unix:{root / "vnc.sock"}',
        '-qmp', f'unix:{root / "qmp.sock"},server=on,wait=off',
        '-serial', f'file:{root / "serial.log"}', '-monitor', 'none',
        '-daemonize', '-pidfile', str(root / 'qemu.pid'),
    ]
    if not state['installed']:
        command += ['-drive', f'file={state["iso"]},media=cdrom,readonly=on,if=none,id=install',
                    '-device', 'ide-cd,drive=install,bus=ide.1,bootindex=1',
                    '-drive', f'file={root / "seed.iso"},media=cdrom,readonly=on,if=none,id=seed',
                    '-device', 'ide-cd,drive=seed,bus=ide.2', '-boot', 'once=d,menu=off']
    elif state.get('fixture_iso'):
        fixture = Path(state['fixture_iso']).resolve(strict=True)
        if not fixture.is_relative_to('/data'):
            raise ValueError('Test fixture media must be under /data')
        command += ['-drive', f'file={fixture},media=cdrom,readonly=on,if=none,id=fixtures',
                    '-device', 'ide-cd,drive=fixtures,bus=ide.1']
    (root / 'qemu-command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (root / 'qemu.log').open('a') as log:
        run(command, stdout=log, stderr=subprocess.STDOUT)
    if not state['installed']:
        # The Windows DVD's UEFI loader asks for a key before Setup starts.
        for _ in range(30):
            time.sleep(1)
            qmp(root, 'human-monitor-command', {'command-line': 'sendkey spc'})
    print(json.dumps({'running': alive(root), 'root': str(root), 'ssh_port': state['ssh_port']}))


def clone(args):
    source = Path(args.root).expanduser().resolve(strict=True)
    if not source.is_relative_to('/data'):
        raise ValueError('Windows VM state and output must be under /data')
    state = read_state(source)
    if alive(source) or not state['installed']:
        raise RuntimeError('Clone only a shut down, initialized Windows baseline')
    # An initialized disk without its private management identity is not a
    # reusable managed baseline. Validate before creating the overlay or
    # touching either directory so failed clones leave no partial VM state.
    for name in ('OVMF_VARS.fd', 'identity', 'identity.pub', 'account.json'):
        if not (source / name).is_file():
            raise RuntimeError(f'Windows baseline is missing required management state: {name}')
    disk = Path(state['disk']).resolve(strict=True)
    if not disk.is_relative_to('/data'):
        raise ValueError('Windows VM disks must be under /data')
    if not (source / 'tpm').is_dir():
        raise RuntimeError('Windows baseline is missing required TPM state')
    destination = Path(args.output).expanduser().resolve()
    if not destination.is_relative_to('/data'):
        raise ValueError('Windows VM state and output must be under /data')
    if (destination / 'guest.json').exists() or (destination / 'disk.qcow2').exists():
        raise FileExistsError('Destination guest already exists')
    destination = directory(destination)
    run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2',
         '-b', disk, destination / 'disk.qcow2'])
    for name in ('OVMF_VARS.fd', 'identity', 'identity.pub', 'account.json'):
        shutil.copy2(source / name, destination / name)
    shutil.copytree(source / 'tpm', destination / 'tpm', ignore=shutil.ignore_patterns('*.lock'))
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        state['ssh_port'] = server.getsockname()[1]
    state['disk'] = str(destination / 'disk.qcow2')
    state['baseline'] = str(source)
    if args.memory:
        state['memory_mib'] = args.memory
    if args.cpus:
        state['cpus'] = args.cpus
    write_state(destination, state)
    print(json.dumps({'overlay': state['disk'], 'ssh_port': state['ssh_port']}))


def qmp(root, command, arguments=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(str(root / 'qmp.sock'))
        file = client.makefile('rwb', buffering=0)
        json.loads(file.readline())
        for index, (execute, params) in enumerate((('qmp_capabilities', {}), (command, arguments or {}))):
            file.write((json.dumps({'execute': execute, 'arguments': params, 'id': index}) + '\n').encode())
            while True:
                response = json.loads(file.readline())
                if response.get('id') == index:
                    if 'error' in response:
                        raise RuntimeError(response['error'])
                    break
        return response['return']


def ssh_arguments(root):
    state = read_state(root)
    if not (root / 'identity').is_file():
        raise RuntimeError('Guest management identity was cleaned up; use a freshly prepared guest for SSH')
    return ['-F', '/dev/null', '-i', str(root / 'identity'),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', f'UserKnownHostsFile={root / "known_hosts"}', '-o', 'LogLevel=ERROR'], state


def powershell(root, command, **kwargs):
    options, state = ssh_arguments(root)
    command = ("$ProgressPreference='SilentlyContinue'; "
               "[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); " + command)
    encoded = base64.b64encode(command.encode('utf-16le')).decode()
    # sshd inherits the Simplified Chinese console code page by default.
    if kwargs.get('capture_output') or kwargs.get('stdout') == subprocess.PIPE:
        kwargs.setdefault('encoding', 'utf-8')
        kwargs.setdefault('errors', 'replace')
    return run(['ssh', *options, '-p', state['ssh_port'],
                f'{state["username"]}@127.0.0.1',
                f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}'], **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    actions = parser.add_subparsers(dest='action', required=True)
    setup = actions.add_parser('prepare')
    setup.add_argument('--iso', type=Path, required=True)
    setup.add_argument('--openssh', type=Path, required=True)
    setup.add_argument('--index', type=int, default=3)
    setup.add_argument('--memory', type=int, default=8192)
    setup.add_argument('--cpus', type=int, default=4)
    setup.add_argument('--disk-size', default='80G')
    setup.add_argument('--password-file', type=Path, help='Private file containing the disposable local lab password')
    actions.add_parser('start')
    actions.add_parser('status')
    actions.add_parser('shutdown')
    actions.add_parser('installed')
    attach = actions.add_parser('attach')
    attach.add_argument('--iso', type=Path, required=True)
    snapshot = actions.add_parser('clone')
    snapshot.add_argument('--output', type=Path, required=True)
    snapshot.add_argument('--memory', type=int)
    snapshot.add_argument('--cpus', type=int)
    shot = actions.add_parser('screenshot')
    shot.add_argument('--output', type=Path)
    keys = actions.add_parser('key')
    keys.add_argument('keys', help='QEMU human-monitor key sequence')
    ps = actions.add_parser('ps')
    ps.add_argument('--command', required=True)
    ps.add_argument('--timeout', type=int, default=600)
    for name in ('put', 'get'):
        transfer = actions.add_parser(name)
        transfer.add_argument('source')
        transfer.add_argument('destination')
    args = parser.parse_args()
    root = directory(args.root)
    if args.action == 'prepare':
        prepare(args)
    elif args.action == 'start':
        start(args)
    elif args.action == 'clone':
        clone(args)
    elif args.action == 'attach':
        media = args.iso.resolve(strict=True)
        if not media.is_relative_to('/data'):
            raise ValueError('Test media must be under /data')
        qmp(root, 'blockdev-add', {'node-name': 'fixtures', 'driver': 'raw',
                                 'read-only': True, 'file': {'driver': 'file', 'filename': str(media)}})
        qmp(root, 'device_add', {'driver': 'usb-storage', 'drive': 'fixtures', 'id': 'fixtures'})
    elif args.action == 'status':
        print(json.dumps({'running': alive(root), **read_state(root)}))
    elif args.action == 'screenshot':
        output = args.output.resolve() if args.output else root / 'screen.ppm'
        if not output.is_relative_to('/data'):
            raise ValueError('VM output must be under /data')
        qmp(root, 'screendump', {'filename': str(output)})
        print(output)
    elif args.action == 'key':
        qmp(root, 'human-monitor-command', {'command-line': 'sendkey ' + args.keys})
    elif args.action == 'ps':
        powershell(root, args.command, timeout=args.timeout)
    elif args.action in ('put', 'get'):
        options, state = ssh_arguments(root)
        remote = f'{state["username"]}@127.0.0.1:'
        # OpenSSH SFTP expects forward slashes even for a native Windows path.
        # Keep host paths unchanged and normalize only the remote operand.
        source = args.source if args.action == 'put' else remote + args.source.replace('\\', '/')
        destination = (remote + args.destination.replace('\\', '/') if args.action == 'put'
                       else str(Path(args.destination).resolve()))
        if args.action == 'get' and not Path(destination).is_relative_to('/data'):
            raise ValueError('VM output must be under /data')
        run(['scp', *options, '-P', state['ssh_port'], source, destination], timeout=600)
    elif args.action == 'installed':
        powershell(root, "$ErrorActionPreference='Stop'; $ready=Get-Content -Raw -LiteralPath C:\\PathChordLab\\ready.json | ConvertFrom-Json; if (-not $ready.ready -or (Get-Service sshd).Status -ne 'Running') { throw 'Guest bootstrap is incomplete' }; $ready | ConvertTo-Json", timeout=30)
        state = read_state(root)
        state['installed'] = True
        write_state(root, state)
    elif args.action == 'shutdown':
        qmp(root, 'system_powerdown')
        print('Requested graceful guest shutdown')


if __name__ == '__main__':
    main()
