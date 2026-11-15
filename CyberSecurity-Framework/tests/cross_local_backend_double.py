#!/usr/bin/python3
"""Recording transport only; no network/privilege or host executable fallback.

Fresh argv receipts/programmed responses; sudo only runs a selected synthetic run
script via /bin/bash without elevation. Record BEFORE parsing/writing/launching.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import subprocess


def main():
    name = Path(sys.argv[0]).name
    argv = sys.argv[1:]
    with Path(os.environ['CROSS_LOCAL_LOG']).open('a') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(json.dumps([name, *argv]) + '\n')
        stream.flush()
    program = json.loads(os.environ.get('CROSS_LOCAL_RESPONSES', '{}'))
    response = program.get(name, {})
    if name in ('psexec.py', 'impacket-psexec'):
        # Synthetic parser boundary, NOT a real backend/import. Match the relevant
        # Impacket argparse grammar read as source: target, command nargs='*',
        # help/debug/Kerberos/connection/copy options. Raw argv above is not proof
        # that an option-looking command survived parsing; record parsed meaning.
        parser = argparse.ArgumentParser(add_help=True)
        parser.add_argument('target')
        parser.add_argument('command', nargs='*', default=' ')
        parser.add_argument('-debug', action='store_true')
        parser.add_argument('-k', action='store_true')
        parser.add_argument('-target-ip')
        parser.add_argument('-c')
        parsed = parser.parse_args(argv)
        with Path(os.environ['CROSS_LOCAL_PARSE_LOG']).open('a') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps({'backend': name, 'target': parsed.target,
                                     'command': parsed.command, 'debug': parsed.debug,
                                     'k': parsed.k, 'target_ip': parsed.target_ip,
                                     'copy': parsed.c}) + '\n')
            stream.flush()
    if name in ('curl', 'wget'):
        option = '-o' if name == 'curl' else '-O'
        if option in argv:
            path = Path(argv[argv.index(option) + 1])
            # Product selects NEW destination. Never clobber an unrelated object.
            with path.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(response.get('body', '#!/bin/bash\necho synthetic-linpeas\n').encode())
    if name == 'sudo':
        # Transport-only privilege removal: run the actual selected synthetic
        # script WITHOUT elevation. No arbitrary command/host binary fallback.
        if response.get('rc', 0):
            print(response.get('stderr', ''), end='', file=sys.stderr)
            return response['rc']
        command = list(argv)
        while command and command[0] in ('-n', '--'):
            command.pop(0)
        if command and command[0] in ('bash', '/bin/bash'):
            command.pop(0)
        if not command:
            return 126
        path = Path(command[0])
        root = Path(os.environ['CROSS_LOCAL_ROOT']) / 'scans/linpeas'
        if (not path.is_absolute() or path.is_symlink() or not path.is_file() or
                root not in path.resolve().parents):
            print('synthetic sudo refuses non-run selected script', file=sys.stderr)
            return 126
        return subprocess.run(['/bin/bash', str(path), *command[1:]], check=False).returncode
    elif name == 'nmap':
        # Genuine classifier requires the report header as well as a port row.
        # Explicit programmed stdout/rc still overrides this transport default.
        print(response.get('stdout', 'Nmap scan report for ' + argv[-1] +
                           '\n445/tcp open microsoft-ds\n| smb-os-discovery: synthetic'))
    elif name == 'rpcclient':
        print(response.get('stdout', 'user:[synthetic] rid:[0x1]'))
    elif name == 'smbclient':
        print(response.get('stdout', 'Sharename       Type\npublic          Disk\n  . D 0'))
    elif name == 'enum4linux':
        print(response.get('stdout', 'Domain Name: SYNTHETIC'))
    elif name == 'host':
        print(response.get('stdout', 'synthetic.example.test.'))
    else:
        print(response.get('stdout', ''), end='')
    print(response.get('stderr', ''), end='', file=sys.stderr)
    return response.get('rc', 0)


if __name__ == '__main__':
    sys.exit(main())
