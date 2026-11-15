"""Twelve upfront local contracts. STATIC NOT RUN; all remain pending RED.

No future business import during discovery. Real leaves run only in a verified
fresh worker fixture, including legacy self-rewriters; no host entrypoint.
"""
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import stat
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor

SMB = '04_Enumeration/smb/enum_smb.sh'
PSEXEC = '06_PostExploitation/lateral_movement/ps_exec.sh'
LINPEAS = '06_PostExploitation/privilege_escalation/linpeas.sh'
PING = '02_Recon/scripts/ping_sweep.sh'
KINDS = {'smb': SMB, 'psexec': PSEXEC, 'linpeas': LINPEAS}
LABS = {
    'htb': ('hackthebox', 'htb_setup.sh', 'machines'),
    'thm': ('tryhackme', 'thm_setup.sh', 'rooms'),
    'ad': ('active_directory', 'ad_setup.sh', 'machines'),
    'web': ('web_apps', 'web_setup.sh', 'machines'),
    'cloud': ('cloud', 'cloud_setup.sh', 'machines'),
}
SECTIONS = {
    'htb': ('IP', 'Puertos abiertos', 'Servicios', 'Hallazgos', 'Explotación', 'Post-explotación', 'Flags'),
    'thm': ('IP', 'Puertos', 'Hallazgos', 'Explotación', 'Flags'),
    'ad': ('Controladores de Dominio', 'Usuarios', 'Grupos', 'Hallazgos', 'Ataques', 'Flags'),
    'web': ('URL', 'Tecnologías', 'Hallazgos', 'Explotación', 'Flags'),
    'cloud': ('Proveedor', 'Recursos', 'Credenciales', 'Hallazgos', 'Explotación'),
}

# Independent cc79715 path inventory, NOT derived from current menu or fixture
# copy allowlist. Only names are inspected; protected loot bodies stay unread.
ORIGINAL_ENTRIES = {
    '04_Enumeration': (
        'api/enum_api.sh', 'database/enum_mysql.sh', 'database/enum_postgres.sh',
        'database/enum_redis.sh', 'ftp/enum_ftp.sh', 'ftp/ftp_anonymous.sh',
        'ldap/enum_ldap.sh', 'ldap/ldap_anonymous.sh', 'run_all_enum.sh',
        'show_results.sh', 'smb/enum_smb.sh', 'smb/enum_smb_advanced.sh',
        'ssh/enum_ssh.sh', 'web/deepseeenum_web.sh', 'web/enum_web.sh', 'web/enum_web_advanced.sh'),
    '06_PostExploitation': (
        'cleanup/logs_cleaner.sh', 'credential_access/history_parser.sh',
        'credential_access/linux_creds.sh', 'lateral_movement/port_forward.sh',
        'lateral_movement/ps_exec.sh', 'lateral_movement/ssh_jump.sh',
        'loot/file_collector.sh', 'loot/screenshot_collector.sh',
        'persistence/cron_persistence.sh', 'persistence/ssh_backdoor.sh',
        'privilege_escalation/capabilities_check.sh', 'privilege_escalation/cron_check.sh',
        'privilege_escalation/linpeas.sh', 'privilege_escalation/suid_check.sh',
        'run_all_post.sh', 'show_results.sh'),
}


def load_helper(path, name):
    # Called INSIDE methods, never discovery; missing source is an explicit ERROR
    # at the authorized first RED, not a skip or fabricated placeholder module.
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def new_text(path, value, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as stream:
        stream.write(value)
    os.chmod(path, mode)
    return path


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode)


def observe_source(path):
    """No-follow observation; missing/unreadable/special objects are evidence."""
    row = {'exists': None, 'type': None, 'mode': None, 'sha256': None, 'errors': []}
    fd = directory = None
    try:
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError('Source observation requires absolute normalized path')
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        row.update(exists=True, mode=stat.S_IMODE(info.st_mode), type=(
            'regular' if stat.S_ISREG(info.st_mode) else 'link' if stat.S_ISLNK(info.st_mode)
            else 'directory' if stat.S_ISDIR(info.st_mode) else 'special'))
        if row['type'] == 'regular':
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise OSError('source identity/type changed during observation')
            digest = hashlib.sha256()
            while chunk := os.read(fd, 65536): digest.update(chunk)
            final = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if (final.st_dev, final.st_ino, final.st_mode, final.st_size, final.st_mtime_ns) != (
                    opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size, opened.st_mtime_ns):
                raise OSError('source identity/metadata changed while hashing')
            row['sha256'] = digest.hexdigest()
    except FileNotFoundError as exc:
        row['exists'] = False if row['exists'] is None else row['exists']
        row['errors'].append({'type': type(exc).__name__, 'errno': exc.errno})
    except OSError as exc:
        row['errors'].append({'type': type(exc).__name__, 'errno': exc.errno})
    finally:
        for descriptor in (fd, directory):
            if descriptor is not None:
                try: os.close(descriptor)
                except OSError as exc:
                    row['errors'].append({'type': type(exc).__name__, 'errno': exc.errno, 'phase': 'close'})
    return row


class LocalCase(unittest.TestCase):
    def fixture(self):
        from cross_module_fixture import CrossModuleFixture
        return CrossModuleFixture('--cross-local')

    def unchanged_sources(self, fixture):
        for relative in fixture.source_files:
            live = fixture.framework / relative
            reference = fixture.repo / 'source-reference' / relative
            self.assertEqual(live.read_bytes(), reference.read_bytes(), relative)
            self.assertEqual(stat.S_IMODE(live.stat().st_mode), 0o500, relative)

    def leaf(self, f, relative, args=(), stdin='', cwd=None):
        before = {p: observe_source(f.framework / p) for p in f.source_files}
        new_text(f.output / ('sources-before-' + str(f._invocations + 1) + '.json'),
                 json.dumps(before, sort_keys=True))
        launch_error = None
        try:
            return f._run(['/bin/bash', '--noprofile', '--norc', str(f.framework / relative), *args], stdin, cwd)
        except BaseException as exc:
            launch_error = exc
            raise
        finally:
            try:
                after = {p: observe_source(f.framework / p) for p in f.source_files}
                new_text(f.output / ('sources-' + str(f._invocations) + '.json'),
                         json.dumps({'before': before, 'after': after,
                                     'launch_error': type(launch_error).__name__ if launch_error else None}, sort_keys=True))
                # Persist observations FIRST. Never mask the original launch
                # exception with a source-integrity assertion/receipt failure.
                if launch_error is None:
                    self.assertEqual(before, after, 'public source changed during invocation')
                    for row in after.values():
                        self.assertEqual(row['type'], 'regular')
                        self.assertEqual(row['errors'], [])
            except BaseException as observation_error:
                if launch_error is None:
                    raise
                launch_error.add_note('Source receipt/integrity observation failed: ' + repr(observation_error))

    def assert_product_privacy(self, f, password, roots=None):
        # Harness stdout/argv/backend receipts deliberately remain raw, outside
        # these product roots. Never exempt canonical repo-level product scans.
        roots = (f.framework, f.repo / 'scans', f.home) if roots is None else roots
        for root in roots:
            if not root.exists(): continue
            for path in root.rglob('*'):
                if path.is_file() and not path.is_symlink():
                    self.assertNotIn(password.encode(), path.read_bytes(), str(path))

    def responses(self, f, **responses):
        f.env['CROSS_LOCAL_RESPONSES'] = json.dumps(responses)


class GenerationTests(LocalCase):
    def test_generation_is_exclusive_and_inert(self):
        f = self.fixture()
        emit_launcher = load_helper(f.framework / '00_Config/lib/consent/generate.py',
                                    'cross_local_generate').emit_launcher
        for kind in KINDS:
            with self.subTest(kind=kind):
                destination = f.repo / (kind + '-new.sh')
                self.assertEqual(emit_launcher(kind, destination, f.framework), destination)
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
                content = destination.read_text()
                self.assertIn('--framework-root', content)
                for secret in (str(f.framework), str(f.home), 'example.test', 'synthetic-password'):
                    self.assertNotIn(secret, content)
                self.assertEqual(f.records(), [])
                for shape in ('empty', 'full', 'link', 'dangling', 'directory', 'inside'):
                    target = f.repo / (kind + '-' + shape)
                    if shape == 'empty': new_text(target, '')
                    if shape == 'full': new_text(target, 'sentinel', 0o640)
                    if shape == 'link': target.symlink_to(destination)
                    if shape == 'dangling': target.symlink_to(f.repo / 'absent')
                    if shape == 'directory': target.mkdir(mode=0o700)
                    if shape == 'inside': target = f.framework / (kind + '-forbidden.sh')
                    before = f.snapshot()
                    with self.assertRaises((ValueError, OSError)):
                        emit_launcher(kind, target, f.framework)
                    self.assertEqual(f.snapshot(), before)
                linked_parent = f.repo / (kind + '-parent-link')
                linked_parent.symlink_to(f.output, target_is_directory=True)
                with self.assertRaises((ValueError, OSError)):
                    emit_launcher(kind, linked_parent / 'new.sh', f.framework)
                with self.assertRaises((ValueError, OSError)):
                    emit_launcher(kind, f.repo / (kind + '-missing-parent') / 'new.sh', f.framework)
        with self.assertRaises(ValueError):
            emit_launcher('unknown', f.repo / 'unknown.sh', f.framework)
        self.assertEqual(f.records(), [])
        self.unchanged_sources(f)

    def test_generated_launcher_requires_root_and_mode(self):
        f = self.fixture()
        emit_launcher = load_helper(f.framework / '00_Config/lib/consent/generate.py',
                                    'cross_local_generate').emit_launcher
        sentinel_root = f.repo / 'sentinel-framework'
        sentinel_root.mkdir(mode=0o700)
        command = 'printf "%s" "one arg"; $(not-executed) & | > sentinel'
        for kind, relative in KINDS.items():
            launcher = emit_launcher(kind, f.repo / (kind + '.sh'), f.framework)
            new_text(sentinel_root / relative, '#!/bin/bash\nrecord-dispatch "$@"\n', 0o700)
            for args in ((), ('--execute',), ('--framework-root', str(f.repo / 'missing'), '--execute'),
                         ('--framework-root', str(sentinel_root))):
                before = len(f.records())
                result = f._run(['/bin/bash', str(launcher), *args], '')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(f.records()), before)
            args = ('example.test', 'SYNTH', 'synthetic-user', 'synthetic-password', command, '--execute')
            result = f._run(['/bin/bash', str(launcher), '--framework-root', str(sentinel_root), *args], '')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.records()[-1], ['record-dispatch', *args])
            self.assertFalse((f.framework / 'sentinel').exists())
        self.unchanged_sources(f)


class StableToolTests(LocalCase):
    def test_smb_keeps_all_methods_without_source_mutation(self):
        f = self.fixture()
        for args in ((), ('example.test',), ('--preview',), ('--help',)):
            self.leaf(f, SMB, args)
            self.assertEqual(f.records(), [])
        generated = f.repo / 'smb-launcher.sh'
        self.assertEqual(self.leaf(f, SMB, ('--generate', str(generated))).returncode, 0)
        image = fingerprint(generated)
        self.assertNotEqual(self.leaf(f, SMB, ('--generate', str(generated))).returncode, 0)
        self.assertEqual(fingerprint(generated), image)
        self.assertEqual(f.records(), [])
        for args in (('--generate', str(f.repo / 'mixed-smb'), '--execute'),
                     ('example.test', '--unknown'), ('example.test', '--execute', '--execute')):
            self.assertNotEqual(self.leaf(f, SMB, args).returncode, 0)
            self.assertEqual(f.records(), [])
        calls = []
        for _ in range(2):
            offset = len(f.records())
            result = self.leaf(f, SMB, ('example.test', 'synthetic_prefix', '--execute'))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls.append(f.records()[offset:])
        self.assertEqual(calls[0], calls[1])
        rows = calls[0]
        self.assertTrue(any(row[0] == 'rpcclient' and 'enumdomusers' in row for row in rows))
        self.assertTrue(any(row[0] == 'enum4linux' and '-a' in row for row in rows))
        self.assertTrue(any(row[0] == 'nmap' and '--script' in row for row in rows))
        self.assertTrue(any(row[0] == 'smbclient' and '-L' in row for row in rows))
        for share in ('ADMIN$', 'IPC$', 'C$', 'public', 'share', 'documents', 'backup'):
            self.assertTrue(any(row[0] == 'smbclient' and '//example.test/' + share in row for row in rows), share)
        for host, prefix in (('--bad', 'ok'), ('bad\nname', 'ok'), ('example.test', '../bad')):
            offset = len(f.records())
            self.assertNotEqual(self.leaf(f, SMB, (host, prefix, '--execute')).returncode, 0)
            self.assertEqual(len(f.records()), offset)
        self.responses(f, rpcclient={'rc': 2, 'stderr': 'synthetic rpc failure'})
        self.assertNotEqual(self.leaf(f, SMB, ('example.test', 'again', '--execute')).returncode, 0)
        # An access-denied classification must not mask a failing backend rc.
        self.responses(f, smbclient={'rc': 1, 'stderr': 'NT_STATUS_ACCESS_DENIED'})
        self.assertNotEqual(self.leaf(f, SMB, ('example.test', 'denied', '--execute')).returncode, 0)
        self.unchanged_sources(f)

    def test_psexec_preserves_argv_and_secret_privacy(self):
        f = self.fixture()
        password = 'synthetic-password'
        command = 'printf "%s" "two words"; $(touch forbidden-local) & | > forbidden-local'
        positions = ('example.test', 'SYNTH', 'synthetic-user', password, command)
        self.leaf(f, PSEXEC, positions)
        self.assertEqual(f.records(), [])
        for args in ((), ('--help',), ('--preview',), (*positions, '--preview')):
            self.assertEqual(self.leaf(f, PSEXEC, args).returncode, 0)
            self.assertEqual(f.records(), [])
        generated = f.repo / 'psexec-launcher.sh'
        self.assertEqual(self.leaf(f, PSEXEC, ('--generate', str(generated))).returncode, 0)
        self.assertNotIn(password, generated.read_text())
        self.assertNotIn('example.test', generated.read_text())
        self.assertNotIn(str(f.framework), generated.read_text())
        self.assertEqual(f.records(), [])
        for rc in (0, 1, 2):
            self.responses(f, **{'psexec.py': {'rc': rc}, 'impacket-psexec': {'rc': rc}})
            for _ in range(2):
                before = len(f.records())
                parses = len(f.psexec_parsed())
                result = self.leaf(f, PSEXEC, (*positions, '--execute'))
                self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
                self.assertEqual(f.records()[before:], [['psexec.py',
                    'SYNTH/synthetic-user:' + password + '@example.test', '--', command]])
                # Explicit expected row for THIS dispatch only: the slice must
                # hold exactly one receipt, so a stale earlier row cannot pass.
                self.assertEqual(f.psexec_parsed()[parses:], [{
                    'backend': 'psexec.py',
                    'target': 'SYNTH/synthetic-user:' + password + '@example.test',
                    'command': [command], 'debug': False, 'k': False, 'target_ip': None, 'copy': None}])
                self.assertNotIn(password, result.stdout + result.stderr)
        self.assertFalse((f.framework / 'forbidden-local').exists())
        for args in ((*positions[:-1], '--execute'), (*positions, '--unknown'),
                     ('--bad', *positions[1:], '--execute'),
                      ('example.test', 'bad/domain', *positions[2:], '--execute'),
                      ('example.test', '-option', *positions[2:], '--execute'),
                      ('example.test', 'SYNTH', 'bad:user', password, command, '--execute'),
                      ('example.test', 'SYNTH', 'user', 'bad@password', command, '--execute'),
                      ('example.test', 'SYNTH', 'user', password, 'bad\ncommand', '--execute'),
                      ('--generate', str(f.repo / 'mixed-psexec'), *positions),
                      ('--generate', str(f.repo / 'mixed-psexec-execute'), '--execute')):
            before = len(f.records())
            self.assertNotEqual(self.leaf(f, PSEXEC, args).returncode, 0)
            self.assertEqual(len(f.records()), before)
        self.responses(f, **{'psexec.py': {'stdout': password, 'stderr': password},
                             'impacket-psexec': {'stdout': password, 'stderr': password}})
        result = self.leaf(f, PSEXEC, (*positions, '--execute'))
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(password, result.stdout + result.stderr)
        # Backend parser, not merely raw argv, must see a literal remote command.
        self.responses(f)
        target = 'SYNTH/synthetic-user:' + password + '@example.test'
        for option_command in ('--help', '-debug', '-k', '-target-ip'):
            with self.subTest(backend_command=option_command):
                count = len(f.psexec_parsed())
                # Mutant/oracle: the former unseparated transport cannot retain
                # this command. Help returns0 without parsing a command; debug/k
                # change backend flags; target-ip lacks its required value.
                mutant = f._run([str(f.bin / 'psexec.py'), target, option_command], '')
                mutant_rows = f.psexec_parsed()[count:]
                self.assertFalse(mutant_rows and mutant_rows[-1]['command'] == [option_command])
                if option_command == '--help': self.assertEqual(mutant.returncode, 0)
                if option_command == '-target-ip': self.assertEqual(mutant.returncode, 2)
                if option_command == '-debug': self.assertTrue(mutant_rows[-1]['debug'])
                if option_command == '-k': self.assertTrue(mutant_rows[-1]['k'])
                dispatch = len(f.records())
                parses = len(f.psexec_parsed())
                result = self.leaf(f, PSEXEC, (*positions[:-1], option_command, '--execute'))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(f.records()[dispatch:], [['psexec.py', target, '--', option_command]])
                self.assertEqual(f.psexec_parsed()[parses:], [{
                    'backend': 'psexec.py', 'target': target, 'command': [option_command],
                    'debug': False, 'k': False, 'target_ip': None, 'copy': None}])
        complex_password = 'synthetic:pass/with\\space and punctuation!'
        dispatch = len(f.records())
        self.assertEqual(self.leaf(f, PSEXEC, (positions[0], positions[1], positions[2],
                                              complex_password, command, '--execute')).returncode, 0)
        self.assertEqual(f.records()[dispatch:], [['psexec.py',
            'SYNTH/synthetic-user:' + complex_password + '@example.test', '--', command]])
        (f.bin / 'psexec.py').rename(f.bin / 'psexec.py.retained')
        self.responses(f, **{'impacket-psexec': {'rc': 2}})
        dispatch = len(f.records())
        parses = len(f.psexec_parsed())
        self.assertEqual(self.leaf(f, PSEXEC, (*positions, '--execute')).returncode, 2)
        self.assertEqual(f.records()[dispatch:], [['impacket-psexec', target, '--', command]])
        self.assertEqual(f.psexec_parsed()[parses:], [{
            'backend': 'impacket-psexec', 'target': target, 'command': [command],
            'debug': False, 'k': False, 'target_ip': None, 'copy': None}])
        (f.bin / 'impacket-psexec').rename(f.bin / 'impacket-psexec.retained')
        before = len(f.records())
        self.assertEqual(self.leaf(f, PSEXEC, (*positions, '--execute')).returncode, 1)
        self.assertEqual(len(f.records()), before)
        # Raw harness receipts deliberately include synthetic argv; product output
        # must not. Do not claim OS argv secrecy or redact evidence to fake it.
        self.assert_product_privacy(f, password)
        # Mutant oracle: a product leak at the canonical sibling scans root MUST
        # be rejected. Preserve the new sentinel; do not redact raw harness logs.
        oracle_root = f.repo / 'scans/privacy-oracle'
        leak = new_text(oracle_root / 'synthetic-leak.log', 'password=' + password)
        with self.assertRaises(AssertionError):
            self.assert_product_privacy(f, password, (oracle_root,))
        self.assertEqual(leak.read_text(), 'password=' + password)
        self.unchanged_sources(f)

    def test_linpeas_requires_explicit_source_and_sudo(self):
        f = self.fixture()
        binary = new_text(f.repo / 'selected.sh', '#!/bin/bash\necho selected-synthetic\n', 0o700)
        new_text(f.framework / 'linpeas_real.sh', '#!/bin/bash\necho cwd-must-not-be-adopted\n', 0o700)
        link = f.repo / 'linked.sh'
        link.symlink_to(binary)
        for args in ((), ('--preview',), ('--execute',), ('--download', '--execute'),
                     ('--binary', str(binary), '--execute'),
                     ('--binary', str(binary), '--allow-sudo'),
                     ('--binary', str(binary), '--download', '--execute', '--allow-sudo'),
                     ('--binary', str(link), '--execute', '--allow-sudo'),
                     ('--binary', str(f.repo / 'missing'), '--execute', '--allow-sudo')):
            self.leaf(f, LINPEAS, args)
            self.assertEqual(f.records(), [])
        for _ in range(2):
            result = self.leaf(f, LINPEAS, ('--binary', str(binary), '--execute', '--allow-sudo'))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([row[0] for row in f.records()], ['sudo', 'sudo'])
        self.assertEqual(binary.read_text(), '#!/bin/bash\necho selected-synthetic\n')
        self.assertTrue(any(p.is_file() and b'selected-synthetic' in p.read_bytes()
                            for p in (f.repo / 'scans/linpeas').rglob('*')))
        self.unchanged_sources(f)

    def test_linpeas_failures_preserve_artifacts(self):
        f = self.fixture()
        old = new_text(f.repo / 'existing-output', 'previous-artifact', 0o640)
        before = fingerprint(old)
        self.responses(f, curl={'rc': 22, 'body': 'partial-download', 'stderr': 'synthetic failure'})
        result = self.leaf(f, LINPEAS, ('--download', '--execute', '--allow-sudo'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([row[0] for row in f.records()], ['curl'])
        runs = f.repo / 'scans/linpeas'
        self.assertTrue(runs.is_dir())
        self.assertTrue(any(p.is_file() and b'partial-download' in p.read_bytes() for p in runs.rglob('*')))
        retained = {str(p): fingerprint(p) for p in runs.rglob('*') if p.is_file()}
        self.responses(f, curl={'rc': 0}, sudo={'rc': 2, 'stderr': 'synthetic sudo failure'})
        self.assertEqual(self.leaf(f, LINPEAS, ('--download', '--execute', '--allow-sudo')).returncode, 2)
        for path, image in retained.items(): self.assertEqual(fingerprint(Path(path)), image)
        self.assertEqual(fingerprint(old), before)
        for path in runs.rglob('*'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        # Wget fallback only for absence, not a curl error: hide NEW double by
        # retaining it, never invoke a real binary from a wider PATH.
        (f.bin / 'curl').rename(f.bin / 'curl.retained')
        self.responses(f, wget={'rc': 1, 'body': 'wget-partial'})
        offset = len(f.records())
        self.assertNotEqual(self.leaf(f, LINPEAS, ('--download', '--execute', '--allow-sudo')).returncode, 0)
        self.assertEqual([row[0] for row in f.records()[offset:]], ['wget'])
        failing = new_text(f.repo / 'failing-selected.sh', '#!/bin/bash\necho partial-selected\nexit 7\n', 0o700)
        self.responses(f)
        self.assertEqual(self.leaf(f, LINPEAS, ('--binary', str(failing), '--execute', '--allow-sudo')).returncode, 7)
        self.assertTrue(any(p.is_file() and b'partial-selected' in p.read_bytes() for p in runs.rglob('*')))
        self.unchanged_sources(f)


class LabTests(LocalCase):
    def test_five_templates_preserve_existing_notes(self):
        f = self.fixture()
        for kind, (category, script, folder) in LABS.items():
            relative = '13_Labs/' + category + '/' + script
            root = f.repo / ('new-' + kind)
            root.mkdir(mode=0o700)
            result = self.leaf(f, relative, ('máquina con espacios', '--root', str(root)))
            self.assertEqual(result.returncode, 0, result.stderr)
            notes = root / 'máquina con espacios/notes/README.md'
            self.assertEqual(stat.S_IMODE(notes.stat().st_mode), 0o600)
            for section in SECTIONS[kind]: self.assertIn('## ' + section, notes.read_text())
            for shape, body in (('full', 'synthetic prior note\n'), ('empty', '')):
                prior = new_text(root / shape / 'notes/README.md', body, 0o640)
                image = fingerprint(prior)
                for _ in range(2):
                    result = self.leaf(f, relative, (shape, '--root', str(root)))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(fingerprint(prior), image)
                    for directory in ('recon', 'exploits', 'loot', 'notes'):
                        self.assertTrue((root / shape / directory).is_dir())
        self.unchanged_sources(f)

    def test_lab_roots_names_and_menu_cwd(self):
        f = self.fixture()
        alien = f.repo / 'unrelated-cwd'
        alien.mkdir(mode=0o700)
        for kind, (category, script, folder) in LABS.items():
            relative = '13_Labs/' + category + '/' + script
            for cwd in (alien, f.framework):
                result = self.leaf(f, relative, ('Máquina ü',), cwd=cwd)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((f.framework / '13_Labs' / category / folder / 'Máquina ü/notes/README.md').is_file())
            for name in ('', '.', '..', '../escape', 'a/b', 'a\\b', 'bad\nname', 'bad\tname'):
                before = f.snapshot()
                result = self.leaf(f, relative, (name,), cwd=alien)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(f.snapshot(), before)
        # Run the actual Labs menu, not a replacement initializer. Its child
        # wrappers and transport doubles remain genuine fixture sources.
        result = self.leaf(f, '13_Labs/main.sh', stdin='1\n1\nMenu machine\n\n5\n11\n', cwd=alien)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((f.framework / '13_Labs/hackthebox/machines/Menu machine/notes/README.md').exists())
        result = self.leaf(f, '13_Labs/main.sh', stdin='1\n2\n\n5\n11\n', cwd=alien)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Menu machine', result.stdout)
        result = self.leaf(f, '13_Labs/main.sh', stdin='1\n3\nMenu machine\n5\n11\n', cwd=alien)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(row[0] == 'editor' and row[-1].endswith('/Menu machine/notes/README.md') for row in f.records()))
        self.assertFalse((alien / 'machines').exists())
        result = self.leaf(f, '13_Labs/main.sh', stdin='', cwd=alien)
        self.assertEqual(result.returncode, 0, 'EOF must return, not recurse/spin')

    def test_lab_links_and_partial_failure(self):
        f = self.fixture()
        relative = '13_Labs/hackthebox/htb_setup.sh'
        root = f.repo / 'lab-root'
        root.mkdir(mode=0o700)
        sentinel = new_text(f.repo / 'referent', 'do not change', 0o640)
        image = fingerprint(sentinel)
        for shape in ('link', 'dangling', 'directory', 'fifo'):
            notes = root / shape / 'notes/README.md'
            notes.parent.mkdir(mode=0o700, parents=True)
            if shape == 'link': notes.symlink_to(sentinel)
            if shape == 'dangling': notes.symlink_to(f.repo / 'absent-note')
            if shape == 'directory': notes.mkdir(mode=0o700)
            if shape == 'fifo': os.mkfifo(notes, 0o600)
            result = self.leaf(f, relative, (shape, '--root', str(root)))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(fingerprint(sentinel), image)
            self.assertFalse((f.repo / 'absent-note').exists())
        ancestor = root / 'ancestor'
        ancestor.symlink_to(root / 'directory', target_is_directory=True)
        self.assertNotEqual(self.leaf(f, relative, ('ancestor', '--root', str(root))).returncode, 0)
        blocked = new_text(root / 'blocked', 'not a directory')
        self.assertNotEqual(self.leaf(f, relative, ('child', '--root', str(blocked))).returncode, 0)
        denied = root / 'denied'
        denied.mkdir(mode=0o500)
        self.assertNotEqual(self.leaf(f, relative, ('child', '--root', str(denied))).returncode, 0)
        # Direct helper under the SAME Landlock worker: no threaded subprocess
        # receipt counter race. Both real initializers compete on O_EXCL.
        initialize_lab = load_helper(f.framework / '00_Config/lib/labs_runtime.py',
                                     'cross_local_labs_runtime').initialize_lab
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: initialize_lab('htb', 'race', root), range(2)))
        self.assertEqual(sum(result.created_notes for result in outcomes), 1)
        self.assertEqual(outcomes[0].path, outcomes[1].path)
        self.assertTrue((root / 'race/notes/README.md').is_file())


class ReconTests(LocalCase):
    def test_ping_target_parser(self):
        # Pure exclusive creation only; no fixture, no disposable grant, no CLI.
        from automation_case_scope import in_worker
        self.assertTrue(in_worker())
        parse_ping_targets = load_helper(Path('/source/CyberSecurity-Framework/00_Config/lib/recon_targets.py'),
                                         'cross_local_recon_targets').parse_ping_targets
        self.assertEqual(parse_ping_targets('192.0.2.7'), ('192.0.2.7',))
        self.assertEqual(parse_ping_targets('192.0.2.7', '1-2'), ('192.0.2.7',))
        for network in ('192.0.2', '192.0.2.0/24', '192.0.2.9/24'):
            self.assertEqual(parse_ping_targets(network, '1-2'), ('192.0.2.1', '192.0.2.2'))
            self.assertEqual(parse_ping_targets(network, '0-255'), tuple('192.0.2.' + str(n) for n in range(256)))
            self.assertEqual(parse_ping_targets(network), tuple('192.0.2.' + str(n) for n in range(1, 255)))
        for network in ('192.0.2/24', '192.0.2.0/16', '256.0.2.1', '192.00.2.1',
                        '--help', '192.0.2.1\n', '192.0.2.1/25', ''):
            with self.assertRaises(ValueError): parse_ping_targets(network)
        for span in ('2-1', '-1-2', '0-256', '1', '01-2', '1-2\n'):
            with self.assertRaises(ValueError): parse_ping_targets('192.0.2', span)

    def test_ping_cli_records_only_selected_targets(self):
        for network, span, expected in (
                ('192.0.2.7', '1-2', ['192.0.2.7']),
                ('192.0.2', '1-2', ['192.0.2.1', '192.0.2.2']),
                ('192.0.2.0/24', '1-2', ['192.0.2.1', '192.0.2.2']),
                ('192.0.2.9/24', '0-0', ['192.0.2.0'])):
            f = self.fixture()
            result = self.leaf(f, PING, (network, span))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual([row[-1] for row in f.records() if row[0] == 'ping'], expected)
            self.assertEqual([row[-1] for row in f.records() if row[0] == 'host'], expected)
            outputs = list((f.framework / '02_Recon/host_discovery').glob('ping_sweep_*.txt'))
            self.assertEqual(len(outputs), 1)
            self.assertEqual([row.split('|')[0] for row in outputs[0].read_text().splitlines()], expected)
            historical = new_text(outputs[0].parent / 'ping_sweep_historical.txt', 'historical-synthetic\n', 0o640)
            image = fingerprint(historical)
            offset = len(f.records())
            second = self.leaf(f, PING, (network, span))
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual([row[-1] for row in f.records()[offset:] if row[0] == 'ping'], expected)
            self.assertEqual(fingerprint(historical), image)
        for network, span in (('192.0.2/24', '1-2'), ('192.0.2.0/16', '1-2'),
                              ('256.0.2.1', '1-2'), ('192.0.2', '2-1'), ('--help', '1-2')):
            f = self.fixture()
            self.assertNotEqual(self.leaf(f, PING, (network, span)).returncode, 0)
            self.assertEqual(f.records(), [])
            self.assertFalse((f.framework / '02_Recon/host_discovery').exists())
        f = self.fixture()
        self.responses(f, ping={'rc': 2, 'stderr': 'synthetic backend error'})
        self.assertNotEqual(self.leaf(f, PING, ('192.0.2.7',)).returncode, 0)
        (f.bin / 'ping').rename(f.bin / 'ping.retained')
        self.assertNotEqual(self.leaf(f, PING, ('192.0.2.7',)).returncode, 0)


class LocalMenuTests(LocalCase):
    def test_modes_marks_and_coordinator_omissions(self):
        f = self.fixture()
        references = {p: observe_source(f.repo / 'source-reference' / p) for p in f.source_files}
        reference_bytes = {p: (Path('/source/CyberSecurity-Framework') / p).read_bytes() for p in f.source_files}
        for p, original in reference_bytes.items():
            self.assertEqual((f.repo / 'source-reference' / p).read_bytes(), original)
        # Observation oracle lives in this existing granted ID: retain every new
        # object and receipt; no repair/deletion to manufacture an intact source.
        observer_root = f.repo / 'source-observer-oracle'
        observer_root.mkdir(mode=0o700)
        regular = new_text(observer_root / 'regular', 'observer sentinel', 0o640)
        (observer_root / 'dangling').symlink_to(observer_root / 'missing')
        (observer_root / 'directory').mkdir(mode=0o700)
        observations = {name: observe_source(observer_root / name)
                        for name in ('regular', 'dangling', 'directory', 'missing')}
        new_text(f.output / 'source-observer-oracle.json', json.dumps(observations, sort_keys=True))
        self.assertEqual(observations['regular']['sha256'], hashlib.sha256(regular.read_bytes()).hexdigest())
        self.assertEqual(observations['regular']['mode'], 0o640)
        self.assertEqual(observations['dangling']['type'], 'link')
        self.assertIsNone(observations['dangling']['sha256'])
        self.assertEqual(observations['directory']['type'], 'directory')
        self.assertFalse(observations['missing']['exists'])
        self.assertTrue(observations['missing']['errors'])
        from automation_sandbox_prepare import source_names
        staged_names = set(source_names())
        for module, entries in ORIGINAL_ENTRIES.items():
            for entry in entries:
                self.assertIn('CyberSecurity-Framework/' + module + '/' + entry, staged_names)
        # Independent pinned names + actual manager listing policy. Create ONLY
        # missing inert scratch leaves, never read protected source-folder bodies.
        listing = self.fixture()
        session_target_value = listing.full_list_target()
        listing.install_local_inventory(ORIGINAL_ENTRIES)
        for menu, choice, module in (('enumeration_menu', '11\n0\n0\n', '04_Enumeration'),
                                     ('postexploitation_menu', '9\n0\n0\n', '06_PostExploitation')):
            result = listing.run_menu(menu, choice, real_list=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for entry in ORIGINAL_ENTRIES[module]: self.assertIn(entry, result.stdout)
            self.assertEqual(listing.records(), [])
        for menu in ('enumeration_menu', 'postexploitation_menu'):
            for text in ('0\n', ''):
                offset = len(f.records())
                self.assertEqual(f.run_menu(menu, text).returncode, 0)
                self.assertEqual(f.records()[offset:], [])
        # Task2 consumers are exercised BEFORE pending Task3 checks, using the
        # real manager list/execute_script and real params/prompt. Only the final
        # external-process boundary is replaced; raw receipts retain argv.
        password = '  synthetic\\menu-password :/  '
        command = 'printf "two words"; $(not-local) & | > literal'
        for relative in (SMB, PSEXEC):
            module, leaf = relative.split('/', 1)
            entries = ORIGINAL_ENTRIES[module]
            order = sorted(e for e in entries if e.startswith('run_all_')) + sorted(
                e for e in entries if not e.startswith('run_all_'))
            index = str(order.index(leaf) + 1) + '\n'
            generate = str(listing.repo / ('new launcher-' + module + '.sh'))
            positions = (['example.test', 'stable_prefix'] if relative == SMB else
                         ['example.test', 'SYNTH', 'user', password, command])
            for mode_input, expected, secret, needs_session in (
                    ('s\n1\n0\n', ['--preview'], False, False),
                    ('s\n\n0\n', ['--preview'], False, False),
                    ('s\n3\n' + generate + '\n0\n', ['--generate', generate], False, False),
                    ('s\n2\n' + '\n'.join(positions) + '\n0\n', [*positions, '--execute'], relative == PSEXEC, True),
                    ('s\n0\n0\n', [], False, False), ('s\n!\n0\n', [], False, False),
                    ('s\n', [], False, False), ('s\n3\n', [], False, False),
                    ('s\n3\n!\n0\n', [], False, False), ('s\n2\n', [], False, False),
                    ('s\n2\n0\n0\n', [], False, False), ('n\n0\n', [], False, False), ('', [], False, False)):
                with self.subTest(full_list=relative, mode=mode_input):
                    offset = len(listing.records())
                    # Execute/generate also traverse the actual inventory entry;
                    # remaining modes call that same extracted execute_script
                    # consumer directly, without broad manager initialization.
                    through_list = expected and expected[0] != '--preview'
                    result = listing.run_full_list(
                        relative, (index if through_list else '') + mode_input,
                        through_list=bool(through_list),
                        needs_session=needs_session)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    rows = listing.records()[offset:]
                    self.assertIn(['record-dispatch', '__params-policy__', 'stable',
                                   '2' if relative == SMB else '5'], rows)
                    dispatch = [r for r in rows if len(r) > 1 and r[1] in (SMB, PSEXEC)]
                    self.assertEqual(dispatch, [['record-dispatch', relative, *expected]] if expected else [])
                    self.assertFalse(any(r[0] in ('smbclient', 'psexec.py', 'impacket-psexec') for r in rows))
                    self.assertNotIn(password, result.stdout + result.stderr)
                    if secret:
                        reads = [r for r in rows if len(r) > 3 and r[1] == '__read-policy__' and r[-1] == 'value']
                        self.assertEqual(len(reads), 5)
                        secret_read = reads[3]
                        self.assertEqual(secret_read[2], '')  # actual IFS at input boundary
                        flags = ''.join(x[1:] for x in secret_read[3:-1] if x.startswith('-'))
                        self.assertIn('s', flags)
                        self.assertIn('r', flags)
            # The synthetic session target is OFFERED as the visible default of
            # the first field and adopted when that field is left empty; it is
            # never silently substituted nor read from operator configuration.
            with self.subTest(full_list_session_default=relative):
                offset = len(listing.records())
                result = listing.run_full_list(
                    relative, index + 's\n2\n\n' + '\n'.join(positions[1:]) + '\n0\n',
                    through_list=True, needs_session=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('[' + session_target_value + ']', result.stderr)
                self.assertEqual(
                    [r for r in listing.records()[offset:] if len(r) > 1 and r[1] in (SMB, PSEXEC)],
                    [['record-dispatch', relative, session_target_value,
                      *positions[1:], '--execute']])
                self.assertNotIn(password, result.stdout + result.stderr)
            # EOF/cancel at the secret boundary, not just at the first prompt.
            if relative == PSEXEC:
                for tail in ('', '0\n0\n', '!\n0\n'):
                    with self.subTest(secret_cancel=tail):
                        offset = len(listing.records())
                        result = listing.run_full_list(
                            relative, 's\n2\nexample.test\nSYNTH\nuser\n' + tail,
                            needs_session=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertFalse(any(len(r) > 1 and r[1] == PSEXEC for r in listing.records()[offset:]))
            self.assertFalse(Path(generate).exists(), 'full-list transport must not generate/execute its dispatch')
        # M2 refusal branch + accepted residual (inside this existing case; no
        # new case ID). prompt_for_slots runs for real with explicit identity
        # pairs and the read-boundary observer shows which route was taken.
        psexec_abs = str(listing.framework / PSEXEC)
        smb_abs = str(listing.framework / SMB)
        refusal = 'identidad no canónica'
        for script, rel, expected_mode in (
                (psexec_abs, './' + PSEXEC, 'stable'),
                (smb_abs, './' + SMB, 'stable'),
                (psexec_abs, psexec_abs, 'slots'),
                (psexec_abs, '', 'slots'),
                (smb_abs, 'external/04_Enumeration/smb/enum_smb.sh', 'slots')):
            with self.subTest(identity=rel or '<empty>'):
                offset = len(listing.records())
                result = listing.run_prompt_identity(script, rel, '1\n')
                rows = listing.records()[offset:]
                self.assertEqual([r for r in rows if r[1:2] == ['__mode__']],
                                 [['record-dispatch', '__mode__', expected_mode]])
                if expected_mode == 'stable':
                    # './'-prefixed canonical identity: the real adapter runs,
                    # previews only, reads no field and dispatches nothing.
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, '--preview\n')
                    self.assertEqual([r for r in rows if r[1:2] == ['__rc__']],
                                     [['record-dispatch', '__rc__', '0']])
                    # Dispatch slot is initialised empty and (no real dispatch
                    # having occurred) stays empty: a recorded fact, not an
                    # inference. Its presence proves the slot is writable.
                    self.assertEqual([r for r in rows if r[1:2] == ['__dispatch__']],
                                     [['record-dispatch', '__dispatch__', '']])
                    self.assertFalse([r for r in rows if r[1:2] == ['__read-policy__']])
                else:
                    # Closed consumer under an absolute/foreign identity: notice,
                    # contract cancel code, and NO generic echo/trim secret read.
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, '')
                    self.assertIn(refusal, result.stderr)
                    self.assertEqual([r for r in rows if r[1:2] == ['__rc__']],
                                     [['record-dispatch', '__rc__', '1']])
                    # Zero dispatch is a recorded fact: the initialised slot
                    # stayed empty and no dispatch target row appeared.
                    self.assertEqual([r for r in rows if r[1:2] == ['__dispatch__']],
                                     [['record-dispatch', '__dispatch__', '']])
                    self.assertFalse(any(len(r) > 1 and r[1] not in ('__mode__', '__rc__', '__dispatch__')
                                        and r[1].endswith(('enum_smb.sh', 'ps_exec.sh')) for r in rows))
                    self.assertFalse([r for r in rows if r[1:2] == ['__read-policy__']])
                    self.assertEqual([r[1:2] for r in rows
                                      if r[1:2] not in (['__mode__'], ['__rc__'], ['__dispatch__'])], [])
                    self.assertFalse(any(len(r) > 1 and r[1].endswith(
                        ('enum_smb.sh', 'ps_exec.sh')) for r in rows))
        # Product call sites of prompt_for_slots: exactly one, and its first
        # argument is the module-relative path derived from $script_path. Counted
        # structurally (invocation, not definition/comment) so a new call site
        # anywhere in the product tree is caught; the wrong (absolute) form is
        # also forbidden.
        import re
        manager = (listing.framework / 'cyber_framework.sh').read_text()
        invocation_re = re.compile(r'(?m)(?<![A-Za-z0-9_])prompt_for_slots\s+("[^"]*"\s+"[^"]*")')
        invocations = [m.group(1).strip() for m in invocation_re.finditer(manager)]
        self.assertEqual(len(invocations), 1, invocations)
        self.assertEqual(invocations[0], '"$rel_path" "$script_path"')
        self.assertEqual(len(re.findall(r'(?m)rel_path="\$\{script_path#\$module_dir/\}"', manager)), 1)
        self.assertNotIn('prompt_for_slots "$script_path"', manager)
        product_invocations = 0
        for path in (listing.framework).rglob('*'):
            if not path.is_file() or path.suffix not in ('.sh', '.bash', '.py'):
                continue
            if 'tests' in path.relative_to(listing.framework).parts:
                continue
            for line in path.read_text(errors='replace').splitlines():
                stripped = line.strip()
                if stripped.startswith('#'):
                    continue
                if (re.search(r'(?<![A-Za-z0-9_])prompt_for_slots\s+\S', stripped) and
                        '()' not in stripped.split('prompt_for_slots', 1)[-1][:3]):
                    product_invocations += 1
        self.assertEqual(product_invocations, 1)
        # Accepted residual, pinned: a bare-basename or module-relative identity
        # still reaches the GENERIC prompt (echoing read, whitespace trimmed).
        # That is safe only because the call site above cannot emit it.
        for identity in ('ps_exec.sh', 'lateral_movement/ps_exec.sh'):
            with self.subTest(module_relative_identity=identity):
                offset = len(listing.records())
                result = listing.run_prompt_identity(
                    'ps_exec.sh', identity, '', module='06_PostExploitation/lateral_movement')
                rows = listing.records()[offset:]
                self.assertEqual([r for r in rows if r[1:2] == ['__mode__']],
                                 [['record-dispatch', '__mode__', 'slots']])
                self.assertEqual([r for r in rows if r[1:2] == ['__rc__']],
                                 [['record-dispatch', '__rc__', '2']])
                reads = [r for r in rows if r[1:2] == ['__read-policy__']]
                self.assertTrue(reads)
                flags = ''.join(x[1:] for x in reads[0][3:-1] if x.startswith('-'))
                self.assertNotIn('s', flags, 'generic secret read must not be silent')
                self.assertEqual(reads[0][2], '')
                self.assertEqual(reads[0][-1], 'value')
        self.unchanged_sources(listing)
        self.assert_product_privacy(listing, password)
        # Real guided menus and their actual secret read boundary, not a PTY
        # simulation. Pipe-output checks alone do NOT establish terminal echo.
        f.set_session('example.test')
        result = f.run_menu('enumeration_menu', '4\nexample.test\ns\n0\n')
        dispatch = [row for row in f.records() if row[0] == 'record-dispatch']
        self.assertTrue(any(SMB in row and '--execute' in row for row in dispatch), result.stdout + result.stderr)
        offset = len(f.records())
        result = f.run_menu('postexploitation_menu', '6\n3\nexample.test\nSYNTH\nuser\n' + password + '\n' + command + '\n0\n', observe_reads=True)
        self.assertNotIn(password, result.stdout + result.stderr)
        rows = f.records()[offset:]
        self.assertIn(['record-dispatch', PSEXEC, '06_PostExploitation', '--prepared',
                       'example.test', 'SYNTH', 'user', password, command, '--execute'], rows)
        reads = [r for r in rows if len(r) > 3 and r[1] == '__read-policy__' and r[-1] == 'pass']
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0][2], '')
        flags = ''.join(x[1:] for x in reads[0][3:-1] if x.startswith('-'))
        self.assertIn('s', flags)
        self.assertIn('r', flags)
        self.assert_product_privacy(f, password)
        for menu, choice, module in (('enumeration_menu', '11\n0\n', '04_Enumeration'),
                                      ('postexploitation_menu', '9\n0\n', '06_PostExploitation')):
            offset = len(f.records())
            f.run_menu(menu, choice)
            self.assertTrue(any(row[0] == 'record-dispatch' and module in row for row in f.records()[offset:]))
        self.assertNotIn('se reemplaza por', (f.framework / SMB).read_text())
        # Pending Task3 assertions remain substantive and independently reached;
        # a failed subtest must not hide the later Task2 or Task3 contracts.
        for text in ('2\n0\n0\n', '2\n'):
            with self.subTest(pending_linpeas_initial_cancel=text):
                offset = len(f.records())
                f.run_menu('postexploitation_menu', text)
                self.assertFalse(any(LINPEAS in row for row in f.records()[offset:]))
        selected = new_text(f.repo / 'menu-selected.sh', '#!/bin/bash\necho selected\n', 0o700)
        # Pin the upcoming public menu contract: option2 asks source choice
        # (1 local, 2 download, 0 cancel); execute_script is ONLY transport.
        for choice, expected in (
                ('2\n1\n' + str(selected) + '\n0\n',
                 ['--binary', str(selected), '--execute', '--allow-sudo']),
                ('2\n2\n0\n', ['--download', '--execute', '--allow-sudo'])):
            with self.subTest(pending_linpeas_source=expected):
                offset = len(f.records())
                result = f.run_menu('postexploitation_menu', choice)
                self.assertEqual(result.returncode, 0, result.stderr)
                linpeas = [row for row in f.records()[offset:] if LINPEAS in row]
                self.assertEqual(linpeas, [['record-dispatch', LINPEAS, '06_PostExploitation', '--prepared', *expected]])
                self.assertFalse(any(row[0] in ('curl', 'wget', 'sudo') for row in f.records()[offset:]))
        for choice in ('2\n1\n0\n0\n', '2\n1\n', '2\n0\n0\n', '2\n'):
            with self.subTest(pending_linpeas_cancel=choice):
                offset = len(f.records())
                self.assertEqual(f.run_menu('postexploitation_menu', choice).returncode, 0)
                self.assertFalse(any(LINPEAS in row for row in f.records()[offset:]))
        dangerous = (f.framework / '00_Config/lib/dangerous.txt').read_text().splitlines()
        with self.subTest(pending_linpeas_dangerous=True):
            self.assertIn(LINPEAS, dangerous)
        policy = new_text(f.output / 'real-params-policy.sh',
            'ROOT="$1"\nsource "$ROOT/00_Config/lib/params.bash"\n'
            'shift\nif [[ "${1:-}" == --dangerous ]]; then\n'
            '  params_is_dangerous "$2"; exit $?\nfi\n'
            'for relative in "$@"; do\n'
            '  params_is_generator "$ROOT/$relative" && exit 31\n'
            'done\nexit 0\n')
        for relative in KINDS.values():
            with self.subTest(generator_mark=relative):
                result = f._run(['/bin/bash', str(policy), str(f.framework), relative], '')
                self.assertEqual(result.returncode, 0, result.stderr)
        with self.subTest(pending_linpeas_sensitive_classifier=True):
            result = f._run(['/bin/bash', str(policy), str(f.framework), '--dangerous', LINPEAS], '')
            self.assertEqual(result.returncode, 0, result.stderr)
        for p, captured in reference_bytes.items():
            self.assertEqual((f.repo / 'source-reference' / p).read_bytes(), captured)
        self.assertEqual({p: observe_source(f.repo / 'source-reference' / p) for p in f.source_files}, references)
        # Retain real source copies; coordinators may only hit these recorders,
        # including protected data-folder leaves that are NEVER read/copied.
        live_linpeas = fingerprint(f.framework / LINPEAS)
        f.record_local_coordinator_leaves()
        self.assertEqual(fingerprint((f.framework / LINPEAS).with_name('linpeas.sh.retained-source')), live_linpeas)
        offset = len(f.records())
        result = self.leaf(f, '06_PostExploitation/run_all_post.sh', ('example.test',))
        with self.subTest(pending_post_rc=True):
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with self.subTest(pending_post_sensitive_omissions=True):
            self.assertFalse(any(LINPEAS in row or PSEXEC in row for row in f.records()[offset:]))
        with self.subTest(pending_post_linpeas_reason=True):
            self.assertRegex(result.stdout.lower(), r'linpeas[^\n]*(?:selecci[oó]n|seleccionar)[^\n]*(?:requerida|requiere|expl[ií]cita)')
        counts = re.search(r'Ejecutadas:\s*(\d+)\s*\|\s*Fallidas:\s*(\d+)\s*\|\s*Omitidas:\s*(\d+)', result.stdout)
        # Five ordinary child recorders:3 privilege checks +2 credentials; loot
        # file collector adds one, screenshot omitted without its backend.
        with self.subTest(pending_post_counts=True):
            self.assertIsNotNone(counts, result.stdout)
            self.assertEqual(tuple(map(int, counts.groups())), (6, 0, 2))
        dispatched = [row for row in f.records()[offset:] if row[0] == 'record-dispatch']
        with self.subTest(pending_post_dispatches=True):
            self.assertEqual(len(dispatched), 6)
        source = (f.framework / 'cyber_framework.sh').read_text()
        self.assertIn('script_arguments_summary', source)
        self.assertIn('ps_exec.sh', source)
        for p, captured in reference_bytes.items():
            self.assertEqual((f.repo / 'source-reference' / p).read_bytes(), captured)
        self.assertEqual({p: observe_source(f.repo / 'source-reference' / p) for p in f.source_files}, references)
