"""Twelve upfront local contracts. STATIC NOT RUN; all remain pending RED.

No future business import during discovery. Real leaves run only in a verified
fresh worker fixture, including legacy self-rewriters; no host entrypoint.
"""
import hashlib
import importlib.util
import json
import os
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
    return path


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode)


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
        before = {p: fingerprint(f.framework / p) for p in f.source_files}
        try:
            return f._run(['/bin/bash', '--noprofile', '--norc', str(f.framework / relative), *args], stdin, cwd)
        finally:
            after = {p: fingerprint(f.framework / p) for p in f.source_files}
            # Receipts survive even if an assertion/legacy rewrite fails.
            new_text(f.output / ('sources-' + str(f._invocations) + '.json'),
                     json.dumps({'before': before, 'after': after}, sort_keys=True))
            self.assertEqual(before, after, 'public source changed during invocation')

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
        for args in ((), ('example.test',), ('--preview',)):
            self.leaf(f, SMB, args)
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
        self.unchanged_sources(f)

    def test_psexec_preserves_argv_and_secret_privacy(self):
        f = self.fixture()
        password = 'synthetic-password'
        command = 'printf "%s" "two words"; $(touch forbidden-local) & | > forbidden-local'
        positions = ('example.test', 'SYNTH', 'synthetic-user', password, command)
        self.leaf(f, PSEXEC, positions)
        self.assertEqual(f.records(), [])
        for rc in (0, 1, 2):
            self.responses(f, **{'psexec.py': {'rc': rc}, 'impacket-psexec': {'rc': rc}})
            for _ in range(2):
                before = len(f.records())
                result = self.leaf(f, PSEXEC, (*positions, '--execute'))
                self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
                self.assertEqual(f.records()[before:], [[f.records()[-1][0],
                    'SYNTH/synthetic-user:' + password + '@example.test', command]])
                self.assertNotIn(password, result.stdout + result.stderr)
        self.assertFalse((f.framework / 'forbidden-local').exists())
        for args in ((*positions[:-1], '--execute'), (*positions, '--unknown'),
                     ('--bad', *positions[1:], '--execute'),
                     ('example.test', 'bad/domain', *positions[2:], '--execute')):
            before = len(f.records())
            self.assertNotEqual(self.leaf(f, PSEXEC, args).returncode, 0)
            self.assertEqual(len(f.records()), before)
        # Raw harness receipts deliberately include synthetic argv; product output
        # must not. Do not claim OS argv secrecy or redact evidence to fake it.
        for path in f.framework.rglob('*'):
            if path.is_file() and path not in [f.framework / p for p in f.source_files]:
                self.assertNotIn(password.encode(), path.read_bytes(), str(path))
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
        for menu in ('enumeration_menu', 'postexploitation_menu'):
            for text in ('0\n', ''):
                offset = len(f.records())
                self.assertEqual(f.run_menu(menu, text).returncode, 0)
                self.assertEqual(f.records()[offset:], [])
        for text in ('2\n0\n0\n', '2\n'):
            offset = len(f.records())
            f.run_menu('postexploitation_menu', text)
            self.assertFalse(any(LINPEAS in row for row in f.records()[offset:]))
        for menu, choice, module in (('enumeration_menu', '11\n0\n', '04_Enumeration'),
                                     ('postexploitation_menu', '9\n0\n', '06_PostExploitation')):
            offset = len(f.records())
            f.run_menu(menu, choice)
            self.assertTrue(any(row[0] == 'record-dispatch' and module in row for row in f.records()[offset:]))
        # Real menu choice/policy with transport-only recorders.
        f.set_session('example.test')
        result = f.run_menu('enumeration_menu', '4\nexample.test\ns\n0\n')
        dispatch = [row for row in f.records() if row[0] == 'record-dispatch']
        self.assertTrue(any(SMB in row and '--execute' in row for row in dispatch), result.stdout + result.stderr)
        password = 'synthetic-menu-password'
        result = f.run_menu('postexploitation_menu', '6\n3\nexample.test\nSYNTH\nuser\n' + password + '\nwhoami\n0\n')
        self.assertNotIn(password, result.stdout + result.stderr)
        self.assertTrue(any(PSEXEC in row and '--execute' in row for row in f.records()))
        dangerous = (f.framework / '00_Config/lib/dangerous.txt').read_text().splitlines()
        self.assertIn(LINPEAS, dangerous)
        policy = new_text(f.output / 'real-params-policy.sh',
            'ROOT="$1"\nsource "$ROOT/00_Config/lib/params.bash"\n'
            'shift\nfor relative in "$@"; do\n'
            '  params_is_generator "$ROOT/$relative" && exit 31\n'
            'done\nparams_is_dangerous "06_PostExploitation/privilege_escalation/linpeas.sh"\n')
        result = f._run(['/bin/bash', str(policy), str(f.framework), *KINDS.values()], '')
        self.assertEqual(result.returncode, 0, result.stderr)
        # Retain real source copies; coordinators may only hit these recorders,
        # including protected data-folder leaves that are NEVER read/copied.
        f.record_local_coordinator_leaves()
        offset = len(f.records())
        self.leaf(f, '06_PostExploitation/run_all_post.sh', ('example.test',))
        self.assertFalse(any(LINPEAS in row or PSEXEC in row for row in f.records()[offset:]))
        source = (f.framework / 'cyber_framework.sh').read_text()
        self.assertIn('script_arguments_summary', source)
        self.assertIn('ps_exec.sh', source)
        self.assertNotIn('se reemplaza por', (f.repo / 'source-reference' / SMB).read_text())
