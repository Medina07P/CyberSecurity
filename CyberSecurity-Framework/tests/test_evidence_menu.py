"""Real Bash UI/dispatch in allowlisted synthetic copies, no backends."""
import subprocess
import unittest
from evidence_fixture import sandbox, copy_sources, closed_env, snapshot, legacy_pair


class EvidenceMenuTests(unittest.TestCase):
    def setUp(self):
        self.ctx = sandbox()
        self.root = self.ctx.__enter__()
        self.addCleanup(self.ctx.__exit__, None, None, None)
        self.fw = copy_sources(self.root)
        self.env = closed_env(self.root, {name: 'echo forbidden >> "$HOME/../forbidden"; exit 97\n' for name in
                                        ('nmap', 'tcpdump', 'cutycapt')})
        self.calls = self.root / 'calls'
        for name in ('evidence_manager', 'auto_capture', 'run_all_evidence'):
            (self.fw / f'10_Evidence/{name}.sh').write_text(
                '#!/bin/bash\nprintf "%s\\0" "$@" >> "$HOME/../calls"\n')

    def run_ui(self, body, inputs='', rc=0):
        before = (snapshot(self.fw / '00_Config'), snapshot(self.root / 'home'),
                  snapshot(self.fw / '10_Evidence'))
        script = '''FRAMEWORK_DIR=$1
source "$1/00_Config/lib/evidence_menu.bash" || exit
ask_confirm() { local answer; IFS= read -r answer && [[ $answer = s ]]; }
execute_script() { evidence_execute_script "$@"; }
''' + body
        result = subprocess.run(['/bin/bash', '-c', script, 'test', str(self.fw)],
                                input=inputs, text=True, capture_output=True,
                                env=self.env, cwd=self.root, timeout=5)
        self.assertEqual(result.returncode, rc, result.stderr)
        self.assertFalse((self.root / 'forbidden').exists(), 'forbidden binary executed')
        self.assertEqual(before, (snapshot(self.fw / '00_Config'), snapshot(self.root / 'home'),
                                  snapshot(self.fw / '10_Evidence')))
        return result

    def test_enter_exit_eof_and_help_have_no_effects(self):
        result = self.run_ui('IFS= read -r value; printf "%s" "$value"', 'sentinel\n')
        self.assertEqual(result.stdout, 'sentinel')
        self.assertEqual(result.stderr, '')
        for inputs in ('', '0\n', '!\n', '8\n0\n'):
            self.run_ui('evidence_menu', inputs)
            self.assertFalse(self.calls.exists())

    def test_availability_never_executes_binaries(self):
        python = self.root / 'bin/python3'
        python.unlink()
        python.write_text('#!/bin/bash\necho forbidden >> "$HOME/../forbidden"\nexit 97\n')
        python.chmod(0o700)
        self.run_ui('evidence_menu', '1\n0\n')
        self.assertFalse(self.calls.exists())

    def test_fixed_inventory_never_discovers_evidence_code(self):
        output = self.run_ui('evidence_original_entries').stdout.splitlines()
        self.assertEqual(output, ['run_all_evidence.sh', 'auto_capture.sh', 'evidence_manager.sh'])
        manager = (self.fw / 'cyber_framework.sh').read_text()
        evil = self.fw / '10_Evidence/proofs/payload.sh'
        evil.parent.mkdir(parents=True)
        evil.write_text('exit 97\n')
        listing = manager.split('run_module_scripts() {', 1)[1].split(
            '# ─── Funciones para módulos específicos', 1)[0]
        result = self.run_ui('''clear_screen() { :; }
module_intro() { :; }
params_is_dangerous() { return 1; }
params_mode() { echo manual; }
params_is_generator() { return 1; }
pause() { :; }
cd "$FRAMEWORK_DIR"
run_module_scripts() {''' + listing + '\nrun_module_scripts 10_Evidence original', '0\n')
        self.assertNotIn('payload.sh', result.stdout + result.stderr)
        self.assertIn('3 scripts', result.stdout)
        self.assertFalse(self.calls.exists())

    def test_manager_dispatch_cannot_bypass_with_absolute_or_module_paths(self):
        manager = (self.fw / 'cyber_framework.sh').read_text()
        dispatch = manager.split('execute_script() {', 1)[1].split(
            '# ─── Función para navegar', 1)[0]
        for path in ('10_Evidence/unknown.sh', './10_Evidence/auto_capture.sh',
                     str(self.fw / '10_Evidence/auto_capture.sh')):
            self.run_ui('execute_script() {' + dispatch + '\nexecute_script "' + path +
                        '" 10_Evidence --prepared --system', rc=2)
        for directory in ('./10_Evidence', str(self.fw / '10_Evidence')):
            self.run_ui('execute_script() {' + dispatch + '\nexecute_script auto_capture.sh "' +
                        directory + '" --prepared --system', rc=2)
        self.assertFalse(self.calls.exists())

    def test_prepared_and_direct_dispatch_reject_unknown_and_symlink(self):
        for mode in ('', '--prepared --list'):
            self.run_ui(f'evidence_execute_script 10_Evidence/proofs/evil.sh 10_Evidence {mode}', rc=2)
            leaf = self.fw / '10_Evidence/evidence_manager.sh'
            saved = leaf.read_text()
            leaf.unlink()
            leaf.symlink_to(self.fw / '10_Evidence/auto_capture.sh')
            self.run_ui(f'evidence_execute_script 10_Evidence/evidence_manager.sh 10_Evidence {mode}', rc=2)
            leaf.unlink()
            leaf.write_text(saved)
        self.assertFalse(self.calls.exists())

    def test_cancellation_at_each_prompt_never_runs_partial_action(self):
        lines = ['screenshot', '/private file', 'description', 'label']
        for n in range(len(lines)):
            for cancel in ('!\n', '0\n', ''):
                self.run_ui('evidence_execute_script 10_Evidence/evidence_manager.sh 10_Evidence',
                            '1\n' + '\n'.join(lines[:n]) + ('\n' if n else '') + cancel)
                self.assertFalse(self.calls.exists())
        capture_lines = ['s', 'https://example.test', 's', 'host.test', 'eth0',
                         '10', '100', 's', 'host.test', 'full', 's']
        for n in range(len(capture_lines) + 1):
            prefix = '\n'.join(capture_lines[:n]) + ('\n' if n else '')
            for cancel in ('', '!\n', '0\n'):
                self.run_ui('evidence_execute_script 10_Evidence/auto_capture.sh 10_Evidence',
                            prefix + cancel)
                self.assertFalse(self.calls.exists())

    def test_prepared_capture_and_package_still_confirm(self):
        for leaf, args in [('auto_capture.sh', '--web https://example.test --authorize-network'),
                           ('run_all_evidence.sh', '--capture --scan host.test --scan-profile basic --authorize-network'),
                           ('evidence_manager.sh', '--package')]:
            self.run_ui(f'evidence_execute_script 10_Evidence/{leaf} 10_Evidence --prepared {args}', 'n\n')
            self.assertFalse(self.calls.exists())
        self.run_ui('evidence_execute_script 10_Evidence/auto_capture.sh 10_Evidence --prepared --system')
        self.assertEqual(self.calls.read_bytes(), b'--system\0')

    def test_capture_selection_and_run_use_explicit_fields(self):
        inputs = 'n\ns\nhost.test\neth0\n7\n42\ns\nhost.test\nbasic\nn\ns\n'
        self.run_ui('evidence_execute_script 10_Evidence/run_all_evidence.sh 10_Evidence', '2\n' + inputs)
        self.assertEqual(self.calls.read_bytes(),
                         b'--capture\0--traffic\0host.test\0--interface\0eth0\0--duration\0'
                         b'7\0--packet-limit\0' + b'42\0--scan\0host.test\0--scan-profile\0basic\0--authorize-network\0')

    def test_menu_import_and_offline_have_no_capture_defaults(self):
        self.run_ui('evidence_menu', '2\nproof\n/private file\n\n\n7\n0\n')
        self.assertEqual(self.calls.read_bytes(), b'--add\0proof\0/private file\0\0--offline\0')

    def test_dispatch_rejects_symlink_parent(self):
        module = self.fw / '10_Evidence'
        module.rename(self.fw / 'saved')
        module.symlink_to(self.fw / 'saved', target_is_directory=True)
        self.run_ui('evidence_execute_script 10_Evidence/auto_capture.sh 10_Evidence --prepared --system', rc=2)
        self.assertFalse(self.calls.exists())

    def test_import_paths_spaces_not_session_target(self):
        self.run_ui('evidence_execute_script 10_Evidence/evidence_manager.sh 10_Evidence',
                    '1\nproof\n/private file\nsecret description\n\n')
        self.assertEqual(self.calls.read_bytes(), b'--add\0proof\0/private file\0secret description\0')

    def test_arguments_and_credentials_not_echoed(self):
        result = self.run_ui('evidence_execute_script 10_Evidence/evidence_manager.sh 10_Evidence --prepared --add credential /secret-password')
        self.assertNotIn('/secret-password', result.stdout + result.stderr)

    def phase(self):
        return self.run_ui('source "$FRAMEWORK_DIR/00_Config/lib/phase_status.bash"; '
                           '_evidence_has_records "$FRAMEWORK_DIR/10_Evidence"; '
                           'if [[ $? = 0 ]]; then echo done; else echo pending; fi').stdout.strip()

    def test_phase_all_categories_legacy_not_diagnostics(self):
        module = self.fw / '10_Evidence'
        for category, kind in (('screenshots', 'screenshot'), ('pcaps', 'pcap'),
                               ('credentials', 'credential'), ('findings', 'finding'),
                               ('proofs', 'proof'), ('logs', 'log')):
            for subdir in ('', '.archive/nested'):
                for name in ('old proof', ' leading and trailing ', '.hidden', 'body.meta'):
                    with self.subTest(category=category, subdir=subdir, name=name):
                        folder = module / category / subdir
                        payload, meta = legacy_pair(folder, name, kind)
                        self.assertEqual(self.phase(), 'done')
                        meta.unlink()
                        self.assertEqual(self.phase(), 'pending')
                        payload.unlink()
        diag = module / 'logs/runs'
        diag.mkdir()
        legacy_pair(diag, kind='log')
        legacy_pair(diag / 'nested', kind='log')
        self.assertEqual(self.phase(), 'pending')

    def test_phase_relative_root_returns_without_effects(self):
        result = self.run_ui('source "$FRAMEWORK_DIR/00_Config/lib/phase_status.bash"; '
                             'if _evidence_has_records CyberSecurity-Framework/10_Evidence; '
                             'then echo done; else echo pending; fi')
        self.assertEqual(result.stdout, 'pending\n')

    def test_phase_hidden_legacy_regular_pair_is_presence(self):
        folder = self.fw / '10_Evidence/proofs/.archive'
        folder.mkdir(parents=True)
        legacy_pair(folder, '.proof')
        self.assertEqual(self.phase(), 'done')

    def test_phase_legacy_reads_only_sidecar_and_rejects_links(self):
        folder = self.fw / '10_Evidence/logs/.archive'
        payload, meta = legacy_pair(folder, ' leading body.meta ', 'log')
        # Corrupt MD5 still counts as presence: the banner must not verify.
        meta.write_text(meta.read_text().replace('900150983cd24fb0d6963f7d28e17f72', 'wrong'))
        probe = '''source "$FRAMEWORK_DIR/00_Config/lib/phase_status.bash"
read() {
    if [[ ! /proc/self/fd/0 -ef "$FRAMEWORK_DIR/10_Evidence/logs/.archive/ leading body.meta .meta" ]]; then
        echo forbidden >> "$HOME/../forbidden"
        return 1
    fi
    builtin read "$@"
}
if _evidence_has_records "$FRAMEWORK_DIR/10_Evidence"; then echo done; else echo pending; fi'''
        self.assertEqual(self.run_ui(probe).stdout, 'done\n')
        payload.rename(self.root / 'outside')
        payload.symlink_to(self.root / 'outside')
        self.assertEqual(self.phase(), 'pending')
        payload.unlink()
        payload.write_bytes(b'abc')
        meta.rename(self.root / 'outside.meta')
        meta.symlink_to(self.root / 'outside.meta')
        self.assertEqual(self.phase(), 'pending')
        meta.unlink()
        legacy_pair(folder, payload.name, 'log')
        folder.rename(self.root / 'outside-directory')
        folder.symlink_to(self.root / 'outside-directory', target_is_directory=True)
        self.assertEqual(self.phase(), 'pending')

    def test_phase_equal_separator_is_not_legacy(self):
        _, meta = legacy_pair(self.fw / '10_Evidence/proofs/access')
        meta.write_text(meta.read_text().replace('FILE: ', 'FILE='))
        self.assertEqual(self.phase(), 'pending')

    def test_phase_legacy_requires_safe_basename_and_regular_pair(self):
        folder = self.fw / '10_Evidence/proofs/access'
        folder.mkdir(parents=True)
        for name in ('.gitkeep', 'back\\slash'):
            payload = folder / name
            meta = folder / (name + '.meta')
            payload.write_text('not evidence')
            meta.write_text('FILE: ' + name + '\n')
            self.assertEqual(self.phase(), 'pending')
            payload.unlink()
            meta.unlink()

    def test_phase_never_reads_payload_or_invokes_python(self):
        folder = self.fw / '10_Evidence/proofs/access' / ('a' * 32)
        folder.mkdir(parents=True)
        (folder / 'artifact').write_text('unread payload')
        (folder / 'evidence.json').write_text('invalid schema still presence')
        # No external commands are available; python3 is explicitly fail-closed.
        (self.root / 'bin/python3').unlink()
        (self.root / 'bin/python3').write_text('#!/bin/bash\necho forbidden >> "$HOME/../forbidden"\nexit 97\n')
        (self.root / 'bin/python3').chmod(0o700)
        probe = '''source "$FRAMEWORK_DIR/00_Config/lib/phase_status.bash"
read() {
    if [[ /proc/self/fd/0 -ef "$FRAMEWORK_DIR/10_Evidence/proofs/access/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/artifact" ]]; then
        echo forbidden >> "$HOME/../forbidden"
        return 1
    fi
    builtin read "$@"
}
if _evidence_has_records "$FRAMEWORK_DIR/10_Evidence"; then echo done; else echo pending; fi'''
        self.assertEqual(self.run_ui(probe).stdout, 'done\n')
        (folder / 'artifact').unlink()
        (folder / 'artifact').symlink_to('/unreadable')
        self.assertEqual(self.phase(), 'pending')
