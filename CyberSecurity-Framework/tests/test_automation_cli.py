"""CLI integration against a synthetic allowlisted tree only."""
import contextlib
import importlib
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from automation_fixture import AutomationFixture, preserve


class CliTests(unittest.TestCase):
    def setUp(self):
        self.fx = AutomationFixture()
        self.addCleanup(self.fx.close)
        self.lib = str(self.fx.framework / '00_Config/lib')
        saved = {name: module for name, module in sys.modules.items()
                 if name == 'automation' or name.startswith('automation.')}
        def restore_modules():
            for name in list(sys.modules):
                if name == 'automation' or name.startswith('automation.'):
                    del sys.modules[name]
            sys.modules.update(saved)
        self.addCleanup(restore_modules)
        for name in list(sys.modules):
            if name == 'automation' or name.startswith('automation.'):
                del sys.modules[name]
        sys.path.insert(0, self.lib)
        self.addCleanup(sys.path.remove, self.lib)
        self.cli = importlib.import_module('automation.cli')
        self.ctx = self.cli.RuntimeContext(self.fx.framework, self.fx.repo,
                                          Path(sys.executable), str(self.fx.bin))

    def call(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return self.cli.main(args, ctx=self.ctx)

    def process(self, relative, args=(), text=''):
        return subprocess.run([sys.executable, '-I', str(self.fx.framework / relative), *args],
                              input=text, text=True, capture_output=True, cwd=self.fx.home,
                              env={'PATH': str(self.fx.bin), 'HOME': str(self.fx.home)})

    def test_menu_eof_is_inert(self):
        for text in ('', '0\n', '3\n', '3\n192.0.2.1\n', '11\n0\n'):
            stream = io.StringIO(text)
            with patch('builtins.input', side_effect=lambda prompt: stream.readline()):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(self.cli.menu(self.ctx), 0)
        self.assertFalse((self.fx.framework / '09_Automation/runs').exists())
        self.assertEqual(self.fx.records(), [])

    def test_cli_rejects_ambiguity(self):
        for args in (['--full', '--phase', 'scan'], ['--full', '--action', 'ping'],
                     ['--menu', '--target', '192.0.2.1'], ['--unknown'],
                     ['--phase', 'post', '--execute'], ['--phase', 'scan', '--ports', '80'],
                     ['--action', 'ping', '--allow', 'absent:scanner'],
                     ['--action', 'full'],
                     ['--action', 'ping', '--allow', 'ping:scanner']):
            self.assertEqual(self.call(['--target', '192.0.2.1', *args]), 2, args)
        self.assertEqual(self.call(['--help']), 0)

    def test_confirmation_is_not_stdin_yes(self):
        result = self.process('09_Automation/python/orchestrator.py',
                              ['--target', '192.0.2.1', '--action', 'ping', '--execute'], 'yes\n')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.fx.records(), [])

    def test_legacy_adapters_plan_only(self):
        for script, args in (('auto_audit.py', ['192.0.2.1']),
                             ('auto_audit.py', ['192.0.2.1', 'scan']),
                             ('orchestrator.py', ['--target', '192.0.2.1'])):
            result = self.process('09_Automation/python/' + script, args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Plan:', result.stdout)
        self.assertEqual(self.process('09_Automation/python/auto_audit.py',
                                     ['192.0.2.1', 'unknown']).returncode, 2)
        self.assertEqual(self.fx.records(), [])
        self.assertEqual(list(self.fx.framework.rglob('__pycache__')), [])

    def test_valid_execute_propagates_status(self):
        for rc in (0, 1, 2, 130, 143):
            result = self.cli.RunResult(rc, None, ())
            with patch.object(self.cli, 'execute_plan', return_value=result) as execute:
                self.assertEqual(self.call(['--target', '192.0.2.1', '--action', 'ping',
                                            '--execute', '--authorized-target', '192.0.2.1']), rc)
                execute.assert_called_once()

    def test_execute_real_core_with_fake_backend(self):
        for rc in (0, 1, 130, 143):
            self.fx.stub('ping', rc)
            self.assertEqual(self.call(['--target', '192.0.2.1', '--action', 'ping',
                                        '--execute', '--authorized-target', '192.0.2.1']),
                             0 if rc == 0 else 1)
        self.assertEqual(len(self.fx.records()), 4)

    def test_readonly_modes_do_not_execute_or_modify_data(self):
        config = self.fx.framework / '00_Config'
        before = {name: (config / name).read_bytes() for name in ('scope.yaml', 'targets.txt')}
        for flag in ('--help', '--list', '--check'):
            self.assertEqual(self.call([flag]), 0)
        self.assertEqual(before, {name: (config / name).read_bytes() for name in before})
        self.assertFalse((config / '.session').exists())
        self.assertEqual(self.fx.records(), [])

    def test_bash_menu_entry_is_readonly_including_bytecode(self):
        (self.fx.bin / 'python3').symlink_to(sys.executable)
        (self.fx.bin / 'dirname').symlink_to('/usr/bin/dirname')
        before = {str(p.relative_to(self.fx.framework)) for p in self.fx.framework.rglob('*')}
        result = subprocess.run(['/bin/bash', str(self.fx.framework / '09_Automation/run_all_automation.sh')],
                                input='11\n0\n', text=True, capture_output=True, cwd=self.fx.home,
                                env={'PATH': str(self.fx.bin), 'HOME': str(self.fx.home)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, {str(p.relative_to(self.fx.framework))
                                  for p in self.fx.framework.rglob('*')})

    def test_menu_confirms_each_run_and_eof_cancels(self):
        for text, count in (('3\n192.0.2.1\nEJECUTAR\n192.0.2.1\n', 0),
                            ('3\n192.0.2.1\nEJECUTAR\n192.0.2.1\nscan_basic:scanner\n'
                             '3\n192.0.2.1\nEJECUTAR\n', 1)):
            stream = io.StringIO(text)
            with patch('builtins.input', side_effect=lambda prompt: stream.readline()), \
                    patch.object(self.cli, 'execute_plan', return_value=self.cli.RunResult(0, None, ())) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.cli.menu(self.ctx), 0)
                self.assertEqual(run.call_count, count)

    def test_advanced_menu_accepts_optional_inputs(self):
        stream = io.StringIO('5\nsqlmap_request\n192.0.2.1\nfixture.req\nhttps\napp\nusers\n0\n')
        with patch('builtins.input', side_effect=lambda prompt: stream.readline()), \
                patch.object(self.cli, 'interactive_plan', return_value=0) as preview, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.cli.menu(self.ctx), 0)
        self.assertEqual(preview.call_args.args[0].steps[0].inputs['table'], 'users')

    def test_sqlmap_can_explicitly_enumerate_databases_without_database_input(self):
        plan = self.cli.build_plan('sqlmap_request', {'target': '192.0.2.1',
                                                     'request_file': 'fixture.req', 'scheme': 'https'})
        permissions = self.cli.permissions_for(plan, ['192.0.2.1'],
                                              ['sqlmap_request:sqlmap_probe',
                                               'sqlmap_request:sqlmap_enum'])
        self.assertIn(('sqlmap_request', 'sqlmap_enum'), permissions.grants)

    def test_bash_wrappers_from_foreign_cwd(self):
        (self.fx.bin / 'python3').symlink_to(sys.executable)
        (self.fx.bin / 'dirname').symlink_to('/usr/bin/dirname')
        for relative, args in (
                ('bash/auto_recon.sh', ['192.0.2.1']),
                ('bash/auto_enum.sh', ['192.0.2.1']),
                ('bash/auto_exploit.sh', ['192.0.2.1']),
                ('bash/auto_exploit.sh', ['192.0.2.1', '--action', 'exploit_lookup',
                                          '--product', 'Apache 2.4']),
                ('run_all_automation.sh', ['192.0.2.1']),
                ('run_all_automation.sh', [])):
            result = subprocess.run(['/bin/bash', str(self.fx.framework / '09_Automation' / relative),
                                     *args], input='', text=True, capture_output=True,
                                    cwd=self.fx.home, env={'PATH': str(self.fx.bin),
                                                         'HOME': str(self.fx.home)})
            self.assertEqual(result.returncode, 0, (relative, result.stderr))
        self.assertEqual(self.fx.records(), [])

    def test_manager_dispatch_09(self):
        # Source only the copied manager; replace unrelated library imports with inert files.
        manager = self.fx.framework / 'cyber_framework.sh'
        import re
        for name in re.findall(r'source "\$LIB_DIR/([^"\n]+)"', manager.read_text()):
            if name != 'automation_menu.bash':
                preserve(self.fx.framework / '00_Config/lib' / name)
                (self.fx.framework / '00_Config/lib' / name).write_text('true\n')
        # Trap all accidental backends, while interpreter/path utilities are explicit.
        for name in ('nmap', 'ping', 'sudo', 'docker', 'curl'):
            self.fx.stub(name, 99)
        (self.fx.bin / 'python3').symlink_to(sys.executable)
        (self.fx.bin / 'bash').symlink_to('/bin/bash')
        (self.fx.bin / 'dirname').symlink_to('/usr/bin/dirname')
        result = subprocess.run(['/bin/bash', '-c', 'source "$1"; main_menu() { :; }; main',
                                 'test', str(manager)], input='09\n11\n0\nQ\n', text=True,
                                capture_output=True, cwd=self.fx.framework,
                                env={'PATH': str(self.fx.bin), 'HOME': str(self.fx.home),
                                     'TERM': 'dumb'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('python/auto_audit.py', result.stdout)
        self.assertIn('powershell/auto_enum.ps1', result.stdout)
        self.assertIn('docker/Dockerfile', result.stdout)
        self.assertEqual(self.fx.records(), [])


if __name__ == '__main__':
    unittest.main()
