"""Report contracts using only allowlisted copied sources and synthetic input."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from automation_fixture import AutomationFixture, preserve

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '00_Config/lib'))
from automation.adapters import execute_plan, preflight
from automation.model import Permissions, Plan, PlanError, PreflightError, RuntimeContext
from automation.planner import build_plan


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.f = AutomationFixture()
        self.addCleanup(self.f.close)
        self.f.stub('python3')
        self.ctx = RuntimeContext(self.f.framework, self.f.repo, Path(sys.executable), str(self.f.bin))
        self.input = self.f.repo / 'synthetic scans'
        self.input.mkdir()
        self.output = self.f.repo / 'new output'
        self.permissions = Permissions(frozenset(), frozenset({('report', 'report_read')}))

    def plan(self):
        return build_plan('report', {'target': 'example.test', 'report_input': self.input})

    def shim(self, *extra):
        env = dict(os.environ, REPORT_PROFILE='/must-not-read', SESSION_FILE='/must-not-read',
                   PYTHONPATH='/must-not-import', BASH_ENV='/must-not-source')
        return subprocess.run([sys.executable, '-I', '-B', str(self.f.framework /
            '09_Automation/python/report_generator.py'), '--input', str(self.input),
            '--output', str(self.output / 'report.html'), *extra], env=env,
            cwd=self.f.home, text=True, capture_output=True)

    def stub_engine(self, rc=3):
        (self.f.framework / '11_Reports/report_engine.py').write_text('''import argparse, json, os
from pathlib import Path
p = argparse.ArgumentParser()
for name in ('objetivo', 'scans', 'salida', 'tipo', 'cliente', 'auditor'):
    p.add_argument('--' + name, required=True)
a = p.parse_args()
assert a.objetivo == 'example.test' and a.tipo == 'ambos'
assert a.cliente == 'No indicado' and a.auditor == 'No indicado'
assert Path(os.environ['REPORT_PROFILE']).read_bytes() == b''
assert 'PYTHONPATH' not in os.environ and 'SESSION_FILE' not in os.environ
out = Path(a.salida)
out.mkdir(exist_ok=True)
for name in ('findings.json', 'informe_tecnico.md', 'informe_tecnico.html', 'informe_cliente.md', 'informe_cliente.html'):
    (out / name).write_text('{}')
raise SystemExit(''' + str(rc) + ')\n')

    def test_report_requires_target_input(self):
        for values in ({'report_input': self.input}, {'target': 'example.test'}):
            with self.assertRaises(PlanError):
                build_plan('report', values)
        result = self.shim()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.output.exists())

    def test_no_implicit_session_or_all_targets(self):
        from automation.reporting import report_command
        run = self.f.repo / 'run'
        run.mkdir(mode=0o700)
        cmd = report_command(self.plan().steps[0], run, self.ctx)
        for flag in ('--objetivo', '--scans', '--salida', '--tipo', '--cliente', '--auditor'):
            self.assertIn(flag, cmd.argv)
        for flag in ('--todos', '--incluir-sin-objetivo', '--abrir'):
            self.assertNotIn(flag, cmd.argv)
        self.assertEqual(cmd.argv[cmd.argv.index('--salida') + 1], str(run / 'reports'))
        self.assertEqual(Path(cmd.env['REPORT_PROFILE']).read_bytes(), b'')

    def test_report_engine_rc3(self):
        self.stub_engine()
        result = execute_plan(self.plan(), self.ctx, self.permissions)
        self.assertEqual(result.rc, 1)
        self.assertEqual(result.steps[0].rc, 3)
        self.assertEqual(result.steps[0].state, 'fallido')
        self.assertEqual(self.shim('--target', 'example.test', '--execute',
                                  '--allow', 'report:report_read').returncode, 3)

    def test_legacy_output_names(self):
        self.stub_engine(0)
        result = self.shim('--target', 'example.test', '--execute', '--allow', 'report:report_read')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('obsoleto', result.stdout)
        self.assertFalse((self.output / 'report.html').exists())
        for name in ('findings.json', 'informe_tecnico.html', 'informe_cliente.html'):
            self.assertTrue((self.output / name).is_file())
            self.assertIn(name, result.stdout)
        again = self.shim('--target', 'example.test', '--execute', '--allow', 'report:report_read')
        self.assertNotEqual(again.returncode, 0)

    def test_preview_is_pure_and_execute_requires_gate(self):
        preserve(self.input)
        preview = self.shim('--target', 'example.test')
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertFalse(self.output.exists())
        self.assertFalse((self.f.repo / 'scans').exists())
        self.assertEqual(self.shim('--target', 'example.test', '--execute').returncode, 2)

    def test_preflight_input_and_all_engine_imports_before_run(self):
        from automation.reporting import ENGINE_SOURCES
        ping = build_plan('ping', {'target': 'example.test'}).steps[0]
        plan = Plan('all-before-any', (ping, *self.plan().steps), 300)
        permissions = Permissions(frozenset({'example.test'}), self.permissions.grants)
        self.f.stub('ping')
        for relative in ENGINE_SOURCES:
            original = self.f.framework / relative
            backup = original.with_suffix('.missing')
            original.rename(backup)
            try:
                with self.subTest(source=relative), self.assertRaises(PreflightError):
                    execute_plan(plan, self.ctx, permissions)
            finally:
                backup.rename(original)
        self.assertFalse((self.f.repo / 'scans').exists())
        self.assertEqual(self.f.records(), [])

    def test_preflight_rejects_missing_input_and_symlinks(self):
        preserve(self.input)
        with self.assertRaises(PreflightError):
            preflight(self.plan(), self.ctx, self.permissions)
        self.input.mkdir()
        (self.input / 'link').symlink_to(self.f.home, target_is_directory=True)
        with self.assertRaises(PreflightError):
            preflight(self.plan(), self.ctx, self.permissions)

    def test_no_local_profile_or_session_defaults(self):
        # Directories would fail read_text() if the engine tried these defaults.
        (self.f.framework / '00_Config/.session').mkdir()
        (self.f.framework / '11_Reports/.report_profile').mkdir()
        self.assertEqual(self.shim('--target', 'example.test', '--execute',
                                  '--allow', 'report:report_read').returncode, 3)

    def test_shim_does_not_trust_stale_reports_or_rc0_without_output(self):
        self.output.mkdir()
        old = self.output / 'informe_cliente.html'
        old.write_text('historical')
        self.stub_engine(0)
        result = self.shim('--target', 'example.test', '--execute', '--allow', 'report:report_read')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(old.read_text(), 'historical')
        self.assertFalse((self.f.repo / 'scans').exists())
        old.unlink()
        self.output.rmdir()
        (self.f.framework / '11_Reports/report_engine.py').write_text('raise SystemExit(0)\n')
        result = self.shim('--target', 'example.test', '--execute', '--allow', 'report:report_read')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((self.output / 'findings.json').exists())

    def test_destination_ancestor_swap_and_symlink_are_rejected(self):
        from automation.reporting import check_report_destination, publish_reports
        parent = self.f.repo / 'external'
        parent.mkdir()
        destination = parent / 'new'
        identity = check_report_destination(destination)
        parent.rename(self.f.repo / 'moved')
        parent.mkdir()
        with self.assertRaises(PreflightError):
            publish_reports(self.f.home, destination, identity)
        self.assertFalse(destination.exists())
        preserve(parent)
        parent.symlink_to(self.f.home, target_is_directory=True)
        with self.assertRaises(PreflightError):
            check_report_destination(destination)

    def test_publication_does_not_adopt_directory_swapped_after_mkdir(self):
        from automation import reporting
        source = self.f.repo / 'private-reports'
        source.mkdir(mode=0o700)
        for name in reporting.REPORT_FILES:
            (source / name).write_text('synthetic report')
        destination = self.output
        identity = reporting.check_report_destination(destination)
        mkdir = os.mkdir
        attacked = []

        def replace_destination(name, mode=0o777, *, dir_fd=None):
            mkdir(name, mode, dir_fd=dir_fd)
            if name == destination.name:
                # Original vulnerable window: replace the just-created inode
                # before the publisher opens that name, keeping its parent.
                os.rename(destination, self.f.repo / 'displaced')
                mkdir(destination, 0o755)
                attacked.append('mkdir/open substitution')
            elif str(name).startswith('.report-publication-'):
                # Secure implementation prepares privately: a competing actor
                # can occupy the external name, but cannot replace the stage.
                mkdir(destination, 0o755)
                attacked.append('external name occupied before publication')

        with patch.object(reporting.os, 'mkdir', side_effect=replace_destination):
            with self.assertRaises(PreflightError):
                reporting.publish_reports(source, destination, identity)
        self.assertEqual(len(attacked), 1)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertEqual({p.name for p in source.iterdir()}, set(reporting.REPORT_FILES))

    def test_publication_compares_exposed_name_with_previously_pinned_identity(self):
        from automation import reporting
        source = self.f.repo / 'private-reports'
        source.mkdir(mode=0o700)
        for name in reporting.REPORT_FILES:
            (source / name).write_text('synthetic report')
        identity = reporting.check_report_destination(self.output)
        rename = reporting._rename_noreplace
        displaced = self.f.repo / 'displaced'

        def substitute_after_publication(*args):
            rename(*args)
            self.output.rename(displaced)
            self.output.mkdir(mode=0o755)

        with patch.object(reporting, '_rename_noreplace', side_effect=substitute_after_publication):
            with self.assertRaises(PreflightError):
                reporting.publish_reports(source, self.output, identity)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual({p.name for p in displaced.iterdir()}, set(reporting.REPORT_FILES))
        self.assertEqual(displaced.stat().st_mode & 0o777, 0o700)
        self.assertEqual({p.name for p in source.iterdir()}, set(reporting.REPORT_FILES))

    def test_publication_cross_filesystem_fails_closed_without_copy_fallback(self):
        import errno
        from automation import reporting
        source = self.f.repo / 'private-reports'
        source.mkdir(mode=0o700)
        for name in reporting.REPORT_FILES:
            (source / name).write_text('synthetic report')
        identity = reporting.check_report_destination(self.output)
        with patch('ctypes.CDLL') as libc, patch('ctypes.get_errno', return_value=errno.EXDEV):
            libc.return_value.renameat2.return_value = -1
            with self.assertRaisesRegex(PreflightError, 'mismo sistema de archivos'):
                reporting.publish_reports(source, self.output, identity)
        self.assertFalse(self.output.exists())
        self.assertEqual({p.name for p in source.iterdir()}, set(reporting.REPORT_FILES))

    def test_helper_rejects_stale_run_reports(self):
        from automation.reporting import report_command
        run = self.f.repo / 'run'
        run.mkdir(mode=0o700)
        (run / 'reports').symlink_to(self.f.home, target_is_directory=True)
        with self.assertRaises(PreflightError):
            report_command(self.plan().steps[0], run, self.ctx)
        self.assertFalse((self.f.home / 'findings.json').exists())

    def test_no_external_output_input_from_workflow(self):
        with self.assertRaises(PlanError):
            build_plan('report', {'target': 'example.test', 'report_input': self.input,
                                  'output': self.output})

    def test_real_copied_engine_filters_target_and_no_evaluable_rc3(self):
        nmap = self.input / 'nmap'
        nmap.mkdir()
        (nmap / 'nmap_example.test.xml').write_text('''<nmaprun><host><status state="up"/>
<address addr="192.0.2.1" addrtype="ipv4"/><hostnames><hostname name="example.test"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
</host></nmaprun>''')
        (nmap / 'nmap_other.test.xml').write_text('<nmaprun><host><address addr="192.0.2.2"/></host></nmaprun>')
        # Nmap attributes assets by address, not XML hostnames. Use the
        # declared address as target; content identity must beat the filename.
        plan = build_plan('report', {'target': '192.0.2.1', 'report_input': self.input})
        result = execute_plan(plan, self.ctx, self.permissions)
        self.assertEqual(result.rc, 0, result.steps)
        data = json.loads((result.run_dir / 'reports/findings.json').read_text())
        self.assertEqual(data['meta']['objetivo'], '192.0.2.1')
        self.assertEqual(data['meta']['modo'], 'objetivo')
        self.assertNotIn('other.test', json.dumps(data.get('hallazgos')))
        self.assertIn('192.0.2.1', data['activos'])
        self.assertNotIn('192.0.2.2', data['activos'])
        for path in nmap.iterdir():
            path.unlink()
        result = execute_plan(plan, self.ctx, self.permissions)
        self.assertEqual(result.rc, 1)
        self.assertEqual(result.steps[0].rc, 3)


if __name__ == '__main__':
    unittest.main()
