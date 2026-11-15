"""Report contracts using only allowlisted copied sources and synthetic input."""
import json
from contextlib import redirect_stderr
from io import StringIO
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from automation_fixture import AutomationFixture, preserve

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '00_Config/lib'))
from automation.adapters import execute_plan, preflight
from automation.model import Permissions, Plan, PlanError, PreflightError, RuntimeContext, Step
from automation.planner import build_plan


# Literal wire fixtures, independent of 11's parser and 09's future resolver.
REPORT_NAMES = ('findings.json', 'informe_tecnico.md', 'informe_tecnico.html',
                'informe_cliente.md', 'informe_cliente.html')
RUN_ID = 'run-20261114T120000000000Z-' + 'a' * 32
REPORT_WARNING = ('Aviso: report_input puede contener históricos; el informe no acredita '
                  'que 09 haya ejecutado esas fases.\n')
NEW_ENGINE_SOURCES = (
    '11_Reports/lib/coverage.py', '11_Reports/lib/exploitation_metadata.py',
    '11_Reports/lib/history.py', '11_Reports/lib/publication.py',
    '11_Reports/lib/validation.py', '11_Reports/lib/parsers/prior_modules.py',
    '11_Reports/lib/parsers/scanner_ports.py',
    '00_Config/lib/evidence/__init__.py', '00_Config/lib/evidence/inventory.py',
    '00_Config/lib/evidence/model.py', '00_Config/lib/evidence/storage.py',
)


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

    def stub_engine(self, rc=3, markers=False):
        engine = self.f.framework / '11_Reports/report_engine.py'
        preserve(engine)
        engine.write_text('''import argparse, json, os
from pathlib import Path
p = argparse.ArgumentParser()
for name in ('objetivo', 'scans', 'salida', 'tipo', 'cliente', 'auditor'):
    p.add_argument('--' + name, required=True)
p.add_argument('--json', action='store_true', required=True)
a = p.parse_args()
assert a.tipo == 'ambos'
assert a.cliente == 'No indicado' and a.auditor == 'No indicado'
profile = Path(os.environ['REPORT_PROFILE'])
assert profile.read_bytes() == b''
assert 'PYTHONPATH' not in os.environ and 'SESSION_FILE' not in os.environ
''' + ('profile.write_text(a.objetivo)\n' if markers else '') + '''
run_id = 'run-20261114T120000000000Z-' + 'a' * 32
out = Path(a.salida) / 'runs' / run_id
out.parent.mkdir(mode=0o700)
out.mkdir(mode=0o700)
names = ['findings.json', 'informe_tecnico.md', 'informe_tecnico.html', 'informe_cliente.md', 'informe_cliente.html']
for name in names:
    with (out / name).open('x') as stream:
        json.dump(''' + ("{'target': a.objetivo, 'input': (Path(a.scans) / 'marker').read_text()}" if markers else '{}') + ''', stream)
    (out / name).chmod(0o600)
receipt = {'schema_version': 1, 'module': '11', 'run_id': run_id,
    'started_at': '2026-11-14T12:00:00+00:00', 'finished_at': '2026-11-14T12:00:01+00:00',
    'objetivo': a.objetivo, 'modo': 'objetivo', 'tipo': 'ambos', 'entrada': 'scans',
    'estado': ''' + repr('COMPLETADO' if rc == 0 else 'NO_EVALUABLE') + ''', 'rc': ''' + str(rc) + ''', 'archivos': names}
with (out / 'run.json').open('x') as stream:
    json.dump(receipt, stream)
(out / 'run.json').chmod(0o600)
print(json.dumps({'objetivo': a.objetivo, 'hallazgos': 0, 'criticos': 0,
    'no_evaluable': ''' + str(int(rc == 3)) + ''', 'salida': str(out), 'run_id': run_id,
    'archivos': [str(out / name) for name in names + ['run.json']]}))
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
        with redirect_stderr(StringIO()) as warning:
            cmd = report_command(self.plan().steps[0], run, self.ctx)
        self.assertEqual(warning.getvalue(), REPORT_WARNING)
        for flag in ('--objetivo', '--scans', '--salida', '--tipo', '--cliente', '--auditor', '--json'):
            self.assertIn(flag, cmd.argv)
        for flag in ('--todos', '--incluir-sin-objetivo', '--abrir'):
            self.assertNotIn(flag, cmd.argv)
        self.assertEqual(cmd.argv[cmd.argv.index('--salida') + 1], str(run / 'report-report/reports'))
        self.assertEqual(Path(cmd.env['REPORT_PROFILE']).read_bytes(), b'')

    def test_two_report_steps_keep_outputs_inputs_and_profiles_independent(self):
        # NOT RUN. Catches global run/report-profile and run/reports collisions.
        from automation.reporting import report_command
        from automation.planner import validate_plan
        second = self.f.repo / 'second scans'
        second.mkdir()
        (self.input / 'marker').write_text('first input')
        (second / 'marker').write_text('second input')
        plan = validate_plan(Plan('two-reports', (
            Step('first', 'report', {'target': 'first.test', 'report_input': self.input}, ()),
            Step('second', 'report', {'target': 'second.test', 'report_input': second}, ()),
        ), 600))
        self.stub_engine(0, markers=True)
        preflight(plan, self.ctx, Permissions(frozenset(), frozenset({
            ('first', 'report_read'), ('second', 'report_read')})))
        run = self.f.repo / 'run'
        run.mkdir(mode=0o700)
        commands = []
        snapshots = []
        for step in plan.steps:
            with redirect_stderr(StringIO()) as warning:
                command = report_command(step, run, self.ctx)
            self.assertEqual(warning.getvalue(), REPORT_WARNING)
            commands.append(command)
            result = subprocess.run(command.argv, cwd=command.cwd, env=command.env,
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = Path(json.loads(result.stdout)['salida'])
            snapshots.append((output, (output / 'findings.json').read_bytes()))
        self.assertNotEqual(snapshots[0][0], snapshots[1][0])
        self.assertNotEqual(commands[0].env['REPORT_PROFILE'], commands[1].env['REPORT_PROFILE'])
        for index, (output, snapshot) in enumerate(snapshots):
            self.assertEqual((output / 'findings.json').read_bytes(), snapshot)
            self.assertEqual(json.loads(snapshot), (
                {'target': 'first.test', 'input': 'first input'},
                {'target': 'second.test', 'input': 'second input'})[index])
            profile = Path(commands[index].env['REPORT_PROFILE'])
            self.assertEqual(profile.read_text(), ('first.test', 'second.test')[index])
            self.assertEqual(profile.stat().st_mode & 0o777, 0o600)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
        with redirect_stderr(StringIO()) as warning, self.assertRaises(PreflightError):
            report_command(plan.steps[0], run, self.ctx)
        self.assertEqual(warning.getvalue(), '')
        self.assertEqual((snapshots[0][0] / 'findings.json').read_bytes(), snapshots[0][1])

    def test_report_engine_rc3(self):
        self.stub_engine()
        result = execute_plan(self.plan(), self.ctx, self.permissions)
        self.assertEqual(result.rc, 1)
        self.assertEqual(result.steps[0].rc, 3)
        self.assertEqual(result.steps[0].state, 'fallido')
        from automation.reporting import report_generation
        generation = report_generation(result.run_dir, 'report', 'example.test', 3)
        self.assertEqual(json.loads((generation / 'run.json').read_text())['estado'], 'NO_EVALUABLE')
        shim = self.shim('--target', 'example.test', '--execute', '--allow', 'report:report_read')
        self.assertEqual(shim.returncode, 3, shim.stderr)
        self.assertEqual({p.name for p in self.output.iterdir()}, set(REPORT_NAMES))

    def test_legacy_output_names(self):
        self.stub_engine(0)
        result = self.shim('--target', 'example.test', '--execute', '--allow', 'report:report_read')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('obsoleto', result.stdout)
        self.assertFalse((self.output / 'report.html').exists())
        self.assertEqual({p.name for p in self.output.iterdir()}, set(REPORT_NAMES))
        for name in REPORT_NAMES:
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
        permissions = Permissions(frozenset({'example.test'}), self.permissions.grants)
        # Independent literal closure: deriving this solely from ENGINE_SOURCES
        # would silently omit exactly the missing transitive dependencies.
        for relative in dict.fromkeys((*ENGINE_SOURCES, *NEW_ENGINE_SOURCES)):
            with self.subTest(source=relative):
                # Separate preserved fixtures keep an actual RED from polluting
                # the remaining missing-source checks with a prior run/log.
                fixture = AutomationFixture()
                self.addCleanup(fixture.close)
                fixture.stub('python3')
                fixture.stub('ping')
                scans = fixture.repo / 'synthetic input'
                scans.mkdir()
                report = build_plan('report', {'target': 'example.test', 'report_input': scans})
                plan = Plan('all-before-any', (ping, *report.steps), 300)
                ctx = RuntimeContext(fixture.framework, fixture.repo, Path(sys.executable), str(fixture.bin))
                self.assertIsNotNone(preserve(fixture.framework / relative), relative)
                with self.assertRaises(PreflightError):
                    execute_plan(plan, ctx, permissions)
                self.assertFalse((fixture.repo / 'scans').exists(), relative)
                self.assertEqual(fixture.records(), [], relative)

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
        preserve(self.f.framework / '11_Reports/report_engine.py')
        (self.f.framework / '11_Reports/report_engine.py').write_text('''import argparse
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--salida')
a, _ = p.parse_known_args()
for name in ('findings.json', 'informe_tecnico.md', 'informe_tecnico.html', 'informe_cliente.md', 'informe_cliente.html'):
    (Path(a.salida) / name).write_text('stale flat output is not a generation')
''')
        result = self.shim('--target', 'example.test', '--execute', '--allow', 'report:report_read')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(self.output.exists())

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
        (run / 'report-report').symlink_to(self.f.home, target_is_directory=True)
        with self.assertRaises(PreflightError):
            report_command(self.plan().steps[0], run, self.ctx)
        self.assertFalse((self.f.home / 'findings.json').exists())

    def test_no_external_output_input_from_workflow(self):
        with self.assertRaises(PlanError):
            build_plan('report', {'target': 'example.test', 'report_input': self.input,
                                  'output': self.output})

    def test_real_copied_engine_filters_target_and_no_evaluable_rc3(self):
        from automation.reporting import report_generation
        nmap = self.input / 'nmap'
        nmap.mkdir()
        (nmap / 'nmap_example.test.xml').write_text('''<nmaprun><host><status state="up"/>
<address addr="192.0.2.1" addrtype="ipv4"/><hostnames><hostname name="example.test"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
</host></nmaprun>''')
        (nmap / 'nmap_other.test.xml').write_text('<nmaprun><host><address addr="192.0.2.2"/></host></nmaprun>')
        # Full runner regression in this already-authorized RunStore case; no
        # expansion of the exact25 disposable-case inventory.
        other_input = self.f.repo / 'other scans'
        other_input.mkdir()
        other_nmap = other_input / 'nmap'
        other_nmap.mkdir()
        (other_nmap / 'nmap_second.xml').write_text(
            '<nmaprun><host><status state="up"/><address addr="192.0.2.2" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http"/></port></ports></host></nmaprun>')
        repeated = Plan('two-reports', (
            Step('first', 'report', {'target': '192.0.2.1', 'report_input': self.input}, ()),
            Step('second', 'report', {'target': '192.0.2.2', 'report_input': other_input}, ()),
        ), 600)
        repeated_result = execute_plan(repeated, self.ctx, Permissions(frozenset(), frozenset({
            ('first', 'report_read'), ('second', 'report_read')})))
        self.assertEqual(repeated_result.rc, 0, repeated_result.steps)
        self.assertEqual([row.state for row in repeated_result.steps], ['completado', 'completado'])
        for step_id, target, other in (('first', '192.0.2.1', '192.0.2.2'),
                                      ('second', '192.0.2.2', '192.0.2.1')):
            private = repeated_result.run_dir / ('report-' + step_id)
            generation = report_generation(repeated_result.run_dir, step_id, target, 0)
            self.assertEqual(generation.parent, private / 'reports/runs')
            receipt = json.loads((generation / 'run.json').read_text())
            self.assertEqual((receipt['objetivo'], receipt['estado'], receipt['rc']),
                             (target, 'COMPLETADO', 0))
            data = json.loads((generation / 'findings.json').read_text())
            self.assertEqual(data['meta']['objetivo'], target)
            self.assertIn(target, data['activos'])
            self.assertNotIn(other, data['activos'])
            self.assertEqual((private / 'report-profile').read_bytes(), b'')
        # Nmap attributes assets by address, not XML hostnames. Use the
        # declared address as target; content identity must beat the filename.
        plan = build_plan('report', {'target': '192.0.2.1', 'report_input': self.input})
        result = execute_plan(plan, self.ctx, self.permissions)
        self.assertEqual(result.rc, 0, result.steps)
        generation = report_generation(result.run_dir, 'report', '192.0.2.1', 0)
        data = json.loads((generation / 'findings.json').read_text())
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
        generation = report_generation(result.run_dir, 'report', '192.0.2.1', 3)
        self.assertEqual(json.loads((generation / 'run.json').read_text())['estado'], 'NO_EVALUABLE')


class ReportGenerationTests(unittest.TestCase):
    """Parser-only fresh synthetic trees: no RunStore, replacement or cleanup.

    Catches adopting latest/flat/foreign generations, trusting stdout alone,
    accepting partial or non-final receipts and following untrusted links.
    """

    def setUp(self):
        self.f = AutomationFixture()
        self.addCleanup(self.f.close)
        self.sequence = 0

    def fixture(self, *, summary_changes=None, receipt_changes=None, stdout=None,
                disk=None, omit=(), link=None):
        self.sequence += 1
        run = self.f.repo / ('parser-' + str(self.sequence))
        run.mkdir(mode=0o700)
        parent = run
        for component in ('report-report', 'reports', 'runs', RUN_ID):
            directory = parent / component
            if link == component:
                target = self.f.repo / ('linked-directory-' + str(self.sequence))
                target.mkdir(mode=0o700)
                directory.symlink_to(target, target_is_directory=True)
            else:
                directory.mkdir(mode=0o700)
            parent = directory
        generation = parent
        receipt = {'schema_version': 1, 'module': '11', 'run_id': RUN_ID,
                   'started_at': '2026-11-14T12:00:00+00:00',
                   'finished_at': '2026-11-14T12:00:01+00:00',
                   'objetivo': 'example.test', 'modo': 'objetivo', 'tipo': 'ambos',
                   'entrada': 'scans', 'estado': 'COMPLETADO', 'rc': 0,
                   'archivos': list(REPORT_NAMES)}
        receipt.update(receipt_changes or {})
        summary = {'objetivo': 'example.test', 'hallazgos': 0, 'criticos': 0,
                   'no_evaluable': 0, 'salida': str(generation), 'run_id': RUN_ID,
                   'archivos': [str(generation / name) for name in (*REPORT_NAMES, 'run.json')]}
        summary.update(summary_changes(generation) if callable(summary_changes) else summary_changes or {})
        for name in (*REPORT_NAMES, 'run.json'):
            if name in omit:
                continue
            path = generation / name
            if name == link:
                foreign = self.f.repo / ('foreign-' + str(self.sequence))
                foreign.write_text('{}')
                path.symlink_to(foreign)
            else:
                with path.open('x') as stream:
                    stream.write((disk(receipt) if callable(disk) else disk if disk is not None else json.dumps(receipt))
                                 if name == 'run.json' else '{}')
                path.chmod(0o600)
        logs = run / 'logs'
        logs.mkdir(mode=0o700)
        if 'stdout' not in omit:
            log = logs / 'report.stdout.log'
            if link == 'stdout':
                log.symlink_to(generation / 'run.json')
            else:
                with log.open('x') as stream:
                    stream.write(stdout(summary) if callable(stdout) else
                                 json.dumps(summary) + '\n' if stdout is None else stdout)
                log.chmod(0o600)
        return run, generation

    def test_current_generation_rc0_and_rc3(self):
        from automation.reporting import report_generation
        run, generation = self.fixture()
        self.assertEqual(report_generation(run, 'report', 'example.test', 0), generation)
        run, generation = self.fixture(receipt_changes={'rc': 3, 'estado': 'NO_EVALUABLE'},
                                       summary_changes={'no_evaluable': 1})
        self.assertEqual(report_generation(run, 'report', 'example.test', 3), generation)

    def test_receipt_selects_current_generation_not_unreferenced_history(self):
        from automation.reporting import report_generation
        run, generation = self.fixture()
        decoy = generation.parent / ('run-20261114T130000000000Z-' + 'b' * 32)
        decoy.mkdir(mode=0o700)
        receipt = json.loads((generation / 'run.json').read_text())
        receipt.update(run_id=decoy.name, objetivo='other.test')
        for name in REPORT_NAMES:
            with (decoy / name).open('x') as stream:
                stream.write('foreign historical report')
        with (decoy / 'run.json').open('x') as stream:
            json.dump(receipt, stream)
        self.assertEqual(report_generation(run, 'report', 'example.test', 0), generation)

    def test_absent_invalid_duplicate_or_oversized_stdout(self):
        from automation.reporting import report_generation
        variants = ({'omit': ('stdout',)}, {'stdout': ''}, {'stdout': '{'},
                    {'stdout': '[]'}, {'stdout': '{}'}, {'stdout': '{}\n{}\n'},
                    # A last-line-only reader would accept the valid second summary;
                    # require rejection of the complete multi-document stdout instead.
                    {'stdout': lambda s: (json.dumps(s) + '\n') * 2},
                    {'stdout': lambda s: json.dumps(s)[:-1] + ',"run_id":"foreign"}'},
                    # Last-wins yields the otherwise valid original summary;
                    # only duplicate-key rejection can reject this object.
                    {'stdout': lambda s: json.dumps(s)[:-1] + ',"run_id":' + json.dumps(RUN_ID) + '}'},
                    {'stdout': ' ' * (1024 * 1024 + 1)})
        for variant in variants:
            with self.subTest(variant=str(variant)[:100]):
                run, _ = self.fixture(**variant)
                with self.assertRaises(PreflightError):
                    report_generation(run, 'report', 'example.test', 0)

    def test_stdout_target_identity_and_paths_are_bound_to_step(self):
        from automation.reporting import report_generation
        variants = (
            {'objetivo': 'other.test'}, {'run_id': 'foreign'},
            {'salida': '/tmp/foreign/reports/runs/' + RUN_ID},
            lambda p: {'salida': str(p).replace('report-report/', 'report-other/')},
            lambda p: {'salida': str(p / '..' / p.name)},
            lambda p: {'archivos': [str(p / n) for n in REPORT_NAMES]},
            lambda p: {'archivos': [str(p / n) for n in (*REPORT_NAMES, 'run.json', 'run.json')]},
            lambda p: {'archivos': ['/tmp/foreign/findings.json'] +
                       [str(p / n) for n in (*REPORT_NAMES[1:], 'run.json')]},
            lambda p: {'archivos': [str(p / '..' / p.name / n) for n in (*REPORT_NAMES, 'run.json')]},
        )
        for variant in variants:
            with self.subTest(variant=variant):
                run, _ = self.fixture(summary_changes=variant)
                with self.assertRaises(PreflightError):
                    report_generation(run, 'report', 'example.test', 0)

    def test_final_disk_receipt_must_match_identity_target_type_mode_and_rc(self):
        from automation.reporting import report_generation
        variants = ({'objetivo': 'other.test'}, {'run_id': 'foreign'}, {'module': '10'},
                    {'schema_version': True}, {'modo': 'todos'}, {'tipo': 'cliente'},
                    {'entrada': 'unknown'}, {'finished_at': None},
                    {'finished_at': '2026-11-14T11:00:00+00:00'},
                    {'estado': 'ESCRIBIENDO', 'finished_at': None, 'rc': None, 'archivos': []},
                    {'estado': 'NO_EVALUABLE', 'rc': 3}, {'rc': True},
                    {'archivos': list(REPORT_NAMES[:-1])},
                    {'archivos': ['../findings.json', *REPORT_NAMES[1:]]})
        for variant in variants:
            with self.subTest(variant=variant):
                run, _ = self.fixture(receipt_changes=variant)
                with self.assertRaises(PreflightError):
                    report_generation(run, 'report', 'example.test', 0)

        # Both rc occurrences are valid0, matching COMPLETADO and process rc0.
        # A last-wins parser must not pass by rejecting an unrelated mismatch.
        run, _ = self.fixture(disk=lambda r: json.dumps(r)[:-1] + ',"rc":0}')
        with self.assertRaises(PreflightError):
            report_generation(run, 'report', 'example.test', 0)

    def test_missing_malformed_or_incomplete_disk_generation(self):
        from automation.reporting import report_generation
        variants = [{'omit': (name,)} for name in (*REPORT_NAMES, 'run.json')]
        variants += [{'disk': '{'}, {'disk': '[]'},
                     {'disk': lambda r: json.dumps(r)[:-1] + ',"rc":3}'},
                     {'disk': ' ' * (1024 * 1024 + 1)}]
        for variant in variants:
            with self.subTest(variant=str(variant)[:100]):
                run, _ = self.fixture(**variant)
                with self.assertRaises(PreflightError):
                    report_generation(run, 'report', 'example.test', 0)

    def test_symlinked_files_and_generation_ancestors_are_rejected(self):
        from automation.reporting import report_generation
        for name in (*REPORT_NAMES, 'run.json', 'stdout', 'report-report', 'reports', 'runs', RUN_ID):
            with self.subTest(link=name):
                run, _ = self.fixture(link=name)
                with self.assertRaises(PreflightError):
                    report_generation(run, 'report', 'example.test', 0)
        run, generation = self.fixture()
        alias = self.f.repo / 'run-alias'
        alias.symlink_to(run, target_is_directory=True)
        with self.assertRaises(PreflightError):
            report_generation(alias, 'report', 'example.test', 0)
        # Fresh name aliases the existing private step: no replacement/removal.
        (run / 'report-alias').symlink_to(generation.parent.parent.parent, target_is_directory=True)
        with self.assertRaises(PreflightError):
            report_generation(run, 'alias', 'example.test', 0)

    def test_invalid_step_ids_and_process_rc_are_rejected(self):
        from automation.reporting import report_generation
        run, _ = self.fixture()
        for step_id in ('', '.', '..', '../report', 'report/child', '/report'):
            with self.subTest(step_id=step_id), self.assertRaises(PreflightError):
                report_generation(run, step_id, 'example.test', 0)
        for rc in (1, 2, -1, True, '0'):
            with self.subTest(rc=rc), self.assertRaises(PreflightError):
                report_generation(run, 'report', 'example.test', rc)


if __name__ == '__main__':
    unittest.main()
