"""Historial CLI/fase con fuentes y destinos sintéticos."""
import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / '11_Reports'))
import report_engine
from lib import history
from lib.publication import write_private


class HistoryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.root / 'out'
        self.scans = self.root / 'scans'
        self.scans.mkdir()
        self.profile = self.root / 'profile'
        self.profile.write_text('cliente=Synthetic\nauditor=Test\n')
        self.session = self.root / 'session'
        self.session.write_text('192.0.2.10\n')
        self.env = patch.dict(os.environ, REPORT_OUT_DIR=str(self.base), REPORT_SCANS_DIR=str(self.scans),
                              REPORT_PROFILE=str(self.profile), SESSION_FILE=str(self.session),
                              REPORT_FRAMEWORK_ROOT=str(self.root / 'no-modules'))
        self.env.start()
        self.addCleanup(self.env.stop)
        folder = self.scans / 'nmap'
        folder.mkdir()
        (folder / 'a.xml').write_text('<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>')

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = report_engine.run([*args, '--json'])
        return rc, json.loads(stdout.getvalue()) if stdout.getvalue() else None, stderr.getvalue()

    def test_cli_generates_distinct_runs_without_overwriting(self):
        for tipo, expected_count in (('tecnico', 4), ('cliente', 4), ('ambos', 6)):
            with self.subTest(tipo=tipo):
                rc, first, _ = self.run_cli('--tipo', tipo)
                self.assertEqual(rc, 0)
                self.assertIn('run_id', first)
                path = Path(first['salida'])
                self.assertEqual(path.parent, self.base / 'runs')
                self.assertEqual(path.name, first['run_id'])
                self.assertEqual(len(first['archivos']), expected_count)
                before = {p: Path(p).read_bytes() for p in first['archivos']}
                rc, second, _ = self.run_cli('--tipo', tipo)
                self.assertNotEqual(first['run_id'], second['run_id'])
                self.assertEqual(before, {p: Path(p).read_bytes() for p in first['archivos']})
                self.assertFalse((self.base / 'findings.json').exists())

    def test_default_custom_and_all_roots(self):
        fw = self.root / 'framework'
        with patch.object(report_engine, '_FRAMEWORK_ROOT', fw):
            del os.environ['REPORT_OUT_DIR']
            rc, default, _ = self.run_cli()
            self.assertEqual(rc, 0)
            self.assertEqual(Path(default['salida']).parent.parent, fw / '11_Reports/generated/192.0.2.10')
            rc, aggregated, _ = self.run_cli('--todos')
            self.assertEqual(rc, 0)
            self.assertEqual(Path(aggregated['salida']).parent.parent, fw / '11_Reports/generated/_todos')
            custom = self.root / 'custom'
            rc, result, _ = self.run_cli('--salida', str(custom))
            self.assertEqual(Path(result['salida']).parent.parent, custom)

    def test_invalid_input_does_not_reserve_run(self):
        rc, receipt, _ = self.run_cli('--objetivo', '')
        self.assertEqual(rc, 1)
        self.assertIsNone(receipt)
        self.assertFalse(self.base.exists())

    def test_ipv6_record_can_be_reported_by_cli_without_dns(self):
        folder = self.scans / 'rustscan'
        folder.mkdir()
        (folder / 'rustscan_ipv6.txt').write_text('Open [2001:db8::10]:443\n')
        rc, result, error = self.run_cli('--objetivo', '2001:db8::10')
        self.assertEqual(rc, 0, error)
        data = json.loads((Path(result['salida']) / 'findings.json').read_text())
        self.assertEqual(data['objetivos'], ['2001:db8::10'])

    def test_aggregated_run_does_not_label_session_host_as_entire_scope(self):
        rc, result, _ = self.run_cli('--todos')
        self.assertEqual(rc, 0)
        receipt = json.loads((Path(result['salida']) / 'run.json').read_text())
        data = json.loads((Path(result['salida']) / 'findings.json').read_text())
        self.assertEqual(receipt['objetivo'], '')
        self.assertNotEqual(data['meta']['alcance'], '192.0.2.10')

    def test_write_failure_never_returns_receipt_or_opens_old_html(self):
        rc, first, _ = self.run_cli()
        before = {p: Path(p).read_bytes() for p in first['archivos']}
        counter = []
        def fail_second(path, text):
            counter.append(path)
            if len(counter) == 2:
                raise OSError('synthetic disk full')
            write_private(path, text)
        with patch('lib.render.write_private', side_effect=fail_second), patch.object(report_engine.subprocess, 'run', side_effect=AssertionError('must not open old HTML')):
            rc, receipt, _ = self.run_cli('--abrir')
        self.assertEqual(rc, 1)
        self.assertIsNone(receipt)
        self.assertEqual(before, {p: Path(p).read_bytes() for p in first['archivos']})
        runs = list((self.base / 'runs').iterdir())
        self.assertEqual(len(runs), 2)
        self.assertEqual(sum(history.published(p) for p in runs), 1)

    def test_rc3_has_final_limited_receipt(self):
        rc, result, _ = self.run_cli('--objetivo', '192.0.2.99')
        self.assertEqual(rc, 3)
        data = json.loads((Path(result['salida']) / 'run.json').read_text())
        self.assertEqual((data['estado'], data['rc']), ('NO_EVALUABLE', 3))
        self.assertTrue(history.published(Path(result['salida'])))

    def test_rerender_never_mutates_input_or_reads_sources(self):
        _, initial, _ = self.run_cli()
        source = Path(initial['salida']) / 'findings.json'
        data = json.loads(source.read_text())
        data['meta']['generado_en'] = '2000-01-01T00:00:00+00:00'
        source.write_text(json.dumps(data))
        before = {p: Path(p).read_bytes() for p in initial['archivos']}
        with patch.object(report_engine, 'collect', side_effect=AssertionError('must not read sources')):
            rc, newer, _ = self.run_cli('--desde-json', str(source))
        self.assertEqual(rc, 0)
        self.assertIn('run_id', newer)
        self.assertNotEqual(newer['run_id'], initial['run_id'])
        self.assertEqual(before, {p: Path(p).read_bytes() for p in initial['archivos']})
        rendered = json.loads((Path(newer['salida']) / 'findings.json').read_text())
        self.assertNotEqual(rendered['meta']['generado_en'], '2000-01-01T00:00:00+00:00')
        self.assertIsNotNone(datetime.fromisoformat(rendered['meta']['generado_en']).tzinfo)
        self.assertEqual(json.loads((Path(newer['salida']) / 'run.json').read_text())['entrada'], 'json')

    def phase(self, fw):
        script = FW / '00_Config/lib/phase_status.bash'
        result = subprocess.run(['bash', '-c', 'source "$1"; phase_state 11_Reports', 'test', str(script)],
                                env=dict(os.environ, PHASE_FW_DIR=str(fw)), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_phase_status_ignores_incomplete_and_accepts_final_and_legacy(self):
        fw = self.root / 'fw'
        run = history.reserve(fw / '11_Reports/generated/target', '192.0.2.10', 'objetivo', 'tecnico', 'scans')
        files = []
        for name in ('findings.json', 'informe_tecnico.md', 'informe_tecnico.html'):
            write_private(run.path / name, 'synthetic')
            files.append(run.path / name)
        self.assertEqual(self.phase(fw), 'pending')
        receipt = history.finish(run, files, 3)
        self.assertEqual(self.phase(fw), 'done')
        valid = receipt.read_bytes()
        receipt.write_text('{}')
        self.assertEqual(self.phase(fw), 'pending')
        receipt.write_bytes(valid)
        files[0].unlink()
        self.assertEqual(self.phase(fw), 'pending')
        legacy = fw / '11_Reports/generated/legacy/findings.json'
        legacy.parent.mkdir(parents=True)
        legacy.write_text('{}')
        self.assertEqual(self.phase(fw), 'done')

    def test_legacy_presence_does_not_follow_symlinks(self):
        fw = self.root / 'fw'
        directory = fw / '11_Reports/generated/legacy'
        directory.mkdir(parents=True)
        outside = self.root / 'private'
        outside.write_text('PRIVATE')
        (directory / 'findings.json').symlink_to(outside)
        self.assertEqual(self.phase(fw), 'pending')


if __name__ == '__main__':
    unittest.main()
