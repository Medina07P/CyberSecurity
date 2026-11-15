"""CLI boundaries: explicit selection, exact outcomes, synthetic closed PATH only."""
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest import mock

from evidence_fixture import sandbox, copy_sources, closed_env, snapshot


class CliTests(unittest.TestCase):
    def setUp(self):
        context = sandbox()
        self.base = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.framework = copy_sources(self.base)
        self.root = self.framework / '10_Evidence'
        self.env = closed_env(self.base)
        for name in list(sys.modules):
            if name == 'evidence' or name.startswith('evidence.'):
                del sys.modules[name]
        sys.path.insert(0, str(self.framework / '00_Config/lib'))
        self.addCleanup(sys.path.pop, 0)
        self.cli = importlib.import_module('evidence.cli')

    def wrapper(self, name, *args, env=None):
        return subprocess.run(['/bin/bash', str(self.root / name), *args], cwd=self.base,
                              env=env or self.env, stdin=subprocess.DEVNULL,
                              text=True, capture_output=True, timeout=15)

    def main(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = self.cli.main(['--root', str(self.root), *args])
        return rc, out.getvalue()

    def test_all_wrappers_help_missing_extra_args_and_external_cwd(self):
        before = snapshot(self.framework)
        for name in ('evidence_manager.sh', 'auto_capture.sh', 'run_all_evidence.sh'):
            for args, expected in [(('--help',), 0), ((), 2), (('--bogus',), 2),
                                   (('--help', 'extra'), 2)]:
                with self.subTest(name=name, args=args):
                    result = self.wrapper(name, *args)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertEqual(snapshot(self.framework), before)

    def test_legacy_target_returns_2_without_launching_tools(self):
        before = snapshot(self.framework)
        for name in ('auto_capture.sh', 'run_all_evidence.sh'):
            result = self.wrapper(name, '192.0.2.1')
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn('explícita', result.stderr)
        self.assertEqual(snapshot(self.framework), before)

    def test_offline_never_calls_capture(self):
        with mock.patch.object(self.cli, 'capture', side_effect=AssertionError('capture offline')):
            rc, text = self.main('run', '--offline')
        self.assertEqual(rc, 1)
        self.assertIn('SIN EVIDENCIA', text)
        self.assertFalse((self.root / 'logs').exists())

    def test_capture_list_verify_failures_are_not_swallowed(self):
        source = self.base / 'sample'
        source.write_text('synthetic')
        self.assertEqual(self.main('manage', '--add', 'proof', str(source))[0], 0)
        for stage in ('capture', 'scan', 'verify'):
            with self.subTest(stage=stage):
                replacement = mock.patch.object(self.cli, stage, return_value=1) if stage == 'capture' else mock.patch.object(
                    self.cli, stage, side_effect=self.cli.EvidenceError('synthetic failure'))
                with replacement:
                    rc, text = self.main('run', '--capture', '--system')
                self.assertEqual(rc, 1, text)
                self.assertNotIn('RESUMEN: COMPLETO', text)
        with mock.patch.object(self.cli, 'capture', return_value=0):
            self.assertEqual(self.main('run', '--capture', '--system')[0], 0)

    def test_signal_rc_not_replaced_by_followup_verify(self):
        for code in (130, 143):
            with mock.patch.object(self.cli, 'capture', return_value=code), mock.patch.object(
                    self.cli, 'scan', side_effect=AssertionError('list after signal')), mock.patch.object(
                    self.cli, 'verify', side_effect=AssertionError('verify after signal')):
                self.assertEqual(self.main('run', '--capture', '--system')[0], code)

    def test_raised_signals_stop_workflow_and_restore_handlers(self):
        for stage in ('capture', 'scan', 'verify'):
            for signum, expected in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
                before = signal.getsignal(signum)
                def interrupt(*args):
                    os.kill(os.getpid(), signum)
                with self.subTest(stage=stage, signum=signum), mock.patch.object(
                        self.cli, stage, side_effect=interrupt):
                    # SIGTERM is raised through the CLI handler, not delivered to
                    # the test runner until a handler exists (RED remains safe).
                    if signal.getsignal(signum) == signal.SIG_DFL:
                        def fallback(number, frame):
                            raise self.cli.CaptureInterrupted(number)
                        signal.signal(signum, fallback)
                    try:
                        expected_handler = signal.getsignal(signum)
                        rc, text = self.main('run', '--capture', '--system')
                        self.assertEqual(signal.getsignal(signum), expected_handler)
                    finally:
                        signal.signal(signum, before)
                self.assertEqual(rc, expected, text)
                self.assertNotIn('RESUMEN: COMPLETO', text)

    def test_wrapper_preserves_capture_signals_without_verification(self):
        for name, prefix in (('auto_capture.sh', []), ('run_all_evidence.sh', ['--capture'])):
            for signum, expected in (('INT', 130), ('TERM', 143)):
                env = closed_env(self.base, {'cutycapt': f'kill -{signum} "$PPID"\nexit 0\n'})
                result = self.wrapper(name, *prefix, '--web', 'https://example.test', '--authorize-network', env=env)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertNotIn('VERIFICACIÓN', result.stdout)

    def test_spaces_in_import_and_description_survive_wrapper(self):
        source = self.base / 'sample with spaces'
        source.write_text('synthetic')
        result = self.wrapper('evidence_manager.sh', '--add', 'proof', str(source), 'two words', '--target', 'label only')
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = list(self.root.glob('proofs/*/*/evidence.json'))
        if not metadata:
            metadata = list(self.root.rglob('evidence.json'))
        data = json.loads(metadata[0].read_text())
        self.assertEqual(data['description'], 'two words')
        self.assertEqual(data['target'], 'label only')
        self.assertEqual(self.wrapper('run_all_evidence.sh', '--offline').returncode, 0)

    def test_invalid_options_leave_roots_absent(self):
        cases = [[], ['--authorize-network'], ['--system', '--duration', '10'],
                 ['--system', '--packet-limit', '100'], ['--system', '--system'],
                 ['--web', 'https://example.test'], ['--scan', '192.0.2.1-5', '--scan-profile', 'basic', '--authorize-network'],
                 ['--system', '--interface', 'lo'], ['--system', '--scan-profile', 'basic'],
                 ['--system', '--web', 'bad', '--authorize-network'],
                 ['--system', '--duration', 'bad'], ['--web', 'https://a.test', '--web', 'https://b.test']]
        before = snapshot(self.framework)
        for args in cases:
            for prefix in (['capture'], ['run', '--capture']):
                with self.subTest(args=prefix + args):
                    self.assertEqual(self.main(*(prefix + args))[0], 2)
        for args in (['--offline', '--capture', '--system'], ['--offline', '--system'],
                     ['--offline', '--authorize-network'], ['--offline', '--duration', '10'],
                     ['--offline', '--offline'], ['--capture', '--capture', '--system']):
            self.assertEqual(self.main('run', *args)[0], 2)
        self.assertEqual(snapshot(self.framework), before)

    def test_system_without_network_and_closed_stdin(self):
        result = self.wrapper('run_all_evidence.sh', '--capture', '--system')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESUMEN: COMPLETO', result.stdout)

    def test_failed_backend_is_visible_and_never_complete(self):
        env = closed_env(self.base, {'cutycapt': 'echo synthetic-failure >&2\nexit 7\n'})
        for name, prefix in (('auto_capture.sh', []), ('run_all_evidence.sh', ['--capture'])):
            result = self.wrapper(name, *prefix, '--web', 'https://example.test', '--authorize-network', env=env)
            self.assertEqual(result.returncode, 1)
            self.assertIn('CAPTURA: FALLIDA', result.stdout + result.stderr)
            self.assertNotIn('RESUMEN: COMPLETO', result.stdout)

    def test_empty_successful_capture_is_not_complete_workflow(self):
        with mock.patch.object(self.cli, 'capture', return_value=0):
            rc, text = self.main('run', '--capture', '--system')
        self.assertEqual(rc, 1)
        self.assertIn('SIN EVIDENCIA', text)

    def test_missing_python_is_visible_without_fallback(self):
        empty = self.base / 'empty-bin'
        empty.mkdir()
        env = dict(self.env, PATH=str(empty))
        before = snapshot(self.framework)
        for name in ('evidence_manager.sh', 'auto_capture.sh', 'run_all_evidence.sh'):
            result = self.wrapper(name, '--help', env=env)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Python 3', result.stderr)
        self.assertEqual(snapshot(self.framework), before)

    def test_expected_os_errors_are_clear_without_traceback(self):
        with mock.patch.object(self.cli, 'scan', side_effect=PermissionError('synthetic denied')):
            rc, text = self.main('run', '--offline')
        self.assertEqual(rc, 1)
        self.assertIn('ERROR', text)
        self.assertNotIn('Traceback', text)


if __name__ == '__main__':
    unittest.main()
