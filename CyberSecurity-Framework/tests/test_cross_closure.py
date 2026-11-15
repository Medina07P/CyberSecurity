"""Closed closure contracts. Business imports occur only inside worker cases."""
from contextlib import ExitStack, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import signal
import sys
from tempfile import mkdtemp
import unittest
from unittest import mock


def scratch():
    from automation_case_scope import fixture_parent, in_worker
    if not in_worker():
        raise RuntimeError('Closure contracts require the isolated case worker')
    return Path(mkdtemp(prefix='closure-', dir=fixture_parent()))


def product():
    sys.path.insert(0, '/source/CyberSecurity-Framework/00_Config/lib')
    from automation import cli, model
    return cli, model


class SummaryTests(unittest.TestCase):
    def test_cli_summary_is_safe(self):
        cli, model = product()
        from automation.summary import render_result
        root = scratch()
        ctx = model.RuntimeContext(root, root, Path(sys.executable), '')
        for rc, code, reason in ((0, 'completed', 'completado'),
                                 (1, 'timeout', 'tiempo agotado'),
                                 (2, 'setup_failed', 'fallo de preparación'),
                                 (1, 'storage_failed', 'fallo de almacenamiento'),
                                 (1, 'backend_failed', 'fallo de backend'),
                                 (130, 'cancelled', 'cancelado por señal'),
                                 (143, 'cancelled', 'cancelado por señal'),
                                 (1, 'untrusted\x1b[31mSYNTHETIC_SECRET', 'no determinado')):
            for run_dir in (None, root / 'new-run', Path('/bad\nSYNTHETIC_SECRET'),
                            Path('relative'), Path('/' + 'a' * 4096)):
                with self.subTest(rc=rc, code=code, run_dir=run_dir):
                    result = model.RunResult(rc, run_dir, (
                        model.StepResult('SYNTHETIC_SECRET\x1b[31m', 'fallido', rc,
                                         'SYNTHETIC_SECRET\n\x1b[31m'),), reason_code=code)
                    text = render_result(result)
                    expected = f'Resultado: rc={rc}; motivo={reason}.'
                    if run_dir == root / 'new-run':
                        expected += '\nRun: ' + str(run_dir)
                    self.assertEqual(text, expected)
                    output = StringIO()
                    with mock.patch.object(cli, 'execute_plan', return_value=result), redirect_stdout(output):
                        actual_rc = cli.main(['--action', 'ping', '--target', 'example.test', '--execute',
                                              '--authorized-target', 'example.test'], ctx=ctx)
                    self.assertEqual(actual_rc, rc)
                    self.assertEqual(output.getvalue().count(expected), 1)
                    self.assertNotIn('SYNTHETIC_SECRET', output.getvalue())
                    self.assertNotIn('\x1b', output.getvalue())
        with mock.patch.object(cli, 'execute_plan', side_effect=AssertionError('preview executed')), \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(cli.main(['--action', 'ping', '--target', 'example.test'], ctx=ctx), 0)
        self.assertNotIn('Resultado:', output.getvalue())

    def test_interactive_summary_and_pre_store_failure(self):
        cli, model = product()
        from automation import runner
        from automation.planner import build_plan
        root = scratch()
        ctx = model.RuntimeContext(root, root, Path(sys.executable), '')
        plan = build_plan('ping', {'target': 'example.test'})
        permissions = model.Permissions(frozenset({'example.test'}), frozenset())
        with mock.patch.object(runner.RunStore, 'create', side_effect=OSError('SYNTHETIC_SECRET')):
            failed = runner.run_plan(plan, ctx, permissions, mock.Mock())
        self.assertEqual((failed.rc, failed.run_dir, failed.reason_code), (1, None, 'storage_failed'))
        for result in (failed, model.RunResult(1, root / 'run', (), 'storage_failed')):
            output = StringIO()
            with mock.patch('builtins.input', side_effect=['EJECUTAR', 'example.test']), \
                    mock.patch.object(cli, 'execute_plan', return_value=result) as execute, redirect_stdout(output):
                self.assertEqual(cli.interactive_plan(plan, ctx), 1)
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(output.getvalue().count('Resultado: rc=1; motivo=fallo de almacenamiento.'), 1)
            self.assertEqual('Run: ' in output.getvalue(), result.run_dir is not None)
            self.assertNotIn('SYNTHETIC_SECRET', output.getvalue())
        with mock.patch('builtins.input', return_value='NO'), \
                mock.patch.object(cli, 'execute_plan', side_effect=AssertionError('cancel executed')), \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(cli.interactive_plan(plan, ctx), 0)
        self.assertNotIn('Resultado:', output.getvalue())


class TerminalTests(unittest.TestCase):
    def simulate(self, exception, *, ready=False, result_first=False, reap_error=False,
                 receipt_error=None, preexisting_terminal=False):
        # Real parent orchestration and receipt IO; ONLY fork/reap/pipe result
        # transport are simulated. No signals or processes are sent/created.
        import automation_case_worker as worker
        import automation_case_scope as scope
        import automation_suite_selection as selection
        import automation_sandbox_inside as inside
        outer = scratch()
        root = outer / 'registered-root'
        root.mkdir(mode=0o700)
        evidence = outer / 'evidence'
        evidence.mkdir(mode=0o700)
        case_id = self.id()
        case = mock.Mock(id=lambda: case_id)
        controller = mock.Mock(__file__='/source/CyberSecurity-Framework/tests/automation_sandbox_inside.py')
        controller.validated_diagnostic_context.return_value = True
        controller.validated_selection.return_value = '--cross-closure'
        result_path = evidence / 'case-00001.result.json'
        terminal = evidence / 'case-00001.terminal.json'
        if result_first:
            result_path.write_text('existing-result\n')
        if preexisting_terminal:
            terminal.write_text('existing-terminal\n')
        originals = {p: (p.read_bytes(), p.stat().st_mode) for p in (result_path, terminal) if p.exists()}
        actual_open = os.open
        actual_write = os.write
        actual_stat = os.stat
        actual_pipe = os.pipe2
        opened_fds = []
        oldmask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        events = []

        def translate(path):
            path = Path(path)
            return evidence / path.name if path.parent == Path('/evidence') else path

        def open_at(path, flags, mode=0o777, *, dir_fd=None):
            translated = translate(path) if not isinstance(path, int) else path
            if not isinstance(translated, int) and str(translated).endswith('.terminal.json'):
                events.append('terminal')
                if receipt_error in ('ENOSPC', 'EACCES'):
                    import errno
                    raise OSError(getattr(errno, receipt_error), 'synthetic IO failure')
            fd = actual_open(translated, flags, mode, dir_fd=dir_fd)
            opened_fds.append(fd)
            return fd

        def stat_at(path, **kwargs):
            return actual_stat(translate(path) if not isinstance(path, int) else path, **kwargs)

        def pipe(flags):
            pair = actual_pipe(flags)
            opened_fds.extend(pair)
            return pair

        def write_json(path, value):
            with translate(path).open('x') as stream:
                json.dump(value, stream)

        def collect(*args, on_ready=None):
            if ready and on_ready is not None:
                on_ready()
            if exception is None:
                return {'id': case_id, 'state': 'FAIL', 'successful': False, 'ready': ready}
            raise exception

        def reap():
            events.append('reap')
            if reap_error:
                raise OSError('synthetic reap failure')

        def write(fd, body):
            if receipt_error == 'shortwrite':
                return actual_write(fd, body[:1])
            return actual_write(fd, body)

        with ExitStack() as stack:
            for patcher in (
                mock.patch.dict(sys.modules, {'__main__': controller}),
                mock.patch.object(scope, 'in_worker', return_value=False),
                mock.patch.object(selection, 'case_disposable_allowed', return_value=False),
                mock.patch.object(worker, '_prctl'),
                mock.patch.object(worker, 'mkdtemp', return_value=str(root)),
                mock.patch.object(worker.os, 'fork', return_value=12345),
                mock.patch.object(worker.os, 'open', side_effect=open_at),
                mock.patch.object(worker.os, 'stat', side_effect=stat_at),
                mock.patch.object(worker.os, 'pipe2', side_effect=pipe),
                mock.patch.object(worker.os, 'write', side_effect=write),
                mock.patch.object(worker, '_collect_result', side_effect=collect),
                mock.patch.object(worker, 'reap_owned', side_effect=reap),
                mock.patch.object(inside, 'write_json', side_effect=write_json),
            ):
                stack.enter_context(patcher)
            with self.assertRaises(type(exception) if exception is not None else OSError) as caught:
                worker.run_case(case, False, 1)
            if exception is not None:
                self.assertIs(caught.exception, exception, 'receipt/reap must not mask primary cancellation')
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), oldmask)
        for fd in set(opened_fds):
            with self.assertRaises(OSError):
                os.fstat(fd)
        for path, before in originals.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mode), before)
        if receipt_error in ('ENOSPC', 'EACCES'):
            self.assertFalse(terminal.exists(), 'failed open must not leave a terminal receipt')
            return
        if receipt_error == 'shortwrite':
            self.assertTrue(terminal.is_file(), 'short write must retain its partial receipt')
            self.assertEqual(terminal.read_bytes(), b'{')
            with self.assertRaises(ValueError):
                json.loads(terminal.read_text())
            return
        if preexisting_terminal:
            self.assertEqual(terminal.read_text(), 'existing-terminal\n')
            return
        self.assertTrue(terminal.is_file(), 'parent terminal receipt is required when IO permits')
        value = json.loads(terminal.read_text())
        self.assertEqual(value, {
            'version': 1, 'case_id': case_id, 'state': 'CANCELLED' if exception is not None else 'ERROR',
            'ready': ready, 'reaped': not reap_error, 'result_present': result_first or exception is None,
            'exception_type': type(exception).__name__ if exception is not None else 'OSError',
            'signal': ('INT' if isinstance(exception, KeyboardInterrupt) else 'TERM') if exception is not None else None})
        self.assertEqual(terminal.stat().st_mode & 0o777, 0o600)

    def test_cancel_before_and_after_ready(self):
        for ready in (False, True):
            for exception in (KeyboardInterrupt(), SystemExit(143)):
                with self.subTest(ready=ready, exception=type(exception).__name__):
                    self.simulate(exception, ready=ready)

    def test_existing_result_is_preserved(self):
        self.simulate(KeyboardInterrupt(), ready=True, result_first=True)
        self.simulate(SystemExit(143), result_first=True, preexisting_terminal=True)

    def test_receipt_io_failure_preserves_cancellation(self):
        for error in ('ENOSPC', 'EACCES', 'shortwrite'):
            with self.subTest(error=error):
                self.simulate(KeyboardInterrupt(), receipt_error=error)

    def test_reap_failure_is_not_success(self):
        self.simulate(KeyboardInterrupt(), ready=True, reap_error=True)
        self.simulate(None, reap_error=True)
