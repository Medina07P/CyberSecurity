"""Landlock/case-worker regressions written first. NOT RUN before review."""
import ast
import ctypes
import errno
from pathlib import Path
import unittest
from unittest import mock


class LandlockContracts(unittest.TestCase):
    def test_mutation_mask_includes_refer_truncate_and_all_creation_removal(self):
        import automation_case_worker as worker
        self.assertEqual(worker.HANDLED, sum(1 << bit for bit in (1, *range(4, 15))))
        self.assertEqual(ctypes.sizeof(worker.PathRule), 12)
        self.assertEqual(worker.SYSCALLS, (444, 445, 446))

    def test_abi_missing_or_too_old_blocks_before_rules_or_test(self):
        import automation_case_worker as worker
        for abi in (0, 1, 2):
            with self.subTest(abi=abi), mock.patch.object(worker, '_syscall', return_value=abi) as call:
                with self.assertRaises(worker.WorkerBlocked):
                    worker.landlock(42)
                self.assertEqual(call.call_count, 1)
        with mock.patch.object(worker, '_syscall', side_effect=OSError(errno.ENOSYS, 'synthetic')):
            with self.assertRaises(worker.WorkerBlocked):
                worker.landlock(42)

    def test_rule_is_only_pinned_case_root_and_restriction_follows_no_new_privs(self):
        import automation_case_worker as worker
        events = []
        def syscall(number, *args):
            events.append(('syscall', number))
            if number == 444:
                return 3 if args[-1] == 1 else 51
            if number == 445:
                rule = ctypes.cast(args[2], ctypes.POINTER(worker.PathRule)).contents
                self.assertEqual((rule.parent_fd, rule.allowed_access), (42, worker.HANDLED))
            return 0
        with mock.patch.object(worker, '_syscall', side_effect=syscall), \
                mock.patch.object(worker, '_prctl', side_effect=lambda *args: events.append(('prctl', *args))), \
                mock.patch.object(worker.os, 'close') as close:
            self.assertEqual(worker.landlock(42), 3)
        self.assertLess(events.index(('prctl', 38, 1)), events.index(('syscall', 446)))
        close.assert_called_once_with(51)

    def test_case_identity_rejects_alias_root_and_wrong_owner_mode(self):
        import automation_case_worker as worker
        good = mock.Mock(st_dev=1, st_ino=2, st_uid=1000, st_mode=0o40700)
        with mock.patch.object(worker.os, 'getuid', return_value=1000), \
                mock.patch.object(worker.os, 'fstat', return_value=good), \
                mock.patch.object(worker.os, 'stat', return_value=good):
            self.assertEqual(worker.identity(Path('/work/fixtures/case-fixed'), 42), (1, 2, 1000, 0o40700))
        bad = mock.Mock(st_dev=1, st_ino=3, st_uid=1000, st_mode=0o40700)
        with mock.patch.object(worker.os, 'getuid', return_value=1000), \
                mock.patch.object(worker.os, 'fstat', return_value=good), \
                mock.patch.object(worker.os, 'stat', return_value=bad):
            with self.assertRaises(worker.WorkerBlocked):
                worker.identity(Path('/work/fixtures/case-fixed'), 42)

    def test_worker_fd_allowlist_and_restriction_before_test(self):
        import automation_case_worker as worker
        text = Path(worker.__file__).read_text()
        tree = ast.parse(text)
        child = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_child')
        calls = {ast.unparse(n.func): n.lineno for n in ast.walk(child) if isinstance(n, ast.Call)}
        self.assertLess(calls['_close_except'], calls['landlock'])
        self.assertLess(calls['landlock'], calls['configure_worker'])
        self.assertLess(calls['configure_worker'], calls['_run_inline'])
        self.assertIn('os.set_inheritable(result_fd, False)', text)
        self.assertNotIn('os.environ', text)

    def test_default_scope_has_no_destructive_permission(self):
        from automation_case_scope import fixture_parent, destructive_path
        self.assertFalse(destructive_path('/source/protected'))
        self.assertFalse(destructive_path('/evidence/protected'))
        self.assertFalse(destructive_path('/work/fixtures/other-case/file'))
        self.assertIsInstance(fixture_parent(), Path)

    def test_snapshot_not_required_for_disposable_intermediate_states(self):
        from automation_suite_selection import preservation_inventory
        permission = preservation_inventory()['authorization']
        self.assertEqual(permission['required_observer'], 'landlock-abi3-current-case-worker')
        self.assertEqual(permission['disposable_states'], 'new-synthetic-intermediate-states')

    def test_scope_has_no_exception_for_foreign_case_evidence_or_root_itself(self):
        import automation_case_scope as scope
        root = Path('/work/fixtures/case-synthetic')
        info = mock.Mock(st_dev=1, st_ino=2, st_uid=1000, st_mode=0o40700)
        record = (123, root, (1, 2, 1000, 0o40700), 'fixed-id', True, 3)
        # Metadata doubles only: the strings do not open/remove any real file.
        with mock.patch.object(scope, '_SCOPE', record), \
                mock.patch.object(Path, 'stat', return_value=info), \
                mock.patch.object(Path, 'resolve', lambda path, **kwargs: path):
            self.assertTrue(scope.destructive_path(root / 'fixtures/new/run.json'))
            for path in (root, Path('/evidence/log'), Path('/source/script.py'),
                         Path('/work/fixtures/case-other/fixtures/run.json')):
                self.assertFalse(scope.destructive_path(path))
        with mock.patch.object(scope, '_SCOPE', record[:-2] + (False, 3)):
            self.assertFalse(scope.destructive_path(root / 'fixtures/new'))

    def test_reap_only_kernel_owned_children_pidfd_and_handles_zombie(self):
        import automation_case_worker as worker
        with mock.patch.object(worker, '_owned_children', side_effect=[[123], []]), \
                mock.patch.object(worker.os, 'pidfd_open', return_value=42) as pin, \
                mock.patch.object(worker.signal, 'pidfd_send_signal', side_effect=ProcessLookupError) as send, \
                mock.patch.object(worker.os, 'waitpid', return_value=(123, 0)) as wait, \
                mock.patch.object(worker.os, 'close') as close:
            worker.reap_owned()
        pin.assert_called_once_with(123)
        send.assert_called_once_with(42, worker.signal.SIGKILL)
        wait.assert_called_once_with(123, 0)
        close.assert_called_once_with(42)

    def test_worker_receipt_limit_cannot_emit_unbounded_pipe_payload(self):
        import automation_case_worker as worker
        chunks = []
        def write(fd, value):
            self.assertEqual(fd, 42)
            chunks.append(bytes(value))
            return len(value)
        with mock.patch.object(worker.os, 'write', side_effect=write):
            worker._send(42, {'large': 'x' * (worker.MAX_RESULT + 1)})
        self.assertLess(len(b''.join(chunks)), worker.MAX_RESULT)
        self.assertIn(b'Worker result exceeded bound', b''.join(chunks))

    def test_existing_outside_log_open_is_denied_without_writing_or_truncating(self):
        import automation_case_worker as worker
        with mock.patch.object(worker.os, 'open', side_effect=PermissionError(errno.EACCES, 'LL denied')) as opened:
            worker.verify_outside_write_denied('/evidence/new-case.stdout.log')
        self.assertEqual(opened.call_args.args[1], worker.os.O_WRONLY | worker.os.O_CLOEXEC)
        with mock.patch.object(worker.os, 'open', return_value=42), \
                mock.patch.object(worker.os, 'close') as close:
            with self.assertRaises(worker.WorkerBlocked):
                worker.verify_outside_write_denied('/evidence/new-case.stdout.log')
        close.assert_called_once_with(42)

    def test_selection_never_runs_whitelisted_case_inline(self):
        import automation_suite_selection as selection
        name = selection.preservation_inventory()['authorization']['case_ids'][0]
        case = mock.Mock()
        case.id.return_value = name
        with mock.patch('automation_case_worker.run_case', return_value={
                'state': 'BLOCKED', 'id': name, 'reason': 'synthetic ABI2'}) as run, \
                mock.patch.object(selection, '_run_inline') as inline:
            result = selection._run([case])
        inline.assert_not_called()
        self.assertTrue(run.call_args.args[1])
        self.assertEqual(result['tests_run'], 0)
        self.assertEqual(result['blocked'], {name: 'synthetic ABI2'})
        self.assertFalse(result['successful'])

    def aggregate_worker_results(self, rows):
        """Doubles only: future regression must not fork/install Landlock."""
        import automation_suite_selection as selection
        cases = []
        for row in rows:
            case = mock.Mock()
            case.id.return_value = row['id']
            cases.append(case)
        with mock.patch('automation_case_worker.run_case', side_effect=rows):
            return selection._run(cases)

    def assert_both_selector_outcomes(self, result, expected):
        import automation_suite_selection as selection
        for label in ('suite', 'race'):
            with self.subTest(selector=label):
                self.assertEqual(selection.selection_outcome(result, label)[:2], expected)

    def test_failure_then_block_retains_real_failure_precedence_and_full_history(self):
        rows = [dict(id='case.fail', state='DONE', tests_run=1, successful=False,
                     failures=1, errors=0, skipped=0, records=[{'state': 'FAIL'}]),
                dict(id='case.block', state='BLOCKED', reason='synthetic ABI unavailable')]
        result = self.aggregate_worker_results(rows)
        self.assertEqual(result['workers'], rows)
        self.assertEqual(result['failures'], 1)
        self.assertEqual(result['blocked'], {'case.block': 'synthetic ABI unavailable'})
        self.assertTrue(result['observed_failure'])
        self.assert_both_selector_outcomes(result, ('FAIL', 1))

    def test_error_then_block_is_rc1_including_worker_setup_or_reap_failure(self):
        for first in (dict(id='case.error', state='DONE', tests_run=1, successful=False,
                           failures=0, errors=1, skipped=0),
                      dict(id='case.setup', state='FAIL', reason='synthetic reap failure')):
            with self.subTest(first=first):
                rows = [first, dict(id='case.block', state='BLOCKED', reason='synthetic missing rule')]
                result = self.aggregate_worker_results(rows)
                self.assertEqual(result['workers'], rows)
                self.assertTrue(result['observed_failure'])
                self.assert_both_selector_outcomes(result, ('FAIL', 1))

    def test_block_only_is_rc2_not_a_real_failure(self):
        rows = [dict(id='case.block', state='BLOCKED', reason='synthetic ABI2')]
        result = self.aggregate_worker_results(rows)
        self.assertEqual(result['workers'], rows)
        self.assertEqual((result['failures'], result['errors'], result['tests_run']), (0, 0, 0))
        self.assertFalse(result['observed_failure'])
        self.assertFalse(result['successful'])  # not sufficient to infer failure
        self.assert_both_selector_outcomes(result, ('BLOCKED', 2))

    def test_skip_then_block_remains_rc2_and_skip_history_is_retained(self):
        rows = [dict(id='case.skip', state='DONE', tests_run=1, successful=True,
                     failures=0, errors=0, skipped=1, records=[{'state': 'SKIP'}]),
                dict(id='case.block', state='BLOCKED', reason='synthetic unavailable')]
        result = self.aggregate_worker_results(rows)
        self.assertEqual(result['workers'], rows)
        self.assertEqual(result['skipped'], 1)
        self.assertFalse(result['observed_failure'])
        self.assert_both_selector_outcomes(result, ('BLOCKED', 2))

    def test_multiple_failures_and_errors_before_block_keep_counts_and_rc1(self):
        rows = [dict(id='case.fail', state='DONE', tests_run=1, successful=False,
                     failures=2, errors=0, skipped=0),
                dict(id='case.error', state='DONE', tests_run=1, successful=False,
                     failures=0, errors=3, skipped=0),
                dict(id='case.block', state='BLOCKED', reason='synthetic unavailable')]
        result = self.aggregate_worker_results(rows)
        self.assertEqual(result['workers'], rows)
        self.assertEqual((result['failures'], result['errors'], result['tests_run']), (2, 3, 2))
        self.assertEqual(len(result['blocked']), 1)
        self.assert_both_selector_outcomes(result, ('FAIL', 1))

    def test_suite_and_race_dispatch_use_same_outcome_before_any_return(self):
        import automation_suite_selection as selection
        tree = ast.parse(Path(selection.__file__).read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == 'run_selection')
        decisions = [n for n in ast.walk(function) if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Name) and n.func.id == 'selection_outcome']
        self.assertEqual(sorted(n.args[1].value for n in decisions), ['race', 'suite'])


if __name__ == '__main__':
    unittest.main()
