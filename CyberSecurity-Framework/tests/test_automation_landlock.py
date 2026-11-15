"""Landlock/case-worker regressions written first. NOT RUN before review."""
import ast
from contextlib import ExitStack
import ctypes
import errno
import json
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

    def test_two_rules_exact_scratch_and_null_write_only_before_restriction(self):
        import automation_case_worker as worker
        events = []
        rules = []
        def syscall(number, *args):
            events.append(('syscall', number))
            if number == 444:
                return 3 if args[-1] == 1 else 51
            if number == 445:
                self.assertEqual((args[0], args[1], args[3]), (51, 1, 0))
                rule = ctypes.cast(args[2], ctypes.POINTER(worker.PathRule)).contents
                rules.append((rule.parent_fd, rule.allowed_access))
            return 0
        with mock.patch.object(worker, '_syscall', side_effect=syscall), \
                mock.patch.object(worker, '_prctl', side_effect=lambda *args: events.append(('prctl', *args))), \
                mock.patch.object(worker, 'pin_devnull', return_value=(43, 44, ('pinned',))), \
                mock.patch.object(worker, 'devnull_identity', return_value=('pinned',)) as identity, \
                mock.patch.object(worker.os, 'close') as close:
            self.assertEqual(worker.landlock(42), 3)
        self.assertLess(events.index(('prctl', 38, 1)), events.index(('syscall', 446)))
        self.assertEqual(rules, [(42, worker.HANDLED), (44, 1 << 1)])
        self.assertEqual(worker.DEVNULL_ALLOWED, 2)
        self.assertEqual(identity.call_count, 2)  # before restrict and after
        self.assertEqual(close.call_args_list, [mock.call(51), mock.call(44), mock.call(43)])

    def test_private_devnull_identity_rejects_symlink_foreign_or_wrong_device(self):
        import stat
        import os
        import automation_case_worker as worker
        directory = mock.Mock(st_dev=7, st_ino=10, st_mode=stat.S_IFDIR | 0o755,
                              st_rdev=0, st_uid=1000, st_gid=1000, st_nlink=2)
        node = mock.Mock(st_dev=7, st_ino=11, st_mode=stat.S_IFCHR | 0o666,
                         st_rdev=os.makedev(1, 3), st_uid=1000, st_gid=1000, st_nlink=1)
        for mode, device, inode in ((stat.S_IFLNK | 0o777, os.makedev(1, 3), 11),
                                    (stat.S_IFREG | 0o600, os.makedev(1, 3), 11),
                                    (stat.S_IFCHR | 0o666, os.makedev(1, 5), 11),
                                    (stat.S_IFCHR | 0o666, os.makedev(2, 3), 11),
                                    (stat.S_IFCHR | 0o666, os.makedev(1, 3), 12)):
            named = mock.Mock(st_dev=7, st_ino=inode, st_mode=mode, st_rdev=device,
                              st_uid=1000, st_gid=1000, st_nlink=1)
            opened_node = node if inode != 11 else named
            with self.subTest(mode=mode, device=device, inode=inode), \
                    mock.patch.object(worker.os, 'fstat', side_effect=[directory, opened_node]), \
                    mock.patch.object(worker.os, 'stat', side_effect=[directory, named]):
                with self.assertRaises(worker.WorkerBlocked):
                    worker.devnull_identity(43, 44)
        with mock.patch.object(worker.os, 'fstat', side_effect=[directory, node]), \
                mock.patch.object(worker.os, 'stat', side_effect=[directory, node]):
            pinned = worker.devnull_identity(43, 44)
        self.assertEqual(pinned[1][3], os.makedev(1, 3))
        alias_directory = mock.Mock(st_dev=7, st_ino=99, st_mode=stat.S_IFDIR | 0o755,
                                    st_rdev=0, st_uid=1000, st_gid=1000, st_nlink=2)
        with mock.patch.object(worker.os, 'fstat', return_value=directory), \
                mock.patch.object(worker.os, 'stat', return_value=alias_directory):
            with self.assertRaises(worker.WorkerBlocked):
                worker.devnull_identity(43, 44)

    def test_devnull_pin_uses_only_nofollow_dev_directory_and_exact_null_name(self):
        import os
        import automation_case_worker as worker
        with mock.patch.object(worker.os, 'open', side_effect=[43, 44]) as opened, \
                mock.patch.object(worker, 'devnull_identity', return_value=('pinned',)), \
                mock.patch.object(worker.os, 'close') as close:
            self.assertEqual(worker.pin_devnull(), (43, 44, ('pinned',)))
        self.assertEqual(opened.call_args_list, [
            mock.call('/dev', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC),
            mock.call('null', os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=43)])
        close.assert_not_called()  # owned by caller until rules installed

    def test_devnull_pin_failure_and_identity_race_close_owned_handles(self):
        import automation_case_worker as worker
        with mock.patch.object(worker.os, 'open', side_effect=[43, 44]), \
                mock.patch.object(worker, 'devnull_identity', side_effect=worker.WorkerBlocked('foreign node')), \
                mock.patch.object(worker.os, 'close') as close:
            with self.assertRaises(worker.WorkerBlocked):
                worker.pin_devnull()
        self.assertEqual(close.call_args_list, [mock.call(44), mock.call(43)])
        for observations in ([('changed',)], [('pinned',), ('changed',)]):
            def syscall(number, *args):
                return (3 if args[-1] == 1 else 51) if number == 444 else 0
            with self.subTest(observations=observations), \
                    mock.patch.object(worker, '_syscall', side_effect=syscall), \
                    mock.patch.object(worker, '_prctl'), \
                    mock.patch.object(worker, 'pin_devnull', return_value=(43, 44, ('pinned',))), \
                    mock.patch.object(worker, 'devnull_identity', side_effect=observations), \
                    mock.patch.object(worker.os, 'close') as close:
                with self.assertRaises(worker.WorkerBlocked):
                    worker.landlock(42)
                self.assertEqual(close.call_args_list, [mock.call(51), mock.call(44), mock.call(43)])

    def test_private_devnull_supports_subprocess_but_outside_evidence_remains_denied(self):
        # Future inside-worker regression. No backend/network; NOT RUN here.
        import os
        import stat
        import subprocess
        import sys
        import automation_case_worker as worker
        fd = os.open('/dev/null', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            self.assertTrue(stat.S_ISCHR(info.st_mode))
            self.assertEqual((os.major(info.st_rdev), os.minor(info.st_rdev)), (1, 3))
        finally:
            os.close(fd)
        result = subprocess.run([sys.executable, '-I', '-B', '-c', 'pass'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5)
        self.assertEqual(result.returncode, 0)
        worker.verify_outside_write_denied(os.readlink('/proc/self/fd/2'))

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
        self.assertLess(calls['_inherited_nproc_gate'], calls['os.write'])
        self.assertLess(calls['verify_outside_write_denied'], calls['os.write'])
        self.assertLess(calls['identity'], calls['os.write'])
        self.assertLess(calls['configure_worker'], calls['os.write'])
        self.assertLess(calls['os.write'], calls['_run_inline'])
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

    def collect_worker_result(self, chunks, status=0, times=(0,)):
        # NOT RUN. Only transport/wait/clock doubles; classification is real.
        import automation_case_worker as worker
        with mock.patch.object(worker.os, 'read', side_effect=chunks), \
                mock.patch.object(worker.os, 'waitpid', return_value=(123, status)), \
                mock.patch.object(worker.time, 'monotonic', side_effect=times), \
                mock.patch.object(worker.time, 'sleep'):
            return worker._collect_result('case.synthetic', 123, 42)

    def child_protocol(self, abi_missing=False):
        """NOT RUN; real child control flow, no fork/fds/Landlock syscalls."""
        import automation_case_worker as worker
        import automation_case_scope as scope
        import automation_sandbox_inside as inside
        import automation_suite_selection as selection
        case = mock.Mock()
        case.id.return_value = 'case.synthetic'
        events = []
        receipts = []
        with ExitStack() as stack:
            for owner, name in ((worker.signal, 'signal'), (worker.os, 'setsid'),
                    (worker.os, 'dup2'), (worker.os, 'set_inheritable'),
                    (worker.os, 'close'), (worker, '_close_except'),
                    (worker, 'identity'), (worker, '_prctl'),
                    (worker, 'verify_outside_write_denied'),
                    (inside, '_inherited_nproc_gate'), (scope, 'configure_worker'),
                    (worker.io, 'FileIO'), (worker.io, 'TextIOWrapper'),
                    (worker.sys, 'stdout'), (worker.sys, 'stderr')):
                stack.enter_context(mock.patch.object(owner, name))
            stack.enter_context(mock.patch.object(worker.os, 'open', return_value=50))
            stack.enter_context(mock.patch.object(worker.os, 'write',
                side_effect=lambda fd, raw: events.append(raw) or len(raw)))
            stack.enter_context(mock.patch.object(worker, 'landlock',
                side_effect=worker.WorkerBlocked('Landlock ABI>=3 required') if abi_missing else None,
                return_value=3))
            def started(cases):
                events.append('case.run')
                raise worker.WorkerBlocked('case raised after readiness')
            stack.enter_context(mock.patch.object(selection, '_run_inline', side_effect=started))
            stack.enter_context(mock.patch.object(worker, 'reap_owned',
                side_effect=lambda: events.append('reap')))
            stack.enter_context(mock.patch.object(worker, '_send',
                side_effect=lambda fd, row: receipts.append(dict(row))))
            stack.enter_context(mock.patch.object(worker.os, '_exit', side_effect=SystemExit(0)))
            with self.assertRaises(SystemExit):
                worker._child(case, Path('/synthetic'), 42, (), 43, 44, 45, False, '/synthetic.log')
        return events, receipts

    def test_child_missing_abi_sends_explicit_block_without_ready_or_case(self):
        events, receipts = self.child_protocol(abi_missing=True)
        self.assertEqual(events, ['reap'])
        self.assertEqual(receipts[0]['state'], 'BLOCKED')
        self.assertIn('ABI>=3', receipts[0]['reason'])

    def test_child_ready_precedes_case_and_late_workerblocked_is_fail(self):
        events, receipts = self.child_protocol()
        self.assertEqual(events, [b'READY\n', 'case.run', 'reap'])
        self.assertEqual(receipts[0]['state'], 'FAIL')
        self.assertIn('after readiness', receipts[0]['reason'])

    def test_ready_worker_timeout_is_fail_rc1_not_prerequisite_block(self):
        import automation_case_worker as worker
        for event, ready in ((b'READY\n', True), (b'', False)):
            with self.subTest(ready=ready), \
                    mock.patch.object(worker.os, 'read', return_value=event), \
                    mock.patch.object(worker.os, 'waitpid', return_value=(0, 0)), \
                    mock.patch.object(worker.time, 'monotonic', side_effect=[0, 61]):
                row = worker._collect_result('case.synthetic', 123, 42)
            self.assertEqual(row['state'], 'FAIL')
            self.assertEqual(row['ready'], ready)
            self.assertIsNone(row['wait_status'])
            self.assertIn('timeout', row['reason'])
            self.assert_both_selector_outcomes(self.aggregate_worker_results([row]), ('FAIL', 1))

    def test_ready_worker_crash_retains_status_and_is_fail_rc1(self):
        row = self.collect_worker_result([b'READY\n', b''], status=9, times=(0, 1))
        self.assertEqual(row['state'], 'FAIL')
        self.assertTrue(row['ready'])
        self.assertEqual(row['wait_status'], 9)
        self.assertIn('terminated', row['reason'])
        self.assert_both_selector_outcomes(self.aggregate_worker_results([row]), ('FAIL', 1))

    def test_explicit_abi_block_before_ready_remains_blocked_rc2(self):
        receipt = json.dumps(dict(id='case.synthetic', state='BLOCKED',
                                  reason='Landlock ABI>=3 required')).encode()
        row = self.collect_worker_result([receipt, b''], times=(0, 1))
        self.assertEqual(row['state'], 'BLOCKED')
        self.assertFalse(row['ready'])
        self.assertEqual(row['reason'], 'Landlock ABI>=3 required')
        self.assert_both_selector_outcomes(self.aggregate_worker_results([row]), ('BLOCKED', 2))

    def test_missing_malformed_or_post_ready_block_is_failure_not_inferred_abi(self):
        for chunks, ready in (([b''], False), ([b'not-json', b''], False),
                ([b'READY\n{', b''], True),
                ([b'READY\n' + json.dumps(dict(id='case.synthetic', state='BLOCKED',
                                              reason='late block')).encode(), b''], True)):
            with self.subTest(chunks=chunks):
                row = self.collect_worker_result(chunks, times=(0, 1))
                self.assertEqual(row['state'], 'FAIL')
                self.assertEqual(row['ready'], ready)
                self.assert_both_selector_outcomes(self.aggregate_worker_results([row]), ('FAIL', 1))

    def test_readiness_may_be_fragmented_and_receipt_stays_bounded(self):
        receipt = json.dumps(dict(id='case.synthetic', state='DONE', successful=True)).encode()
        row = self.collect_worker_result([b'RE', b'ADY\n' + receipt, b''], times=(0, 1, 2))
        self.assertEqual(row['state'], 'DONE')
        self.assertTrue(row['ready'])
        import automation_case_worker as worker
        row = self.collect_worker_result([b'READY\n' + b'x' * (worker.MAX_RESULT + 1)])
        self.assertEqual(row['state'], 'FAIL')
        self.assertIn('large', row['reason'])

    def test_worker_transport_does_not_catch_cancellation(self):
        import automation_case_worker as worker
        for code in (130, 143):
            with self.subTest(code=code), \
                    mock.patch.object(worker.os, 'read', side_effect=SystemExit(code)), \
                    mock.patch.object(worker.time, 'monotonic', return_value=0):
                with self.assertRaises(SystemExit) as caught:
                    worker._collect_result('case.synthetic', 123, 42)
                self.assertEqual(caught.exception.code, code)

    def assert_both_selector_outcomes(self, result, expected):
        import automation_suite_selection as selection
        for label in ('suite', 'race', 'cross-consent', 'cross-web', 'cross-local'):
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
        self.assertEqual(sorted(n.args[1].value for n in decisions
                                if isinstance(n.args[1], ast.Constant)), ['race', 'suite'])
        self.assertEqual([n.args[1].id for n in decisions if isinstance(n.args[1], ast.Name)], ['label'])


if __name__ == '__main__':
    unittest.main()
