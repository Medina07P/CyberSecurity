"""Task3 negatives, NOT RUN. Import only through the reviewed inside selector.

No old fixtures, host launch, cleanup or backend execution.
"""
import errno
import ast
from pathlib import Path
import unittest
from unittest import mock

import automation_sandbox_inside as inside


class SandboxBoundaryTests(unittest.TestCase):
    def test_cross_selector_is_closed(self):
        from cross_module_selection import group_cases, group_grants, validate_cases
        names = group_cases('--cross-consent')
        self.assertEqual(len(names), 9)
        self.assertEqual(len(set(names)), 9)
        for selector in ('--cross-web', '--cross-local', '--suite', '', '--unsafe'):
            with self.assertRaises(ValueError):
                group_cases(selector)
            with self.assertRaises(ValueError):
                group_grants(selector)
        for changed in ((), names[:-1], names + names[:1],
                        names[:-1] + ('test_cross_consent.ConsentTests.test_changed',)):
            with self.assertRaises(ValueError):
                validate_cases('--cross-consent', [mock.Mock(id=lambda n=n: n) for n in changed])
        validate_cases('--cross-consent', [mock.Mock(id=lambda n=n: n) for n in names])

    def test_cross_grants_are_selection_bound(self):
        from cross_module_selection import group_cases, group_grants
        import automation_suite_selection as selection
        cross = group_cases('--cross-consent')[0]
        old = selection.preservation_inventory()['authorization']['case_ids']
        self.assertEqual(len(old), 25)
        self.assertEqual(group_grants('--cross-consent'), frozenset(group_cases('--cross-consent')))
        self.assertTrue(set(old).isdisjoint(group_grants('--cross-consent')))
        controller = mock.Mock(__file__=inside.SELF)
        for selector in ('--suite', '--races', '--cross-consent', None):
            controller.validated_selection.return_value = selector
            with mock.patch.dict('sys.modules', {'__main__': controller}):
                self.assertEqual(selection.case_disposable_allowed(cross), selector == '--cross-consent')
                self.assertEqual(selection.case_disposable_allowed(old[0]), selector in ('--suite', '--races'))
                self.assertFalse(selection.case_disposable_allowed(cross + '_changed'))
        with mock.patch.dict('sys.modules', {'__main__': None}):
            self.assertFalse(selection.case_disposable_allowed(cross))

    def test_cross_root_and_protected_paths_remain_blocked(self):
        import automation_case_scope as scope
        root = Path('/work/fixtures/case-synthetic')
        info = mock.Mock(st_dev=1, st_ino=2, st_uid=1000, st_mode=0o40700)
        pinned = (1, 2, 1000, 0o40700)
        with mock.patch.object(scope, '_SCOPE', None), \
                mock.patch('automation_suite_selection.case_disposable_allowed', return_value=True), \
                mock.patch.object(Path, 'stat', return_value=info), \
                mock.patch.object(Path, 'resolve', autospec=True, side_effect=lambda p, **kw: p):
            scope.configure_worker(root, pinned, 'synthetic-cross', True, 3)
            for path in (root, '/source/file', '/evidence/file', '/work/fixtures/case-other/file'):
                self.assertFalse(scope.destructive_path(path))
            self.assertTrue(scope.destructive_path(root / 'new'))
            info.st_ino = 3
            self.assertFalse(scope.destructive_path(root / 'new'))
        with mock.patch.object(scope, '_SCOPE', None), \
                mock.patch('automation_suite_selection.case_disposable_allowed', return_value=False):
            with self.assertRaises(ValueError):
                scope.configure_worker(root, pinned, 'changed-case', True, 3)

    def test_suite_excludes_cross_modules(self):
        import automation_suite_selection as selection
        from automation_sandbox_prepare import source_names
        modules = selection.legacy_modules(source_names())
        self.assertTrue(modules)
        self.assertFalse(any(name.startswith('test_cross_') for name in modules))
        self.assertEqual(len(selection.preservation_inventory()['authorization']['case_ids']), 25)
        with mock.patch.object(inside, '_VALIDATED', False), \
                mock.patch.object(inside, '_SELECTION', '--cross-consent'):
            self.assertIsNone(inside.validated_selection())

    def test_parent_scope_mapping_requires_vfs_composition_not_parent_uid_guess(self):
        host = {'dev': 11, 'ino': 22, 'mode': 0o100400, 'size': 52,
                'uid': 1000, 'gid': 1000, 'nlink': 1, 'mtime_ns': 5, 'ctime_ns': 6}
        local = dict(host, uid=1234, gid=1234)
        for parent in (0, 1000):
            proof = inside._compose_identity(1234, 1234, 1000, [[1234, parent, 1]],
                                             host, local, 'user:[private]', 'user:[host]')
            self.assertEqual(proof['uid_map_scope'], 'immediate-parent-user-namespace')
            self.assertEqual(proof['canary']['inside']['uid'], 1234)
        for mapping, observed in (([[1234, 0, 65536]], local),
                                  ([[0, 0, 1]], local),
                                  ([[1234, 0, 1]], dict(local, uid=0)),
                                  ([[1234, 0, 1]], dict(local, ino=23)),
                                  ([[1234, 0, 1]], dict(local, dev=12)),
                                  ([[1234, 0, 1]], dict(local, mode=0o100600)),
                                  ([[1234, 0, 1]], {k: v for k, v in local.items() if k != 'ino'}),
                                  ([[1234, 0, 1]], dict(local, size=53))):
            with self.subTest(mapping=mapping, observed=observed):
                with self.assertRaises(inside.NprocBlocked):
                    inside._compose_identity(1234, 1234, 1000, mapping, host,
                                             observed, 'user:[private]', 'user:[host]')

    def test_inside_canary_rejects_named_alias_and_metadata_race(self):
        fields = {'dev': 11, 'ino': 22, 'mode': 0o100400, 'size': 52,
                  'uid': 1000, 'gid': 1000, 'nlink': 1, 'mtime_ns': 5, 'ctime_ns': 6}
        good = mock.Mock(**{'st_' + key: value for key, value in fields.items()})
        changed = mock.Mock(**{'st_' + key: value for key, value in dict(fields, ino=23).items()})
        for named, reads in ((changed, [good]), (good, [good, changed])):
            with mock.patch.object(inside.os, 'open', return_value=42), \
                    mock.patch.object(inside.os, 'close') as close, \
                    mock.patch.object(inside.os, 'stat', return_value=named), \
                    mock.patch.object(inside.os, 'fstat', side_effect=reads):
                with self.assertRaises(inside.NprocBlocked):
                    inside._identity_canary()
            close.assert_called_once_with(42)
        # Stat numeric equality alone is not proof: owner-only read-open must
        # succeed, including when an unmapped owner has an overflow UID alias.
        with mock.patch.object(inside.os, 'open', side_effect=PermissionError('owner mismatch')):
            with self.assertRaises(PermissionError):
                inside._identity_canary()

    def test_identity_mapping_failure_reports_exact_metadata_before_any_probe(self):
        for mapping, namespace in (('999 0 1\n', 'user:[private]'),
                                   ('999 0 1\n', 'user:[private]\n\tescaped'),
                                   ('1000 1000 65536\n', 'user:[private]'),
                                   ('1000 1000 1\n', 'user:[host]')):
            with self.subTest(mapping=mapping, namespace=namespace), \
                    mock.patch.object(inside.resource, 'getrlimit', return_value=(256, 256)), \
                    mock.patch.object(inside.os, 'getuid', return_value=1000), \
                    mock.patch.object(inside.os, 'geteuid', return_value=1000), \
                    mock.patch.object(inside, 'read_json', return_value={
                        'host_uid': 1000, 'host_namespaces': {'user': 'user:[host]'}}), \
                    mock.patch.object(Path, 'read_text', return_value=mapping), \
                    mock.patch.object(inside.os, 'readlink', return_value=namespace), \
                    mock.patch('builtins.open') as metadata_after_failure, \
                    mock.patch.object(inside, 'run_probes') as probes, \
                    mock.patch.object(inside.subprocess, 'Popen') as spawn:
                with self.assertRaises(inside.NprocBlocked) as failure:
                    inside._nproc_observation()
                text = str(failure.exception)
                self.assertIn('NPROC accounting identity/user namespace not demonstrable', text)
                self.assertNotIn('\n', text)
                observed = inside.json.loads(text.split('identity_metadata=', 1)[1])
                self.assertEqual(observed, {
                    'uid': 1000, 'euid': 1000, 'host_uid': 1000,
                    'uid_map': [[int(p) for p in line.split()] for line in mapping.splitlines()],
                    'user_namespace': namespace, 'expected_user_namespace': 'user:[host]'})
                metadata_after_failure.assert_not_called()
                probes.assert_not_called()
                spawn.assert_not_called()

    def test_identity_diagnostic_is_retained_in_blocked_receipt_without_probe(self):
        reason = ('NPROC accounting identity/user namespace not demonstrable; '
                  'identity_metadata={"uid":1000,"euid":1000,"host_uid":1000,'
                  '"uid_map":[[1000,0,1]],"user_namespace":"user:[private]",'
                  '"expected_user_namespace":"user:[host]"}')
        with mock.patch.object(inside, '_NPROC_ENTRY', None), \
                mock.patch.object(inside, '_workload_nproc_gate',
                                  side_effect=inside.NprocBlocked(reason)), \
                mock.patch.object(inside, '_context') as context, \
                mock.patch.object(inside, 'run_probes') as probes, \
                mock.patch.object(inside, 'write_json') as receipt:
            self.assertEqual(inside.inside_main(['--probes']), 2)
        context.assert_not_called()
        probes.assert_not_called()
        self.assertEqual(receipt.call_args.args[1]['reason'], reason)
        self.assertEqual(receipt.call_args.args[1]['state'], 'BLOCKED')
        self.assertIs(receipt.call_args.args[1]['tests_started'], False)

    def test_entry_gate_precedes_sys_path_and_all_probe_dispatch(self):
        tree = ast.parse(Path(inside.__file__).read_text())
        entry = next(node for node in tree.body if isinstance(node, ast.If) and
                     '__name__' in ast.unparse(node.test))
        calls = [node for node in ast.walk(entry) if isinstance(node, ast.Call)]
        gate = next(node.lineno for node in calls if ast.unparse(node.func) == '_entry_nproc_gate')
        for node in calls:
            if ast.unparse(node.func) in ('sys.path.extend', '_observe', '_capture',
                                        '_cancel_worker', 'inside_main'):
                self.assertLess(gate, node.lineno)

    def test_unknown_accounting_and_privileged_identity_block(self):
        with mock.patch.object(inside, '_read_nproc_observation',
                               side_effect=PermissionError('metadata denied')):
            with self.assertRaises(inside.NprocBlocked):
                inside._nproc_observation()
        with mock.patch.object(inside.resource, 'getrlimit', return_value=(256, 256)), \
                mock.patch.object(inside.os, 'getuid', return_value=0), \
                mock.patch.object(inside.os, 'geteuid', return_value=0), \
                mock.patch.object(inside, 'read_json') as context:
            with self.assertRaises(inside.NprocBlocked):
                inside._nproc_observation()
        context.assert_not_called()

    def test_accounting_scope_mapping_caps_and_task_count_are_required(self):
        canary = {'dev': 11, 'ino': 22, 'mode': 0o100400, 'size': 52,
                  'uid': 1000, 'gid': 1000, 'nlink': 1, 'mtime_ns': 5, 'ctime_ns': 6}
        status = ('Uid:\t1000 1000 1000 1000\nThreads:\t3\n'
                  'CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n')
        for mapping, metadata, valid in (
                ('1000 1000 1\n', status, True),
                ('1000 0 1\n', status, True),
                ('0 1000 1\n', status, False),
                ('1000 1000 65536\n', status, False),
                ('1000 1000 1\n', status.replace('CapEff:\t0', 'CapEff:\t1'), False),
                ('1000 1000 1\n', status.replace('Threads:\t3', 'Threads:\t256'), False)):
            with self.subTest(mapping=mapping, valid=valid), \
                    mock.patch.object(inside.resource, 'getrlimit', return_value=(256, 256)), \
                    mock.patch.object(inside.os, 'getuid', return_value=1000), \
                    mock.patch.object(inside.os, 'geteuid', return_value=1000), \
                     mock.patch.object(inside, 'read_json', return_value={
                        'host_uid': 1000, 'host_namespaces': {'user': 'user:[host]'},
                        'identity_canary': canary}), \
                    mock.patch.object(inside, '_identity_canary', return_value=canary), \
                    mock.patch.object(Path, 'read_text', return_value=mapping), \
                    mock.patch.object(inside.os, 'readlink', return_value='user:[private]'), \
                    mock.patch.object(inside.os, 'listdir', return_value=['1']), \
                    mock.patch('builtins.open', mock.mock_open(read_data=metadata)):
                if valid:
                    result = inside._nproc_observation()
                    self.assertEqual(result['observed_uid_tasks'], 3)
                    self.assertEqual(result['user_namespace'], 'user:[private]')
                else:
                    with self.assertRaises(inside.NprocBlocked):
                        inside._nproc_observation()

    def test_workload_limit_is_lowered_and_read_back_before_observation(self):
        events = []
        def impose(kind, values):
            events.append(('set', values))
        def inspect():
            events.append(('observe',))
            return {'soft': 256, 'hard': 256}
        with mock.patch.object(inside.resource, 'setrlimit', side_effect=impose), \
                mock.patch.object(inside.resource, 'getrlimit',
                                  side_effect=[(4096, 8192), (256, 256)]), \
                mock.patch.object(inside, '_nproc_observation', side_effect=inspect):
            self.assertEqual(inside._workload_nproc_gate(), {
                'soft': 256, 'hard': 256, 'inherited_soft_hard': [4096, 8192]})
        self.assertEqual(events, [('set', (256, 256)), ('observe',)])

    def test_descendant_rejects_high_inheritance_even_if_later_readback_would_be256(self):
        for mode in ('--probe-child', '--probe-grandchild', '--probe-bash', '--probe-cancel'):
            with self.subTest(mode=mode), \
                    mock.patch.object(inside.resource, 'getrlimit',
                                      side_effect=[(4096, 8192), (256, 256)]) as read, \
                    mock.patch.object(inside.resource, 'setrlimit') as repair, \
                    mock.patch.object(inside, 'write_json') as receipt, \
                    mock.patch.object(inside, '_nproc_observation') as observe:
                with self.assertRaises(inside.NprocBlocked):
                    inside._entry_nproc_gate([mode])
            self.assertEqual(read.call_count, 1)
            repair.assert_not_called()
            observe.assert_not_called()
            self.assertEqual(receipt.call_args.args[1]['inherited_soft_hard'], [4096, 8192])

    def test_descendant_keeps_inherited_readback_without_setting_any_limit(self):
        with mock.patch.object(inside.resource, 'getrlimit', return_value=(256, 256)), \
                mock.patch.object(inside.resource, 'setrlimit') as repair, \
                mock.patch.object(inside, '_nproc_observation', return_value={'soft': 256, 'hard': 256}):
            result = inside._entry_nproc_gate(['--probe-child'])
        self.assertEqual(result['inherited_soft_hard'], [256, 256])
        repair.assert_not_called()

    def test_cancel_fork_rejects_inheritance_before_repair_or_signal_wait(self):
        with mock.patch.object(inside, '_descendant_nproc', return_value={}), \
                mock.patch.object(inside, '_context'), \
                mock.patch.object(inside.signal, 'pthread_sigmask'), \
                mock.patch.object(inside.os, 'fork', return_value=0), \
                mock.patch.object(inside.resource, 'getrlimit', return_value=(4096, 8192)), \
                mock.patch.object(inside.resource, 'setrlimit') as repair, \
                mock.patch.object(inside, 'write_json') as receipt, \
                mock.patch.object(inside.signal, 'pause') as wait:
            with self.assertRaises(inside.NprocBlocked):
                inside._cancel_worker()
        repair.assert_not_called()
        wait.assert_not_called()
        self.assertEqual(receipt.call_args.args[1]['inherited_soft_hard'], [4096, 8192])

    def test_cancel_worker_and_fork_receipts_preserve_both_nproc_observations(self):
        for key in ('worker_nproc', 'fork_nproc'):
            nproc = self.result['cancel'][key]
            self.assertEqual(nproc['inherited_soft_hard'], [256, 256])
            self.assertEqual((nproc['soft'], nproc['hard']), (256, 256))
            self.assertEqual(nproc['uid_map'], self.result['nproc']['uid_map'])
            self.assertEqual(nproc['uid_map_scope'], 'immediate-parent-user-namespace')
            self.assertEqual(nproc['identity_canary'], self.result['nproc']['identity_canary'])
            self.assertEqual(nproc['user_namespace'], self.result['nproc']['user_namespace'])
            self.assertTrue(all(value == 0 for value in nproc['capabilities'].values()))

    def test_nproc_gate_never_continues_after_wrong_readback_or_missing_identity(self):
        for readback in ((256, 8192), (4096, 8192)):
            with mock.patch.object(inside.resource, 'setrlimit'), \
                    mock.patch.object(inside.resource, 'getrlimit',
                                      side_effect=[(4096, 8192), readback]), \
                    mock.patch.object(inside, '_nproc_observation') as observe:
                with self.assertRaises(ValueError):
                    inside._workload_nproc_gate()
            observe.assert_not_called()
        with mock.patch.object(inside, '_workload_nproc_gate',
                               side_effect=ValueError('unprovable identity')), \
                mock.patch.object(inside, '_NPROC_ENTRY', None), \
                mock.patch.object(inside, '_context') as context, \
                mock.patch.object(inside, 'run_probes') as probes, \
                mock.patch.object(inside, 'write_json'):
            self.assertEqual(inside.inside_main(['--probes']), 2)
        context.assert_not_called()
        probes.assert_not_called()

    def test_descendants_preserve_hard256_and_unprivileged_identity(self):
        for result in self.result['descendants']:
            nproc = result['nproc']
            self.assertEqual(nproc['inherited_soft_hard'], [256, 256])
            self.assertEqual(nproc['entry']['inherited_soft_hard'], [256, 256])
            self.assertEqual(nproc['uid_map_scope'], 'immediate-parent-user-namespace')
            self.assertEqual(nproc['identity_canary'], self.result['nproc']['identity_canary'])
            self.assertEqual((nproc['soft'], nproc['hard']), (256, 256))
            self.assertGreater(nproc['uid'], 0)
            self.assertEqual(nproc['uid'], nproc['euid'])
            self.assertTrue(all(value == 0 for value in nproc['capabilities'].values()))
            self.assertGreaterEqual(nproc['observed_uid_tasks'], 1)
            self.assertLess(nproc['observed_uid_tasks'], 256)
            self.assertEqual(nproc['user_namespace'], self.result['nproc']['user_namespace'])

    def setUp(self):
        # Reuse the current fresh run's probe receipt, never invoke the launcher.
        self.result = inside.read_json(Path('/evidence/probes.json'))

    def test_child_and_grandchild_cannot_read_outside(self):
        self.assertEqual(self.result['state'], 'PASS')
        for result in self.result['descendants']:
            self.assertTrue(result['inside_canary_read'])
            self.assertFalse(result['outside_canary_read'])
            self.assertEqual(result['outside_errno'], errno.ENOENT)
        self.assertEqual({r['role'] for r in self.result['descendants']},
                         {'python-child', 'bash-grandchild', 'bash-child'})

    def test_no_real_backend_fallback(self):
        for result in self.result['descendants']:
            self.assertFalse(result['external_stub_visible'])
            self.assertFalse(result['backend_visible'])
        # This refers only to a new synthetic marker, not any real evidence.
        self.assertFalse(Path(self.result['context']['external_marker']).exists())

    def test_sockets_denied(self):
        for result in self.result['descendants']:
            self.assertEqual(result['socket_errno'], [errno.EPERM, errno.EPERM])
        text = Path(inside.__file__).read_text()
        self.assertNotIn('.connect(', text)
        self.assertNotIn('.bind(', text)
        self.assertNotIn('.send(', text)

    def test_namespace_identity_and_cancel(self):
        entry = self.result['entry_fds']
        self.assertTrue(entry['valid'])
        self.assertEqual(entry['observed'], [0, 1, 2, 3])
        self.assertEqual(entry['live'], [0, 1, 2])
        self.assertEqual(entry['closed_transient'], [3])
        self.assertTrue(self.result['cancel']['descendant_reaped'])
        self.assertTrue(self.result['cancel']['direct_child_reaped'])
        for result in self.result['descendants']:
            self.assertEqual(result['fds'], [0, 1, 2])
            self.assertTrue(result['fd_observation']['valid'])
            self.assertEqual(result['fd_observation']['observed'], [0, 1, 2, 3])
            self.assertEqual(result['fd_observation']['closed_transient'], [3])
            for name, value in result['namespaces'].items():
                self.assertNotEqual(value, self.result['context']['host_namespaces'][name])
                self.assertEqual(value, self.result['namespaces'][name])

    def test_entry_fd_leak_fails_before_sanitizing_children_and_is_retained(self):
        leaked = {'valid': False, 'observed': [0, 1, 2, 3, 41],
                  'live': [0, 1, 2, 41], 'closed_transient': [3]}
        with mock.patch.object(inside, '_fd_observation', return_value=leaked), \
                mock.patch.object(inside, '_nproc_observation', return_value={}), \
                mock.patch.object(inside, '_context', return_value={'run_id': 'synthetic'}), \
                mock.patch.object(inside, 'namespaces', return_value={'mnt': 'synthetic'}), \
                mock.patch.object(inside, '_capture') as capture, \
                mock.patch.object(inside, '_cancel') as cancel, \
                mock.patch.object(inside.subprocess, 'Popen') as spawn:
            result = inside.run_probes('synthetic')
        self.assertEqual(result['state'], 'FAIL')
        self.assertEqual(result['entry_fds'], leaked)
        self.assertEqual(result['checks'][0]['id'], 'entry-fds')
        self.assertEqual(result['checks'][0]['result'], 'FAIL')
        capture.assert_not_called()
        cancel.assert_not_called()
        spawn.assert_not_called()

    def test_clean_entry_snapshot_precedes_first_child(self):
        events = []
        def snapshot():
            events.append('entry')
            return {'valid': True, 'observed': [0, 1, 2, 3],
                    'live': [0, 1, 2], 'closed_transient': [3]}
        def first_child(*args):
            events.append('spawn')
            raise ValueError('synthetic stop, no process')
        with mock.patch.object(inside, '_fd_observation', side_effect=snapshot), \
                mock.patch.object(inside, '_nproc_observation', return_value={}), \
                mock.patch.object(inside, '_context', return_value={'run_id': 'synthetic'}), \
                mock.patch.object(inside, 'namespaces', return_value={'mnt': 'synthetic'}), \
                mock.patch.object(inside, '_capture', side_effect=first_child):
            with self.assertRaisesRegex(ValueError, 'synthetic stop'):
                inside.run_probes('synthetic')
        self.assertEqual(events, ['entry', 'spawn'])

    def test_fd_snapshot_rejects_extra_missing_stdio_and_live_transient(self):
        for observed, live, valid in (
                ([0, 1, 2, 3], {0, 1, 2}, True),
                ([0, 1, 2, 3, 41], {0, 1, 2, 41}, False),
                ([0, 1, 2, 3, 41], {0, 1, 2}, False),
                ([0, 1, 2, 3, 4], {0, 1, 2, 3}, False),
                ([0, 1, 2], {1, 2}, False)):
            def metadata(number):
                if number not in live:
                    raise OSError(errno.EBADF, 'synthetic closed')
                return mock.sentinel.metadata
            with self.subTest(observed=observed, live=live), \
                    mock.patch.object(inside.os, 'listdir', return_value=list(map(str, observed))), \
                    mock.patch.object(inside.os, 'fstat', side_effect=metadata), \
                    mock.patch.object(inside.os, 'close') as close:
                result = inside._fd_observation()
                self.assertEqual(result['valid'], valid)
                self.assertEqual(result['observed'], observed)
                self.assertEqual(result['live'], sorted(live))
                self.assertEqual(result['closed_transient'], sorted(set(observed) - live))
                close.assert_not_called()

    def test_no_environment_authority_or_legacy_discovery(self):
        with mock.patch.object(inside, 'run_probes') as probes, \
                mock.patch.object(inside, 'write_json'):
            self.assertEqual(inside.inside_main(['--unsafe']), 2)
        probes.assert_not_called()

    def test_guard_host_default_stays_blocked(self):
        from automation_test_guard import check_event
        with mock.patch.dict('sys.modules', {'__main__': None}), self.assertRaises(PermissionError):
            check_event('/synthetic-checkout', 'subprocess.Popen', ())

    def test_unexpected_socket_is_closed_without_any_traffic(self):
        descriptor = mock.Mock()
        with mock.patch.object(inside, '_context', return_value={
                'run_id': 'synthetic', 'outside_canary': '/synthetic-outside',
                 'external_stub': '/synthetic-double'}), \
                mock.patch.object(inside, '_descendant_nproc', return_value={}), \
                mock.patch.object(Path, 'read_text', return_value='synthetic'), \
                mock.patch.object(Path, 'read_bytes', side_effect=FileNotFoundError(
                    errno.ENOENT, 'synthetic absent')), \
                mock.patch.object(Path, 'exists', return_value=False), \
                mock.patch.object(inside.socket, 'socket', return_value=descriptor) as create:
            with self.assertRaisesRegex(ValueError, 'unexpectedly created'):
                inside._observe('synthetic')
        create.assert_called_once_with(inside.socket.AF_INET, inside.socket.SOCK_STREAM)
        descriptor.close.assert_called_once_with()
        self.assertEqual(descriptor.mock_calls, [mock.call.close()])

    def test_visible_synthetic_canary_stops_before_socket_or_exec(self):
        with mock.patch.object(inside, '_context', return_value={
                 'run_id': 'synthetic', 'outside_canary': '/synthetic-outside'}), \
                mock.patch.object(inside, '_descendant_nproc', return_value={}), \
                mock.patch.object(Path, 'read_text', return_value='synthetic'), \
                mock.patch.object(Path, 'read_bytes', return_value=b'synthetic'), \
                mock.patch.object(inside.socket, 'socket') as create, \
                mock.patch.object(inside.subprocess, 'Popen') as execute:
            with self.assertRaisesRegex(ValueError, 'outside canary'):
                inside._observe('synthetic')
        create.assert_not_called()
        execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
