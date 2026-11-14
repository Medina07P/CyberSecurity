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
        status = ('Uid:\t1000 1000 1000 1000\nThreads:\t3\n'
                  'CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n')
        for mapping, metadata, valid in (
                ('1000 1000 1\n', status, True),
                ('0 1000 1\n', status, False),
                ('1000 1000 65536\n', status, False),
                ('1000 1000 1\n', status.replace('CapEff:\t0', 'CapEff:\t1'), False),
                ('1000 1000 1\n', status.replace('Threads:\t3', 'Threads:\t256'), False)):
            with self.subTest(mapping=mapping, valid=valid), \
                    mock.patch.object(inside.resource, 'getrlimit', return_value=(256, 256)), \
                    mock.patch.object(inside.os, 'getuid', return_value=1000), \
                    mock.patch.object(inside.os, 'geteuid', return_value=1000), \
                    mock.patch.object(inside, 'read_json', return_value={
                        'host_uid': 1000, 'host_namespaces': {'user': 'user:[host]'}}), \
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
        with self.assertRaises(PermissionError):
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
