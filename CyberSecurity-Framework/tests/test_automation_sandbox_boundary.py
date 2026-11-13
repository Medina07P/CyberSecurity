"""Task3 negatives, NOT RUN. Import only through the reviewed inside selector.

No old fixtures, host launch, cleanup or backend execution.
"""
import errno
from pathlib import Path
import unittest
from unittest import mock

import automation_sandbox_inside as inside


class SandboxBoundaryTests(unittest.TestCase):
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
