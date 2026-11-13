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
        self.assertTrue(self.result['cancel']['descendant_reaped'])
        self.assertTrue(self.result['cancel']['direct_child_reaped'])
        for result in self.result['descendants']:
            self.assertEqual(result['fds'], [0, 1, 2])
            for name, value in result['namespaces'].items():
                self.assertNotEqual(value, self.result['context']['host_namespaces'][name])
                self.assertEqual(value, self.result['namespaces'][name])

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
