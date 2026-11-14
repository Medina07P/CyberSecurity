"""Consent block regressions. Written first; STATIC NOT RUN, exact worker only.

Backend doubles record effects; production CLI/policy/results are never replaced.
Future imports intentionally occur inside methods, so missing cores are ERROR,
not discovery omissions. Synthetic fixtures and final artifacts persist.
"""
from pathlib import Path
import importlib
import os
import signal
import sys
import unittest

CLEANER = '06_PostExploitation/cleanup/logs_cleaner.sh'
BURP = '03_Scanners/web_scanners/burpsuite/burp_launcher.sh'


class ConsentTests(unittest.TestCase):
    def fixture(self):
        from cross_module_fixture import CrossModuleFixture
        return CrossModuleFixture('--cross-consent')

    def core(self, fixture, name):
        # Only the source copy in this case, never checkout/host module fallback.
        for key in tuple(sys.modules):
            if key == 'consent' or key.startswith('consent.'):
                del sys.modules[key]
        sys.path.insert(0, str(fixture.framework / '00_Config/lib'))
        self.addCleanup(sys.path.remove, str(fixture.framework / '00_Config/lib'))
        return importlib.import_module('consent.' + name)

    def test_cleanup_nonexecution_is_inert(self):
        for args, rc in (((), 0), (('--preview',), 0), (('--help',), 0),
                         (('--estado',), 2), (('--parar',), 2), (('--unknown',), 2),
                         (('--execute',), 2)):
            with self.subTest(args=args):
                f = self.fixture()
                before = f.snapshot()
                result = f.run_leaf(CLEANER, args, stdin='')
                self.assertEqual(result.returncode, rc, result.stderr)
                self.assertEqual(f.records(), [])
                self.assertEqual(f.snapshot(), before)

    def test_cleanup_requires_both_flags(self):
        for args in (('--execute',), ('--confirm-local-cleanup',),
                     ('--execute', '--preview', '--confirm-local-cleanup')):
            f = self.fixture()
            f.env.update({'CONFIRM_LOCAL_CLEANUP': '1', 'FRAMEWORK_ASSUME_YES': '1'})
            result = f.run_leaf(CLEANER, args, stdin='no\n')
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(f.records(), [])
        f = self.fixture()
        f.set_session('remote.example.test')
        result = f.run_leaf(CLEANER, ('--execute', '--confirm-local-cleanup'))
        # Synthetic sudo refuses every operation; cannot be complete success.
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn('remote.example.test', result.stdout + result.stderr)
        self.assertTrue(f.records())
        self.assertNotIn('remote.example.test', repr(f.records()))

    def test_cleanup_local_plan_and_partial_failure(self):
        f = self.fixture()
        cleanup = self.core(f, 'cleanup')
        plan = cleanup.plan_cleanup(f.home)
        self.assertEqual([(op.kind, str(op.path) if op.path else None) for op in plan], [
            ('truncate', '/var/log/auth.log'), ('truncate', '/var/log/syslog'),
            ('truncate', '/var/log/btmp'), ('truncate', '/var/log/wtmp'),
            ('history', str(f.home / '.bash_history')), ('child-history', None),
            ('snapshot', None)])
        # Only operations are doubled; apply_cleanup owns iteration/error policy.
        class Ops:
            def __init__(self):
                self.seen = []
            def perform(self, operation, report_root):
                self.seen.append(operation.kind)
                if operation.path == Path('/var/log/syslog'):
                    raise OSError('synthetic syslog failure')
                if operation.kind in ('truncate', 'history'):
                    target = f.home / ('synthetic-' + operation.path.name)
                    target.write_text('synthetic log\n')
                    files.truncate_regular(target)
                    if target.read_bytes() != b'':
                        raise AssertionError('real file operation did not truncate')
        files = self.core(f, 'files')
        ops = Ops()
        result = cleanup.apply_cleanup(plan, f.repo / 'reports', ops)
        self.assertEqual(result.rc, 1)
        self.assertEqual(ops.seen, ['truncate', 'truncate', 'truncate', 'truncate',
                                    'history', 'child-history', 'snapshot'])
        self.assertEqual([row.success for row in result.operations],
                         [True, False, True, True, True, True, True])
        self.assertIn('synthetic syslog failure', result.operations[1].error)

    def test_cleanup_refuses_links(self):
        f = self.fixture()
        files = self.core(f, 'files')
        target = f.home / 'referent'
        target.write_text('preserve synthetic bytes')
        link = f.home / 'history-link'
        link.symlink_to(target)
        directory = f.home / 'log-directory'
        directory.mkdir()
        fifo = f.home / 'log-fifo'
        os.mkfifo(fifo)
        for path in (link, directory, fifo):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                files.truncate_regular(path)
        self.assertEqual(target.read_text(), 'preserve synthetic bytes')
        self.assertTrue(link.is_symlink())

    def test_burp_open_is_not_network_consent(self):
        for session in (None, 'remote.example.test'):
            f = self.fixture()
            if session:
                f.set_session(session)
            result = f.run_leaf(BURP, ('8080',), stdin='no\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            names = [row[0] for row in f.records()]
            self.assertIn('burpsuite', names)
            self.assertNotIn('curl', names)
            self.assertIn('Community', result.stdout)
            self.assertNotIn('captura certificada', result.stdout)

    def test_burp_status_has_no_side_effects(self):
        for legacy, missing_ss in ((False, False), (True, False), (True, True)):
            f = self.fixture()
            if legacy:
                state = f.repo / 'scans/burp'
                state.mkdir(parents=True)
                (state / 'burp.pid').write_text('999999\n')
                (state / 'config_sin_objetivo.json').write_text('{"listener_port":8080}\n')
            if missing_ss:
                # Preserve the double instead of deleting it; PATH no longer sees it.
                (f.bin / 'ss').rename(f.repo / 'retained-ss')
            before = f.snapshot()
            result = f.run_leaf(BURP, ('--estado',))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.snapshot(), before)
            self.assertFalse(any(r[0] in ('curl', 'burpsuite', 'sudo') for r in f.records()))
            if missing_ss:
                self.assertIn('NO_DETERMINADO', result.stdout)

    def test_burp_verify_explicit_url(self):
        for args in (('--verificar', 'https://example.test/a', '--proxy-port', '8080'),
                     ('--verificar', 'https://example.test/a', '--proxy-port', '8080', '--execute'),
                     ('--verificar', 'https://example.test/a', '--proxy-port', '8080', '--confirm-network'),
                     ('--verificar', 'https://u:p@example.test/a', '--proxy-port', '8080',
                      '--execute', '--confirm-network'),
                     ('--verificar', 'https://example.test/\n', '--proxy-port', '8080',
                      '--execute', '--confirm-network'),
                     ('--verificar', 'example.test', '--proxy-port', '0',
                      '--execute', '--confirm-network'),
                     ('--verificar', 'https://example.test/a', '--proxy-port', '65536',
                      '--execute', '--confirm-network')):
            f = self.fixture()
            self.assertNotEqual(f.run_leaf(BURP, args).returncode, 0)
            self.assertFalse(any(r[0] == 'curl' for r in f.records()))
        f = self.fixture()
        result = f.run_leaf(BURP, ('--verificar', 'https://example.test/a?token=secret',
                                  '--proxy-port', '8080', '--execute', '--confirm-network'))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [r for r in f.records() if r[0] == 'curl']
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1:], ['--request', 'GET', '--max-time', '5', '--noproxy', '',
                                      '--proxy', 'http://127.0.0.1:8080', '--output', '/dev/null',
                                      '--write-out', '%{http_code}', '--',
                                      'https://example.test/a?token=secret'])
        self.assertNotIn('secret', result.stdout + result.stderr)

    def test_burp_stop_pins_owned_identity(self):
        f = self.fixture()
        burp = self.core(f, 'burp')
        # Entire process transport is synthetic: no foreign PID or real signal.
        class Ops:
            def __init__(self):
                self.events = []
                self.ticks = 20
            def identity(self, pid):
                self.events.append(('identity', pid))
                return {'pid': 123, 'start_ticks': self.ticks, 'uid': 1000, 'boot_id': 'synthetic-boot'}
            def pidfd_open(self, pid):
                self.events.append(('open', pid))
                return 42
            def pidfd_send_signal(self, fd, number):
                self.events.append(('signal', fd, number))
            def wait(self, fd, timeout):
                self.events.append(('wait', fd, timeout))
                return False
            def close(self, fd):
                self.events.append(('close', fd))
        instance = 'burp-' + 'a' * 32
        root = f.repo / 'scans/burp'
        state = root / 'instances' / instance
        state.mkdir(parents=True, mode=0o700)
        import json
        receipt = state / 'instance.json'
        receipt.write_text(json.dumps({'version': 1, 'instance_id': instance, 'pid': 123,
                                      'start_ticks': 20, 'uid': 1000, 'boot_id': 'synthetic-boot'}))
        receipt.chmod(0o600)
        before = receipt.read_bytes()
        ops = Ops()
        self.assertEqual(burp.stop_burp(root, instance, ops), 0)
        self.assertEqual(ops.events, [('identity', 123), ('open', 123), ('identity', 123),
                                     ('signal', 42, signal.SIGTERM), ('wait', 42, 5),
                                     ('signal', 42, signal.SIGKILL), ('close', 42)])
        self.assertEqual(receipt.read_bytes(), before)
        for ticks in (21, None):
            ops = Ops()
            ops.ticks = ticks
            self.assertNotEqual(burp.stop_burp(root, instance, ops), 0)
            self.assertFalse(any(e[0] == 'signal' for e in ops.events))
        ops = Ops()
        def unavailable(pid):
            raise OSError('pidfd absent')
        ops.pidfd_open = unavailable
        self.assertNotEqual(burp.stop_burp(root, instance, ops), 0)
        self.assertFalse(any(e[0] == 'signal' for e in ops.events))
        legacy_root = f.repo / 'legacy-burp'
        legacy_root.mkdir()
        (legacy_root / 'burp.pid').write_text('123\n')
        ops = Ops()
        self.assertNotEqual(burp.stop_burp(legacy_root, None, ops), 0)
        self.assertFalse(any(e[0] == 'signal' for e in ops.events))
        # PID reuse between first observation and pidfd pin must fail closed.
        ops = Ops()
        original_pin = ops.pidfd_open
        def reused(pid):
            ops.ticks = 21
            return original_pin(pid)
        ops.pidfd_open = reused
        self.assertNotEqual(burp.stop_burp(root, instance, ops), 0)
        self.assertFalse(any(e[0] == 'signal' for e in ops.events))
        forged = 'burp-' + 'b' * 32
        forged_state = root / 'instances' / forged
        forged_state.mkdir(mode=0o700)
        (forged_state / 'instance.json').write_bytes(before)  # wrong instance namespace
        (forged_state / 'instance.json').chmod(0o600)
        ops = Ops()
        self.assertNotEqual(burp.stop_burp(root, forged, ops), 0)
        self.assertFalse(any(e[0] == 'signal' for e in ops.events))

    def test_menu_cancel_and_coordinator_exclusions(self):
        for menu, stdin in (('scanners_menu', '6\n0\n0\n'),
                            ('scanners_menu', '6\n2\n\n'),
                            ('postexploitation_menu', '7\nno\n0\n'),
                            ('postexploitation_menu', '7\n')):
            f = self.fixture()
            result = f.run_menu(menu, stdin)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(any('--execute' in row for row in f.records()))
        f = self.fixture()
        result = f.run_menu('postexploitation_menu', '7\nno\n0\n')
        self.assertIn('LOCAL', result.stdout + result.stderr)
        f = self.fixture()
        result = f.run_menu('scanners_menu', '4\ns\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(f.records(), [['record-dispatch', BURP, '03_Scanners']])
        f = self.fixture()
        result = f.run_menu('scanners_menu', '6\n2\nhttps://example.test/a\n8080\ns\n0\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(f.records(), [[
            'record-dispatch', BURP, '03_Scanners', '--prepared', '--verificar',
            'https://example.test/a', '--proxy-port', '8080', '--execute', '--confirm-network']])
        f = self.fixture()
        result = f.run_menu('postexploitation_menu', '7\n2\ns\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(f.records(), [[
            'record-dispatch', CLEANER, '06_PostExploitation', '--prepared',
            '--execute', '--confirm-local-cleanup']])
        self.assertIn('LOCAL', result.stdout + result.stderr)
        # Coordinator leaves are replaced ONLY with inert transport recorders;
        # coordinator's actual exclusion/dispatch logic still executes.
        for coordinator in ('03_Scanners/run_all_scanners.sh',
                            '06_PostExploitation/run_all_post.sh'):
            f = self.fixture()
            f.record_coordinator_leaves()
            result = f.run_leaf(coordinator, ('example.test',))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(f.records())
            self.assertFalse(any('burp_launcher' in repr(r) or 'logs_cleaner' in repr(r)
                                 for r in f.records()))
