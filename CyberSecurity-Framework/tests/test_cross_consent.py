"""Consent block regressions. Written first; STATIC NOT RUN, exact worker only.

Backend doubles record effects; production CLI/policy/results are never replaced.
Future imports intentionally occur inside methods, so missing cores are ERROR,
not discovery omissions. Synthetic fixtures and final artifacts persist.
"""
from pathlib import Path
import importlib
import io
import os
import signal
import stat
import subprocess
import sys
import unittest
from unittest import mock
import json
import uuid

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
                          (('--help', '--unknown'), 2), (('--help', '--execute'), 2),
                          (('--execute',), 2)):
            with self.subTest(args=args):
                f = self.fixture()
                before = f.snapshot()
                result = f.run_leaf(CLEANER, args, stdin='')
                self.assertEqual(result.returncode, rc, result.stderr)
                self.assertEqual(f.records(), [])
                self.assertEqual(f.snapshot(), before)
        # TTY-specific refusal/EOF/generic yes cannot authorize LOCAL effects.
        class TTY(io.StringIO):
            def isatty(self):
                return True
        f = self.fixture()
        cli = self.core(f, 'cleanup_cli')
        before = f.snapshot()
        ops = mock.Mock()
        for answer in ('', 'no\n', 'si\n'):
            with mock.patch.object(cli.sys, 'stdin', TTY(answer)), \
                    mock.patch.object(cli.sys, 'stderr', TTY()):
                self.assertEqual(cli.main(['--execute'], framework=f.framework, ops=ops), 2)
        ops.perform.assert_not_called()
        self.assertEqual(f.snapshot(), before)
        # Exact LOCAL consent uses the real parser, plan, iteration and results;
        # only the operation boundary is recorded (no real log/history backend).
        f.set_session('remote.example.test')
        class Recorder:
            def __init__(self):
                self.seen = []
            def perform(self, operation, child):
                self.seen.append((operation.kind, operation.path, child))
                if operation.kind == 'snapshot':
                    return b'synthetic TTY snapshot\n'
                return None
        recorder = Recorder()
        stdout, stderr = io.StringIO(), TTY()
        with mock.patch.dict(os.environ, {'HOME': str(f.home),
                                         'CONFIRM_LOCAL_CLEANUP': '1',
                                         'FRAMEWORK_ASSUME_YES': '1'}):
            with mock.patch.object(cli.sys, 'stdin', TTY('LIMPIAR LOCAL\n')), \
                    mock.patch.object(cli.sys, 'stderr', stderr), \
                    mock.patch.object(cli.sys, 'stdout', stdout):
                self.assertEqual(cli.main(['--execute'], framework=f.framework,
                                          ops=recorder), 0)
            expected = [('truncate', Path('/var/log') / name)
                        for name in ('auth.log', 'syslog', 'btmp', 'wtmp')] + [
                            ('history', f.home / '.bash_history'),
                            ('child-history', None), ('snapshot', None)]
            self.assertEqual([(kind, path) for kind, path, _ in recorder.seen], expected)
            child = recorder.seen[0][2]
            self.assertEqual(child.parent, f.repo / 'scans/cleanup')
            uuid.UUID(child.name)
            self.assertTrue(all(row[2] == child for row in recorder.seen))
            self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o700)
            self.assertEqual((child / 'last_access.txt').read_bytes(), b'synthetic TTY snapshot\n')
            self.assertEqual(stat.S_IMODE((child / 'last_access.txt').stat().st_mode), 0o600)
            self.assertIn('LIMPIAR LOCAL', stderr.getvalue())
            self.assertEqual(len([row for row in stdout.getvalue().splitlines()
                                  if row.startswith('OK LOCAL ')]), 7)
            self.assertIn('Operaciones LOCAL completadas.', stdout.getvalue())
            self.assertNotIn('FALLO', stdout.getvalue() + stderr.getvalue())
            self.assertNotIn('remote.example.test', stdout.getvalue() + stderr.getvalue())
            # A successful launch grants nothing to a subsequent invocation,
            # even with stale global yes variables and the remote session intact.
            after = f.snapshot()
            accepted_rows = list(recorder.seen)
            for answer in ('', 'no\n', 'si\n'):
                with mock.patch.object(cli.sys, 'stdin', TTY(answer)), \
                        mock.patch.object(cli.sys, 'stderr', TTY()), \
                        mock.patch.object(cli.sys, 'stdout', io.StringIO()):
                    self.assertEqual(cli.main(['--execute'], framework=f.framework,
                                              ops=recorder), 2)
                self.assertEqual(recorder.seen, accepted_rows)
                self.assertEqual(f.snapshot(), after)
        self.assertEqual(f.records(), [])
        # Fixture transport contracts use doubles only: no timed-out real leaf.
        for state in ('DONE', 'TIMEOUT', 'LAUNCH_ERROR'):
            f = self.fixture()
            argv = ['/bin/bash', 'synthetic-transport-only']
            def transport(actual, **kwargs):
                self.assertEqual(actual, argv)
                root = f.output / '1'
                self.assertEqual(json.loads((root / 'argv.json').read_text()), argv)
                self.assertEqual(json.loads((root / 'started.json').read_text())['state'], 'STARTING')
                self.assertTrue((root / 'stdout').is_file())
                self.assertTrue((root / 'stderr').is_file())
                self.assertEqual(kwargs['timeout'], 15)
                kwargs['stdout'].write(b'partial synthetic stdout\n')
                kwargs['stdout'].flush()
                kwargs['stderr'].write(b'partial synthetic stderr\n')
                kwargs['stderr'].flush()
                if state == 'TIMEOUT':
                    raise subprocess.TimeoutExpired(actual, 15)
                if state == 'LAUNCH_ERROR':
                    raise OSError(2, 'synthetic launch failure')
                return subprocess.CompletedProcess(actual, 7)
            with mock.patch('cross_module_fixture.subprocess.run', side_effect=transport):
                if state == 'DONE':
                    result = f._run(argv, '')
                    self.assertEqual(result.returncode, 7)
                    self.assertEqual(result.stdout, 'partial synthetic stdout\n')
                    self.assertEqual(result.stderr, 'partial synthetic stderr\n')
                else:
                    with self.assertRaises(subprocess.TimeoutExpired if state == 'TIMEOUT' else OSError):
                        f._run(argv, '')
            root = f.output / '1'
            self.assertEqual((root / 'stdout').read_bytes(), b'partial synthetic stdout\n')
            self.assertEqual((root / 'stderr').read_bytes(), b'partial synthetic stderr\n')
            receipt = json.loads((root / 'result.json').read_text())
            self.assertEqual(receipt['state'], state)
            self.assertEqual(receipt['argv'], argv)
            self.assertEqual(receipt['returncode'], 7 if state == 'DONE' else None)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            for path in root.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            # Reusing an invocation number may not overwrite retained evidence.
            retained = {p.name: p.read_bytes() for p in root.iterdir()}
            f._invocations = 0
            with mock.patch('cross_module_fixture.subprocess.run') as not_launched:
                with self.assertRaises(FileExistsError):
                    f._run(argv, '')
                not_launched.assert_not_called()
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, retained)

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
        prior = f.repo / 'scans/cleanup/11111111111141118111111111111111'
        prior.mkdir(parents=True, mode=0o700)
        (prior / 'last_access.txt').write_bytes(b'previous synthetic report\n')
        (prior / 'last_access.txt').chmod(0o600)
        prior_bytes = (prior / 'last_access.txt').read_bytes()
        prior_info = (prior / 'last_access.txt').stat()
        result = f.run_leaf(CLEANER, ('--execute', '--confirm-local-cleanup'))
        # Fixed system logs are missing/inaccessible in the confined fixture;
        # no sudo escalation occurs, while the synthetic user history succeeds.
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual((f.home / '.bash_history').read_bytes(), b'')
        self.assertFalse(any(row[0] == 'sudo' for row in f.records()))
        failed_rows = [row for row in result.stderr.splitlines() if row.startswith('FALLO LOCAL ')]
        self.assertEqual(len(failed_rows), 4, result.stdout + result.stderr)
        for name in ('auth.log', 'syslog', 'btmp', 'wtmp'):
            self.assertTrue(any(row.startswith('FALLO LOCAL truncate: /var/log/' + name + ':')
                                for row in failed_rows), failed_rows)
        self.assertIn('OK LOCAL history: ' + str(f.home / '.bash_history'), result.stdout)
        self.assertIn('Resultado parcial: hay fallos.', result.stdout)
        self.assertNotIn('remote.example.test', result.stdout + result.stderr)
        self.assertTrue(f.records())
        self.assertNotIn('remote.example.test', repr(f.records()))
        created = [p for p in prior.parent.iterdir() if p != prior]
        self.assertEqual(len(created), 1)
        uuid.UUID(created[0].name)
        self.assertEqual(stat.S_IMODE(created[0].stat().st_mode), 0o700)
        self.assertEqual((created[0] / 'last_access.txt').read_bytes(), b'synthetic login snapshot\n')
        self.assertEqual(stat.S_IMODE((created[0] / 'last_access.txt').stat().st_mode), 0o600)
        for path in created[0].rglob('*'):
            self.assertFalse(path.is_symlink())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        self.assertEqual((prior / 'last_access.txt').read_bytes(), prior_bytes)
        self.assertEqual(stat.S_IMODE((prior / 'last_access.txt').stat().st_mode), 0o600)
        self.assertEqual(((prior / 'last_access.txt').stat().st_dev,
                          (prior / 'last_access.txt').stat().st_ino),
                         (prior_info.st_dev, prior_info.st_ino))

    def test_cleanup_local_plan_and_partial_failure(self):
        f = self.fixture()
        cleanup = self.core(f, 'cleanup')
        before_plan = f.snapshot()
        plan = cleanup.plan_cleanup(f.home)
        self.assertEqual(f.snapshot(), before_plan)
        self.assertEqual([(op.kind, str(op.path) if op.path else None) for op in plan], [
            ('truncate', '/var/log/auth.log'), ('truncate', '/var/log/syslog'),
            ('truncate', '/var/log/btmp'), ('truncate', '/var/log/wtmp'),
            ('history', str(f.home / '.bash_history')), ('child-history', None),
            ('snapshot', None)])
        # Only operations are doubled; apply_cleanup owns iteration/error policy.
        class Ops:
            def __init__(self):
                self.seen = []
                self.child_history = ['synthetic child-only command']
            def perform(self, operation, report_root):
                self_test.assertEqual(report_root.parent, reports)
                self_test.assertTrue(report_root.is_dir())  # allocated by business, not Ops
                self_test.assertEqual(stat.S_IMODE(report_root.stat().st_mode), 0o700)
                self.seen.append(operation.kind)
                if operation.path == Path('/var/log/syslog'):
                    raise OSError('synthetic syslog failure')
                if operation.kind in ('truncate', 'history'):
                    target = f.home / ('synthetic-' + operation.path.name)
                    target.write_text('synthetic log\n')
                    files.truncate_regular(target)
                    if target.read_bytes() != b'':
                        raise AssertionError('real file operation did not truncate')
                elif operation.kind == 'child-history':
                    self.child_history.clear()  # synthetic child transport state only
                elif operation.kind == 'snapshot':
                    return b'synthetic access snapshot\n'
        files = self.core(f, 'files')
        self_test = self
        reports = f.repo / 'scans/cleanup'
        prior = reports / '11111111111141118111111111111111'
        prior.mkdir(parents=True, mode=0o700)
        (prior / 'last_access.txt').write_bytes(b'prior report intact\n')
        (prior / 'last_access.txt').chmod(0o600)
        ops = Ops()
        result = cleanup.apply_cleanup(plan, reports, ops)
        self.assertEqual(result.rc, 1)
        self.assertEqual(ops.seen, ['truncate', 'truncate', 'truncate', 'truncate',
                                    'history', 'child-history', 'snapshot'])
        self.assertEqual([row.success for row in result.operations],
                         [True, False, True, True, True, True, True])
        self.assertIn('synthetic syslog failure', result.operations[1].error)
        self.assertEqual(ops.child_history, [])
        self.assertEqual(result.report_dir.parent, reports)
        uuid.UUID(result.report_dir.name)
        self.assertEqual((result.report_dir / 'last_access.txt').read_bytes(), b'synthetic access snapshot\n')
        self.assertEqual(stat.S_IMODE((result.report_dir / 'last_access.txt').stat().st_mode), 0o600)
        previous_output = {str(p.relative_to(reports)): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode),
                                                       p.stat().st_dev, p.stat().st_ino)
                           for p in reports.rglob('*') if p.is_file()}
        second = cleanup.apply_cleanup(plan, reports, Ops())
        self.assertEqual(second.rc, 1)
        self.assertNotEqual(second.report_dir, result.report_dir)
        self.assertEqual(second.report_dir.parent, reports)
        self.assertEqual(stat.S_IMODE(second.report_dir.stat().st_mode), 0o700)
        self.assertEqual((second.report_dir / 'last_access.txt').read_bytes(), b'synthetic access snapshot\n')
        self.assertEqual(stat.S_IMODE((second.report_dir / 'last_access.txt').stat().st_mode), 0o600)
        for relative, expected in previous_output.items():
            path = reports / relative
            self.assertEqual((path.read_bytes(), stat.S_IMODE(path.stat().st_mode),
                              path.stat().st_dev, path.stat().st_ino), expected)

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
        alias = f.home / 'hardlink'
        os.link(target, alias)
        parent_link = f.home / 'parent-link'
        parent_link.symlink_to(f.home, target_is_directory=True)
        for path in (link, directory, fifo, alias, parent_link / 'referent'):
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
            instances = list((f.repo / 'scans/burp/instances').iterdir())
            self.assertEqual(len(instances), 1)
            self.assertRegex(instances[0].name, r'^burp-[0-9a-f]{32}$')
            self.assertEqual(stat.S_IMODE(instances[0].stat().st_mode), 0o700)
            for path in instances[0].iterdir():
                self.assertFalse(path.is_symlink())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            config = json.loads((instances[0] / 'config.json').read_text())
            self.assertEqual(config['proxy']['request_listeners'][0]['listener_port'], 8080)
            if session:
                self.assertEqual(config['target']['scope']['include'][0]['host'],
                                 r'^remote\.example\.test$')
            else:
                self.assertNotIn('target', config)
        f = self.fixture()
        f.set_session('remote.example.test')
        f.configure_ss(('State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
                        'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("foreign-synthetic",pid=999999,fd=3))\n',))
        result = f.run_leaf(BURP, ('8080',), stdin='no\n')
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(r[0] in ('curl', 'burpsuite') for r in f.records()))
        self.assertIn('Puerto ocupado: 8080', output)
        self.assertIn('Propietario: NO_DETERMINADO', output)
        self.assertIn('Captura: NO_VERIFICADA', output)
        self.assertNotRegex(output, r'(?i)Burp escucha|proxy comprobado|captura (certificada|confirmada|verificada)|propietario: (Burp|PROPIO)')
        # Receipt publication uses actual business/file logic; only process
        # launch/identity and executable availability are synthetic transports.
        f = self.fixture()
        burp = self.core(f, 'burp')
        class LaunchOps:
            def listening_ports(self):
                return set()
            def launch(self, config, log_fd):
                self.config = config
                self.log_mode = stat.S_IMODE(os.fstat(log_fd).st_mode)
                return 123
            def identity(self, pid):
                return {'pid': pid, 'start_ticks': 20, 'uid': os.getuid(),
                        'boot_id': 'synthetic-boot'}
        ops = LaunchOps()
        with mock.patch.object(burp.shutil, 'which', return_value=str(f.bin / 'burpsuite')):
            first = burp.start_burp(f.framework, 8081, ops)
            before = {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mode)
                      for p in first.directory.iterdir()}
            second = burp.start_burp(f.framework, 8081, ops)
        self.assertTrue(first.managed)
        self.assertNotEqual(first.instance_id, second.instance_id)
        self.assertEqual(ops.log_mode, 0o600)
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mode)
                                  for p in first.directory.iterdir()})
        self.assertEqual(json.loads((first.directory / 'instance.json').read_text()),
                         {'version': 1, 'instance_id': first.instance_id, 'pid': 123,
                          'start_ticks': 20, 'uid': os.getuid(),
                          'boot_id': 'synthetic-boot', 'port': 8081})
        for instance in (first, second):
            self.assertEqual(stat.S_IMODE(instance.directory.stat().st_mode), 0o700)
            for path in instance.directory.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_burp_status_has_no_side_effects(self):
        for args, rc in ((('--help',), 0), (('--unknown',), 2),
                         (('--help', '--execute'), 2), (('--estado', '--execute'), 2),
                         (('--estado', '--instance', '../legacy'), 2)):
            f = self.fixture()
            before = f.snapshot()
            result = f.run_leaf(BURP, args)
            self.assertEqual(result.returncode, rc, result.stderr)
            self.assertEqual(f.snapshot(), before)
            self.assertEqual(f.records(), [])
        for legacy, missing_ss in ((False, False), (True, False), (True, True)):
            f = self.fixture()
            f.configure_ss(('State Recv-Q Send-Q Local Address:Port Peer Address:Port\n'
                            'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\n',))
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
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.snapshot(), before)
            self.assertFalse(any(r[0] in ('curl', 'burpsuite', 'sudo') for r in f.records()))
            self.assertIn('Propietario: NO_DETERMINADO', output)
            self.assertIn('Captura: NO_VERIFICADA', output)
            self.assertNotRegex(output, r'(?i)Burp escucha|proxy comprobado|captura (certificada|confirmada|verificada)|propietario: (Burp|PROPIO)')
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
                      '--execute', '--confirm-network'),
                     ('--verificar', 'https://example.test/{a,b}', '--proxy-port', '8080',
                      '--execute', '--confirm-network'),
                     ('--verificar', 'https://example.test/a[1-9]', '--proxy-port', '8080',
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
        # Exact public TTY gate; generic yes/EOF cannot authorize network.
        class TTY(io.StringIO):
            def isatty(self):
                return True
        cli = self.core(f, 'burp_cli')
        class Recorder:
            def __init__(self):
                self.calls = []
            def request(self, url, port):
                self.calls.append((url, port))
                return 0, '200'
        ops = Recorder()
        before = f.snapshot()
        for answer in ('', 'no\n', 'si\n'):
            with mock.patch.object(cli.sys, 'stdin', TTY(answer)), \
                    mock.patch.object(cli.sys, 'stderr', TTY()), \
                    mock.patch.object(cli.sys, 'stdout', io.StringIO()):
                self.assertEqual(cli.main(['--verificar', 'https://example.test/a?token=secret',
                                           '--proxy-port', '8080', '--execute'],
                                          framework=f.framework, ops=ops), 2)
        self.assertEqual(ops.calls, [])
        stdout = io.StringIO()
        with mock.patch.object(cli.sys, 'stdin', TTY('ENVIAR GET\n')), \
                mock.patch.object(cli.sys, 'stderr', TTY()), \
                mock.patch.object(cli.sys, 'stdout', stdout):
            self.assertEqual(cli.main(['--verificar', 'https://example.test/a?token=secret',
                                       '--proxy-port', '8080', '--execute'],
                                      framework=f.framework, ops=ops), 0)
        self.assertEqual(ops.calls, [('https://example.test/a?token=secret', 8080)])
        self.assertNotIn('secret', stdout.getvalue())
        self.assertEqual(f.snapshot(), before)
        # Curl's own configuration must not silently enable redirects/retries or
        # URL globbing: exercise real argument/env construction, double transport.
        burp = self.core(f, 'burp')
        response = subprocess.CompletedProcess([], 0, '200', '')
        with mock.patch.object(burp.subprocess, 'run', return_value=response) as run:
            self.assertEqual(burp.BurpOps().request('https://example.test/a', 8080), (0, '200'))
        environment = run.call_args.kwargs['env']
        for variable in ('CURL_HOME', 'XDG_CONFIG_HOME', 'HOME'):
            self.assertEqual(environment[variable], '/dev/null')

    def test_burp_stop_pins_owned_identity(self):
        f = self.fixture()
        # Public wrapper gate, with no receipt/PID to adopt even on the old code.
        before_cli = f.snapshot()
        rejected = f.run_leaf(BURP, ('--parar', '--instance', 'burp-' + 'a' * 32))
        self.assertEqual(rejected.returncode, 2, rejected.stdout + rejected.stderr)
        self.assertEqual(f.records(), [])
        self.assertEqual(f.snapshot(), before_cli)
        burp = self.core(f, 'burp')
        # Entire process transport is synthetic: no foreign PID or real signal.
        class Ops:
            def __init__(self):
                self.events = []
                self.ticks = 20
                self.uid = 1000
                self.boot_id = 'synthetic-boot'
            def identity(self, pid):
                self.events.append(('identity', pid))
                return {'pid': 123, 'start_ticks': self.ticks, 'uid': self.uid, 'boot_id': self.boot_id}
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
        receipt = state / 'instance.json'
        receipt.write_text(json.dumps({'version': 1, 'instance_id': instance, 'pid': 123,
                                      'start_ticks': 20, 'uid': 1000, 'boot_id': 'synthetic-boot'}))
        receipt.chmod(0o600)
        before = receipt.read_bytes()
        # Same public argument parser with a real new receipt, but injected
        # process transport: no possible signal to a numeric OS PID in this test.
        cli = self.core(f, 'burp_cli')
        ops = Ops()
        before_gate = f.snapshot()
        self.assertEqual(cli.main(['--parar', '--instance', instance],
                                  framework=f.framework, ops=ops), 2)
        self.assertEqual(ops.events, [])
        self.assertEqual(f.snapshot(), before_gate)
        ops = Ops()
        self.assertEqual(cli.main(['--parar', '--instance', instance, '--execute'],
                                  framework=f.framework, ops=ops), 0)
        self.assertEqual(ops.events, [('identity', 123), ('open', 123), ('identity', 123),
                                     ('signal', 42, signal.SIGTERM), ('wait', 42, 5),
                                     ('signal', 42, signal.SIGKILL), ('close', 42)])
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
        for field, changed in (('uid', 1001), ('boot_id', 'other-synthetic-boot')):
            for after_pin in (False, True):
                ops = Ops()
                if after_pin:
                    original_pin = ops.pidfd_open
                    def changed_after_pin(pid):
                        setattr(ops, field, changed)
                        return original_pin(pid)
                    ops.pidfd_open = changed_after_pin
                else:
                    setattr(ops, field, changed)
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

        # No-instance inference is intentionally blocked once multiple namespaces
        # exist, rather than adopting the first receipt/PID in a directory listing.
        ops = Ops()
        self.assertNotEqual(burp.stop_burp(root, None, ops), 0)
        self.assertEqual(ops.events, [])
        linked = 'burp-' + 'c' * 32
        linked_state = root / 'instances' / linked
        linked_state.mkdir(mode=0o700)
        (linked_state / 'instance.json').symlink_to(receipt)
        ops = Ops()
        self.assertNotEqual(burp.stop_burp(root, linked, ops), 0)
        self.assertEqual(ops.events, [])
        self.assertEqual(receipt.read_bytes(), before)

    def test_menu_cancel_and_coordinator_exclusions(self):
        for menu, stdin in (('scanners_menu', '6\n0\n0\n'),
                            ('scanners_menu', '6\n2\n\n'),
                            ('postexploitation_menu', '7\n0\n0\n'),
                            ('postexploitation_menu', '7\n2\nno\n0\n'),
                            ('postexploitation_menu', '7\n2\n'),
                            ('postexploitation_menu', '7\n2\n0\n0\n')):
            f = self.fixture()
            f.set_session('remote.example.test')
            session = f.framework / '00_Config/.session'
            before_session = (session.read_bytes(), stat.S_IMODE(session.stat().st_mode))
            before_tree = f.snapshot()
            result = f.run_menu(menu, stdin)
            self.assertEqual(result.returncode, 0, result.stderr)
            if menu == 'postexploitation_menu' and stdin.startswith('7\n2\n'):
                self.assertRegex(result.stdout, r'(?im)^CONSENT_PROMPT: .*LOCAL')
                self.assertIn('LOCAL', result.stdout + result.stderr)
            # Only an explicitly inert preview is permitted, never unflagged
            # historical cleaner dispatch or a session-derived destination.
            for row in f.records():
                self.assertEqual(menu, 'postexploitation_menu')
                self.assertEqual(row, ['record-dispatch', CLEANER, '06_PostExploitation',
                                       '--prepared', '--preview'])
            self.assertEqual((session.read_bytes(), stat.S_IMODE(session.stat().st_mode)), before_session)
            self.assertEqual(f.snapshot(), before_tree)
        f = self.fixture()
        f.set_session('remote.example.test')
        result = f.run_menu('postexploitation_menu', '7\n2\nno\n0\n')
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
        f.set_session('remote.example.test')
        session = f.framework / '00_Config/.session'
        before_session = (session.read_bytes(), stat.S_IMODE(session.stat().st_mode))
        before_tree = f.snapshot()
        result = f.run_menu('postexploitation_menu', '7\n2\ns\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(f.records(), [[
            'record-dispatch', CLEANER, '06_PostExploitation', '--prepared',
            '--execute', '--confirm-local-cleanup']])
        self.assertIn('LOCAL', result.stdout + result.stderr)
        self.assertEqual((session.read_bytes(), stat.S_IMODE(session.stat().st_mode)), before_session)
        self.assertEqual(f.snapshot(), before_tree)
        # Coordinator leaves are replaced ONLY with inert transport recorders;
        # coordinator's actual exclusion/dispatch logic still executes.
        for coordinator in ('03_Scanners/run_all_scanners.sh',
                            '06_PostExploitation/run_all_post.sh'):
            f = self.fixture()
            from cross_module_fixture import COORDINATOR_LEAVES
            # Coordinator-only transports start absent: no copied child source
            # (especially loot) may be needed just to initialize a fixture.
            for relative in COORDINATOR_LEAVES:
                self.assertFalse((f.framework / relative).exists())
            originals = {relative: (f.framework / relative).read_bytes()
                         for relative in (CLEANER, BURP)}
            f.record_coordinator_leaves()
            for relative in COORDINATOR_LEAVES:
                self.assertTrue((f.framework / relative).is_file())
                self.assertFalse((f.framework / (relative + '.retained-source')).exists())
            for relative, content in originals.items():
                self.assertEqual((f.framework / (relative + '.retained-source')).read_bytes(), content)
            result = f.run_leaf(coordinator, ('example.test',))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(f.records())
            self.assertFalse(any('burp_launcher' in repr(r) or 'logs_cleaner' in repr(r)
                                 for r in f.records()))
