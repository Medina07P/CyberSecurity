"""Task3: private storage and synthetic, sequential child ownership."""
import atexit
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

from automation_fixture import AutomationFixture, preserve

SOURCES = AutomationFixture()
atexit.register(SOURCES.close)
sys.path.insert(0, str(SOURCES.framework / '00_Config/lib'))
from automation.model import Command, Permissions, Plan, RuntimeContext, Step
try:
    from automation.storage import RunStore
    from automation.runner import run_plan
except ImportError:
    RunStore = None
    run_plan = None


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = AutomationFixture()
        self.addCleanup(self.fixture.close)
        self.ctx = RuntimeContext(self.fixture.framework, self.fixture.repo,
                                  Path(sys.executable), str(self.fixture.bin))
        self.plan = Plan('synthetic', (Step('first', 'ping', {}, ()),
                                     Step('second', 'ping', {}, ('first',))), 10)
        self.permissions = Permissions(frozenset(), frozenset())

    def command(self, code, timeout=3):
        return Command((sys.executable, '-c', code), self.fixture.repo, {}, timeout)

    def run_codes(self, codes, plan=None):
        return run_plan(plan or self.plan, self.ctx, self.permissions,
                        lambda step, root: (self.command(codes[step.id]),))

    def test_stop_on_failure(self):
        self.assertIsNotNone(run_plan, 'Task3 runner missing')
        result = self.run_codes({'first': 'raise SystemExit(7)', 'second': 'pass'})
        self.assertEqual(result.rc, 1)
        self.assertEqual(result.steps[0].rc, 7)
        self.assertEqual(result.steps[0].state, 'fallido')
        self.assertEqual(result.steps[1].state, 'omitido')
        data = json.loads((result.run_dir / 'run.json').read_text())
        self.assertEqual(data['schema_version'], 1)
        self.assertEqual(data['steps'][0]['rc'], 7)
        self.assertNotIn('grants', data)

    def test_pending_and_executing_manifest_states(self):
        snapshots = []
        original = RunStore.write_state
        def write(store, data):
            original(store, data)
            snapshots.append(json.loads((store.path / 'run.json').read_text()))
        with patch.object(RunStore, 'write_state', write):
            result = self.run_codes({'first': 'pass', 'second': 'pass'})
        self.assertEqual(result.rc, 0)
        self.assertEqual([s['state'] for s in snapshots[0]['steps']],
                         ['pendiente', 'pendiente'])
        running = [data for data in snapshots if any(
            s['state'] == 'ejecutando' for s in data['steps'])]
        self.assertTrue(running)
        self.assertEqual([s['state'] for s in running[0]['steps']],
                         ['ejecutando', 'pendiente'])
        self.assertIsNone(running[0]['steps'][0]['rc'])
        self.assertIsNone(running[0]['finished_at'])

    def test_cancelled_step_state_and_no_spawn(self):
        def compile_step(step, root):
            os.kill(os.getpid(), signal.SIGINT)
            return (self.command('pass'),)
        with patch('automation.runner.subprocess.Popen',
                   side_effect=AssertionError('must not spawn')) as spawn:
            result = run_plan(self.plan, self.ctx, self.permissions, compile_step)
        spawn.assert_not_called()
        self.assertEqual(result.rc, 130)
        self.assertEqual(result.steps[0].state, 'cancelado')
        self.assertIsNone(result.steps[0].rc)
        self.assertEqual(result.steps[1].state, 'omitido')
        data = json.loads((result.run_dir / 'run.json').read_text())
        self.assertEqual(data['steps'][0]['state'], 'cancelado')

    def test_preflight_failure_does_not_inherit_previous_rc(self):
        def compile_step(step, root):
            if step.id == 'second':
                raise ValueError('synthetic preflight')
            return (self.command('pass'),)
        result = run_plan(self.plan, self.ctx, self.permissions, compile_step)
        self.assertEqual(result.rc, 1)
        self.assertEqual(result.steps[0].rc, 0)
        self.assertEqual(result.steps[1].state, 'fallido')
        self.assertIsNone(result.steps[1].rc)

    def test_private_atomic_logs(self):
        self.assertIsNotNone(run_plan, 'Task3 runner missing')
        old = os.umask(0)
        try:
            result = self.run_codes({'first': 'import sys; print("out"); print("err", file=sys.stderr)',
                                     'second': 'import sys; assert sys.stdin.read() == ""'})
        finally:
            os.umask(old)
        self.assertEqual(result.rc, 0)
        self.assertEqual(result.run_dir.stat().st_mode & 0o777, 0o700)
        for path in result.run_dir.rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
        self.assertEqual((result.run_dir / 'logs/first.stdout.log').read_text(), 'out\n')
        self.assertEqual((result.run_dir / 'logs/first.stderr.log').read_text(), 'err\n')
        self.assertNotIn('hallazgos', (result.run_dir / 'run.json').read_text())

    def test_storage_errors(self):
        self.assertIsNotNone(run_plan, 'Task3 runner missing')
        for number in (errno.ENOSPC, errno.EACCES):
            with self.subTest(errno=number), patch.object(RunStore, 'open_log', side_effect=OSError(number, 'synthetic')):
                result = self.run_codes({'first': 'pass', 'second': 'pass'})
            self.assertEqual(result.rc, 1)
            self.assertEqual(result.steps[1].state, 'omitido')

    def test_lock_contention(self):
        self.assertIsNotNone(RunStore, 'Task3 storage missing')
        with RunStore.create(self.fixture.repo):
            lock = self.fixture.repo / 'scans/automation/.lock'
            inode = lock.stat().st_ino
            result = self.run_codes({'first': 'pass', 'second': 'pass'})
            self.assertEqual(result.rc, 1)
            self.assertIn('lock', result.steps[0].reason.lower())
            self.assertEqual(lock.stat().st_ino, inode)
        with RunStore.create(self.fixture.repo):
            pass

    def test_lock_contention_between_processes(self):
        code = ('import sys; from pathlib import Path; '
                f'sys.path.insert(0, {str(SOURCES.framework / "00_Config/lib")!r}); '
                'from automation.storage import RunStore; '
                f'store=RunStore.create(Path({str(self.fixture.repo)!r})); '
                'print("locked", flush=True); sys.stdin.read(); store.close()')
        holder = subprocess.Popen((sys.executable, '-c', code), stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, start_new_session=True)
        try:
            self.assertEqual(holder.stdout.readline(), b'locked\n')
            inode = (self.fixture.repo / 'scans/automation/.lock').stat().st_ino
            result = self.run_codes({'first': 'pass', 'second': 'pass'})
            self.assertEqual(result.rc, 1)
            self.assertIn('lock ocupado', result.steps[0].reason)
            self.assertEqual((self.fixture.repo / 'scans/automation/.lock').stat().st_ino, inode)
        finally:
            holder.stdin.close()
            try:
                holder.wait(timeout=5)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.wait(timeout=5)
            holder.stdout.close()

    def test_ancestor_swap_after_spawn_reaps(self):
        original = subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            scans = self.fixture.repo / 'scans'
            scans.rename(self.fixture.repo / 'detached')
            scans.symlink_to(self.fixture.home, target_is_directory=True)
            return child
        with patch('automation.runner.subprocess.Popen', spawn):
            result = self.run_codes({'first': 'import signal; signal.pause()', 'second': 'pass'})
        self.assertEqual(result.rc, 1)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertEqual(result.steps[1].state, 'omitido')
        self.assertEqual(list(self.fixture.home.iterdir()), [])

    def test_symlinks_and_ancestor_swap(self):
        self.assertIsNotNone(RunStore, 'Task3 storage missing')
        scans = self.fixture.repo / 'scans'
        scans.mkdir()
        (scans / 'automation').symlink_to(self.fixture.home, target_is_directory=True)
        with self.assertRaises(OSError):
            RunStore.create(self.fixture.repo)
        preserve(scans / 'automation')
        with RunStore.create(self.fixture.repo) as store:
            (store.path / 'run.json').symlink_to(self.fixture.home / 'untouched')
            with self.assertRaises(OSError):
                store.write_state({'schema_version': 1})
            (store.path / 'logs/first.stdout.log').symlink_to(self.fixture.home / 'untouched')
            with self.assertRaises(OSError):
                store.open_log('first', 'stdout')
            scans.rename(self.fixture.repo / 'detached')
            scans.symlink_to(self.fixture.home, target_is_directory=True)
            with self.assertRaises(OSError):
                store.write_state({})
        self.assertFalse((self.fixture.home / 'untouched').exists())

    def test_timeout_and_signals(self):
        self.assertIsNotNone(run_plan, 'Task3 runner missing')
        result = run_plan(self.plan, self.ctx, self.permissions,
                          lambda step, root: (self.command('import signal; signal.pause()', 0.1),))
        self.assertEqual(result.rc, 1)
        self.assertIn('timeout', result.steps[0].reason.lower())
        self.assertEqual(result.steps[1].state, 'omitido')
        for sig, rc in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            def compile_step(step, root):
                os.kill(os.getpid(), sig)
                return (self.command('raise Exception("must not start")'),)
            result = run_plan(self.plan, self.ctx, self.permissions, compile_step)
            self.assertEqual(result.rc, rc)
            self.assertEqual(result.steps[1].state, 'omitido')

    def test_term_is_not_inherited_blocked(self):
        marker = self.fixture.repo / 'term-received'
        code = ('import signal, pathlib; '
                f'signal.signal(signal.SIGTERM, lambda *a: (pathlib.Path({str(marker)!r}).touch(), exit(0))); '
                'signal.pause()')
        result = run_plan(self.plan, self.ctx, self.permissions,
                          lambda step, root: (self.command(code, 0.2),))
        self.assertEqual(result.rc, 1)
        self.assertTrue(marker.exists(), 'Child inherited parent signal mask')

    def test_signal_during_final_state(self):
        original = RunStore.write_state
        def write(store, data):
            original(store, data)
            if data.get('finished_at'):
                os.kill(os.getpid(), signal.SIGTERM)
        with patch.object(RunStore, 'write_state', write):
            result = self.run_codes({'first': 'pass', 'second': 'pass'})
        self.assertEqual(result.rc, 143)

    def test_spawn_publication_race(self):
        original = subprocess.Popen
        children = []
        for sig, rc in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            def spawn(*args, **kwargs):
                child = original(*args, **kwargs)
                children.append(child)
                os.kill(os.getpid(), sig)
                return child
            with patch('automation.runner.subprocess.Popen', spawn):
                result = self.run_codes({'first': 'import signal; signal.pause()', 'second': 'pass'})
            self.assertEqual(result.rc, rc)
            self.assertEqual(result.steps[1].state, 'omitido')
            self.assertIsNotNone(children[-1].returncode)
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[-1].pid, os.WNOHANG)

    def test_storage_error_after_spawn_reaps(self):
        original_write = RunStore.write_state
        original_spawn = subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = original_spawn(*args, **kwargs)
            children.append(child)
            return child
        def write(store, data):
            if children:
                raise OSError(errno.ENOSPC, 'synthetic after spawn')
            return original_write(store, data)
        with patch.object(RunStore, 'write_state', write), patch('automation.runner.subprocess.Popen', spawn):
            result = self.run_codes({'first': 'import signal; signal.pause()', 'second': 'pass'})
        self.assertEqual(result.rc, 1)
        self.assertEqual(len(children), 1)
        self.assertEqual(result.steps[1].state, 'omitido')
        self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)

    def test_grandchild_ignoring_term_and_leader_exit(self):
        pidfile = self.fixture.repo / 'grandchild'
        # The leader waits for the grandchild's readiness pipe before signalling
        # the runner. No test sleeps: the child's handshake establishes ordering.
        code = f'''import os, signal
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    with open({str(pidfile)!r}, 'w') as f: f.write(str(os.getpid()))
    os.write(w, b'1')
    os.close(w)
    while True: signal.pause()
os.close(w)
assert os.read(r, 1) == b'1'
os.close(r)
os.kill(os.getppid(), signal.SIGTERM)
os._exit(0)
'''
        result = self.run_codes({'first': code, 'second': 'pass'})
        self.assertEqual(result.rc, 143)
        self.assertEqual(result.steps[1].state, 'omitido')
        pid = int(pidfile.read_text())
        try:
            text = Path(f'/proc/{pid}/stat').read_text()
        except FileNotFoundError:
            pass
        else:
            self.assertIn(text[text.rfind(')') + 2:].split()[0], ('Z', 'X'))

    def test_no_signal_to_reaped_group(self):
        from automation.runner import _finish_group
        process = subprocess.Popen((sys.executable, '-c', 'pass'), start_new_session=True)
        process.wait(timeout=5)
        with patch('automation.runner.os.killpg') as kill:
            with self.assertRaises(ChildProcessError):
                _finish_group(process)
            kill.assert_not_called()

    def test_sigchld_autoreap_rejected(self):
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            # A permissive MagicMock has an integer-like pid (1), unsafe for
            # real killpg if production incorrectly reaches spawn/cleanup.
            with patch('automation.runner.subprocess.Popen',
                       side_effect=AssertionError('must reject before spawn')) as spawn:
                result = self.run_codes({'first': 'pass', 'second': 'pass'})
                spawn.assert_not_called()
            self.assertEqual(result.rc, 1)
            self.assertIn('SIGCHLD', result.steps[0].reason)
        finally:
            signal.signal(signal.SIGCHLD, previous)

    def test_empty_plan_does_not_create_outputs(self):
        result = self.run_codes({}, Plan('post', (), 10))
        self.assertEqual(result.rc, 2)
        self.assertIsNone(result.run_dir)
        self.assertFalse((self.fixture.repo / 'scans').exists())

    def test_multicommand_and_global_timeout(self):
        calls = []
        def compile_step(step, root):
            calls.append(step.id)
            return (self.command('print("one")'), self.command('print("two")'))
        result = run_plan(self.plan, self.ctx, self.permissions, compile_step)
        self.assertEqual(result.rc, 0)
        self.assertEqual(calls, ['first', 'second'])
        self.assertEqual((result.run_dir / 'logs/first.stdout.log').read_text(), 'one\ntwo\n')
        plan = Plan('deadline', self.plan.steps, 0.15)
        result = run_plan(plan, self.ctx, self.permissions,
                          lambda step, root: (self.command('import signal; signal.pause()', 30),))
        self.assertEqual(result.rc, 1)
        self.assertEqual(result.steps[1].state, 'omitido')
        self.assertIn('Timeout', result.steps[0].reason)

    def test_storage_files_lock_and_modes(self):
        scans = self.fixture.repo / 'scans'
        scans.mkdir()
        root = scans / 'automation'
        root.mkdir(mode=0o755)
        with self.assertRaises(OSError):
            RunStore.create(self.fixture.repo)
        self.assertEqual(root.stat().st_mode & 0o777, 0o755)
        root.chmod(0o700)
        lock = root / '.lock'
        lock.symlink_to(self.fixture.home / 'do-not-create')
        with self.assertRaises(OSError):
            RunStore.create(self.fixture.repo)
        self.assertFalse((self.fixture.home / 'do-not-create').exists())
        preserve(lock)
        victim = self.fixture.home / 'victim'
        victim.write_text('unchanged')
        victim.chmod(0o600)
        os.link(victim, lock)
        with self.assertRaises(OSError):
            RunStore.create(self.fixture.repo)
        self.assertEqual(victim.read_text(), 'unchanged')

    def test_state_atomic_on_write_failure(self):
        with RunStore.create(self.fixture.repo) as store:
            store.write_state({'schema_version': 1, 'rc': None})
            before = (store.path / 'run.json').read_text()
            with patch('automation.storage.os.fsync', side_effect=OSError(errno.ENOSPC, 'synthetic')):
                with self.assertRaises(OSError):
                    store.write_state({'schema_version': 1, 'rc': 0})
            self.assertEqual((store.path / 'run.json').read_text(), before)
            self.assertEqual(list(store.path.glob('.state-*')), [])

    def test_handlers_restored_and_foreign_process_untouched(self):
        original = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        # Independent session: its readiness pipe means the sentinel is alive
        # before runner cancellation and must still be alive afterwards.
        sentinel = subprocess.Popen((sys.executable, '-c',
            'import sys, signal; print("ready", flush=True); signal.pause()'),
            stdout=subprocess.PIPE, start_new_session=True)
        try:
            self.assertEqual(sentinel.stdout.readline(), b'ready\n')
            def compile_step(step, root):
                os.kill(os.getpid(), signal.SIGINT)
                return (self.command('pass'),)
            result = run_plan(self.plan, self.ctx, self.permissions, compile_step)
            self.assertEqual(result.rc, 130)
            self.assertIsNone(sentinel.poll())
            self.assertEqual({sig: signal.getsignal(sig) for sig in original}, original)
        finally:
            sentinel.terminate()
            sentinel.wait(timeout=5)
            sentinel.stdout.close()


if __name__ == '__main__':
    unittest.main()
