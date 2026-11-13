"""Only owned Python stubs; readiness handshakes and bounded outer harnesses."""
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock
import warnings

from evidence_fixture import sandbox, copy_sources


class ProcessTests(unittest.TestCase):
    def setUp(self):
        context = sandbox()
        self.root = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.framework = copy_sources(self.root)
        self.lib = self.framework / '00_Config/lib'
        for name in list(sys.modules):
            if name == 'evidence' or name.startswith('evidence.'):
                del sys.modules[name]
        sys.path.insert(0, str(self.lib))
        self.addCleanup(sys.path.pop, 0)
        self.storage = importlib.import_module('evidence.storage')
        previous_alarm = signal.signal(signal.SIGALRM, self.safety_deadline)
        signal.alarm(15)
        self.addCleanup(signal.signal, signal.SIGALRM, previous_alarm)
        self.addCleanup(signal.alarm, 0)

    @staticmethod
    def safety_deadline(signum, frame):
        raise TimeoutError('synthetic test safety deadline exceeded')

    def product(self, name):
        self.assertIsNotNone(importlib.util.find_spec('evidence.' + name), name + ' missing')
        return importlib.import_module('evidence.' + name)

    def run_stub(self, code, **options):
        return self.product('process').run_child(
            [sys.executable, '-B', '-c', code], self.root / 'out', self.root / 'err', **options)

    def assert_gone(self, pid):
        self.assertFalse(Path(f'/proc/{pid}').exists(), f'owned process remains: {pid}')

    def test_deadline_stops_and_reaps_owned_group(self):
        result = self.run_stub('import os,time; print(os.getpid(),flush=True); time.sleep(60)', timeout=.3)
        self.assertTrue(result.timed_out)
        self.assertIsNotNone(result.stopped_by)
        self.assert_gone(int((self.root / 'out').read_text()))

    def test_descendant_remaining_after_leader_exit_is_stopped(self):
        code = ('import os,time,signal; r,w=os.pipe(); p=os.fork(); '
                '\nif p: os.close(w); os.read(r,1); print(p,flush=True); os._exit(0)'
                '\nos.close(r); signal.signal(signal.SIGTERM,signal.SIG_IGN); os.write(w,b"1"); time.sleep(60)')
        result = self.run_stub(code, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertIsNotNone(result.stopped_by)
        self.assertEqual(result.stopped_by, 'SIGKILL')
        self.assert_gone(int((self.root / 'out').read_text()))

    def test_unrelated_process_is_not_signalled(self):
        other = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'])
        try:
            self.run_stub('import time;time.sleep(60)', timeout=.1)
            self.assertIsNone(other.poll())
        finally:
            other.terminate()
            other.wait(timeout=5)

    def test_streams_are_private_and_failures_visible(self):
        old = os.umask(0)
        try:
            result = self.run_stub('import sys;print("out");print("failure",file=sys.stderr);sys.exit(7)', timeout=3)
        finally:
            os.umask(old)
        self.assertEqual(result.returncode, 7)
        self.assertIsNone(result.stopped_by)
        self.assertEqual((self.root / 'err').read_text(), 'failure\n')
        for name in ('out', 'err'):
            self.assertEqual((self.root / name).stat().st_mode & 0o777, 0o600)
        with self.assertRaises(self.product('process').EvidenceError):
            self.run_stub('pass', timeout=1)

    def test_parent_only_int_term_returns_130_143(self):
        self.product('process')
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                ready = self.root / f'ready-{signum}'
                stub = ('import os,time,signal;r,w=os.pipe();p=os.fork()\n'
                        f'if p: os.close(w);os.read(r,1);open({str(ready)!r},"w").write(str(os.getpid())+" "+str(p));time.sleep(60)\n'
                        'else: os.close(r);signal.signal(signal.SIGTERM,signal.SIG_IGN);os.write(w,b"1");time.sleep(60)\n')
                harness = ('import sys;from pathlib import Path;'
                           f'sys.path.insert(0,{str(self.lib)!r});'
                           'from evidence.process import run_child,CaptureInterrupted\n'
                           'try:\n'
                           f' run_child([sys.executable,"-c",{stub!r}],Path({str(ready)+".out"!r}),Path({str(ready)+".err"!r}),timeout=20)\n'
                           'except CaptureInterrupted as exc: sys.exit(128+exc.signum)\n')
                parent = subprocess.Popen([sys.executable, '-B', '-c', harness])
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and parent.poll() is None and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue(ready.exists(), 'child readiness missing')
                    parent.send_signal(signum)
                    self.assertEqual(parent.wait(timeout=8), 128 + signum)
                    for pid in ready.read_text().split():
                        self.assert_gone(int(pid))
                finally:
                    if parent.poll() is None:
                        parent.kill()
                        parent.wait()

    def test_run_ledger_is_not_evidence(self):
        capture = self.product('capture')
        module = self.root / 'module'
        source = self.root / 'source'
        source.write_text('synthetic')
        record = self.storage.add(module, 'proof', source)
        ledger = capture.RunLedger(module, ['scan', 'web'])
        ledger.start('web')
        ledger.finish('web', 'success', 0, None, [record.id])
        ledger.start('scan')
        ledger.finish('scan', 'failed', 1, 'synthetic failure', [])
        ledger.close('failed')
        (ledger.path / 'work' / 'diagnostic').write_text('not evidence')
        inventory = importlib.import_module('evidence.inventory')
        with warnings.catch_warnings(record=True) as notices:
            warnings.simplefilter('always')
            result = inventory.verify(module)
        self.assertTrue(result.ok, result.issues)
        self.assertEqual(len(result.entries), 1)
        self.assertTrue(notices)
        data = json.loads((ledger.path / 'run.json').read_text())
        self.assertEqual([a['action'] for a in data['actions']], ['web', 'scan'])
        self.assertEqual(ledger.path.stat().st_mode & 0o777, 0o700)
        self.assertEqual((ledger.path / 'run.json').stat().st_mode & 0o777, 0o600)

    def test_malformed_run_directory_is_reported(self):
        capture = self.product('capture')
        inventory = importlib.import_module('evidence.inventory')
        module = self.root / 'module'
        ledger = capture.RunLedger(module, ['web'])
        (ledger.path / 'run.json').write_text('{"schema_version":1,"schema_version":1}')
        self.assertTrue(inventory.scan(module).issues)
        (module / 'logs/runs/arbitrary').write_text('not evidence')
        self.assertTrue(inventory.scan(module).issues)

    def test_leader_returncode_survives_reap_race(self):
        process = self.product('process')
        # A leader that exits during cleanup must still be reaped by Popen,
        # not by the orphan-group reaper (which would lose its actual status).
        for index in range(20):
            result = process.run_child([sys.executable, '-c', 'import sys;sys.exit(7)'],
                                       self.root / f'o{index}', self.root / f'e{index}', timeout=3)
            self.assertEqual(result.returncode, 7)

    def test_interval_stop_uses_int_and_restores_handlers(self):
        before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        result = self.run_stub('import signal,time,sys;signal.signal(signal.SIGINT,lambda *_:sys.exit(0));time.sleep(60)',
                               timeout=.3, interval_stop=True)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stopped_by, 'SIGINT')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(before, {s: signal.getsignal(s) for s in before})

    def test_interval_stop_escalates_int_term_kill(self):
        result = self.run_stub(
            'import signal,time;'
            'signal.signal(signal.SIGINT,lambda *_:print("INT",flush=True));'
            'signal.signal(signal.SIGTERM,lambda *_:print("TERM",flush=True));time.sleep(60)',
            timeout=.3, interval_stop=True)
        self.assertEqual((self.root / 'out').read_text().splitlines(), ['INT', 'TERM'])
        self.assertEqual(result.stopped_by, 'SIGKILL')
        self.assertEqual(result.returncode, -signal.SIGKILL)

    def test_orphan_reaper_does_not_steal_live_leaders_status(self):
        process = self.product('process')
        real_popen, real_wait = subprocess.Popen, os.waitpid
        children, unsafe = [], []
        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child
        def wait(pid, options):
            if pid < 0 and children[-1].returncode is None:
                unsafe.append(pid)
            return real_wait(pid, options)
        with mock.patch.object(process.subprocess, 'Popen', side_effect=spawn), mock.patch.object(process.os, 'waitpid', side_effect=wait):
            self.run_stub('import time;time.sleep(60)', timeout=.2)
        self.assertEqual(unsafe, [], 'group wait can reap leader between poll and waitpid')

    def test_interrupted_ledger_cannot_publish_success_or_reference_evidence(self):
        capture = self.product('capture')
        ledger = capture.RunLedger(self.root / 'module', ['web', 'scan'])
        ledger.start('web')
        with self.assertRaises(capture.EvidenceError):
            ledger.finish('web', 'interrupted', -15, 'signal', [ledger.id])
        ledger.close('interrupted')
        data = capture.read_run(ledger.path)
        self.assertEqual([a['status'] for a in data['actions']], ['interrupted', 'not-run'])
        with self.assertRaises(capture.EvidenceError):
            ledger.close('success')

    def test_ledger_schema_and_names_are_fail_closed(self):
        capture = self.product('capture')
        ledger = capture.RunLedger(self.root / 'module', ['web'])
        original = (ledger.path / 'run.json').read_text()
        for mutate in (
            lambda d: d.update(extra=1),
            lambda d: d.update(schema_version=True),
            lambda d: d.update(status='success'),
            lambda d: d['actions'][0].update(stdout='../escape'),
            lambda d: d['actions'][0].update(status='running', rc=0),
            lambda d: d['actions'][0].update(status='pending', reason='inconsistent'),
            lambda d: d['actions'][0].update(status='running', started_at=d['started_at'], rc=0),
        ):
            data = json.loads(original)
            mutate(data)
            (ledger.path / 'run.json').write_text(json.dumps(data))
            with self.assertRaises(capture.EvidenceError):
                capture.read_run(ledger.path)
        (ledger.path / 'run.json').write_text(original)
        (ledger.path / 'unknown').write_text('not an allowed stream')
        with self.assertRaises(capture.EvidenceError):
            capture.read_run(ledger.path)

    def test_ledger_requires_work_and_ordered_state_times(self):
        capture = self.product('capture')
        ledger = capture.RunLedger(self.root / 'module', ['web', 'scan'])
        data = json.loads((ledger.path / 'run.json').read_text())
        data['actions'][1].update(status='running', started_at=data['started_at'])
        (ledger.path / 'run.json').write_text(json.dumps(data))
        with self.subTest('action order'):
            with self.assertRaises(capture.EvidenceError):
                capture.read_run(ledger.path)
        data['actions'][1].update(status='pending', started_at=None)
        (ledger.path / 'run.json').write_text(json.dumps(data))
        (ledger.path / 'work').rmdir()
        with self.subTest('missing work'):
            with self.assertRaises(capture.EvidenceError):
                capture.read_run(ledger.path)

    def test_ledger_collision_and_modes_under_both_umasks(self):
        capture = self.product('capture')
        for mask in (0, 0o777):
            old = os.umask(mask)
            try:
                ledger = capture.RunLedger(self.root / str(mask), ['web'])
            finally:
                os.umask(old)
            before = (ledger.path / 'run.json').read_bytes()
            for directory in (ledger.path, ledger.path / 'work', ledger.path.parent, ledger.path.parent.parent):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual((ledger.path / 'run.json').stat().st_mode & 0o777, 0o600)
            with mock.patch.object(capture.uuid, 'uuid4', return_value=type('Fixed', (), {'hex': ledger.id})()):
                with self.assertRaises(capture.EvidenceError):
                    capture.RunLedger(self.root / str(mask), ['web'])
            self.assertEqual((ledger.path / 'run.json').read_bytes(), before)

    def test_run_ledger_excluded_from_package(self):
        module = self.root / 'module'
        source = self.root / 'source'
        source.write_text('synthetic')
        self.storage.add(module, 'proof', source)
        ledger = self.product('capture').RunLedger(module, ['scan'])
        ledger.close('failed')
        import tarfile
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            package = importlib.import_module('evidence.package').create(module)
        with tarfile.open(package) as archive:
            self.assertFalse(any('runs' in name or 'run.json' in name for name in archive.getnames()))


if __name__ == '__main__':
    unittest.main()
