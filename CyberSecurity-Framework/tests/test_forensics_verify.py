"""Read-only verifier and runner contracts; synthetic inputs, closed backends."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from forensics_fixture import inventory, load_evidence, runtime_environment, sandbox

FW = Path(__file__).resolve().parents[1]


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.box = sandbox()
        self.root = self.box.__enter__()
        self.addCleanup(self.box.__exit__, None, None, None)
        self.env = runtime_environment(self.root)
        self.e = load_evidence()
        self.code = self.root / 'code'
        (self.code / 'tests').mkdir(parents=True)
        (self.code / '00_Config/lib').mkdir(parents=True)
        shutil.copy2(FW / '00_Config/lib/forensics_evidence.py', self.code / '00_Config/lib')
        if (FW / 'tests/verify_forensics.py').exists():
            shutil.copy2(FW / 'tests/verify_forensics.py', self.code / 'tests')

    def make_run(self, state='COMPLETADO', finished=True):
        source = self.root / 'sources/input with spaces'
        source.write_bytes(b'SYNTHETIC-PRIVATE-CONTENT')
        with contextlib.redirect_stderr(io.StringIO()):
            run = self.e.start_run(self.root / 'outputs', 'strings', 'offline', [])
        self.e.stage_input(run, source)
        artifact = run / 'analysis/result'
        artifact.touch(mode=0o600)
        artifact.write_bytes(b'PRIVATE-RESULT')
        self.e.record_step(run, 'analyze', 0 if state == 'COMPLETADO' else 9, state,
                           dict(code='analysis', complete=state == 'COMPLETADO', requested=True), [artifact])
        if finished:
            self.e.finish_run(run)
        return run

    def verify(self, path):
        env = dict(self.env)
        env.pop('PYTHONDONTWRITEBYTECODE', None)
        before = inventory(self.root)
        result = subprocess.run([sys.executable, str(self.code / 'tests/verify_forensics.py'), str(path)],
                                env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(inventory(self.root), before, 'verification wrote code/evidence')
        self.assertNotIn('Traceback', result.stderr)
        self.assertNotIn('PRIVATE', result.stdout + result.stderr)
        self.assertNotIn(str(self.root), result.stdout + result.stderr)
        return result

    def test_complete_without_original_is_readonly_and_successful(self):
        run = self.make_run()
        (self.root / 'sources/input with spaces').unlink()
        self.assertEqual(self.verify(run / 'run.json').returncode, 0)

    def test_unfinished_and_no_data_are_incomplete(self):
        self.assertEqual(self.verify(self.make_run(finished=False) / 'run.json').returncode, 2)
        self.assertEqual(self.verify(self.root / 'outputs/missing/run.json').returncode, 2)

    def test_partial_failed_cancelled_are_not_success(self):
        for state in ('PARCIAL', 'FALLIDO', 'CANCELADO', 'NO_EVALUABLE'):
            with self.subTest(state=state):
                self.assertEqual(self.verify(self.make_run(state) / 'run.json').returncode, 1)

    def test_discrepancies_and_strict_schema_rejected(self):
        changes = {
            'version_bool': lambda d: d.update(version=True),
            'version': lambda d: d.update(version=2),
            'module': lambda d: d.update(module='11'),
            'schema': lambda d: d.update(unknown='secret'),
            'state': lambda d: d.update(complete=False),
            'hash': lambda d: d['steps'][0]['artifacts'][0].update(sha256='0' * 64),
            'escape': lambda d: d['steps'][0]['artifacts'][0].update(path='../outside'),
            'absolute': lambda d: d['steps'][0]['artifacts'][0].update(path='/etc/passwd'),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                run = self.make_run()
                path = run / 'run.json'
                data = json.loads(path.read_text())
                change(data)
                path.write_text(json.dumps(data))
                self.assertEqual(self.verify(path).returncode, 1)

    def test_artifact_mutation_sidecar_rc_permissions_and_link_rejected(self):
        for mutation in ('artifact', 'sidecar', 'mode', 'link'):
            with self.subTest(mutation=mutation):
                run = self.make_run()
                artifact = run / 'analysis/result'
                if mutation == 'artifact':
                    artifact.write_bytes(b'changed')
                elif mutation == 'sidecar':
                    sidecar = next((run / 'steps').iterdir())
                    data = json.loads(sidecar.read_text())
                    data['rc'] = 3
                    sidecar.write_text(json.dumps(data))
                elif mutation == 'mode':
                    artifact.chmod(0o644)
                else:
                    artifact.unlink()
                    artifact.symlink_to(self.root / 'sources/input with spaces')
                self.assertEqual(self.verify(run / 'run.json').returncode, 1)

    def test_corrupt_containers_fail_without_traceback(self):
        for payload in ('[]', 'null', 'true', '42', '"text"', '{', '{"steps":null}'):
            with self.subTest(payload=payload):
                run = self.make_run()
                (run / 'run.json').write_text(payload)
                self.assertEqual(self.verify(run / 'run.json').returncode, 1)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.box = sandbox()
        self.root = self.box.__enter__()
        self.addCleanup(self.box.__exit__, None, None, None)
        self.env = runtime_environment(self.root)
        self.fw = self.root / 'fixture/CyberSecurity-Framework'
        (self.fw / 'tests').mkdir(parents=True)
        (self.fw / '00_Config/lib').mkdir(parents=True)
        if (FW / 'tests/run_forensics.sh').exists():
            shutil.copy2(FW / 'tests/run_forensics.sh', self.fw / 'tests')
        shutil.copy2(FW / '00_Config/lib/forensics_evidence.py', self.fw / '00_Config/lib')

    def run_fixture(self, body):
        # One representative test; never recursively execute the full suite.
        (self.fw / 'tests/test_forensics_sample.py').write_text(
            'import unittest\nfrom pathlib import Path\nclass Sample(unittest.TestCase):\n'
            ' def test_sample(self):\n  ' + body + '\n')
        return subprocess.run(['/bin/bash', str(self.fw / 'tests/run_forensics.sh')],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def test_runner_discovers_tests_and_preserves_failure_rc(self):
        good = self.run_fixture('self.assertTrue(True)')
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        bad = self.run_fixture('self.fail("representative failure")')
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('representative failure', bad.stdout + bad.stderr)

    def test_runner_detects_changed_and_new_files(self):
        for body in ('Path("00_Config/scope.yaml").write_text("mutation")',
                     'Path("tests/unexpected.py").write_text("new")',
                     'Path("home/unexpected").touch()'):
            with self.subTest(body=body):
                result = self.run_fixture(body)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('GUARD', result.stdout + result.stderr)

    def test_runner_does_not_follow_source_or_evidence_symlinks(self):
        secret = self.root / 'sources/DO-NOT-READ'
        secret.write_text('PRIVATE')
        data = self.fw / '08_Forensics/analysis'
        data.parent.mkdir(parents=True)
        data.symlink_to(secret.parent, target_is_directory=True)
        self.assertEqual(self.run_fixture('self.assertFalse(Path("08_Forensics/analysis").exists())').returncode, 0)
        target = self.fw / '00_Config/lib/forensics_evidence.py'
        target.unlink()
        target.symlink_to(secret)
        result = self.run_fixture('self.fail("must not run")')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('PRIVATE', result.stdout + result.stderr)

    def test_runner_detects_new_source_in_original_without_scanning_evidence(self):
        added = self.fw / '00_Config/lib/unexpected.py'
        result = self.run_fixture('Path(' + repr(str(added)) + ').write_text("new")')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('GUARD', result.stdout + result.stderr)

    def test_runner_normalizes_child_umask_without_changing_private_copy(self):
        # Existing tests deliberately create public synthetic parents to verify
        # that the evidence store preserves their modes, not the runner's umask.
        parent = self.root / 'sources/public-parent'
        result = self.run_fixture('p=Path(' + repr(str(parent)) + '); '
                                  'p.mkdir(mode=0o755); self.assertEqual(p.stat().st_mode & 0o777, 0o755)')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
