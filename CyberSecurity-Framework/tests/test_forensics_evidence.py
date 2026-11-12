"""Evidence-store contracts. No real evidence, subprocess backend or host acquisition."""
import contextlib
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from forensics_fixture import LIBRARY, closed_environment, inventory, load_evidence, sandbox


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = sandbox()
        self.root = self.sandbox.__enter__()
        self.addCleanup(self.sandbox.__exit__, None, None, None)
        self.e = load_evidence()
        self.diagnostics = io.StringIO()
        self.stderr = contextlib.redirect_stderr(self.diagnostics)
        self.stderr.__enter__()
        self.addCleanup(self.stderr.__exit__, None, None, None)
        self.source = self.root / 'sources' / 'input with spaces'
        self.source.write_bytes(b'synthetic SECRET-CONTENT\x00abc')
        self.source.chmod(0o640)
        self.before = self.source.read_bytes()

    def run_new(self, inputs=None, operation='strings'):
        return self.e.start_run(self.root / 'outputs', operation, 'offline', inputs or [])

    def staged(self):
        run = self.run_new()
        item = self.e.stage_input(run, self.source)
        return run, item

    def step(self, run, **changes):
        values = dict(name='analyze', rc=0, state='COMPLETADO',
                      coverage={'code': 'analysis', 'complete': True, 'requested': True},
                      artifacts=[])
        values.update(changes)
        return self.e.record_step(run, **values)

    def rewrite(self, run, change):
        path = run / 'run.json'
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def test_unique_private_independent_and_identity(self):
        run, item = self.staged()
        other, other_item = self.staged()
        self.assertNotEqual(run, other)
        self.assertNotEqual(item['work_path'], other_item['work_path'])
        self.assertEqual(item['sha256'], hashlib.sha256(self.before).hexdigest())
        self.assertEqual(item['mode'], 0o640)
        self.assertEqual(self.e.read_run(run)['module'], '08')
        for path in run.rglob('*'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        self.assertEqual(stat.S_IMODE(run.stat().st_mode), 0o700)
        self.assertEqual(Path(item['work_path']).read_bytes(), self.before)
        self.assertEqual(self.source.read_bytes(), self.before)
        self.assertNotEqual(self.source.stat().st_ino, Path(item['work_path']).stat().st_ino)
        self.assertEqual(self.e.read_run(run)['identity'], self.e.read_run(other)['identity'])

    def test_empty_file_and_initial_inputs(self):
        self.source.write_bytes(b'')
        run = self.run_new([{'source': str(self.source), 'kind': 'file'}])
        self.assertEqual(self.e.read_run(run)['inputs'][0]['size'], 0)
        self.assertTrue(self.e.check_integrity(run))

    def test_tree_original_time_and_time_only_mutation(self):
        tree = self.root / 'sources' / 'dated tree'
        tree.mkdir()
        leaf = tree / 'old file'
        leaf.write_text('synthetic')
        stamp = 946684800123456789
        os.utime(leaf, ns=(stamp, stamp))
        run = self.run_new()
        item = self.e.stage_input(run, tree, 'tree')
        temporal = item['original'].get('temporal')
        self.assertIsNotNone(temporal, 'original timestamps lost during staging')
        self.assertEqual(temporal['entries'][1], {'path': 'old file', 'mtime_ns': stamp})
        self.assertNotEqual((Path(item['work_path']) / 'old file').stat().st_mtime_ns, stamp)
        self.assertTrue(self.e.check_integrity(run))
        os.utime(leaf, ns=(stamp + 1, stamp + 1))
        self.assertFalse(self.e.check_integrity(run))
        self.assertEqual(self.e.finish_run(run)['state'], 'FALLIDO')

    def test_tree_temporal_types_digest_paths_and_legacy(self):
        tree = self.root / 'sources' / 'dated tree'
        tree.mkdir()
        (tree / 'file').write_text('synthetic')
        run = self.run_new()
        self.e.stage_input(run, tree, 'tree')
        original = (run / 'run.json').read_text()
        self.assertIn('temporal', json.loads(original)['inputs'][0]['original'])
        for invalid in (True, '123', 2**63, -2**63 - 1):
            data = json.loads(original)
            temporal = data['inputs'][0]['original']['temporal']
            temporal['entries'][0]['mtime_ns'] = invalid
            temporal['sha256'] = hashlib.sha256(self.e._encoded(temporal['entries'])).hexdigest()
            (run / 'run.json').write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                self.e.read_run(run, verify_artifacts=False)
        data = json.loads(original)
        data['inputs'][0]['original']['temporal']['entries'][0]['path'] = 'wrong'
        (run / 'run.json').write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.e.read_run(run, verify_artifacts=False)
        data = json.loads(original)
        for snapshot in ('original', 'work'):
            data['inputs'][0][snapshot].pop('temporal')
        (run / 'run.json').write_text(json.dumps(data))
        self.assertTrue(self.e.check_integrity(run))
        self.step(run)
        self.assertEqual(self.e.finish_run(run)['rc'], 0)

    def test_tree_inventory_and_mode_integrity(self):
        tree = self.root / 'sources' / 'tree'
        tree.mkdir()
        (tree / 'empty').mkdir()
        (tree / 'x').write_bytes(b'x')
        run = self.run_new()
        item = self.e.stage_input(run, tree, 'tree')
        self.assertTrue((Path(item['work_path']) / 'empty').is_dir())
        self.assertTrue(self.e.check_integrity(run))
        (tree / 'x').chmod(0o600)
        self.assertFalse(self.e.check_integrity(run))

    def test_tree_rejects_symlink_without_reading_target(self):
        tree = self.root / 'sources' / 'tree'
        tree.mkdir()
        (tree / 'escape').symlink_to(self.source)
        with self.assertRaises(ValueError):
            self.e.stage_input(self.run_new(), tree, 'tree')

    def test_missing_unreadable_fifo_and_symlink_rejected(self):
        fifo = self.root / 'sources' / 'fifo'
        os.mkfifo(fifo)
        link = self.root / 'sources' / 'link'
        link.symlink_to(self.source)
        unreadable = self.root / 'sources' / 'unreadable'
        unreadable.write_bytes(b'')
        unreadable.chmod(0)
        for source in (fifo, link, unreadable, self.root / 'sources' / 'missing'):
            with self.subTest(source=source.name), self.assertRaises(ValueError):
                self.e.stage_input(self.run_new(), source)

    def test_output_parent_unchanged_symlinks_and_overlap_rejected(self):
        parent = self.root / 'outputs'
        parent.chmod(0o755)
        self.run_new()
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
        link = self.root / 'alias'
        link.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.e.start_run(link, 'logs', 'offline', [])
        with self.assertRaises(ValueError):
            self.e.start_run(self.root / 'sources' / 'out', 'timeline', 'offline',
                             [{'source': str(self.root / 'sources'), 'kind': 'tree'}])
        with self.assertRaises(ValueError):
            self.e.stage_input(self.run_new(), parent, 'tree')

    def test_original_and_copy_mutations_fail_and_block_dependents(self):
        for which in ('original', 'copy', 'mode'):
            with self.subTest(which=which):
                run, item = self.staged()
                self.step(run)
                if which == 'original':
                    self.source.write_bytes(b'changed')
                elif which == 'copy':
                    Path(item['work_path']).write_bytes(b'changed')
                else:
                    self.source.chmod(0o600)
                self.assertFalse(self.e.check_integrity(run))
                data = self.e.finish_run(run)
                self.assertEqual((data['state'], data['rc']), ('FALLIDO', 1))
                self.assertTrue(data['dependents_blocked'])
                with self.assertRaises(ValueError):
                    self.step(run, name='dependent')
                self.source.write_bytes(self.before)
                self.source.chmod(0o640)

    def test_read_does_not_reopen_original(self):
        run, _ = self.staged()
        self.source.unlink()
        self.assertEqual(self.e.read_run(run)['state'], 'PARCIAL')
        self.assertFalse(self.e.check_integrity(run))

    def test_no_steps_never_complete(self):
        self.assertNotEqual(self.e.finish_run(self.run_new())['state'], 'COMPLETADO')

    def test_requested_coverage_and_rc_preserved(self):
        cases = [('COMPLETADO', 0, True, True, 'COMPLETADO', 0),
                 ('OMITIDO', 0, False, True, 'PARCIAL', 1),
                 ('NO_EVALUABLE', 127, False, True, 'PARCIAL', 1),
                 ('FALLIDO', 42, False, True, 'FALLIDO', 1),
                 ('CANCELADO', 143, False, True, 'CANCELADO', 1),
                 ('PARCIAL', 0, False, True, 'PARCIAL', 1)]
        for state, rc, complete, requested, expected, wrapper_rc in cases:
            with self.subTest(state=state):
                run = self.run_new()
                self.step(run, state=state, rc=rc,
                          signal=15 if state == 'CANCELADO' else None,
                          coverage={'code': 'analysis', 'complete': complete, 'requested': requested})
                data = self.e.finish_run(run)
                self.assertEqual((data['state'], data['rc']), (expected, wrapper_rc))
                self.assertEqual(data['steps'][0]['rc'], rc)
        run = self.run_new()
        self.step(run)
        self.step(run, name='optional', state='OMITIDO', coverage={
            'code': 'not_requested', 'complete': False, 'requested': False})
        self.assertEqual(self.e.finish_run(run)['rc'], 0)

    def test_artifact_hash_and_sidecar_validated_even_on_failure(self):
        run = self.run_new()
        artifact = run / 'analysis' / 'product'
        fd = os.open(artifact, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b'private output')
        os.close(fd)
        self.step(run, artifacts=[str(artifact)], state='FALLIDO', rc=9,
                  coverage={'code': 'analysis', 'complete': False, 'requested': True})
        self.e.read_run(run)
        artifact.write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            self.e.read_run(run)
        self.e.read_run(run, verify_artifacts=False)
        sidecar = next((run / 'steps').glob('*.json'))
        sidecar.write_text('{}')
        with self.assertRaises(ValueError):
            self.e.read_run(run, verify_artifacts=False)

    def test_artifact_escape_symlink_and_arbitrary_roots_rejected(self):
        for kind in ('outside', 'symlink'):
            run = self.run_new()
            target = self.source
            if kind == 'symlink':
                target = run / 'analysis' / 'escape'
                target.symlink_to(self.source)
            with self.assertRaises(ValueError):
                self.step(run, artifacts=[str(target)])
        run = self.run_new()
        self.rewrite(run, lambda d: d.update(artifact_roots={'analysis': str(self.root / 'sources')}))
        with self.assertRaises(ValueError):
            self.e.read_run(run)

    def test_strict_corrupt_schema_no_container_tracebacks(self):
        corruptions = [lambda d: d.update(version=True), lambda d: d.update(module=8),
                       lambda d: d.update(state=[]), lambda d: d.update(operation={}),
                       lambda d: d.update(rc=False), lambda d: d.update(complete=1),
                       lambda d: d.update(started='2026-11-11T12:00:00'),
                       lambda d: d.update(identity='fake'), lambda d: d.pop('steps'),
                       lambda d: d.update(inputs={}), lambda d: d.update(steps=[[]]),
                       lambda d: d.update(state='COMPLETADO', complete=True, rc=0)]
        for mutate in corruptions:
            run = self.run_new()
            self.rewrite(run, mutate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.e.read_run(run)

    def test_bad_step_types_secrets_and_contradictions_rejected(self):
        for changes in ({'rc': True}, {'rc': -1}, {'rc': 256}, {'signal': True},
                        {'name': 'unsafe\x1b[31m'}, {'tool': 'tool --secret=value'},
                        {'rc': 5}, {'coverage': []},
                        {'coverage': {'code': 'free text SECRET', 'complete': True, 'requested': True}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.step(self.run_new(), **changes)

    def test_latest_failure_does_not_revive_success_and_identity_groups(self):
        first, _ = self.staged()
        self.step(first)
        self.e.finish_run(first)
        latest, _ = self.staged()
        self.step(latest, rc=7, state='FALLIDO', coverage={
            'code': 'analysis', 'complete': False, 'requested': True})
        self.e.finish_run(latest)
        self.source.write_bytes(b'different identity')
        different, _ = self.staged()
        selected = self.e.select_runs(self.root / 'outputs', {})
        indexed = {row['run_id']: row for row in selected}
        self.assertFalse(indexed[first.name]['current'])
        self.assertTrue(indexed[latest.name]['current'])
        self.assertTrue(indexed[different.name]['current'])

    def test_invalid_last_conservatively_blocks_current(self):
        first, _ = self.staged()
        self.step(first)
        self.e.finish_run(first)
        broken = self.run_new()
        (broken / 'run.json').write_text('{')
        rows = self.e.select_runs(self.root / 'outputs', {})
        self.assertFalse(next(row for row in rows if row['run_id'] == first.name)['current'])
        self.assertTrue(any(row.get('invalid') for row in rows))

    def test_order_is_utc_start_not_finish_or_text(self):
        early, _ = self.staged()
        late, _ = self.staged()
        self.rewrite(early, lambda d: d.update(started='2026-11-11T12:00:00+02:00'))
        self.rewrite(late, lambda d: d.update(started='2026-11-11T10:30:00+00:00'))
        rows = self.e.select_runs(self.root / 'outputs', {})
        self.assertEqual([r['run_id'] for r in rows], [late.name, early.name])

    def test_metadata_and_viewer_do_not_expose_bodies(self):
        run, _ = self.staged()
        self.step(run)
        self.e.finish_run(run)
        text = ''.join(p.read_text() for p in run.rglob('*.json'))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.e.show_results(self.root / 'outputs', {})
        self.assertNotIn('SECRET-CONTENT', text + output.getvalue())
        self.assertNotIn(str(self.source), output.getvalue())

    def test_persistence_failure_is_not_success(self):
        run = self.run_new()
        with patch.object(self.e.os, 'replace', side_effect=OSError(errno.ENOSPC, 'synthetic')):
            with self.assertRaises((OSError, ValueError)):
                self.step(run)
        self.assertNotEqual(self.e.finish_run(run)['rc'], 0)

    def test_read_list_cli_without_B_do_not_write_bytecode_or_evidence(self):
        run, _ = self.staged()
        before = inventory(self.root)
        code_before = inventory(LIBRARY.parent)
        env = closed_environment(self.root)
        env.pop('PYTHONDONTWRITEBYTECODE')
        for args in (['validate', '--run', str(run)], ['list', '--root', str(self.root / 'outputs')]):
            result = subprocess.run([sys.executable, str(LIBRARY), *args], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(inventory(self.root), before)
        self.assertEqual(inventory(LIBRARY.parent), code_before)

    def test_missing_or_nonprivate_work_is_integrity_failure_not_exception(self):
        for mutation in ('unlink', 'chmod', 'symlink'):
            run, item = self.staged()
            work = Path(item['work_path'])
            if mutation == 'chmod':
                work.chmod(0o644)
            else:
                work.unlink()
                if mutation == 'symlink':
                    work.symlink_to(self.source)
            with self.subTest(mutation=mutation):
                self.assertFalse(self.e.check_integrity(run))
                self.assertEqual(self.e.finish_run(run)['state'], 'FALLIDO')

    def test_work_hash_checked_on_read_without_original_access(self):
        run, item = self.staged()
        Path(item['work_path']).write_bytes(b'changed')
        self.source.unlink()
        with self.assertRaises(ValueError):
            self.e.read_run(run)

    def test_sidecar_bool_integer_substitution_invalid(self):
        run = self.run_new()
        self.step(run)
        path = next((run / 'steps').iterdir())
        data = json.loads(path.read_text())
        data['rc'] = False
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.e.read_run(run)

    def test_file_copy_enospc_blocks_run_preserves_original(self):
        run = self.run_new()
        original_open = self.e.os.open

        def full_disk(path, flags, *args, **kwargs):
            if Path(path).parent == run / 'work':
                raise OSError(errno.ENOSPC, 'synthetic')
            return original_open(path, flags, *args, **kwargs)

        with patch.object(self.e.os, 'open', side_effect=full_disk):
            with self.assertRaises(ValueError):
                self.e.stage_input(run, self.source)
        self.assertEqual(self.e.finish_run(run)['state'], 'FALLIDO')
        self.assertEqual(self.source.read_bytes(), self.before)

    def test_uuid_collision_never_overwrites(self):
        run = self.run_new()
        before = inventory(run)
        class Fixed:
            hex = run.name[4:]
        with patch.object(self.e.uuid, 'uuid4', return_value=Fixed()):
            with self.assertRaises((OSError, ValueError)):
                self.run_new()
        self.assertEqual(inventory(run), before)

    def test_filters_and_equivalent_utc_offsets(self):
        first, _ = self.staged()
        second = self.run_new(operation='logs')
        self.e.stage_input(second, self.source)
        self.rewrite(first, lambda d: d.update(started='2026-11-11T12:00:00+02:00'))
        self.rewrite(second, lambda d: d.update(started='2026-11-11T10:00:00Z'))
        identity = self.e.read_run(first)['identity']
        self.assertEqual(len(self.e.select_runs(self.root / 'outputs', {'identity': identity})), 2)
        self.assertEqual(len(self.e.select_runs(self.root / 'outputs', {'operation': 'logs'})), 1)
        rows = self.e.select_runs(first / 'run.json', {})
        self.assertEqual(rows[0]['run_id'], first.name)

    def test_cli_lifecycle_and_safe_errors(self):
        env = closed_environment(self.root)
        def cli(*args):
            return subprocess.run([sys.executable, str(LIBRARY), *map(str, args)],
                                  capture_output=True, text=True, env=env)
        created = cli('init', '--root', self.root / 'outputs', '--operation', 'strings')
        self.assertEqual(created.returncode, 0, created.stderr)
        run = Path(json.loads(created.stdout)['run_dir'])
        self.assertEqual(cli('stage', '--run', run, '--source', self.source).returncode, 0)
        recorded = cli('step', '--run', run, '--name', 'analysis', '--rc', 0,
                       '--state', 'COMPLETADO', '--coverage-code', 'analysis', '--complete')
        self.assertEqual(recorded.returncode, 0, recorded.stderr)
        self.assertEqual(cli('finish', '--run', run).returncode, 0)
        self.assertEqual(cli('integrity', '--run', run).returncode, 0)
        bad = cli('validate', '--run', self.root / 'SECRET-FILENAME')
        self.assertEqual(bad.returncode, 2)
        self.assertNotIn('SECRET-FILENAME', bad.stderr + bad.stdout)
        self.assertNotIn('Traceback', bad.stderr)

    def test_closed_path_has_no_fallback_and_accepts_dangerous_stubs(self):
        env = closed_environment(self.root, {'sudo': '#!/bin/sh\nexit 99\n',
                                             'mount': '#!/bin/sh\nexit 99\n'})
        self.assertEqual(env['PATH'], str(self.root / 'bin'))
        self.assertTrue((self.root / 'bin' / 'sudo').exists())
        self.assertFalse((self.root / 'bin' / 'dd').exists())

    def test_cli_usage_does_not_echo_arbitrary_sensitive_arguments(self):
        result = subprocess.run([sys.executable, str(LIBRARY), 'init', '--root',
                                 str(self.root / 'outputs'), '--operation', 'SECRET-ARGUMENT'],
                                capture_output=True, text=True, env=closed_environment(self.root))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('SECRET-ARGUMENT', result.stdout + result.stderr)

    def test_cli_stage_missing_source_is_precondition_rc2(self):
        run = self.run_new()
        result = subprocess.run([sys.executable, str(LIBRARY), 'stage', '--run', str(run),
                                 '--source', str(self.root / 'sources' / 'missing')],
                                capture_output=True, text=True, env=closed_environment(self.root))
        self.assertEqual(result.returncode, 2)

    def test_artifact_deleted_at_finish_is_failed_not_exception(self):
        run = self.run_new()
        artifact = run / 'analysis' / 'result'
        artifact.touch(mode=0o600)
        self.step(run, artifacts=[str(artifact)])
        artifact.unlink()
        self.assertEqual(self.e.finish_run(run)['state'], 'FALLIDO')
        with self.assertRaises(ValueError):
            self.e.read_run(run)

    def test_private_modes_at_creation_with_permissive_umask(self):
        observations = []
        original_open = self.e.os.open
        def observe(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if flags & os.O_CREAT:
                observations.append(stat.S_IMODE(os.fstat(fd).st_mode))
            return fd
        previous = os.umask(0)
        try:
            with patch.object(self.e.os, 'open', side_effect=observe):
                run, _ = self.staged()
                self.step(run)
                self.e.finish_run(run)
        finally:
            os.umask(previous)
        self.assertTrue(observations)
        self.assertEqual(set(observations), {0o600})
        self.assertEqual(stat.S_IMODE(run.stat().st_mode), 0o700)

    def test_synthetic_block_metadata_never_opened_as_file(self):
        original_lstat = Path.lstat
        def block_metadata(path):
            if path == self.source:
                return SimpleNamespace(st_mode=stat.S_IFBLK | 0o600)
            return original_lstat(path)
        run = self.run_new()
        with patch.object(Path, 'lstat', block_metadata):
            with self.assertRaises(ValueError):
                self.e.stage_input(run, self.source)
        self.assertEqual(self.source.read_bytes(), self.before)

    def test_tree_digest_reproducible_and_copy_mode_is_private(self):
        tree = self.root / 'sources' / 'tree'
        tree.mkdir(mode=0o755)
        (tree / 'a').write_bytes(b'a')
        (tree / 'a').chmod(0o644)
        first = self.e.stage_input(self.run_new(), tree, 'tree')
        second = self.e.stage_input(self.run_new(), tree, 'tree')
        self.assertEqual(first['sha256'], second['sha256'])
        self.assertEqual(stat.S_IMODE((Path(first['work_path']) / 'a').stat().st_mode), 0o600)

    def test_cli_failed_step_preserves_tool_rc_but_wrapper_is_one(self):
        run = self.run_new()
        result = subprocess.run([sys.executable, str(LIBRARY), 'step', '--run', str(run),
                                 '--name', 'failure', '--rc', '42', '--state', 'FALLIDO',
                                 '--coverage-code', 'analysis'], capture_output=True,
                                text=True, env=closed_environment(self.root))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['rc'], 42)

    def assert_contradictory_snapshots_rejected(self, run):
        consumers = {
            'read_with_artifacts': lambda: self.e.read_run(run),
            'read_without_artifacts': lambda: self.e.read_run(run, verify_artifacts=False),
            'record_complete': lambda: self.step(run),
            'finish': lambda: self.e.finish_run(run),
            'integrity': lambda: self.e.check_integrity(run),
        }
        before = inventory(run)
        for name, consume in consumers.items():
            with self.subTest(consumer=name):
                with self.assertRaises(ValueError) as error:
                    consume()
                self.assertNotIn('SECRET', str(error.exception))
        self.assertEqual(inventory(run), before)

    def test_file_contradictory_original_and_work_snapshots_rejected(self):
        for changed in (b'X' * len(self.before), b'changed synthetic SECRET content'):
            with self.subTest(size=len(changed)):
                run, item = self.staged()
                Path(item['work_path']).write_bytes(changed)
                def change_only_work(data):
                    data['inputs'][0]['work'].update(
                        sha256=hashlib.sha256(changed).hexdigest(), size=len(changed))
                self.rewrite(run, change_only_work)
                self.assert_contradictory_snapshots_rejected(run)
                self.assertEqual(self.source.read_bytes(), self.before)

    def test_tree_contradictory_original_and_work_snapshots_rejected(self):
        tree = self.root / 'sources' / 'tree'
        tree.mkdir(mode=0o755)
        (tree / 'data').write_bytes(b'original synthetic')
        (tree / 'data').chmod(0o644)
        for changed in (b'X' * len(b'original synthetic'), b'changed synthetic SECRET content'):
            with self.subTest(size=len(changed)):
                run = self.run_new()
                item = self.e.stage_input(run, tree, 'tree')
                (Path(item['work_path']) / 'data').write_bytes(changed)
                def change_only_work(data):
                    work = data['inputs'][0]['work']
                    entry = next(e for e in work['inventory'] if e['path'] == 'data')
                    entry.update(sha256=hashlib.sha256(changed).hexdigest(), size=len(changed))
                    work['size'] = len(changed)
                    canonical = json.dumps(work['inventory'], sort_keys=True, separators=(',', ':'),
                                           ensure_ascii=True).encode()
                    work['sha256'] = hashlib.sha256(canonical).hexdigest()
                self.rewrite(run, change_only_work)
                self.assert_contradictory_snapshots_rejected(run)
                self.assertEqual((tree / 'data').read_bytes(), b'original synthetic')

    def test_public_tree_original_private_copy_can_complete(self):
        tree = self.root / 'sources' / 'public-tree'
        tree.mkdir(mode=0o755)
        (tree / 'nested').mkdir(mode=0o755)
        (tree / 'nested' / 'data').write_bytes(b'synthetic')
        (tree / 'nested' / 'data').chmod(0o644)
        run = self.run_new()
        item = self.e.stage_input(run, tree, 'tree')
        self.assertNotEqual(item['original']['sha256'], item['work']['sha256'])
        self.assertEqual(item['original']['mode'], 0o755)
        self.assertEqual(item['work']['mode'], 0o700)
        self.e.read_run(run)
        self.e.read_run(run, verify_artifacts=False)
        self.step(run)
        self.assertEqual(self.e.finish_run(run)['state'], 'COMPLETADO')
        self.assertEqual(stat.S_IMODE((tree / 'nested' / 'data').stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((Path(item['work_path']) / 'nested' / 'data').stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main()
