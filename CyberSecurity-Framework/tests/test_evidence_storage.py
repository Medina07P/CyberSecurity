"""Import regressions: no network, only allowlisted code and synthetic files."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import unittest
from unittest import mock

from evidence_fixture import sandbox, copy_sources, closed_env, snapshot


ROOTS = {'screenshot': 'screenshots/web', 'pcap': 'pcaps/traffic',
         'credential': 'credentials/found', 'finding': 'findings/vulnerabilities',
         'proof': 'proofs/access'}
KEYS = {'schema_version', 'id', 'type', 'original_name', 'stored_name', 'size',
        'sha256', 'created_at', 'description', 'origin', 'target', 'run_id', 'method'}


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.context = sandbox()
        self.root = self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.framework = copy_sources(self.root)
        self.env = closed_env(self.root)
        environment = mock.patch.dict(os.environ, self.env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.module = self.framework / '10_Evidence'
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.source = self.inputs / 'original with spaces.bin'
        self.source.write_bytes(b'abc')
        self.before = snapshot(self.inputs)
        self.addCleanup(lambda: self.assertEqual(snapshot(self.inputs), self.before))

    def load(self):
        for name in list(sys.modules):
            if name == 'evidence' or name.startswith('evidence.'):
                del sys.modules[name]
        sys.path.insert(0, str(self.framework / '00_Config/lib'))
        self.addCleanup(sys.path.pop, 0)
        self.storage = importlib.import_module('evidence.storage')
        self.model = importlib.import_module('evidence.model')
        self.cli = importlib.import_module('evidence.cli')
        return self.storage

    def command(self, *args, env=None):
        return subprocess.run(['/bin/bash', str(self.module / 'evidence_manager.sh'), *args],
                              cwd=self.inputs, env=env or self.env, text=True,
                              capture_output=True, timeout=10)

    def records(self):
        return list(self.module.rglob('evidence.json'))

    def assert_record(self, record, kind, description='', target=None):
        self.assertRegex(record.id, r'^[0-9a-f]{32}$')
        self.assertEqual(record.format, 'sha256-v1')
        self.assertEqual(record.payload.parent, self.module / ROOTS[kind] / record.id)
        self.assertEqual(record.payload.name, 'artifact')
        self.assertEqual(record.metadata.name, 'evidence.json')
        self.assertEqual(record.payload.read_bytes(), b'abc')
        data = json.loads(record.metadata.read_text())
        self.assertEqual(set(data), KEYS)
        self.assertEqual(data['schema_version'], 1)
        self.assertIs(type(data['size']), int)
        self.assertEqual(data['size'], 3)
        self.assertEqual(data['sha256'], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertEqual(data['id'], record.id)
        self.assertEqual(data['type'], kind)
        self.assertEqual(data['original_name'], self.source.name)
        self.assertEqual(data['stored_name'], 'artifact')
        self.assertEqual(data['description'], description)
        self.assertEqual(data['target'], target)
        self.assertEqual(record.target, target)
        self.assertEqual(data['origin'], 'import')
        self.assertIsNone(data['method'])
        self.assertIsNone(data['run_id'])
        self.assertRegex(data['created_at'], r'^\d{4}-\d\d-\d\dT.*Z$')

    def test_relative_input_uses_callers_cwd(self):
        result = self.command('--add', 'proof', self.source.name, 'literal $(touch BAD)',
                              '--target', 'explicit label')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(len(self.records()), 1)
        data = json.loads(self.records()[0].read_text())
        self.assertEqual(data['description'], 'literal $(touch BAD)')
        self.assertEqual(data['target'], 'explicit label')

    def test_all_five_public_types(self):
        storage = self.load()
        for kind in ROOTS:
            with self.subTest(kind=kind):
                self.assert_record(storage.add(self.module, kind, self.source), kind)
        result = self.command('--add', 'log', str(self.source))
        self.assertEqual(result.returncode, 2)

    def test_same_basename_and_second_never_overwrite(self):
        storage = self.load()
        first = storage.add(self.module, 'proof', self.source)
        before = snapshot(first.payload.parent)
        second = storage.add(self.module, 'proof', self.source)
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(snapshot(first.payload.parent), before)
        self.assert_record(second, 'proof')

    def test_private_modes_under_umask_000(self):
        storage = self.load()
        mask = os.umask(0)
        try:
            storage.add(self.module, 'credential', self.source)
        finally:
            os.umask(mask)
        for path in (self.module / 'credentials').rglob('*'):
            expected = 0o700 if path.is_dir() else 0o600
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), expected, str(path))
        self.assertEqual(stat.S_IMODE((self.module / 'credentials').stat().st_mode), 0o700)

    def test_private_modes_under_restrictive_umask(self):
        storage = self.load()
        mask = os.umask(0o777)
        try:
            record = storage.add(self.module, 'credential', self.source)
        finally:
            os.umask(mask)
        self.assert_record(record, 'credential')
        for path in (self.module / 'credentials').rglob('*'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)

    def test_reject_symlink_ancestor_fifo_device_directory(self):
        storage = self.load()
        (self.root / 'link').symlink_to(self.source)
        (self.root / 'linked-parent').symlink_to(self.inputs, target_is_directory=True)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        for source in (self.root / 'link', self.root / 'linked-parent' / self.source.name,
                       fifo, Path('/dev/null'), self.inputs):
            with self.subTest(source=source):
                result = self.command('--add', 'proof', str(source))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        (self.module / 'screenshots').symlink_to(self.inputs, target_is_directory=True)
        with self.assertRaises(self.model.EvidenceError):
            storage.add(self.module, 'screenshot', self.source)
        self.assertEqual(self.records(), [])

    def test_changed_source_is_not_published(self):
        storage = self.load()
        real_read = storage.os.read
        changed = False
        def mutate(fd, count):
            nonlocal changed
            data = real_read(fd, count)
            if data and not changed:
                changed = True
                self.source.write_bytes(b'changed')
            return data
        with mock.patch.object(storage.os, 'read', side_effect=mutate):
            with self.assertRaises(self.model.EvidenceError):
                storage.add(self.module, 'proof', self.source)
        self.source.write_bytes(b'abc')
        self.assertEqual(self.records(), [])

    def test_copy_or_metadata_failure_has_no_success(self):
        storage = self.load()
        for operation in ('read', 'write', 'link'):
            with self.subTest(operation=operation):
                with mock.patch.object(storage.os, operation, side_effect=OSError('synthetic I/O failure')), redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(self.cli.main(['--root', str(self.module), 'manage',
                                                  '--add', 'proof', str(self.source)]), 1)
                self.assertIn('ERROR:', error.getvalue())
                self.assertEqual(self.records(), [])
        with mock.patch.object(storage.json, 'dump', side_effect=OSError('synthetic metadata failure')), redirect_stderr(io.StringIO()) as error:
            self.assertEqual(self.cli.main(['--root', str(self.module), 'manage',
                                          '--add', 'proof', str(self.source)]), 1)
        self.assertIn('ERROR:', error.getvalue())
        self.assertEqual(self.records(), [])
        self.assertEqual(list((self.module / 'proofs/access').iterdir()), [])

    def test_controls_are_escaped(self):
        storage = self.load()
        self.assertEqual(storage.safe_text('a\n\r\t\x1b\x00\x7f\u0085'),
                         r'a\n\r\t\x1b\x00\x7f\x85')
        result = self.command('--add', 'proof', str(self.source), 'evil\n\x1b[31m',
                              '--target', 'label\n\x1b')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('\x1b', result.stdout + result.stderr)
        self.assertNotIn('evil\n', result.stdout + result.stderr)
        data = json.loads(self.records()[0].read_text())
        self.assertEqual(data['description'], 'evil\n\x1b[31m')

    def test_concurrent_adds_and_forced_id_collision(self):
        storage = self.load()
        with ThreadPoolExecutor(max_workers=4) as pool:
            records = list(pool.map(lambda _: storage.add(self.module, 'proof', self.source), range(8)))
        self.assertEqual(len({r.id for r in records}), 8)
        with mock.patch.object(storage.uuid, 'uuid4', return_value=type('UUID', (), {'hex': records[0].id})()):
            before = snapshot(self.module)
            with self.assertRaises(self.model.EvidenceError):
                storage.add(self.module, 'proof', self.source)
            self.assertEqual(snapshot(self.module), before)
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda _: self.command('--add', 'proof', str(self.source)), range(4)))
        self.assertEqual([r.returncode for r in outcomes], [0] * 4)
        self.assertEqual(len(self.records()), 12)

    def test_forced_collision_simultaneous_reservations(self):
        storage = self.load()
        barrier = threading.Barrier(2)
        forced_id = 'c' * 32
        def reserve_id():
            barrier.wait(timeout=5)
            return type('UUID', (), {'hex': forced_id})()
        def add_one(_):
            try:
                return storage.add(self.module, 'proof', self.source)
            except self.model.EvidenceError:
                return None
        with mock.patch.object(storage.uuid, 'uuid4', side_effect=reserve_id):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(add_one, range(2)))
        self.assertEqual(sum(record is not None for record in results), 1)
        self.assertEqual(len(self.records()), 1)
        self.assert_record(next(record for record in results if record is not None), 'proof')

    def test_path_replacement_during_copy_is_not_published(self):
        storage = self.load()
        original_read = storage.os.read
        replaced = False
        saved = self.root / 'saved-original'
        def replace_path(fd, count):
            nonlocal replaced
            data = original_read(fd, count)
            if data and not replaced:
                replaced = True
                self.source.rename(saved)
                self.source.write_bytes(b'abc')
            return data
        try:
            with mock.patch.object(storage.os, 'read', side_effect=replace_path):
                with self.assertRaises(self.model.EvidenceError):
                    storage.add(self.module, 'proof', self.source)
        finally:
            if saved.exists():
                saved.replace(self.source)
        self.assertEqual(self.records(), [])

    def test_streaming_handles_short_writes_and_empty_files(self):
        storage = self.load()
        original_write = storage.os.write
        with mock.patch.object(storage.os, 'write',
                               side_effect=lambda fd, data: original_write(fd, data[:1])):
            record = storage.add(self.module, 'proof', self.source)
        self.assert_record(record, 'proof')
        empty = self.root / 'empty'
        empty.write_bytes(b'')
        size, digest = storage.copy_regular(empty, self.root / 'empty-copy')
        self.assertEqual(size, 0)
        self.assertEqual(digest, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_metadata_failure_preserves_existing_history_and_modes(self):
        storage = self.load()
        history = self.module / 'proofs/access'
        history.mkdir(parents=True)
        history.chmod(0o755)
        (history / 'legacy.bin').write_bytes(b'historical data')
        (history / 'legacy.bin.meta').write_text('historical metadata\n')
        before = snapshot(history)
        with mock.patch.object(storage.os, 'link', side_effect=OSError('publish failure')):
            with self.assertRaises(self.model.EvidenceError):
                storage.add(self.module, 'proof', self.source)
        self.assertEqual(snapshot(history), before)

    def test_reservation_setup_failure_cleans_only_own_reservation(self):
        storage = self.load()
        parent = storage.private_directory(self.module / 'proofs/access')
        original_chmod = storage.os.chmod
        def fail_reservation(path, *args, **kwargs):
            if re.fullmatch(r'[0-9a-f]{32}', str(path)):
                raise OSError('synthetic reservation chmod failure')
            return original_chmod(path, *args, **kwargs)
        with mock.patch.object(storage.os, 'chmod', side_effect=fail_reservation):
            with self.assertRaises(self.model.EvidenceError):
                storage.add(self.module, 'proof', self.source)
        self.assertEqual(list(parent.iterdir()), [])

    def test_cli_help_invalid_and_missing_dependencies(self):
        for args, rc in [(('--help',), 0), ((), 2), (('--list',), 2),
                         (('--verify',), 2), (('--package',), 2),
                         (('--add', 'proof'), 2),
                         (('--help', 'extra'), 2),
                         (('--ad', 'proof', str(self.source)), 2),
                         (('--add', 'proof', str(self.source), '--add', 'proof', str(self.source)), 2),
                         (('--add', 'proof', str(self.source), '--target', 'a', '--target', 'b'), 2),
                         (('--add', 'proof', str(self.source), 'desc', 'extra'), 2)]:
            with self.subTest(args=args):
                result = self.command(*args)
                self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
        self.assertEqual(self.records(), [])
        empty = self.root / 'empty-bin'
        empty.mkdir()
        result = self.command('--help', env={**self.env, 'PATH': str(empty)})
        self.assertEqual(result.returncode, 1)
        self.assertTrue(result.stderr)
        helper = self.framework / '00_Config/lib/evidence/cli.py'
        if helper.exists():
            helper.unlink()
        result = self.command('--help')
        self.assertEqual(result.returncode, 1)
        self.assertTrue(result.stderr)

    def test_copy_regular_exclusive_and_preserves_existing_file(self):
        storage = self.load()
        dest = self.root / 'artifact'
        self.assertEqual(storage.copy_regular(self.source, dest),
                         (3, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'))
        with self.assertRaises(self.model.EvidenceError):
            storage.copy_regular(self.source, dest)
        self.assertEqual(dest.read_bytes(), b'abc')
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)

    def test_fixture_refuses_source_symlinks(self):
        # Exercise the fixture itself from a synthetic copy, not the checkout.
        fixture = self.framework / 'tests/evidence_fixture.py'
        spec = importlib.util.spec_from_file_location('synthetic_fixture', fixture)
        fixture_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture_module)
        wrapper = self.module / 'evidence_manager.sh'
        wrapper.unlink()
        wrapper.symlink_to(self.source)
        with self.assertRaises(ValueError):
            fixture_module.copy_sources(self.root / 'second')


if __name__ == '__main__':
    unittest.main()
