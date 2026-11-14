"""Strict inventory regressions, using only copied code and synthetic data.

Each test catches acceptance of an uncovered/invalid record or a misleading
status; the read guard catches listing that opens payload content.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

from evidence_fixture import sandbox, copy_sources, closed_env, snapshot, legacy_pair


class InventoryTests(unittest.TestCase):
    def setUp(self):
        context = sandbox()
        self.root = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.framework = copy_sources(self.root)
        self.env = closed_env(self.root)
        env_patch = mock.patch.dict(os.environ, self.env, clear=True)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.module = self.framework / '10_Evidence'
        self.source = self.root / 'synthetic.bin'
        self.source.write_bytes(b'abc')
        for name in list(sys.modules):
            if name == 'evidence' or name.startswith('evidence.'):
                del sys.modules[name]
        sys.path.insert(0, str(self.framework / '00_Config/lib'))
        self.addCleanup(sys.path.pop, 0)
        self.storage = importlib.import_module('evidence.storage')

    def inventory(self):
        # Load in each test body: absence is a missing implementation, not a
        # discovery/import failure that prevents the independent CLI REDs.
        self.assertIsNotNone(importlib.util.find_spec('evidence.inventory'),
                             'Task 2 inventory implementation is missing')
        return importlib.import_module('evidence.inventory')

    def add(self):
        return self.storage.add(self.module, 'proof', self.source)

    def command(self, *args):
        return subprocess.run(['/bin/bash', str(self.module / 'evidence_manager.sh'), *args],
                              env=self.env, cwd=self.root, capture_output=True,
                              text=True, timeout=10)

    def legacy(self, name='old proof with spaces.bin'):
        return legacy_pair(self.module / 'proofs/access', name)

    def assert_bad(self):
        self.assertFalse(self.inventory().verify(self.module).ok)
        result = self.command('--verify')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn('Todas las evidencias están íntegras', result.stdout)

    def test_modified_payload_never_reports_global_success(self):
        good = self.add()
        bad = self.add()
        bad.payload.write_bytes(b'bad')
        self.assert_bad()
        self.assertEqual(len(self.inventory().verify(self.module).entries), 1)
        self.assertTrue(good.payload.exists())

    def test_empty_inventory_is_not_verified(self):
        result = self.command('--verify')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('SIN EVIDENCIAS', result.stdout)
        self.assertFalse(self.inventory().verify(self.module).ok)
        self.assertEqual(self.command('--list').returncode, 0)

    def test_invalid_evidence_is_not_reported_as_empty_inventory(self):
        record = self.add()
        record.payload.write_bytes(b'bad')
        result = self.command('--verify')
        self.assertEqual(result.returncode, 1)
        self.assertIn('INVÁLIDA', result.stdout)
        self.assertNotIn('SIN EVIDENCIAS', result.stdout)

    def test_list_does_not_read_payload(self):
        record = self.add()
        inv = self.inventory()
        original = os.open
        def guarded(path, *args, **kwargs):
            if Path(path).name == 'artifact':
                raise AssertionError('listing opened payload')
            return original(path, *args, **kwargs)
        with mock.patch('os.open', side_effect=guarded):
            result = inv.scan(self.module)
        self.assertEqual(len(result.records), 1)
        self.assertFalse(result.issues)
        record.payload.write_bytes(b'changed')
        listing = self.command('--list')
        self.assertEqual(listing.returncode, 0)
        self.assertIn('NUEVA — NO VERIFICADA', listing.stdout)

    def test_legacy_spaces_and_md5_are_read_only(self):
        payload, metadata = self.legacy(' leading and trailing .bin ')
        before = snapshot(self.module)
        inv = self.inventory()
        result = inv.verify(self.module)
        self.assertTrue(result.ok, result.issues)
        entry = result.entries[0]
        self.assertEqual(entry.record.format, 'legacy-md5')
        self.assertEqual(entry.record.payload, payload)
        self.assertEqual(entry.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertEqual(entry.metadata_sha256, hashlib.sha256(metadata.read_bytes()).hexdigest())
        self.assertEqual(entry.metadata_size, metadata.stat().st_size)
        self.assertEqual(inv.read_record(metadata, self.module), entry.record)
        command = self.command('--verify')
        self.assertEqual(command.returncode, 0, command.stdout + command.stderr)
        self.assertIn('MD5', command.stdout)
        self.assertIn('HISTÓRICA MD5 — NO VERIFICADA', self.command('--list').stdout)
        self.assertEqual(snapshot(self.module), before)
        payload.write_bytes(b'bad')
        self.assert_bad()

    def test_missing_or_orphaned_payload_or_metadata_fails(self):
        record = self.add()
        for pair in ((record.payload, record.metadata), self.legacy()):
            for path in pair:
                with self.subTest(missing=path):
                    original = path.read_bytes()
                    path.unlink()
                    self.assert_bad()
                    path.write_bytes(original)
                    self.assertTrue(self.inventory().verify(self.module).ok)

    def test_duplicate_json_keys_nan_wrong_version_and_bool_size_fail(self):
        record = self.add()
        original = record.metadata.read_text()
        malformed = [original.replace('{', '{"id":"duplicate",', 1),
                     original.replace('"size": 3', '"size": NaN'),
                     original.replace('"schema_version": 1', '"schema_version": 2'),
                     original.replace('"schema_version": 1', '"schema_version": true'),
                     original.replace('"size": 3', '"size": true')]
        for text in malformed:
            with self.subTest(text=text):
                record.metadata.write_text(text)
                self.assert_bad()

    def test_metadata_paths_type_id_and_digest_are_confined(self):
        record = self.add()
        data = json.loads(record.metadata.read_text())
        mutations = [('stored_name', '../synthetic.bin'), ('stored_name', '/etc/passwd'),
                     ('id', '0' * 32), ('type', 'pcap'), ('sha256', 'A' * 64),
                     ('size', -1), ('target', 42), ('created_at', 'yesterday'),
                     ('origin', 'other'), ('method', 'unexpected'), ('extra', 1)]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                record.metadata.write_text(json.dumps(dict(data, **{key: value})))
                self.assert_bad()

    def test_duplicate_legacy_file_reference_fails(self):
        _, metadata = self.legacy()
        metadata.with_name('duplicate.meta').write_bytes(metadata.read_bytes())
        self.assert_bad()

    def test_legacy_bad_identity_and_hash_fields_fail(self):
        _, metadata = self.legacy()
        original = metadata.read_text()
        for text in (original + 'FILE: old proof with spaces.bin\n',
                     original + 'HASH: 900150983cd24fb0d6963f7d28e17f72\n',
                     original.replace('TYPE: proof', 'TYPE: pcap'),
                     original.replace('FILE: old proof with spaces.bin', 'FILE: ../outside'),
                     original.replace('900150983cd24fb0d6963f7d28e17f72', 'bad'),
                     original.replace('DESCRIPTION: \n', '')):
            with self.subTest(text=text):
                metadata.write_text(text)
                self.assert_bad()

    def test_unreadable_subtree_is_an_issue_not_omitted(self):
        self.add()
        blocked = self.module / 'pcaps'
        blocked.mkdir()
        inv = self.inventory()
        original = os.scandir
        # Simulate an OS denial, including under privileged test runners.
        def denied(path):
            if isinstance(path, int) and Path(f'/proc/self/fd/{path}').readlink() == blocked:
                raise PermissionError('synthetic denied subtree')
            return original(path)
        with mock.patch('os.scandir', side_effect=denied):
            result = inv.verify(self.module)
        self.assertFalse(result.ok)
        self.assertTrue(any('denied' in issue.message for issue in result.issues))

    def test_no_follow_symlinks_and_unknown_files_fail(self):
        self.add()
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'secret').write_bytes(b'never read')
        before = snapshot(outside)
        (self.module / 'pcaps').symlink_to(outside, target_is_directory=True)
        self.assert_bad()
        self.assertEqual(snapshot(outside), before)
        (self.module / 'pcaps').unlink()
        unknown = self.module / 'proofs/access/unregistered.bin'
        unknown.write_bytes(b'abc')
        self.assert_bad()
        listing = self.command('--list')
        self.assertIn('SIN METADATOS', listing.stdout)

    def test_logs_runs_is_not_silently_excluded(self):
        self.add()
        runs = self.module / 'logs/runs'
        runs.mkdir(parents=True)
        (runs / 'run.json').write_text('{}')
        self.assert_bad()

    def test_new_metadata_and_payload_snapshot_digests(self):
        record = self.add()
        result = self.inventory().verify(self.module)
        self.assertTrue(result.ok, result.issues)
        entry = result.entries[0]
        self.assertEqual(entry.size, 3)
        self.assertEqual(entry.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertEqual(entry.metadata_sha256, hashlib.sha256(record.metadata.read_bytes()).hexdigest())

    def test_list_controls_are_escaped_and_operations_exclusive(self):
        self.storage.add(self.module, 'proof', self.source, target='label\nFORGED')
        result = self.command('--list')
        self.assertEqual(result.returncode, 0)
        self.assertIn('label\\nFORGED', result.stdout)
        for args in (('--list', '--verify'), ('--list', '--target', 'x'),
                     ('--help', '--verify'), ('--list', '--list')):
            self.assertEqual(self.command(*args).returncode, 2)

    def test_legacy_payload_named_meta_is_not_lost(self):
        payload, _ = self.legacy('foo.meta')
        result = self.inventory().verify(self.module)
        self.assertTrue(result.ok, result.issues)
        self.assertEqual([entry.record.payload for entry in result.entries], [payload])

    def test_list_never_opens_legacy_payload_with_metadata_name(self):
        inv = self.inventory()
        for name in ('foo.meta', 'evidence.json', 'nested.meta.meta'):
            with self.subTest(name=name):
                payload, _ = self.legacy(name)
                original = os.open
                def guarded(path, *args, **kwargs):
                    if Path(path).name == payload.name:
                        raise AssertionError('listing opened legacy payload')
                    return original(path, *args, **kwargs)
                with mock.patch('os.open', side_effect=guarded):
                    result = inv.scan(self.module)
                self.assertFalse(result.issues, result.issues)

    def test_ambiguous_legacy_sidecar_chain_fails(self):
        payload, metadata = self.legacy('foo')
        metadata.with_name('foo.meta.meta').write_text(
            'TYPE: proof\nDATE: old\nFILE: foo.meta\nDESCRIPTION: \nHASH: ' +
            hashlib.md5(metadata.read_bytes(), usedforsecurity=False).hexdigest() + '\nUSER: old\n')
        self.assert_bad()
        self.assertTrue(any(issue.code == 'AMBIGUOUS' for issue in self.inventory().scan(self.module).issues))

    def test_list_does_not_read_legacy_payload_when_sidecar_is_invalid(self):
        payload, metadata = self.legacy('foo.meta')
        metadata.write_text('broken sidecar')
        inv = self.inventory()
        original = os.open
        def guarded(path, *args, **kwargs):
            if Path(path).name == payload.name:
                raise AssertionError('listing opened payload after invalid sidecar')
            return original(path, *args, **kwargs)
        with mock.patch('os.open', side_effect=guarded):
            result = inv.scan(self.module)
        self.assertTrue(result.issues)
        self.assert_bad()

    def test_new_identity_requires_uuid4_not_just_hex(self):
        record = self.add()
        data = json.loads(record.metadata.read_text())
        data['id'] = '0' * 32
        record.metadata.write_text(json.dumps(data))
        record.metadata.parent.rename(record.metadata.parent.with_name('0' * 32))
        self.assert_bad()

    def test_symlink_payload_metadata_ancestor_and_fifo_fail(self):
        for component in ('payload', 'metadata'):
            with self.subTest(component=component):
                record = self.add()
                path = getattr(record, component)
                original = path.read_bytes()
                path.unlink()
                path.symlink_to(self.source)
                self.assert_bad()
                path.unlink()
                path.write_bytes(original)
                self.assertTrue(self.inventory().verify(self.module).ok)
        fifo_record = self.add()
        fifo_record.payload.unlink()
        os.mkfifo(fifo_record.payload)
        self.assert_bad()
        fifo_record.payload.unlink()
        fifo_record.payload.write_bytes(b'abc')
        self.assertTrue(self.inventory().verify(self.module).ok)
        inv = self.inventory()
        linked_root = self.root / 'module-link'
        linked_root.symlink_to(self.module, target_is_directory=True)
        self.assertFalse(inv.verify(linked_root).ok)

    def test_internal_logs_and_category_root_legacy_are_included(self):
        for method in ('scan', 'system'):
            self.storage.add(self.module, 'log', self.source, origin='capture',
                             run_id='synthetic-run', method=method)
        payload, metadata = self.legacy()
        payload.rename(payload.parent.parent / payload.name)
        metadata.rename(metadata.parent.parent / metadata.name)
        result = self.inventory().verify(self.module)
        self.assertTrue(result.ok, result.issues)
        self.assertEqual(len(result.entries), 3)


if __name__ == '__main__':
    unittest.main()
