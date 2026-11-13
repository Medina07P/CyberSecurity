"""Synthetic exports: catch live-source tar, replacement and incomplete manifests."""
import hashlib
from concurrent.futures import ThreadPoolExecutor
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import threading
import unittest
from unittest import mock

from evidence_fixture import sandbox, copy_sources, closed_env, snapshot


class PackageTests(unittest.TestCase):
    def setUp(self):
        context = sandbox()
        self.root = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.framework = copy_sources(self.root)
        self.env = closed_env(self.root)
        patch = mock.patch.dict(os.environ, self.env, clear=True)
        patch.start()
        self.addCleanup(patch.stop)
        self.module = self.framework / '10_Evidence'
        self.output = self.framework / '11_Reports/evidence'
        self.source = self.root / 'source'
        self.source.write_bytes(b'abc')
        for name in list(sys.modules):
            if name == 'evidence' or name.startswith('evidence.'):
                del sys.modules[name]
        sys.path.insert(0, str(self.framework / '00_Config/lib'))
        self.addCleanup(sys.path.pop, 0)
        self.storage = importlib.import_module('evidence.storage')
        self.error = importlib.import_module('evidence.model').EvidenceError

    def package(self):
        self.assertIsNotNone(importlib.util.find_spec('evidence.package'),
                             'Task 3 package implementation is missing')
        return importlib.import_module('evidence.package')

    def add(self):
        return self.storage.add(self.module, 'proof', self.source)

    def command(self, *args):
        return subprocess.run(['/bin/bash', str(self.module / 'evidence_manager.sh'), *args],
                              env=self.env, cwd=self.root, capture_output=True, text=True, timeout=10)

    def assert_no_package(self):
        self.assertEqual(list(self.output.glob('*.tar.gz')), [])
        self.assertEqual(list(self.output.glob('.export-*')), [])

    def test_archive_contains_metadata_manifest_not_code(self):
        record = self.add()
        (self.module / 'diagnostic.txt').write_text('not evidence')
        before = snapshot(self.framework)
        archive = self.package().create(self.module)
        self.assertEqual(archive.parent, self.output)
        self.assertRegex(archive.name, r'^\d{8}_evidence_[0-9a-f]{32}\.tar\.gz$')
        with tarfile.open(archive) as tar:
            names = set(tar.getnames())
            expected = {str(record.payload.relative_to(self.module)),
                        str(record.metadata.relative_to(self.module)), 'manifest.json'}
            self.assertEqual(names, expected)
            self.assertTrue(all(m.isfile() and m.mode == 0o600 for m in tar.getmembers()))
            self.assertEqual(tar.extractfile(str(record.metadata.relative_to(self.module))).read(),
                             record.metadata.read_bytes())
        after = snapshot(self.framework)
        self.assertEqual({k: after[k] for k in before}, before)
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

    def test_no_manifest_txt_is_touched(self):
        self.add()
        sentinel = self.module / 'manifest.txt'
        sentinel.write_bytes(b'historical manifest\x00')
        before = snapshot(self.module)
        self.package().create(self.module)
        self.assertEqual(snapshot(self.module), before)

    def test_invalid_or_empty_inventory_blocks_publication(self):
        package = self.package()
        with self.assertRaises(self.error):
            package.create(self.module)
        self.assert_no_package()
        record = self.add()
        record.payload.write_bytes(b'bad')
        with self.assertRaises(self.error):
            package.create(self.module)
        self.assert_no_package()
        record.payload.write_bytes(b'abc')
        (record.payload.parent / 'orphan').write_bytes(b'unknown')
        with self.assertRaises(self.error):
            package.create(self.module)
        self.assert_no_package()

    def test_legacy_metadata_is_included_unchanged(self):
        parent = self.module / 'proofs/access'
        parent.mkdir(parents=True)
        payload = parent / 'old proof.bin'
        payload.write_bytes(b'abc')
        raw = (b'TYPE: proof\nDATE: old: date\nFILE: old proof.bin\nDESCRIPTION:  two spaces\n'
               b'HASH: 900150983CD24FB0D6963F7D28E17F72\nUSER: $(not executed)\n')
        metadata = parent / 'old proof.bin.meta'
        metadata.write_bytes(raw)
        before = snapshot(self.module)
        archive = self.package().create(self.module)
        with tarfile.open(archive) as tar:
            self.assertEqual(tar.extractfile('proofs/access/old proof.bin.meta').read(), raw)
            manifest = json.load(tar.extractfile('manifest.json'))
            self.assertEqual(manifest['records'][0]['format'], 'legacy-md5')
        self.assertEqual(snapshot(self.module), before)

    def test_package_name_cannot_escape(self):
        self.add()
        for name in ('', '.', '..', '../outside', '/tmp/a', 'a.b', 'a/b', 'a\\b',
                     'a\n', 'á', 'x' * 81):
            with self.subTest(name=name), self.assertRaises(self.error):
                self.package().create(self.module, name)
        self.assert_no_package()

    def test_two_exports_and_forced_collision_never_replace(self):
        self.add()
        package = self.package()
        first = package.create(self.module, 'Case_1')
        original = first.read_bytes()
        second = package.create(self.module, 'Case_1')
        self.assertNotEqual(first, second)
        fixed_id = first.name[len('Case_1_'):-len('.tar.gz')]
        with mock.patch.object(package.uuid, 'uuid4', return_value=mock.Mock(hex=fixed_id)):
            with self.assertRaises(self.error):
                package.create(self.module, 'Case_1')
        self.assertEqual(first.read_bytes(), original)
        self.assertEqual(len(list(self.output.glob('*.tar.gz'))), 2)
        self.assertEqual(list(self.output.glob('.export-*')), [])

    def test_payload_or_metadata_changes_during_snapshot_abort(self):
        record = self.add()
        package = self.package()
        original = package.copy_regular
        for source in (record.payload, record.metadata):
            saved = source.read_bytes()
            def changed(src, dst):
                if src == source:
                    source.write_bytes(saved + b' ')
                return original(src, dst)
            with self.subTest(source=source), mock.patch.object(package, 'copy_regular', side_effect=changed):
                with self.assertRaises(self.error):
                    package.create(self.module)
            source.write_bytes(saved)
            self.assert_no_package()

    def test_inventory_changes_after_snapshot_abort(self):
        record = self.add()
        package = self.package()
        original = package.check_archive
        for change in ('member', 'metadata', 'payload', 'valid-member'):
            added = []
            def changed(path):
                original(path)
                if change == 'member':
                    (record.payload.parent / 'unexpected').write_bytes(b'new')
                elif change == 'metadata':
                    record.metadata.write_bytes(record.metadata.read_bytes() + b' ')
                elif change == 'valid-member':
                    added.append(self.add())
                else:
                    record.payload.write_bytes(b'bad')
            before = record.metadata.read_bytes()
            with self.subTest(change=change), mock.patch.object(package, 'check_archive', side_effect=changed):
                with self.assertRaises(self.error):
                    package.create(self.module)
            (record.payload.parent / 'unexpected').unlink(missing_ok=True)
            record.metadata.write_bytes(before)
            record.payload.write_bytes(b'abc')
            for extra in added:
                extra.payload.unlink()
                extra.metadata.unlink()
                extra.payload.parent.rmdir()
            self.assert_no_package()

    def test_write_inside_streaming_copy_aborts_and_removes_stage(self):
        record = self.add()
        package = self.package()
        copy = package.copy_regular
        read = os.read
        for source in (record.payload, record.metadata):
            saved = source.read_bytes()
            identity = (source.stat().st_dev, source.stat().st_ino)
            modified = []
            def read_and_change(fd, count):
                chunk = read(fd, count)
                info = os.fstat(fd)
                if chunk and (info.st_dev, info.st_ino) == identity and not modified:
                    source.write_bytes(saved + b' changed during read')
                    modified.append(True)
                return chunk
            def copying(src, dst):
                # Other verification reads stay real; mutate only the copy's open descriptor.
                with mock.patch.object(package.os, 'read', side_effect=read_and_change):
                    return copy(src, dst)
            with self.subTest(source=source), mock.patch.object(package, 'copy_regular', side_effect=copying):
                with self.assertRaises(self.error):
                    package.create(self.module)
            self.assertTrue(modified)
            source.write_bytes(saved)
            self.assert_no_package()

    def test_tar_or_output_failure_leaves_no_final_package(self):
        self.add()
        package = self.package()
        before = snapshot(self.module)
        with mock.patch.object(package.tarfile, 'open', side_effect=OSError('synthetic tar failure')):
            with self.assertRaises(self.error):
                package.create(self.module)
        self.assert_no_package()
        with mock.patch.object(package.os, 'link', side_effect=OSError('synthetic publish failure')):
            with self.assertRaises(self.error):
                package.create(self.module)
        self.assert_no_package()
        self.assertEqual(snapshot(self.module), before)

    def test_cleanup_failure_rolls_back_own_publication(self):
        self.add()
        package = self.package()
        with mock.patch.object(package.shutil, 'rmtree', side_effect=OSError('synthetic cleanup failure')):
            with self.assertRaises(self.error):
                package.create(self.module)
        self.assertEqual(list(self.output.glob('*.tar.gz')), [])

    def test_concurrent_exports_publish_distinct_complete_packages(self):
        self.add()
        package = self.package()
        link = package.os.link
        barrier = threading.Barrier(2, timeout=10)
        def simultaneous(*args, **kwargs):
            barrier.wait()
            return link(*args, **kwargs)
        with mock.patch.object(package.os, 'link', side_effect=simultaneous):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(package.create, self.module, 'Concurrent') for _ in range(2)]
                paths = [f.result(timeout=15) for f in futures]
        self.assertNotEqual(*paths)
        for path in paths:
            package.check_archive(path)
        self.assertEqual(list(self.output.glob('.export-*')), [])

    def rewrite_archive(self, original, name, transform):
        with tarfile.open(original) as tar:
            members = [(m, tar.extractfile(m).read()) for m in tar]
        destination = self.root / name
        with tarfile.open(destination, 'w:gz') as tar:
            for member, data in transform(members):
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        return destination

    def test_archive_member_set_and_hashes_are_exact(self):
        self.add()
        package = self.package()
        archive = package.create(self.module)
        package.check_archive(archive)
        with tarfile.open(archive) as tar:
            manifest = json.load(tar.extractfile('manifest.json'))
            self.assertEqual(manifest['schema_version'], 1)
            self.assertEqual(set(manifest), {'schema_version', 'id', 'created_at', 'records', 'members'})
            self.assertEqual(len(manifest['members']), 2)
            for entry in manifest['members']:
                content = tar.extractfile(entry['path']).read()
                self.assertEqual(entry['size'], len(content))
                self.assertEqual(entry['sha256'], hashlib.sha256(content).hexdigest())
        def extra(members):
            return members + [(tarfile.TarInfo('extra'), b'not listed')]
        def changed(members):
            return members[:1] + [(members[1][0], b'wrong')] + members[2:]
        def link(members):
            members[1][0].type = tarfile.SYMTYPE
            members[1][0].linkname = '/etc/passwd'
            return members
        def absolute(members):
            members[1][0].name = '/outside'
            return members
        def traversal(members):
            members[1][0].name = 'a/../outside'
            return members
        for i, transform in enumerate((extra, changed, link, absolute, traversal,
                                       lambda m: m[:-1], lambda m: m + m[1:2])):
            bad = self.rewrite_archive(archive, f'bad-{i}.tgz', transform)
            with self.subTest(case=i), self.assertRaises(self.error):
                package.check_archive(bad)

    def test_cli_package_is_explicit_noninteractive_and_validated(self):
        self.add()
        result = self.command('--package', 'Test')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(list(self.output.glob('Test_*.tar.gz'))), 1)
        for args in (('--package', ''), ('--package', '../no'), ('--package', '--verify'),
                     ('--package', '--target', 'x'), ('--package', '--force'),
                     ('--package', '--package')):
            self.assertEqual(self.command(*args).returncode, 2, args)
        result = self.command('--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn('confidencial', result.stdout.lower())
        self.assertIn('sin cifrar', result.stdout.lower())
        self.assertEqual(self.command('--package').returncode, 0)

    def test_symlink_output_is_rejected(self):
        self.add()
        self.output.parent.mkdir()
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(self.error):
            self.package().create(self.module)
        self.assertEqual(list(self.root.glob('*.tar.gz')), [])

    def test_invalid_inventory_diagnostic_identifies_each_problem(self):
        record = self.add()
        for name in ('orphan-one', 'orphan-two'):
            (record.payload.parent / name).write_bytes(b'unknown')
        result = self.command('--package')
        self.assertEqual(result.returncode, 1)
        self.assertIn('orphan-one', result.stderr)
        self.assertIn('orphan-two', result.stderr)
        self.assert_no_package()

    def test_checker_rejects_malformed_manifests_and_unreadable_archives(self):
        self.add()
        package = self.package()
        archive = package.create(self.module)
        def mutate(members, mutation):
            manifest = json.loads(members[0][1])
            mutation(manifest)
            return [(members[0][0], json.dumps(manifest).encode())] + members[1:]
        for i, mutation in enumerate((
                lambda d: d.update(schema_version=True),
                lambda d: d['members'][0].update(size=True),
                lambda d: d['members'][0].update(path='../escape'),
                lambda d: d['records'][0].update(payload='missing'),
                lambda d: d['members'].append(d['members'][0]),
                lambda d: d.update(records=[]))):
            bad = self.rewrite_archive(archive, f'manifest-{i}.tgz', lambda m: mutate(m, mutation))
            with self.subTest(case=i), self.assertRaises(self.error):
                package.check_archive(bad)
        for i, raw in enumerate((b'{"schema_version":1,"schema_version":1}', b'{"size":NaN}')):
            bad = self.rewrite_archive(archive, f'json-{i}.tgz',
                                       lambda m: [(m[0][0], raw)] + m[1:])
            with self.assertRaises(self.error):
                package.check_archive(bad)
        bad = self.root / 'broken.tgz'
        bad.write_bytes(b'not gzip')
        with self.assertRaises(self.error):
            package.check_archive(bad)
        bad.unlink()
        bad.symlink_to(archive)
        with self.assertRaises(self.error):
            package.check_archive(bad)

    def test_restrictive_umask_still_creates_private_output(self):
        self.add()
        old = os.umask(0o777)
        try:
            archive = self.package().create(self.module)
        finally:
            os.umask(old)
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        self.package().check_archive(archive)

    def test_checker_rejects_truncated_or_corrupt_gzip_trailer(self):
        self.add()
        package = self.package()
        archive = package.create(self.module)
        raw = archive.read_bytes()
        for i, content in enumerate((raw[:-8], raw[:-8] + bytes([raw[-8] ^ 1]) + raw[-7:])):
            bad = self.root / f'trailer-{i}.tgz'
            bad.write_bytes(content)
            with self.subTest(case=i), self.assertRaises(self.error):
                package.check_archive(bad)
