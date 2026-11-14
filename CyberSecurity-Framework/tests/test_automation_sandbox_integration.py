"""Task4 regressions written first; NOT RUN, independent review required."""
import ast
import json
from pathlib import Path
import unittest
from unittest import mock


class IntegrationTests(unittest.TestCase):
    def test_fd_attachment_checks_metadata_only_and_preserves_invalid_errors(self):
        import errno
        import os
        from automation_test_guard import preservation_event
        with mock.patch('automation_test_guard.os.fstat', return_value=mock.sentinel.metadata) as metadata, \
                mock.patch('automation_test_guard.os.stat') as named, \
                mock.patch('automation_test_guard.os.read') as read:
            for mode in ('w', 'wb', 'w+'):
                preservation_event('open', (42, mode, os.O_WRONLY | os.O_TRUNC))
            self.assertEqual(metadata.call_args_list, [mock.call(42)] * 3)
            named.assert_not_called()
            read.assert_not_called()
        for descriptor in (-1, 42):
            with self.subTest(descriptor=descriptor), mock.patch(
                    'automation_test_guard.os.fstat', side_effect=OSError(errno.EBADF, 'synthetic closed fd')):
                with self.assertRaises(OSError) as failure:
                    preservation_event('open', (descriptor, 'wb', os.O_TRUNC))
                self.assertEqual(failure.exception.errno, errno.EBADF)
        with mock.patch('automation_test_guard.os.fstat', side_effect=OverflowError('synthetic invalid fd')):
            with self.assertRaises(OverflowError):
                preservation_event('open', (2 ** 100, 'wb', os.O_TRUNC))

    def test_fdopen_and_pipe_attachments_keep_synthetic_bytes_and_borrowed_handles(self):
        import io
        import os
        from automation_fixture import AutomationFixture
        fixture = AutomationFixture()
        path = fixture.repo / 'attachment-only'
        original = b'SYNTHETIC existing bytes; wrapping wb must not truncate\x00'
        with path.open('xb') as stream:
            stream.write(original)
        fd = os.open(path, os.O_WRONLY)
        try:
            with os.fdopen(fd, 'wb', closefd=False):
                pass  # Attach only: no write/truncate or replacement of content.
            os.fstat(fd)  # Borrowed descriptor must still be live.
        finally:
            os.close(fd)
        self.assertEqual(path.read_bytes(), original)
        reader, writer = os.pipe()
        try:
            with io.open(writer, 'wb', closefd=False):
                pass
            os.fstat(reader)
            os.fstat(writer)
        finally:
            os.close(reader)
            os.close(writer)

    def test_real_truncation_events_and_existing_path_alias_stay_blocked(self):
        import os
        from automation_test_guard import preservation_event
        for target in (42, 'synthetic-path'):
            with self.subTest(target=target), self.assertRaises(PermissionError):
                preservation_event('os.truncate', (target, 0))  # ftruncate uses same audit event.
        with mock.patch('automation_test_guard.os.stat', return_value=mock.sentinel.existing), \
                mock.patch('automation_test_guard.os.fstat') as attach:
            for path in ('synthetic-path', '/proc/self/fd/42'):
                with self.subTest(path=path), self.assertRaises(PermissionError):
                    preservation_event('open', (path, 'wb', os.O_TRUNC))
            attach.assert_not_called()

    def test_storage_mode_rejection_sets_755_explicitly_before_assertion(self):
        tree = ast.parse(Path(__file__).with_name('test_automation_runner.py').read_text())
        case = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                    and n.name == 'test_storage_files_lock_and_modes')
        chmod = next(n for n in ast.walk(case) if isinstance(n, ast.Call)
                     and ast.unparse(n.func) == 'root.chmod' and
                     isinstance(n.args[0], ast.Constant) and n.args[0].value == 0o755)
        rejection = next(n for n in ast.walk(case) if isinstance(n, ast.With))
        self.assertLess(chmod.lineno, rejection.lineno)

    def test_all_case_roots_use_persistent_work_fixtures(self):
        # Source regression only; no launcher/prepare call or nested bwrap.
        here = Path(__file__).parent
        for filename in ('automation_fixture.py', 'test_automation_isolation.py'):
            tree = ast.parse((here / filename).read_text())
            calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Name) and n.func.id == 'mkdtemp']
            directories = [ast.literal_eval(k.value) for n in calls for k in n.keywords
                           if k.arg == 'dir' and isinstance(k.value, ast.Constant)]
            self.assertIn('/work/fixtures', directories, filename)
            self.assertNotIn('/tmp/opencode', directories, filename)
        tree = ast.parse((here / 'test_automation_sandbox_prepare.py').read_text())
        case = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                    and n.name == 'persistent_case')
        roots = [n.args[0].value for n in ast.walk(case) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == 'Path'
                 and n.args and isinstance(n.args[0], ast.Constant)]
        self.assertEqual(roots, ['/work/fixtures'])
        tree = ast.parse((here / 'automation_sandbox_launch.py').read_text())
        loop = next(n for n in ast.walk(tree) if isinstance(n, ast.For)
                    and ast.unparse(n.target) == 'name' and
                    isinstance(n.iter, ast.Tuple) and
                    all(isinstance(item, ast.Constant) for item in n.iter.elts) and
                    'fixtures' in ast.literal_eval(n.iter))
        self.assertEqual(ast.unparse(loop.body[0]),
                         '(run.work / name).mkdir(mode=448)')

    def test_previous_stub_bytes_and_receipt_are_under_bin(self):
        from automation_fixture import AutomationFixture
        fixture = AutomationFixture()
        self.assertEqual(fixture.repo.parent, Path('/work/fixtures'))
        previous = fixture.stub('synthetic', 17).read_bytes()
        current = fixture.stub('synthetic', 19)
        archives = list(fixture.bin.glob('.preserved-*/synthetic'))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), previous)
        self.assertNotEqual(current.read_bytes(), previous)
        receipt = json.loads((archives[0].parent / 'preservation.json').read_text())
        self.assertEqual(receipt['original'], str(fixture.bin / 'synthetic'))
        self.assertEqual(receipt['retained'], str(archives[0]))
        self.assertEqual(receipt['before'], receipt['after'])

    def test_preservation_diagnostic_never_allows_delete_or_overwrite(self):
        import os
        from automation_test_guard import preservation_event
        for event, args in (('os.remove', ('synthetic', -1)),
                            ('os.rmdir', ('synthetic', -1)),
                            ('os.truncate', ('synthetic', 0))):
            with self.assertRaises(PermissionError):
                preservation_event(event, args)
        with mock.patch('automation_test_guard.os.stat', return_value=mock.sentinel.existing):
            with self.assertRaises(PermissionError):
                preservation_event('os.rename', ('source', 'target', -1, -1))
            with self.assertRaises(PermissionError):
                preservation_event('open', ('target', 'w', os.O_TRUNC))

    def test_fixture_close_preserves_tree(self):
        from automation_fixture import AutomationFixture
        fixture = AutomationFixture()
        sentinel = fixture.repo / 'sentinel'
        original = b'preserve every byte\x00\xff'
        sentinel.write_bytes(original)
        fixture.close()
        fixture.close()
        self.assertEqual(sentinel.read_bytes(), original)
        self.assertEqual(fixture.repo.stat().st_mode & 0o777, 0o700)

    def test_preserve_retains_symlink_and_previous_stub(self):
        from automation_fixture import AutomationFixture, preserve
        fixture = AutomationFixture()
        first = fixture.stub('synthetic', 17).read_bytes()
        fixture.stub('synthetic', 19)
        self.assertTrue(any(p.read_bytes() == first for p in
                            fixture.bin.glob('.preserved-*/synthetic')))
        link = fixture.repo / 'dangling'
        link.symlink_to('not-created')
        archived = preserve(link)
        self.assertTrue(archived.is_symlink())
        self.assertEqual(archived.readlink(), Path('not-created'))
        self.assertFalse(link.is_symlink())
        receipt = json.loads((archived.parent / 'preservation.json').read_text())
        self.assertEqual(receipt['original'], str(link))
        self.assertEqual(receipt['retained'], str(archived))
        self.assertEqual(receipt['before'], receipt['after'])

    def test_manifest_mutation_cannot_admit_configuration_or_unknown_data(self):
        import automation_sandbox_prepare as prepare
        for name in ('CyberSecurity-Framework/00_Config/scope.yaml',
                     'CyberSecurity-Framework/scans/fake.py',
                     'CyberSecurity-Framework/tests/arbitrary.json',
                     '../outside.py'):
            with self.subTest(name=name), mock.patch.object(
                    prepare, 'load_json', return_value={'version': 1, 'files': [name]}):
                with self.assertRaises(prepare.IsolationBlocked):
                    prepare.source_names()

    def test_sources_manifest_replaces_git(self):
        from test_automation_contract import source_paths, ROOT
        names = json.loads(Path(__file__).with_name('automation_sandbox_sources.json').read_text())['files']
        self.assertEqual(source_paths(), [ROOT / p for p in names
                                         if p.startswith('CyberSecurity-Framework/')])
        tree = ast.parse(Path(__file__).with_name('test_automation_contract.py').read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'source_paths')
        self.assertNotIn('subprocess', ast.unparse(function))

    def test_launcher_reentry_is_rejected(self):
        import automation_sandbox_launch as launcher
        with mock.patch.object(launcher, 'REPO', Path('/source')), \
                mock.patch.object(launcher, 'prepare') as prepare, \
                mock.patch.object(launcher, '_open_bwrap') as bwrap:
            self.assertEqual(launcher.launch(), 2)
        prepare.assert_not_called()
        bwrap.assert_not_called()

    def test_operational_entrypoints_unchanged(self):
        # Fixed source-only digest baseline from BASE367b9db, no data/config hashes.
        import hashlib
        root = Path(__file__).resolve().parents[2]
        baseline = json.loads(Path(__file__).with_name('automation_operational_baseline.json').read_text())
        for relative, digest in baseline['sha256'].items():
            self.assertEqual(hashlib.sha256((root / relative).read_bytes()).hexdigest(), digest, relative)

    def test_blocked_cases_are_not_silently_lost_or_green(self):
        from automation_suite_selection import classify, flatten
        from automation_sandbox_prepare import source_names
        modules = [Path(name).stem for name in source_names()
                   if name.startswith('CyberSecurity-Framework/tests/test_automation_')
                   and name.endswith('.py')]
        cases = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(modules)))
        allowed, blocked = classify(cases)
        self.assertTrue(blocked)
        self.assertEqual({t.id() for t in cases}, {t.id() for t in allowed} | set(blocked))
        self.assertTrue(all(reason.startswith('BLOCKED-preservation:') for reason in blocked.values()))

    def test_no_new_selector_or_nested_launcher_in_suite_dispatch(self):
        import automation_suite_selection as selection
        tree = ast.parse(Path(selection.__file__).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self.assertNotIn(ast.unparse(node.func), ('subprocess.run', 'subprocess.Popen', 'os.system'))

    def test_current_race_cases_are_named_blocks_not_passing_repetitions(self):
        from automation_suite_selection import RACES
        blocked = json.loads(Path(__file__).with_name('automation_preservation_cases.json').read_text())['blocked']
        self.assertEqual(len(RACES), 8)
        self.assertTrue(set(RACES) <= set(blocked))


if __name__ == '__main__':
    unittest.main()
