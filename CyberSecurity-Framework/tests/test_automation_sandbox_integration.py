"""Task4 regressions written first; NOT RUN, independent review required."""
import ast
import json
from pathlib import Path
import unittest
from unittest import mock


class IntegrationTests(unittest.TestCase):
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
                            fixture.repo.glob('.preserved-*/synthetic')))
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
