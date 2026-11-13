"""Regression of pending run_all fixes: copied coordinator, inert leaves only."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / '06_PostExploitation/run_all_post.sh'
LEAVES = (
    'privilege_escalation/linpeas.sh', 'privilege_escalation/suid_check.sh',
    'privilege_escalation/capabilities_check.sh', 'privilege_escalation/cron_check.sh',
    'credential_access/linux_creds.sh', 'credential_access/history_parser.sh',
    'loot/file_collector.sh', 'loot/screenshot_collector.sh',
)


class PendingRunAllTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='post-pending-', dir='/tmp/opencode')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.module = self.root / 'framework/06_PostExploitation'
        self.module.mkdir(parents=True)
        shutil.copy2(SOURCE, self.module / 'run_all_post.sh')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('bash', 'dirname', 'basename', 'mkdir', 'mktemp'):
            (self.bin / name).symlink_to(shutil.which(name))
        # Presence check only; the screenshot leaf below is an inert fixture.
        (self.bin / 'scrot').write_text('#!/bin/bash\nexit 99\n')
        (self.bin / 'scrot').chmod(0o755)
        self.calls = self.root / 'calls'
        for name in LEAVES:
            p = self.module / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('#!/bin/bash\n'
                         'printf "%s|%s|%s\\n" "${0##*/}" "${POSTEXPLOIT_TARGET:-}" "$#" >> "$CALLS"\n'
                         'printf "fixture diagnostic\\n" >&2\n'
                         'exit "${LEAF_RC:-0}"\n')
        self.scans = self.root / 'scans'
        self.env = {'PATH': str(self.bin), 'HOME': str(self.root),
                    'CALLS': str(self.calls), 'LC_ALL': 'C'}

    def run_flow(self, *args, **env):
        return subprocess.run([str(self.bin / 'bash'), str(self.module / 'run_all_post.sh'), *args],
                              cwd=self.root, env={**self.env, **env},
                              capture_output=True, text=True, timeout=10)

    def logs(self):
        return list(self.scans.rglob('*.log')) if self.scans.exists() else []

    def test_preserves_real_leaf_rc_in_private_log(self):
        r = self.run_flow('example.test', LEAF_RC='7')
        self.assertEqual(r.returncode, 1)
        logs = self.logs()
        self.assertTrue(any('rc=7' in p.read_text() for p in logs))
        self.assertIn('Ejecutadas: 8 | Fallidas: 8', r.stdout)

    def test_preserves_previous_error_log_and_separates_runs(self):
        old = self.scans / 'postexploitation/errores.log'
        old.parent.mkdir(parents=True)
        old.write_text('historical sentinel\n')
        self.assertEqual(self.run_flow('example.test').returncode, 0)
        first = {p: p.read_bytes() for p in self.logs()}
        self.assertEqual(self.run_flow('example.test').returncode, 0)
        self.assertEqual(old.read_text(), 'historical sentinel\n')
        for p, content in first.items():
            self.assertEqual(p.read_bytes(), content)
        self.assertGreater(len(self.logs()), len(first))

    def test_passes_explicit_context_not_positional_arguments(self):
        self.assertEqual(self.run_flow('example.test').returncode, 0)
        lines = self.calls.read_text().splitlines()
        self.assertEqual(len(lines), 8)
        self.assertTrue(all(s.endswith('|example.test|0') for s in lines))

    def test_usage_matches_required_target(self):
        usage = next(s for s in SOURCE.read_text().splitlines() if 'Uso:' in s)
        self.assertIn('<TARGET>', usage)

    def test_invalid_input_has_no_effects(self):
        for args in ((), ('bad target',), ('example.test', 'extra')):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_flow(*args).returncode, 0)
                self.assertFalse(self.calls.exists())
                self.assertFalse(self.scans.exists())

    def test_log_setup_failure_never_starts_leaves(self):
        self.scans.write_text('not a directory')
        r = self.run_flow('example.test')
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertFalse((self.module / 'run_all_post_errores.log').exists())

    def test_new_logs_and_directories_are_private(self):
        self.assertEqual(self.run_flow('example.test').returncode, 0)
        self.assertTrue(self.logs())
        for p in self.scans.rglob('*'):
            self.assertEqual(p.stat().st_mode & 0o777, 0o700 if p.is_dir() else 0o600)

    def test_screenshot_omitted_without_backend(self):
        (self.bin / 'scrot').unlink()
        r = self.run_flow('example.test')
        self.assertEqual(r.returncode, 0)
        self.assertIn('Ejecutadas: 7 | Fallidas: 0 | Omitidas: 1', r.stdout)
        self.assertEqual(len(self.calls.read_text().splitlines()), 7)


if __name__ == '__main__':
    unittest.main()
