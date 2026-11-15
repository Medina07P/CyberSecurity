"""Runner boundaries: excluded data is never opened, PATH never inherits backends."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import unittest
from unittest.mock import patch

import evidence_fixture as fixture


class RunnerTests(unittest.TestCase):
    def synthetic_sources(self, root):
        source = root / 'source'
        for relative in fixture.SOURCES:
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic source\n')
        return source

    def test_runner_copies_only_fixed_sources_and_synthetic_config(self):
        with fixture.sandbox() as root:
            source = self.synthetic_sources(root)
            # Opening these FIFOs would hang; links must not be followed either.
            poison = ['00_Config/scope.yaml', '00_Config/targets.txt',
                      '00_Config/.session', '10_Evidence/proofs/access/secret',
                      '00_Config/credentials/api-keys.yaml']
            for relative in poison:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                os.mkfifo(path)
            (source / '10_Evidence/recovered.py').symlink_to('/nonexistent/poison')
            with patch.object(fixture, '__file__', str(source / 'tests/evidence_fixture.py')):
                copied = fixture.copy_sources(root / 'destination')
            files = {str(p.relative_to(copied)) for p in copied.rglob('*') if p.is_file()}
            self.assertEqual(files, set(fixture.SOURCES) | {
                '00_Config/scope.yaml', '00_Config/targets.txt', '00_Config/.session'})
            self.assertEqual((copied / '00_Config/scope.yaml').read_text(),
                             'targets: {ips: [], domains: []}\n')
            self.assertEqual((copied / '00_Config/targets.txt').read_text(), '# synthetic only\n')
            self.assertEqual((copied / '00_Config/.session').read_text(), '')
            for p in copied.rglob('*'):
                self.assertEqual(p.stat().st_mode & 0o777, 0o700 if p.is_dir() else 0o600)

    def test_runner_rejects_source_symlinks(self):
        with fixture.sandbox() as root:
            source = self.synthetic_sources(root)
            selected = source / '10_Evidence/auto_capture.sh'
            selected.unlink()
            selected.symlink_to('/nonexistent/poison')
            with patch.object(fixture, '__file__', str(source / 'tests/evidence_fixture.py')):
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    fixture.copy_sources(root / 'destination')
            selected.unlink()
            selected.write_text('synthetic')
            selected.parent.rename(source / 'moved')
            selected.parent.symlink_to(source / 'moved', target_is_directory=True)
            with patch.object(fixture, '__file__', str(source / 'tests/evidence_fixture.py')):
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    fixture.copy_sources(root / 'destination2')

    def test_runner_never_runs_backend_from_host_path(self):
        with fixture.sandbox() as root:
            framework = fixture.copy_sources(root)
            host = root / 'host-bin'
            host.mkdir()
            marker = root / 'HOST_BACKEND_EXECUTED'
            for name in ('cutycapt', 'tcpdump', 'nmap'):
                path = host / name
                path.write_text(f'#!/bin/bash\necho unsafe > "{marker}"\n')
                path.chmod(0o700)
            with patch.dict(os.environ, {'PATH': str(host)}):
                env = fixture.closed_env(root)
            result = subprocess.run([str(root / 'bin/bash'),
                str(framework / '10_Evidence/auto_capture.sh'),
                '--web', 'https://example.invalid/', '--scan', '192.0.2.10',
                '--scan-profile', 'basic', '--traffic', '192.0.2.10',
                '--interface', 'fixture0', '--authorize-network'],
                env=env, cwd=root, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse(any((framework / '10_Evidence').glob('screenshots/web/*/artifact')))

    def test_runner_detects_source_content_or_mode_changes(self):
        self.assertTrue(hasattr(fixture, 'source_manifest'), 'source preservation guard missing')
        with fixture.sandbox() as root:
            source = self.synthetic_sources(root)
            before = fixture.source_manifest(source)
            selected = source / '10_Evidence/auto_capture.sh'
            selected.write_text('changed source\n')
            self.assertNotEqual(before, fixture.source_manifest(source))
            selected.write_text('synthetic source\n')
            selected.chmod(0o700)
            self.assertNotEqual(before, fixture.source_manifest(source))
            selected.unlink()
            with self.assertRaises(ValueError):
                fixture.source_manifest(source)

    def test_documented_commands_match_parser(self):
        with fixture.sandbox() as root:
            framework = fixture.copy_sources(root)
            env = fixture.closed_env(root)
            cwd = root / 'operator directory'
            cwd.mkdir()
            (cwd / 'sample evidence.txt').write_text('synthetic data only\n')
            commands = []
            for name in ('README.md', 'USE.md', 'FLUJO.md'):
                doc = framework / '10_Evidence' / name
                self.assertTrue(doc.is_file(), f'documented CLI source missing: {name}')
                for block in re.findall(r'```bash\n(.*?)```', doc.read_text(), re.S):
                    commands.extend(line.strip() for line in block.splitlines()
                                    if line.strip().startswith('./'))
            self.assertGreaterEqual(len(commands), 10)
            for command in commands:
                argv = shlex.split(command)
                self.assertIn(argv[0], ('./evidence_manager.sh', './auto_capture.sh',
                                       './run_all_evidence.sh'))
                # Documentation examples executed here must stay offline.
                self.assertFalse(set(argv) & {'--web', '--traffic', '--scan', '--system'})
                result = subprocess.run([str(root / 'bin/bash'),
                    str(framework / '10_Evidence' / argv[0][2:]), *argv[1:]],
                    cwd=cwd, env=env, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, (command, result.stdout, result.stderr))

    def test_runner_fails_when_original_allowed_source_changes_during_suite(self):
        with fixture.sandbox() as root:
            framework = fixture.copy_sources(root)
            # Replace only synthetic test copies; do not recursively run this guard.
            for path in (framework / 'tests').glob('test_evidence_*.py'):
                path.write_text('')
            victim = framework / '10_Evidence/auto_capture.sh'
            (framework / 'tests/test_evidence_storage.py').write_text(
                'import unittest\nfrom pathlib import Path\n'
                'class Mutation(unittest.TestCase):\n'
                ' def test_change_original(self):\n'
                f'  Path({str(victim)!r}).write_text("changed during suite")\n')
            result = subprocess.run(['/bin/bash', str(framework / 'tests/run_evidence.sh')],
                cwd=root, env=fixture.closed_env(root), capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn(b'fuentes de origen', result.stderr)


if __name__ == '__main__':
    unittest.main()
