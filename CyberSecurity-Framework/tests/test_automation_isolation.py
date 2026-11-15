"""Task4 NOT RUN: reentry negatives use synthetic data, never nested bwrap.

These negatives test arbitrary-payload rejection, not an OS sandbox. Child/grandchild
payloads only reference freshly created fake data and fake backends/network
doubles. Only the fresh independent probe receipt corroborates inherited
isolation; these argument-rejection tests do not establish it.
"""
from pathlib import Path
import subprocess
import sys
from tempfile import mkdtemp
from contextlib import nullcontext
from automation_case_scope import fixture_parent
import unittest


class BlockedLauncherTests(unittest.TestCase):
    def test_child_and_grandchild_payloads_cannot_be_launched(self):
        source = Path(__file__).resolve().parent / 'run_automation.sh'
        with nullcontext(mkdtemp(prefix='automation-blocked-', dir=fixture_parent())) as temporary:
            root = Path(temporary)
            runner = root / 'run_automation.sh'
            runner.write_text(source.read_text())
            fake_data = root / 'fake-host-data.txt'
            fake_data.write_text('SYNTHETIC CANARY ONLY\n')
            read_marker = root / 'read-attempted'
            backend_marker = root / 'backend-attempted'
            network_marker = root / 'network-double-attempted'
            child_marker = root / 'child-started'
            parent_marker = root / 'parent-started'
            fake_backend = root / 'synthetic_backend.py'
            fake_backend.write_text(
                'from pathlib import Path\n'
                f'Path({str(backend_marker)!r}).write_text("stub reached")\n'
                'raise SystemExit(97)\n')
            network_double = root / 'network_double.py'
            network_double.write_text(
                'from pathlib import Path\n'
                f'Path({str(network_marker)!r}).write_text("double reached")\n'
                'raise SystemExit(97)\n')
            child = root / 'synthetic_child.py'
            child.write_text(
                'from pathlib import Path\nimport subprocess, sys\n'
                f'Path({str(child_marker)!r}).write_text("child")\n'
                f'Path({str(fake_data)!r}).read_text()\n'
                f'Path({str(read_marker)!r}).write_text("fake data read")\n'
                f'subprocess.run([sys.executable, {str(fake_backend)!r}], check=False)\n'
                f'subprocess.run([sys.executable, {str(network_double)!r}], check=False)\n')
            grandchild = root / 'synthetic_parent.py'
            grandchild.write_text(
                'from pathlib import Path\nimport subprocess, sys\n'
                f'Path({str(parent_marker)!r}).write_text("parent")\n'
                f'raise SystemExit(subprocess.run([sys.executable, {str(child)!r}]).returncode)\n')
            # PATH has no host tools: if a stale launcher tries discovery via
            # python3, this deny double is a second barrier, not real Python.
            fake_python = root / 'python3'
            fake_python.write_text('#!/bin/bash\nexit 97\n')
            fake_python.chmod(0o700)
            for payload in (child, grandchild):
                with self.subTest(depth=payload.name):
                    result = subprocess.run(
                        ['/bin/bash', str(runner), '--', sys.executable, str(payload)],
                        cwd=root, env={'PATH': str(root), 'HOME': str(root),
                                       'PYTHONDONTWRITEBYTECODE': '1'},
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('BLOCKED', result.stderr)
                    for marker in (child_marker, parent_marker, read_marker,
                                   backend_marker, network_marker):
                        self.assertFalse(marker.exists(), marker.name)

    def test_inherited_os_filesystem_and_network_barrier(self):
        # Consume this selection's fresh receipt, never launch recursively.
        import json
        result = json.loads(Path('/evidence/probes.json').read_text())
        self.assertEqual(result['state'], 'PASS')
        self.assertEqual(len(result['checks']), 6)
        for child in result['descendants']:
            self.assertFalse(child['outside_canary_read'])
            self.assertEqual(child['socket_errno'], [1, 1])
            self.assertFalse(child['backend_visible'])
