"""WRITTEN ONLY: no execution authorized during Task9 round1.

These negatives test the CURRENT BLOCK, not an OS sandbox. Child/grandchild
payloads only reference freshly created fake data and fake backends/network
doubles. A future OS launcher needs separate reviewed containment tests; these
must never be used to infer inherited filesystem/network isolation.
"""
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


class BlockedLauncherTests(unittest.TestCase):
    def test_child_and_grandchild_payloads_cannot_be_launched(self):
        source = Path(__file__).resolve().parent / 'run_automation.sh'
        with TemporaryDirectory(prefix='automation-blocked-', dir='/tmp/opencode') as temporary:
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

    @unittest.skip('BLOCKED I1: no independently reviewed inherited OS launcher; no probes authorized')
    def test_inherited_os_filesystem_and_network_barrier(self):
        # Intentionally not a fake passing sandbox test. This unresolved
        # requirement needs a reviewed launcher/manifest and separate approval
        # before a child/grandchild containment probe can even be designed/run.
        self.fail('Inherited OS containment is not implemented or accredited')
