"""Static contract and optional PowerShell mocks; never collect host data."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import unittest

from automation_fixture import AutomationFixture


class PowerShellTests(unittest.TestCase):
    def setUp(self):
        self.fixture = AutomationFixture()
        self.addCleanup(self.fixture.close)
        self.script = self.fixture.framework / '09_Automation/powershell/auto_enum.ps1'
        self.source = self.script.read_text()

    def test_ps_no_implicit_collection(self):
        self.assertRegex(self.source, r'param\(\s*\[string\]\$OutputDirectory,\s*\[switch\]\$Execute\s*\)')
        guard = self.source.index('if (-not $Execute -or')
        self.assertLess(guard, self.source.index('Get-ComputerInfo'))
        self.assertIn('exit 2', self.source)
        self.assertIn('Win32NT', self.source)
        self.assertIn('ReparsePoint', self.source)
        self.assertIn('Assert-SafeDirectory', self.source)
        self.assertIn('[guid]::NewGuid()', self.source)
        self.assertIn('-LiteralPath', self.source)
        self.assertIn('-NoClobber', self.source)

    def test_ps_five_blocks_and_paths(self):
        for filename in ('system_info.txt', 'local_users.txt', 'top_processes.txt',
                         'connections.txt', 'scheduled_tasks.txt'):
            self.assertIn(filename, self.source)
        self.assertIn('Join-Path', self.source)
        for cmdlet in ('Get-ComputerInfo', 'Get-LocalUser', 'Get-Process', 'Get-ScheduledTask'):
            self.assertRegex(self.source, re.escape(cmdlet) + r' -ErrorAction Stop')
        self.assertIn('Sort-Object -Property CPU -Descending -ErrorAction Stop', self.source)
        self.assertIn('Select-Object -First 20 -ErrorAction Stop', self.source)
        self.assertIn('netstat -ano', self.source)

    def test_ps_failure_contract(self):
        for token in ('$LASTEXITCODE', 'raw_exit', 'reason', "state = 'failed'",
                      "state = 'skipped'", 'exit 1', 'ConvertTo-Json', 'catch {'):
            self.assertIn(token, self.source)
        self.assertNotIn('Enumeración completada', self.source)
        self.assertIn('Remove-Item -LiteralPath', self.source)

    @unittest.skipUnless(shutil.which('pwsh'), 'SKIP dinámico: pwsh no está en PATH')
    def test_ps_mock_contract_and_ast(self):
        contract = self.fixture.framework / 'tests/fixtures/automation/powershell_contract.ps1'
        # Fixed test-only transformation permits mocks on non-Windows; production
        # retains its platform/path checks and exposes no bypass switch.
        result = subprocess.run(
            [shutil.which('pwsh'), '-NoLogo', '-NoProfile', '-NonInteractive',
             '-File', str(contract), '-ScriptPath', str(self.script),
             '-TestRoot', str(self.fixture.repo / 'ps mocks')],
            env={'PATH': os.environ.get('PATH', ''), 'HOME': str(self.fixture.home)},
            cwd=self.fixture.repo, text=True, capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('MOCK CONTRACT OK; AST OK', result.stdout)


if __name__ == '__main__':
    unittest.main()
