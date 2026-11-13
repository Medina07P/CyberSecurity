"""UI de mantenimiento únicamente; fuentes copiadas y datos sintéticos."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


FW = Path(__file__).resolve().parents[1]
TOOLS = ('sudo', 'ip', 'iw', 'airodump-ng', 'aireplay-ng', 'aircrack-ng',
         'hcitool', 'bluetoothctl', 'sdptool', 'gatttool')
LEAVES = ('bluetooth/bt_discover.sh', 'bluetooth/bt_scan.sh',
          'run_all_wireless.sh', 'scripts/channel_hopper.sh',
          'scripts/interface_manager.sh', 'wifi/wifi_crack.sh',
          'wifi/wifi_deauth.sh', 'wifi/wifi_handshake.sh',
          'wifi/wifi_monitor.sh', 'wifi/wifi_scan.sh')


class WirelessMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wireless-ui-', dir='/tmp/opencode')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = self.root / 'framework'
        self.lib = self.fw / '00_Config/lib'
        self.lib.mkdir(parents=True)
        shutil.copy2(FW / 'cyber_framework.sh', self.fw)
        for path in (FW / '00_Config/lib').glob('*.bash'):
            shutil.copy2(path, self.lib)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        (self.bin / 'dirname').symlink_to('/usr/bin/dirname')
        (self.bin / 'python3').symlink_to(sys.executable)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.marker = self.root / 'FORBIDDEN'
        self.env = dict(HOME=str(self.home), PATH=str(self.bin),
                        TMPDIR='/tmp/opencode', PYTHONDONTWRITEBYTECODE='1',
                        MARKER=str(self.marker), LC_ALL='C.UTF-8')
        for name in TOOLS + ('airmon-ng', 'systemctl', 'service', 'tcpdump',
                             'tshark', 'curl', 'wget', 'chmod', 'cat'):
            self.stub(name)
        config = self.fw / '00_Config'
        for name in ('scope.yaml', 'targets.txt', '.session'):
            (config / name).write_text('SYNTHETIC ONLY\n')
        captures = self.fw / '07_Wireless/captures'
        captures.mkdir(parents=True)
        (captures / 'synthetic.cap').write_bytes(b'NOT A REAL CAPTURE')
        for name in LEAVES:
            path = self.fw / '07_Wireless' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#!/bin/bash\nprintf "leaf\\n" >> "$MARKER"\nexit 97\n')
            path.chmod(0o755)

    def stub(self, name):
        path = self.bin / name
        path.write_text('#!/bin/bash\nprintf "%s\\n" "$0" >> "$MARKER"\nexit 97\n')
        path.chmod(0o755)

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.stat().st_mode,
                hashlib.sha256(p.read_bytes()).hexdigest())
                for tree in (self.fw, self.home) for p in tree.rglob('*') if p.is_file()}

    def run_ui(self, command='module_wireless', inputs='0\n', manager=True):
        source = self.fw / 'cyber_framework.sh' if manager else self.lib / 'wireless_menu.bash'
        before = self.snapshot()
        code = '''source "$1" || exit
clear_screen() { :; }
pause() { printf 'PAUSE\\n'; }
run_module_scripts() { printf 'LIST:%s:%s:%s\\n' "$#" "$1" "$2"; }
''' + command
        result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', code,
                                 'wireless-test', str(source)], input=inputs,
                                text=True, capture_output=True, cwd=self.root,
                                env=self.env, timeout=10)
        self.assertEqual(before, self.snapshot(), 'fuentes/modos/config/capturas alterados')
        self.assertFalse(self.marker.exists(), 'herramienta u hoja ejecutada')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout

    def test_source_from_external_cwd_only_loads(self):
        self.assertEqual(self.run_ui(command=':', inputs=''), '')

    def test_entry_and_return_do_not_dispatch_original_list(self):
        output = self.run_ui()
        self.assertIn('MANTENIMIENTO', output)
        for option in ('1.', '2.', '11.', '0.'):
            self.assertIn(option, output)
        self.assertNotIn('LIST:', output)
        self.assertNotIn('PAUSE', output)

    def test_eof_returns_without_dispatch(self):
        output = self.run_ui(inputs='')
        self.assertIn('MANTENIMIENTO', output)
        self.assertNotIn('LIST:', output)
        self.assertNotIn('PAUSE', output)

    def test_invalid_and_blank_choices_never_dispatch(self):
        output = self.run_ui(inputs='3\n99\n\n0\n')
        self.assertEqual(output.count('Opción no válida'), 3)
        self.assertNotIn('LIST:', output)

    def test_check_lists_exact_tools_without_executing(self):
        output = self.run_ui(command='wireless_check_tools', inputs='', manager=False)
        rows = [line.strip() for line in output.splitlines() if ' disponible' in line]
        self.assertEqual(rows, [f'✓ {tool} disponible' for tool in TOOLS])
        self.assertNotIn('no instalado', output)

    def test_check_reports_missing_tools_without_system_fallback(self):
        for tool in TOOLS:
            (self.bin / tool).unlink()
        output = self.run_ui(command='wireless_check_tools', inputs='', manager=False)
        rows = [line.strip() for line in output.splitlines() if 'no instalado' in line]
        self.assertEqual(rows, [f'— {tool} no instalado' for tool in TOOLS])

    def test_option_one_checks_then_returns_to_menu(self):
        output = self.run_ui(inputs='1\n0\n')
        self.assertIn('✓ iw disponible', output)
        self.assertEqual(output.count('PAUSE'), 1)
        self.assertNotIn('LIST:', output)

    def test_guide_does_not_claim_capture_or_verification(self):
        output = self.run_ui(command='wireless_maintenance_guide', inputs='', manager=False)
        self.assertIn('handshake', output.lower())
        self.assertIn('guía', output.lower())
        self.assertIn('no prueba captura', output.lower())
        self.assertIn('verificación', output.lower())
        for recipe in ('sudo ', 'aireplay-ng ', 'airodump-ng ', 'aircrack-ng ', '--deauth'):
            self.assertNotIn(recipe, output)

    def test_option_two_shows_guide_and_returns(self):
        output = self.run_ui(inputs='2\n0\n')
        self.assertIn('no prueba captura', output.lower())
        self.assertEqual(output.count('PAUSE'), 1)
        self.assertNotIn('LIST:', output)

    def test_option_eleven_delegates_exact_original_boundary_then_returns(self):
        output = self.run_ui(inputs='11\n0\n')
        self.assertEqual(output.count('LIST:2:07_Wireless:07_Wireless'), 1)
        self.assertGreaterEqual(output.count('MANTENIMIENTO'), 2)

    def test_runner_discovers_only_target_and_propagates_failure(self):
        tests = self.fw / 'tests'
        tests.mkdir()
        runner = tests / 'run_wireless_maintenance.sh'
        source = FW / 'tests/run_wireless_maintenance.sh'
        self.assertTrue(source.exists(), 'runner de mantenimiento inexistente')
        shutil.copy2(source, runner)
        (tests / 'test_wireless_maintenance.py').write_text(
            'import unittest\nclass Sentinel(unittest.TestCase):\n'
            ' def test_expected_failure(self): self.fail("EXPECTED_SENTINEL")\n')
        (tests / 'test_unrelated.py').write_text('raise RuntimeError("UNRELATED_DISCOVERED")\n')
        result = subprocess.run(['/bin/bash', str(runner)], cwd=self.root, env=self.env,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('EXPECTED_SENTINEL', result.stderr)
        self.assertNotIn('UNRELATED_DISCOVERED', result.stderr)
        self.assertFalse(self.marker.exists())


if __name__ == '__main__':
    unittest.main()
