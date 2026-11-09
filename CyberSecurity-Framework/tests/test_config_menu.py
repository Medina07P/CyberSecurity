"""Configuración desde menú real, con HOME, claves y objetivos sintéticos."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]


class ConfigFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='config-menu-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = self.root/'framework with spaces'
        self.config = self.fw/'00_Config'
        self.config.mkdir(parents=True)
        # Copiar solo código; jamás copiar credenciales/scope/targets reales.
        shutil.copy2(FW/'cyber_framework.sh', self.fw/'cyber_framework.sh')
        shutil.copy2(FW/'00_Config/run_all_config.sh', self.config/'run_all_config.sh')
        shutil.copytree(FW/'00_Config/scripts', self.config/'scripts', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(FW/'00_Config/lib', self.config/'lib', ignore=shutil.ignore_patterns('__pycache__'))
        (self.config/'scope.yaml').write_text('targets:\n  ips: []\n  domains: []\n')
        (self.config/'targets.txt').write_text('192.0.2.10|443|HTTPS|Fixture|M\n')
        (self.config/'README.md').write_text('# Fixture\n')
        shutil.copy2(FW/'00_Config/.gitignore', self.config/'.gitignore')
        for directory, files in {'wordlists': ['custom.lst', 'users.txt', 'passwords.txt', 'directories.txt'],
                                 'credentials': ['README.md', '.gitkeep']}.items():
            (self.config/directory).mkdir()
            for name in files:
                (self.config/directory/name).write_text('fixture\n')
        self.registry = self.root/'keys/registry.yaml'
        self.home = self.root/'home'; self.home.mkdir()
        self.template = self.root/'template.yaml'
        self.template.write_text('apikeys:\n  brave:\n    key: ""\n')
        self.caller = self.root/'caller'; self.caller.mkdir()
        (self.root/'sitecustomize.py').write_text(
            'import socket\ndef forbidden(*a, **k):\n    raise AssertionError("Red prohibida en tests config")\n'
            'socket.create_connection=forbidden\nsocket.socket.connect=forbidden\n')
        self.env = dict(os.environ, HOME=str(self.home), TERM='xterm', KEYS_FILE=str(self.registry),
                        KEYS_HARVESTER_DIRS=str(self.root/'external-keys'), KEYS_HARVESTER_TEMPLATE=str(self.template),
                        SESSION_FILE=str(self.root/'.session'), SESSION_SCOPE_FILE=str(self.config/'scope.yaml'),
                        SESSION_TARGETS_FILE=str(self.config/'targets.txt'), PYTHONPATH=str(self.root),
                        PYTHONDONTWRITEBYTECODE='1')
        self.initial = {name: (self.config/name).read_bytes() for name in ('scope.yaml', 'targets.txt')}

    def menu(self, inputs):
        result = subprocess.run(['bash', str(self.fw/'cyber_framework.sh')], input=inputs, text=True,
                                capture_output=True, env=self.env, cwd=self.caller, timeout=25)
        result.stdout = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', result.stdout)
        return result

    def assert_untouched(self):
        self.assertEqual(self.initial, {name: (self.config/name).read_bytes() for name in self.initial})
        self.assertFalse(self.registry.exists())


class GuidedMenuTests(ConfigFixture):
    def test_module_keys_opens_guided_menu_and_cancels(self):
        result = self.menu('00\n5\n0\n0\nQ\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CLAVES DE API', result.stdout)
        self.assertIn('Volver al módulo de configuración', result.stdout)
        self.assertNotIn('usage: api_keys.py', result.stdout+result.stderr)
        self.assertNotIn('Sin argumentos', result.stdout)
        self.assert_untouched()

    def test_module_keys_can_show_state_without_writing(self):
        result = self.menu('00\n5\n3\n\n0\nQ\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CLAVES DE API', result.stdout)
        self.assertIn('theHarvester', result.stdout)
        self.assertNotIn('usage: api_keys.py', result.stdout+result.stderr)
        self.assertNotIn('Código de salida: 1', result.stdout)
        self.assert_untouched()

    def test_module_guides_key_entry_without_echo_or_argv(self):
        secret = 'config-fixture-%42-secret'
        result = self.menu('00\n5\n2\n2\n'+secret+'\n\n0\nQ\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.registry.exists(), result.stdout+result.stderr)
        import yaml
        self.assertEqual(yaml.safe_load(self.registry.read_text())['shodan']['key'], secret)
        self.assertEqual((self.home/'.shodan/api_key').read_text().strip(), secret)
        self.assertNotIn(secret, result.stdout+result.stderr)
        self.assertNotIn('Argumentos:', result.stdout)
        self.assertEqual(self.initial, {name: (self.config/name).read_bytes() for name in self.initial})

    def test_existing_k_menu_still_returns_to_main(self):
        result = self.menu('K\n0\nQ\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CLAVES DE API', result.stdout)
        self.assertIn('Volver al menú principal', result.stdout)
        self.assert_untouched()

    def test_module_keys_eof_is_safe(self):
        result = self.menu('00\n5\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CLAVES DE API', result.stdout)
        self.assertNotIn('usage: api_keys.py', result.stdout+result.stderr)
        self.assert_untouched()

    def test_wizard_still_asks_own_questions(self):
        result = self.menu('00\n2\n0\n\n0\nQ\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ASISTENTE DE OBJETIVOS', result.stdout)
        self.assertNotIn('Sin argumentos', result.stdout)
        self.assert_untouched()

    def test_other_leaf_entries_work_without_argument_prompts(self):
        for choice, marker in [('3', 'Validación completada'), ('4', 'Verificación completada'), ('6', 'RESUMEN DE OBJETIVOS')]:
            with self.subTest(choice=choice):
                result = self.menu('00\n'+choice+'\n\n0\nQ\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(marker, result.stdout)
                self.assertNotIn('Sin argumentos', result.stdout)
                self.assertNotIn('Código de salida: 1', result.stdout)
                self.assert_untouched()

    def test_absolute_dispatch_preserves_callers_directory(self):
        code = 'source "$1/cyber_framework.sh"; cd "$2"; execute_script "$1/00_Config/scripts/api_keys.py" "$1/00_Config"; printf "\\nCWD=%s\\n" "$PWD"'
        result = subprocess.run(['bash', '-c', code, 'test', str(self.fw), str(self.caller)], input='0\n',
                                text=True, capture_output=True, env=self.env, cwd=self.caller, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CLAVES DE API', result.stdout)
        self.assertIn('CWD='+str(self.caller), result.stdout)
        self.assertNotIn('usage: api_keys.py', result.stdout+result.stderr)
        self.assert_untouched()


if __name__ == '__main__':
    unittest.main()
