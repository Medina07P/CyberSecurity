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


class ConfigChecksTests(ConfigFixture):
    def command(self, name, *args):
        script = self.config/name
        executable = 'python3' if script.suffix == '.py' else 'bash'
        return subprocess.run([executable, str(script), *map(str, args)], capture_output=True, text=True,
                              env=self.env, cwd=self.caller, input='', timeout=20)

    def test_valid_checks_exit_zero(self):
        for name in ('validate_config.sh', 'verify_00_config.sh'):
            with self.subTest(name=name):
                result = self.command('scripts/'+name)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assert_untouched()

    def test_validate_missing_file_exits_one(self):
        (self.config/'scope.yaml').unlink()
        result = self.command('scripts/validate_config.sh')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('scope.yaml NO encontrado', result.stdout)
        self.assertNotIn('TODO OK', result.stdout)

    def test_verify_missing_files_exits_one(self):
        (self.config/'scope.yaml').unlink()
        (self.config/'wordlists/custom.lst').unlink()
        result = self.command('scripts/verify_00_config.sh')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('FALTA: scope.yaml', result.stdout)
        self.assertIn('FALTA: wordlists/custom.lst', result.stdout)
        self.assertNotIn('✅ Verificación completada', result.stdout)

    def test_parser_missing_input_exits_one(self):
        result = self.command('scripts/parse_targets.py', '--input', self.root/'missing.txt')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Archivo no encontrado', result.stderr)
        self.assertNotIn('Traceback', result.stdout+result.stderr)

    def test_parser_bad_input_and_export_are_friendly_errors(self):
        bad = self.root/'bad.txt'; bad.write_bytes(b'\xff\xfe\xff')
        for args in (('--input', self.root), ('--input', bad), ('--json', self.root), ('--csv', self.root)):
            with self.subTest(args=args):
                result = self.command('scripts/parse_targets.py', *args)
                self.assertEqual(result.returncode, 1)
                self.assertIn('❌', result.stderr)
                self.assertNotIn('Traceback', result.stdout+result.stderr)

    def test_parser_preserves_export_contract_and_cwd(self):
        result = self.command('scripts/parse_targets.py', '--input', '../targets.txt', '--json', 'targets out.json', '--csv', 'targets out.csv', '--summary')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        data = json.loads((self.caller/'targets out.json').read_text())
        self.assertEqual(data, [{'ip':'192.0.2.10', 'port':'443', 'protocol':'HTTPS', 'description':'Fixture', 'priority':'M'}])
        self.assertIn('192.0.2.10,443,HTTPS,Fixture,M', (self.caller/'targets out.csv').read_text())
        self.assertIn('RESUMEN DE OBJETIVOS', result.stdout)
        self.assert_untouched()

    def test_run_all_from_other_cwd_is_read_only_and_explicit(self):
        result = self.command('run_all_config.sh')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(result.stdout.count('▶️  Ejecutando:'), 4)
        self.assertIn('scripts/api_keys.py estado', result.stdout)
        self.assertNotIn('usage: api_keys.py', result.stdout+result.stderr)
        self.assertNotIn('ASISTENTE DE OBJETIVOS', result.stdout)
        self.assertNotIn('Ejecutando: scripts/config_wizard', result.stdout)
        self.assertIn('✅ Configuración completada', result.stdout)
        self.assert_untouched()

    def test_run_all_reports_child_failure_and_visible_stderr(self):
        (self.config/'scripts/api_keys.py').write_text('import sys\nprint("fixture status error",file=sys.stderr)\nraise SystemExit(7)\n')
        result = self.command('run_all_config.sh')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('fixture status error', result.stderr)
        self.assertIn('7', result.stdout)
        self.assertNotIn('✅ Configuración completada', result.stdout)
        self.assertEqual(result.stdout.count('▶️  Ejecutando:'), 4)
        self.assert_untouched()

    def test_run_all_keeps_running_after_validation_failure(self):
        (self.config/'scope.yaml').unlink()
        result = self.command('run_all_config.sh')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('scripts/api_keys.py estado', result.stdout)
        self.assertIn('RESUMEN DE OBJETIVOS', result.stdout)
        self.assertNotIn('✅ Configuración completada', result.stdout)
        self.assertFalse(self.registry.exists())

    def test_run_all_from_menu_does_not_prompt_for_keys(self):
        result = self.menu('00\n1\ns\n\n0\nQ\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scripts/api_keys.py estado', result.stdout)
        self.assertIn('✅ Configuración completada', result.stdout)
        self.assertNotIn('usage: api_keys.py', result.stdout+result.stderr)
        self.assertNotIn('Elige una opción [0-5]', result.stdout)
        self.assert_untouched()


if __name__ == '__main__':
    unittest.main()
