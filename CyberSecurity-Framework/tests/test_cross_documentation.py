"""Eleven closed documentation/source contracts, never operational audits."""
import ast
from contextlib import redirect_stdout
import hashlib
from io import StringIO
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest import mock

from test_cross_closure import product, scratch

SOURCE = Path('/source/CyberSecurity-Framework')
MENU = Path('/source/docs/MENU-OPCIONES.md')


def text(relative):
    return (SOURCE / relative).read_text()


class DocumentationTests(unittest.TestCase):
    def documented(self, phrase):
        self.assertIn(phrase, MENU.read_text())

    def test_dns_resolution_and_dictionary_gate(self):
        product()
        from osint import dns
        from types import SimpleNamespace
        run = SimpleNamespace(cache={}, limits=SimpleNamespace(dns_qps=1, tool_seconds=1, dns_candidates=10))
        observed = []

        def resolve(name, *args):
            observed.append(name)
            return dns.DnsAnswer(name, 'resolved', {'A': ['192.0.2.1']})

        with mock.patch.object(dns, 'collect', side_effect=lambda run, source, callback: callback()), \
                mock.patch.object(dns, 'resolve_name', side_effect=resolve), \
                mock.patch.object(dns, 'DnsLimiter') as limiter:
            limiter.return_value.remaining.return_value = 10
            dns.resolve_discovered(run, 'example.test', ['www.example.test'])
            with self.assertRaisesRegex(ValueError, 'DNS_SI'):
                dns.enumerate_dns(run, 'example.test', '/never/read', confirmed=False)
        self.assertEqual(len(observed), 4)
        self.assertTrue(all(name.endswith('.example.test') for name in observed))
        self.assertEqual(observed[-1], 'www.example.test')
        self.documented('DNS normal y controles wildcard sin diccionario; DNS_SI solo para diccionario')

    def test_ftp_login_vs_listing(self):
        root = scratch()
        driver = '''source "$1/00_Config/lib/enumeration_services.bash" || exit
enum_init() { :; }
enum_step() { if [[ "$3" == ftp ]]; then cat; fi; }
enum_nse() { :; }
enum_finish() { :; }
enum_service "$2" example.test
'''
        env = {'PATH': '/usr/bin', 'HOME': str(root), 'LC_ALL': 'C'}
        for service, count in (('ftp_anon', 3), ('ftp', 1)):
            result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', driver,
                                     'ftp-contract', str(SOURCE), service], env=env,
                                    cwd=root, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.count('quote USER anonymous'), count)
            self.assertEqual(result.stdout.count('quote PASS anonymous@'), count)
            self.assertEqual(result.stdout.count('ls -la'), 0 if service == 'ftp_anon' else 1)
        self.documented('ftp_anonymous prueba login; enum_ftp añade listado')

    def test_actual_exploitation_children(self):
        attacks = re.findall(r'run_one "\./([^"\n]+)"', text('05_Exploitation/run_all_attacks.sh'))
        exploits = re.findall(r'run_one "\./([^"\n]+)"', text('05_Exploitation/run_all_exploits.sh'))
        self.assertEqual(attacks, ['network/ssh_attack.sh', 'web/web_attack.sh',
                                  'database/postgres_attack.sh', 'database/mysql_attack.sh', 'database/redis_attack.sh'])
        self.assertEqual(exploits, ['network/ssh_bruteforce.sh', 'exploits/cve_2024_6387.sh',
                                   'web/sql_injection.sh', 'web/xss.sh'])
        self.documented('run_all_attacks selecciona SSH/web/Postgres/MySQL/Redis; no AD')
        self.documented('run_all_exploits selecciona cuatro hojas; no descubre exploits/')

    def test_templates_and_ssh_have_real_effects(self):
        source = ast.parse(text('05_Exploitation/custom_exploits/template.py'))
        calls = [n for n in ast.walk(source) if isinstance(n, ast.Call)]
        self.assertTrue(any(isinstance(n.func, ast.Attribute) and n.func.attr == 'connect' for n in calls))
        self.assertIn('nc', text('05_Exploitation/custom_exploits/template.sh'))
        ssh = text('05_Exploitation/network/ssh_attack.sh')
        self.assertIn('ssh-enum-users', ssh)
        self.assertIn('hydra', ssh)
        self.assertIn('-L', ssh)
        self.assertIn('-P', ssh)
        self.documented('Plantillas: conexiones TCP80/nc22; SSH: NSE e Hydra con dos listas, sin topes de 09')

    def test_forensic_metadata_vs_private_hash_reads(self):
        root = scratch()
        private = root / 'private-copy'
        body = b'synthetic-private-body-not-for-stdout'
        private.write_bytes(body)
        spec = importlib.util.spec_from_file_location('closure_forensic', SOURCE / '00_Config/lib/forensics_evidence.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        original = module._open_read
        observed = []

        def read(path):
            self.assertEqual(Path(path), private, 'original must never be opened')
            observed.append(Path(path))
            return original(path)

        with mock.patch.object(module, '_open_read', side_effect=read), redirect_stdout(StringIO()) as output:
            digest, size = module._digest_file(private)
        self.assertEqual((digest, size), (hashlib.sha256(body).hexdigest(), len(body)))
        self.assertEqual(observed, [private])
        self.assertEqual(output.getvalue(), '')
        self.documented('Visor forense: stdout de metadatos, lectura privada para hashes; no reabre originales')

    def test_scope_backup_vs_targets_append(self):
        session = text('00_Config/lib/session.bash')
        start = session.index('targets_add_entry()')
        targets = session[start:]
        self.assertIn('>>', targets)
        self.assertNotIn('targets.txt.bak', targets)
        self.assertIn('.bak', session[:start])
        self.documented('scope.yaml tiene .bak; targets.txt se añade por append sin backup')

    def test_forensic_menu_vs_cli_filters(self):
        menu = text('00_Config/lib/forensics_menu.bash')
        self.assertRegex(menu, r'execute_script[^\n]*show_results.sh[^\n]*--prepared')
        self.assertIn('--operation', text('08_Forensics/show_results.sh'))
        self.documented('08.10 no pide filtros; los filtros pertenecen a la CLI del visor')

    def test_99_warning_matches_omissions(self):
        coordinator = text('06_PostExploitation/run_all_post.sh')
        children = re.findall(r'run_child\s+([^\s";]+)', coordinator)
        self.assertFalse(any(value.startswith(('persistence/', 'lateral_movement/', 'cleanup/'))
                             for value in children))
        manager = text('cyber_framework.sh')
        self.assertNotIn('Incluye fuerza bruta, persistencia y limpieza', manager)
        self.documented('99 conserva peligro; 06 omite persistencia/lateral/cleanup y no garantiza cobertura completa')

    def test_wizard_defaults_and_resolved_components(self):
        wizard = text('00_Config/scripts/config_wizard.sh')
        self.assertIn('desc="${desc:-$proto}"', wizard)
        function = re.search(r'(?ms)^wz_default_protocol\(\) \{\n.*?^\}', wizard)
        self.assertIsNotNone(function)
        root = scratch()
        for port, protocol in (('22', 'SSH'), ('80', 'HTTP'), ('12345', '')):
            result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c',
                                     function.group() + '\nwz_default_protocol "$1"',
                                     'wizard-protocol', port], env={'PATH': '/usr/bin', 'HOME': str(root)},
                                    cwd=root, capture_output=True, text=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout.strip()), (0, protocol))
        evidence = ast.parse(text('00_Config/lib/evidence/cli.py'))
        self.assertTrue(any(isinstance(n, ast.Constant) and n.value == '--add' for n in ast.walk(evidence)))
        reports = text('11_Reports/run_all_reports.sh')
        self.assertIn('[[ $# -ne 1 || -z "$1" ]]', reports)
        self.documented('Wizard: descripción opcional y protocolo por defecto; 10 --add admite descripción opcional; 11 exige objetivo')

    def test_key_cli_signatures(self):
        tree = ast.parse(text('00_Config/scripts/api_keys.py'))
        parsers = {}
        arguments = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == 'add_parser' and call.args:
                    if isinstance(call.args[0], ast.Constant):
                        for target in node.targets:
                            if isinstance(target, ast.Name): parsers[target.id] = call.args[0].value
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument':
                if isinstance(node.func.value, ast.Name) and node.args and isinstance(node.args[0], ast.Constant):
                    arguments.setdefault(node.func.value.id, []).append(node.args[0].value)
        status = [arguments.get(var, []) for var, name in parsers.items() if name == 'estado']
        request = [arguments.get(var, []) for var, name in parsers.items() if name == 'pedir']
        self.assertEqual(len(status), 1)
        self.assertEqual(set(status[0]), {'--json', '--faltan'})
        self.assertEqual(len(request), 1)
        self.assertIn('--campo', request[0])
        self.assertEqual(len([arg for arg in request[0] if not arg.startswith('-')]), 1)
        self.documented('Claves: estado [--json|--faltan H]; pedir H [--campo C]')

    def test_sqlmap_gates_by_channel(self):
        cli, model = product()
        from automation.planner import build_plan
        plan = build_plan('sqlmap_request', {'target': 'example.test', 'request_file': '/unread/a.req',
                                           'scheme': 'https', 'table': 'base.tabla'})
        self.assertEqual(cli.gates(plan.steps[0]), ('sqlmap_probe', 'sqlmap_replay', 'sqlmap_dump'))
        adapters = ast.parse(text('00_Config/lib/automation/adapters.py'))
        self.assertTrue(any(isinstance(n, ast.Constant) and n.value == 'sqlmap_replay' for n in ast.walk(adapters)))
        source = text('00_Config/lib/automation/adapters.py')
        self.assertIn("('GET', 'HEAD')", source)
        self.documented('SQLmap CLI: replay solo no-GET/HEAD; enum con database y dump con table independientes; menú conservador')
