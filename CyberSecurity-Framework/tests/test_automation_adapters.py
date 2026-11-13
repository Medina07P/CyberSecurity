"""Synthetic backend contracts: no checkout leaves, configuration or network run."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

from automation_fixture import AutomationFixture

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '00_Config/lib'))
from automation.catalog import _ACTIONS, get_action
from automation.model import Permissions, Plan, PlanError, PreflightError, RuntimeContext, Step
from automation.planner import build_plan
from automation.adapters import child_env, compile_step, execute_plan, preflight


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.f = AutomationFixture()
        self.addCleanup(self.f.close)
        for tool in {tool for action in _ACTIONS for tool in action.tools}:
            self.f.stub(tool)
        self.ctx = RuntimeContext(self.f.framework, self.f.repo, Path(sys.executable), str(self.f.bin))
        self.run = self.f.repo / 'private-run'
        self.run.mkdir(mode=0o700)
        self.req = self.f.repo / 'input.req'
        self.req.write_bytes(b'GET /?id=1 HTTP/1.1\r\nHost: example.test:8443\r\n\r\n')
        self.words = self.f.repo / 'words.txt'
        self.words.write_bytes(b'one\ntwo\nthree\nfour\n')

    def plan(self, action, **values):
        defaults = {'target': 'example.test', 'ports': '22,80', 'url': 'https://example.test/',
                    'domain': 'example.test', 'account': 'audit', 'wordlist': self.words,
                    'max_attempts': 2, 'max_seconds': 5, 'request_file': self.req,
                    'scheme': 'https', 'product': 'Apache 2.4', 'report_input': self.f.repo / 'synthetic'}
        defaults.update(values)
        return build_plan(action, {k: v for k, v in defaults.items() if k in get_action(action).input_types})

    def permissions(self, plan):
        grants = set()
        for step in plan.steps:
            gates = get_action(step.action).gates
            if step.action == 'sqlmap_request':
                gates = ('sqlmap_probe', 'sqlmap_replay')
                if 'database' in step.inputs:
                    gates += ('sqlmap_enum',)
                if 'table' in step.inputs:
                    gates += ('sqlmap_dump',)
            grants.update((step.id, gate) for gate in gates)
        return Permissions(frozenset({'example.test'}), frozenset(grants))

    def command(self, plan):
        return compile_step(plan.steps[0], self.run, self.ctx, self.permissions(plan))[0]

    def test_exact_argv_for_every_action(self):
        expected = {
            'ping': ('ping', '-c', '1', 'example.test'),
            'ports_full': ('nmap', '-sT', '-Pn', '-p-', '-T4', '-oX', str(self.run/'ports_full.xml'), 'example.test'),
            'services': ('nmap', '-Pn', '-sV', '-p', '22,80', '-oX', str(self.run/'services.xml'), 'example.test'),
            'nse_services': ('nmap', '-Pn', '-sV', '-sC', '-p', '22,80', '-oX', str(self.run/'nse_services.xml'), 'example.test'),
            'os_detect': ('nmap', '-Pn', '-O', '-oX', str(self.run/'os_detect.xml'), 'example.test'),
            'scan_vuln': ('nmap', '-Pn', '-sV', '--script', 'vuln', '-p', '22,80', '-oX', str(self.run/'scan_vuln.xml'), 'example.test'),
            'db_versions': ('nmap', '-Pn', '-sV', '-p', '3306,5432,6379', '-oX', str(self.run/'db_versions.xml'), 'example.test'),
            'smb_shares': ('smbclient', '-L', '//example.test', '-N'),
            'web_tech': ('whatweb', 'https://example.test/', '-a', '3'),
            'exploit_lookup': ('searchsploit', 'Apache 2.4'),
            'ssh_attempts': ('hydra', '-l', 'audit', '-P', str(self.run/'ssh_attempts.wordlist'), '-s', '22', '-t', '1', '-f', 'example.test', 'ssh'),
        }
        leaves = {
            'scan_basic': ('03_Scanners/network_scanners/nmap/nmap_smart.sh', 'example.test', 'basico'),
            'ssh_enum': ('04_Enumeration/ssh/enum_ssh.sh', 'example.test', '22'),
            'smb_audit': ('04_Enumeration/smb/enum_smb_advanced.sh', 'example.test'),
            'web_scan': ('03_Scanners/web_scanners/nikto/nikto_scan.sh', 'https://example.test/'),
            'config_check': ('00_Config/scripts/validate_config.sh',),
            'osint_domains': ('01_OSINT/scripts/osint_harvester.sh', 'example.test', str(self.run/'osint')),
            'sqlmap_request': ('05_Exploitation/web/sqlmap_request.sh', str(self.run/'sqlmap_request.req'), 'example.test'),
        }
        for action, parts in leaves.items():
            expected[action] = ('bash', str(self.f.framework / parts[0]), *parts[1:])
        for action, argv in expected.items():
            with self.subTest(action=action):
                plan = self.plan(action)
                preflight(plan, self.ctx, self.permissions(plan))
                command = self.command(plan)
                self.assertEqual(command.argv, (str(self.f.bin/argv[0]), *argv[1:]))
                self.assertEqual(command.cwd, self.f.framework)
                self.assertLessEqual(command.timeout, 900 if action == 'sqlmap_request' else 300)
                self.assertFalse(any('run_all' in arg or arg in ('sudo', '-c') and index == 1 and argv[0] == 'bash'
                                     for index, arg in enumerate(command.argv)))
        # Task5 does not exist yet. Only the report branch may import its API.
        module = types.ModuleType('automation.reporting')
        sentinel = object()
        module.report_command = lambda step, run_dir, ctx: sentinel
        with patch.dict(sys.modules, {'automation.reporting': module}):
            self.assertEqual(compile_step(self.plan('report').steps[0], self.run, self.ctx,
                                         self.permissions(self.plan('report'))), (sentinel,))
        self.assertEqual(set(expected) | {'report'}, {a.id for a in _ACTIONS})

    def test_permissions_are_step_and_target_bound(self):
        plan = self.plan('scan_basic')
        for permissions in (Permissions(frozenset({'other.test'}), self.permissions(plan).grants),
                            Permissions(frozenset({'example.test'}), frozenset({('other', 'scanner')}))):
            with self.assertRaises(PlanError):
                preflight(plan, self.ctx, permissions)
        sql = self.plan('sqlmap_request', database='app', table='users')
        for gate in ('sqlmap_probe', 'sqlmap_enum', 'sqlmap_dump'):
            allowed = self.permissions(sql)
            with self.assertRaises(PlanError):
                preflight(sql, self.ctx, Permissions(allowed.targets, allowed.grants - {(sql.steps[0].id, gate)}))

    def test_env_cannot_grant_permissions(self):
        poisoned = {'SQLMAP_TABLA': 'app.users', 'SQLMAP_ENUMERAR': '1', 'SQLMAP_SI': '1',
                    'BASH_ENV': '/bad', 'ENV': '/bad', 'PYTHONPATH': '/bad', 'PYTHONHOME': '/bad',
                    'LD_PRELOAD': '/bad', 'SESSION_SCOPE_FILE': '/bad', 'REPORT_INPUT': '/bad', 'ENUM_TARGET': '/bad'}
        with patch.dict(os.environ, poisoned):
            env = child_env(self.ctx, self.run)
            for key in poisoned:
                self.assertNotIn(key, env)
            plan = self.plan('sqlmap_request', table='app.users')
            with self.assertRaises(PlanError):
                preflight(plan, self.ctx, Permissions(frozenset({'example.test'}), frozenset()))
            probe = self.command(self.plan('sqlmap_request'))
            self.assertEqual(probe.env['SQLMAP_ENUMERAR'], '0')
            self.assertNotIn('SQLMAP_TABLA', probe.env)
            self.assertEqual(probe.env['SQLMAP_FILAS'], '50')
        self.assertEqual(Path(env['KEYS_FILE']).read_text(), '{}\n')
        self.assertEqual(list(Path(env['KEYS_HARVESTER_DIRS']).iterdir()), [])
        self.assertEqual(stat.S_IMODE(Path(env['HOME']).stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(Path(env['KEYS_FILE']).stat().st_mode), 0o600)

    def test_request_destination_matches(self):
        plan = self.plan('sqlmap_request')
        variants = [b'GET / HTTP/1.1\r\nHost: other.test\r\n\r\n',
                    b'GET https://example.test:443/ HTTP/1.1\r\nHost: example.test:8443\r\n\r\n',
                    b'GET http://example.test:8443/ HTTP/1.1\r\nHost: example.test:8443\r\n\r\n',
                    b'GET / HTTP/1.1\r\nHost: example.test\r\nHost: other.test\r\n\r\n']
        for request in variants:
            self.req.write_bytes(request)
            with self.assertRaises(PlanError):
                preflight(plan, self.ctx, self.permissions(plan))
        self.req.write_bytes(b'POST / HTTP/1.1\r\nHost: example.test:8443\r\n\r\na=1')
        allowed = self.permissions(plan)
        with self.assertRaises(PlanError):
            preflight(plan, self.ctx, Permissions(allowed.targets, allowed.grants - {('sqlmap_request', 'sqlmap_replay')}))
        preflight(plan, self.ctx, allowed)
        for context in ('esquema=http\n', 'host=other.test:8443\n', 'host=example.test:443\n', 'metodo=GET\n'):
            (self.req.parent/'contexto.txt').write_text(context)
            with self.assertRaises(PlanError):
                preflight(plan, self.ctx, allowed)

    def test_dictionary_bound(self):
        plan = self.plan('ssh_attempts')
        command = self.command(plan)
        copied = self.run/'ssh_attempts.wordlist'
        self.assertEqual(copied.read_bytes(), b'one\ntwo\n')
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)
        self.assertEqual(command.timeout, 5)
        self.assertEqual(self.words.read_bytes(), b'one\ntwo\nthree\nfour\n')
        self.words.unlink()
        self.words.symlink_to(self.req)
        with self.assertRaises(PreflightError):
            preflight(plan, self.ctx, self.permissions(plan))

    def test_backend_missing(self):
        plan = self.plan('scan_basic')
        (self.f.bin/'nmap').unlink()
        with self.assertRaises(PreflightError):
            preflight(plan, self.ctx, self.permissions(plan))
        self.f.stub('nmap')
        (self.f.framework/'03_Scanners/network_scanners/nmap/nmap_smart.sh').unlink()
        with self.assertRaises(PreflightError):
            preflight(plan, self.ctx, self.permissions(plan))

    def test_yaml_missing_preflight_fails_before_run_with_diagnostic(self):
        plan = self.plan('osint_domains')
        with patch('importlib.util.find_spec', return_value=None) as find_spec:
            with self.assertRaisesRegex(PreflightError, 'PyYAML.*yaml'):
                execute_plan(plan, self.ctx, self.permissions(plan))
            find_spec.assert_called_once_with('yaml')
        self.assertEqual(self.f.records(), [])
        self.assertFalse((self.f.repo/'scans').exists())
        with patch('importlib.util.find_spec', side_effect=AssertionError('builtin must not probe yaml')):
            builtin = self.plan('ping')
            preflight(builtin, self.ctx, self.permissions(builtin))

    def test_preflight_all_steps_before_creating_run(self):
        good = self.plan('ping').steps[0]
        bad = self.plan('scan_basic').steps[0]
        plan = Plan('all', (good, bad), 10)
        with self.assertRaises(PlanError):
            execute_plan(plan, self.ctx, Permissions(frozenset({'example.test'}), frozenset()))
        self.assertFalse((self.f.repo/'scans').exists())
        self.assertEqual(self.f.records(), [])

    def test_revalidate_forged_plan_and_nikto_comma(self):
        for step in (Step('web', 'web_tech', {'target': 'example.test', 'url': 'https://other.test'}, ()),
                     Step('ssh', 'ssh_attempts', {'target': 'example.test', 'account': 'bad account'}, ()),
                     Step('web', 'web_scan', {'target': 'example.test', 'url': 'https://example.test/a,b'}, ())):
            plan = Plan('forged', (step,), 10)
            with self.assertRaises(PlanError):
                preflight(plan, self.ctx, self.permissions(plan))

    def test_regular_inputs_no_symlink_ancestors_or_directory(self):
        alias = self.f.repo/'alias'
        alias.symlink_to(self.f.repo, target_is_directory=True)
        for path in (alias/'input.req', self.f.repo):
            plan = self.plan('sqlmap_request', request_file=path)
            with self.assertRaises(PreflightError):
                preflight(plan, self.ctx, self.permissions(plan))

    def test_compile_rechecks_request_and_private_snapshot(self):
        plan = self.plan('sqlmap_request')
        preflight(plan, self.ctx, self.permissions(plan))
        original = self.req.read_bytes()
        cmd = self.command(plan)
        self.assertEqual(Path(cmd.argv[2]).read_bytes(), original)
        self.assertEqual(stat.S_IMODE(Path(cmd.argv[2]).stat().st_mode), 0o600)
        self.req.write_bytes(b'GET / HTTP/1.1\r\nHost: other.test\r\n\r\n')
        with self.assertRaises(PlanError):
            self.command(plan)

    def test_dangerous_mapping_and_dependency_contract(self):
        dangerous = set((self.f.framework/'00_Config/lib/dangerous.txt').read_text().splitlines())
        for action, leaf, gate in (
                ('scan_basic', '03_Scanners/network_scanners/nmap/nmap_smart.sh', 'scanner'),
                ('ssh_enum', '04_Enumeration/ssh/enum_ssh.sh', 'users'),
                ('smb_audit', '04_Enumeration/smb/enum_smb_advanced.sh', 'smb_users'),
                ('sqlmap_request', '05_Exploitation/web/sqlmap_request.sh', 'sqlmap_probe')):
            self.assertIn(leaf, dangerous)
            self.assertIn(gate, get_action(action).gates)
        for action in _ACTIONS:
            for tool in action.tools:
                with self.subTest(action=action.id, tool=tool):
                    executable = self.f.bin/tool
                    executable.rename(self.f.bin/(tool+'.absent'))
                    try:
                        plan = self.plan(action.id)
                        with self.assertRaises(PreflightError):
                            preflight(plan, self.ctx, self.permissions(plan))
                    finally:
                        (self.f.bin/(tool+'.absent')).rename(executable)

    def test_stub_records_env_cwd_and_no_inherited_credentials(self):
        executable = self.f.bin/'ping'
        executable.write_text('#!' + sys.executable + '\nimport os,json,sys\n'
                              'print(json.dumps([sys.argv,dict(os.environ),os.getcwd()]))\n')
        command = self.command(self.plan('ping'))
        result = subprocess.run(command.argv, cwd=command.cwd, env=dict(command.env),
                                shell=False, capture_output=True, text=True, check=True)
        argv, env, cwd = json.loads(result.stdout)
        self.assertEqual(argv[1:], ['-c', '1', 'example.test'])
        self.assertEqual(cwd, str(self.ctx.framework))
        self.assertEqual(env['PATH'], self.ctx.path)
        self.assertEqual(env['HOME'], str(self.run/'home'))

    def test_private_run_and_empty_key_directory_enforced(self):
        self.run.chmod(0o755)
        with self.assertRaises(PreflightError):
            child_env(self.ctx, self.run)
        self.run.chmod(0o700)
        child_env(self.ctx, self.run)
        (self.run/'empty-keys/api-keys.yaml').write_text('not-empty')
        with self.assertRaises(PreflightError):
            child_env(self.ctx, self.run)

    def test_fixed_source_dependencies_required_before_run(self):
        for action, source in (
                ('scan_basic', '00_Config/lib/scanner_runtime.bash'),
                ('ssh_enum', '00_Config/lib/enumeration_evidence.py'),
                ('sqlmap_request', '00_Config/lib/http_request.bash'),
                ('osint_domains', '00_Config/lib/osint/credentials.py'),
                ('report', '11_Reports/report_engine.py')):
            path = self.f.framework/source
            path.rename(path.with_suffix('.absent'))
            try:
                plan = self.plan(action)
                with self.assertRaises(PreflightError):
                    preflight(plan, self.ctx, self.permissions(plan))
            finally:
                path.with_suffix('.absent').rename(path)

    def test_execute_wrapper_with_real_synthetic_child(self):
        plan = self.plan('ping')
        result = execute_plan(plan, self.ctx, self.permissions(plan))
        self.assertEqual(result.rc, 0)
        self.assertEqual(self.f.records(), [[str(self.f.bin/'ping'), '-c', '1', 'example.test']])
        state = json.loads((result.run_dir/'run.json').read_text())
        self.assertEqual(state['steps'][0]['state'], 'completado')
        self.assertEqual(stat.S_IMODE((result.run_dir/'logs/ping.stdout.log').stat().st_mode), 0o600)

    def test_explicit_enum_gate_without_database_preserves_dbs_capability(self):
        plan = self.plan('sqlmap_request')
        allowed = self.permissions(plan)
        allowed = Permissions(allowed.targets, allowed.grants | {('sqlmap_request', 'sqlmap_enum')})
        command = compile_step(plan.steps[0], self.run, self.ctx, allowed)[0]
        self.assertEqual(command.env['SQLMAP_ENUMERAR'], '1')
        self.assertNotIn('SQLMAP_DB', command.env)
        self.assertNotIn('SQLMAP_TABLA', command.env)

    def test_dump_typed_table_and_independent_enum_permission(self):
        plan = self.plan('sqlmap_request', table='app.users')
        command = self.command(plan)
        self.assertEqual(command.env['SQLMAP_TABLA'], 'app.users')
        self.assertEqual(command.env['SQLMAP_ENUMERAR'], '0')
        self.assertEqual(command.env['SQLMAP_FILAS'], '50')
        self.assertEqual(command.env['SQLMAP_ESQUEMA'], 'https')
        self.assertEqual(command.env['SQLMAP_MAX_SEG'], '900')

    def test_optional_tools_are_not_required_dependencies(self):
        for action, tools in (('smb_audit', {'enum4linux'}),
                              ('osint_domains', {'whois', 'whatweb', 'dig'})):
            self.assertTrue(tools.isdisjoint(get_action(action).tools))
            plan = self.plan(action)
            preflight(plan, self.ctx, self.permissions(plan))
        self.assertEqual(self.f.records(), [])

    def test_compile_rejects_preexisting_snapshot_symlink(self):
        plan = self.plan('sqlmap_request')
        destination = self.run/'sqlmap_request.req'
        destination.symlink_to(self.req)
        before = self.req.read_bytes()
        with self.assertRaises(PreflightError):
            self.command(plan)
        self.assertEqual(self.req.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
