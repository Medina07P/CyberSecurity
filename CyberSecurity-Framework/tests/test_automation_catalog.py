"""Task1 contracts: pure validation, immutable models and inert PATH probes."""
import atexit
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from automation_fixture import AutomationFixture

SOURCES = AutomationFixture()
atexit.register(SOURCES.close)
sys.path.insert(0, str(SOURCES.framework / '00_Config/lib'))
from automation.model import (ActionSpec, Command, Permissions, Plan, PlanError,
                              PreflightError, RunResult, RuntimeContext, Step, StepResult)
from automation.validation import validate
from automation.catalog import availability, get_action


GATES = {
    'ping': (), 'scan_basic': ('scanner',), 'ports_full': ('full_ports',),
    'services': (), 'nse_services': ('nse',), 'os_detect': ('os',),
    'scan_vuln': ('nse_vuln',), 'ssh_enum': ('users',),
    'smb_shares': ('anonymous_access',), 'db_versions': (), 'web_tech': (),
    'web_scan': ('web_scan',), 'smb_audit': ('smb_users',),
    'osint_domains': ('osint',), 'config_check': ('config_read',),
    'ssh_attempts': ('credential_attempts',),
    'sqlmap_request': ('sqlmap_probe', 'sqlmap_replay', 'sqlmap_enum', 'sqlmap_dump'),
    'exploit_lookup': (), 'report': ('report_read',),
}


class CatalogTests(unittest.TestCase):
    def test_typed_inputs(self):
        for raw, expected in [('EXAMPLE.COM.', 'example.com'), ('192.0.2.1', '192.0.2.1')]:
            self.assertEqual(validate('target', raw), expected)
        for raw in ['999.1.2.3', '192.168.1.999', '1.2.3', '::1', '192.0.2.1/24', '-oX', '', 'a..test', 'a_test', ' x.test', True]:
            with self.subTest(raw=raw), self.assertRaises(PlanError):
                validate('target', raw)
        self.assertEqual(validate('domain', 'EXAMPLE.COM.'), 'example.com')
        with self.assertRaises(PlanError):
            validate('domain', '192.0.2.1')

    def test_ports(self):
        for raw in [1, 65535, '22']:
            self.assertEqual(validate('port', raw), int(raw))
        for raw in [0, 65536, True, False, 1.0, '-1', ' 22', '1e2']:
            with self.subTest(raw=raw), self.assertRaises(PlanError):
                validate('port', raw)
        self.assertEqual(validate('ports', '80,443,1000-1002'), (80, 443, 1000, 1001, 1002))
        self.assertEqual(len(validate('ports', '1-65535')), 65535)
        for raw in ['80,80', '1-3,3', '0', '65536', '3-1', '80,', True]:
            with self.subTest(raw=raw), self.assertRaises(PlanError):
                validate('ports', raw)

    def test_urls(self):
        self.assertEqual(validate('url', 'HTTPS://EXAMPLE.COM.:443/a?q=x'), 'https://example.com:443/a?q=x')
        for raw in ['ftp://example.test', 'http://a:b@example.test', 'http://@example.test',
                    'http://example.test/#', 'http://example.test/#x', 'http://example.test/\n',
                    'http://example.test:0', 'http://example.test:65536', 'http://[::1]',
                    'http://example.test\\@evil.test', 'http://example.test/a b', 'http://example.test/%0a']:
            with self.subTest(raw=raw), self.assertRaises(PlanError):
                validate('url', raw)

    def test_product_and_paths(self):
        self.assertEqual(validate('product', 'Apache HTTP Server 2.4'), 'Apache HTTP Server 2.4')
        for raw in ['-oX', 'x;id', '$(id)', 'x|id', '`id`', 'x\ny', 'x&y', 'x>y']:
            with self.subTest(raw=raw), self.assertRaises(PlanError):
                validate('product', raw)
        self.assertEqual(validate('path', '/not read/a file.req'), Path('/not read/a file.req'))
        with self.assertRaises(PlanError):
            validate('path', 'x\x00y')
        with self.assertRaises(PlanError):
            validate('unknown', 'x')

    def test_sensitive_scalar_limits(self):
        for kind, good, bad in [('account', 'user.name@example', '-root'),
                                ('max_attempts', 200, 201), ('max_seconds', 300, 301),
                                ('timeout', 86400, 86401), ('scheme', 'https', 'ftp'),
                                ('database', 'db_1', '-db'), ('table', 'db.table', 'db;table')]:
            self.assertEqual(validate(kind, good), good)
            with self.subTest(kind=kind), self.assertRaises(PlanError):
                validate(kind, bad)
        for kind in ['max_attempts', 'max_seconds', 'timeout']:
            with self.assertRaises(PlanError):
                validate(kind, True)

    def test_catalog_preserves_capabilities(self):
        for action, gates in GATES.items():
            spec = get_action(action)
            self.assertIsInstance(spec, ActionSpec)
            self.assertEqual(spec.id, action)
            self.assertEqual(spec.gates, gates)
            self.assertTrue(spec.effects)
            self.assertTrue(spec.limitations)
            self.assertTrue(set(spec.required) <= set(spec.input_types))
        for action in ['post', 'cleanup', 'persistence', 'not_an_action']:
            with self.assertRaises(PlanError):
                get_action(action)
        self.assertEqual(get_action('ssh_enum').gates, ('users',))
        self.assertEqual(get_action('services').required, ('target', 'ports'))
        self.assertEqual(get_action('report').required, ('target', 'report_input'))
        self.assertEqual(set(get_action('ssh_attempts').input_types),
                         {'target', 'port', 'account', 'wordlist', 'max_attempts', 'max_seconds'})
        for action in ['web_scan', 'web_tech']:
            self.assertEqual(get_action(action).required, ('target', 'url'))

    def test_defensive_immutability(self):
        schema = {'target': 'target'}
        required = ['target']
        spec = ActionSpec('test', schema, required, [], ['ping'], True, 'effect', 'limit')
        schema.clear(); required.clear()
        self.assertEqual(dict(spec.input_types), {'target': 'target'})
        self.assertEqual(spec.required, ('target',))
        data = {'nested': [{'x': [1]}]}
        step = Step('s', 'ping', data, [])
        data['nested'][0]['x'].append(2)
        self.assertEqual(step.inputs['nested'][0]['x'], (1,))
        with self.assertRaises(TypeError):
            step.inputs['nested'][0]['x'] = ()
        with self.assertRaises(FrozenInstanceError):
            step.id = 'other'
        env = {'A': 'B'}
        cmd = Command(['x'], Path('/synthetic'), env, 300)
        env['A'] = 'changed'
        self.assertEqual(cmd.env['A'], 'B')
        self.assertEqual(cmd.argv, ('x',))
        with self.assertRaises(TypeError):
            get_action('ping').input_types['target'] = 'url'
        targets, grants = {'example.test'}, {('s', 'users')}
        perms = Permissions(targets, grants)
        targets.clear(); grants.clear()
        self.assertEqual(perms.targets, frozenset({'example.test'}))
        self.assertEqual(perms.grants, frozenset({('s', 'users')}))
        steps = [step]
        plan = Plan('test', steps, 600)
        steps.clear()
        self.assertEqual(plan.steps, (step,))
        result = StepResult('s', 'OMITIDO', None, 'synthetic')
        self.assertEqual(RunResult(1, None, [result]).steps, (result,))
        self.assertIsInstance(PreflightError(), RuntimeError)

    def test_availability_does_not_execute(self):
        with AutomationFixtureContext() as fixture:
            tools = set(tool for action in GATES for tool in get_action(action).tools)
            for tool in tools:
                fixture.stub(tool)
            ctx = RuntimeContext(fixture.framework, fixture.repo, Path(sys.executable), str(fixture.bin))
            with patch('subprocess.Popen', side_effect=AssertionError('process forbidden')):
                found = availability(ctx)
            self.assertEqual(set(found), set(GATES))
            self.assertTrue(all(found.values()))
            self.assertEqual(fixture.records(), [])
            self.assertFalse((fixture.repo / 'scans').exists())
            (fixture.bin / 'nmap').unlink()
            self.assertFalse(availability(ctx)['scan_basic'])
            self.assertTrue(availability(ctx)['ping'])
            empty = RuntimeContext(ctx.framework, ctx.repo, ctx.python, '')
            self.assertFalse(any(availability(empty).values()))

    def test_leaf_dependencies(self):
        self.assertTrue({'bash', 'python3', 'nmap', 'timeout'} <= set(get_action('ssh_enum').tools))
        self.assertTrue({'bash', 'python3', 'nmap', 'timeout', 'rpcclient', 'smbclient'} <= set(get_action('smb_audit').tools))
        self.assertNotIn('enum4linux', get_action('smb_audit').tools)
        self.assertTrue({'sqlmap', 'timeout', 'mktemp', 'sed', 'awk', 'od'} <= set(get_action('sqlmap_request').tools))

    def test_osint_requires_discoverable_yaml_only(self):
        with AutomationFixtureContext() as fixture:
            for tool in {tool for action in GATES for tool in get_action(action).tools}:
                fixture.stub(tool)
            ctx = RuntimeContext(fixture.framework, fixture.repo, Path(sys.executable), str(fixture.bin))
            with patch('importlib.util.find_spec', return_value=None) as find_spec, \
                    patch('subprocess.Popen', side_effect=AssertionError('process forbidden')):
                found = availability(ctx)
                self.assertFalse(found['osint_domains'])
                self.assertTrue(all(found[action] for action in GATES if action != 'osint_domains'))
                find_spec.assert_called_once_with('yaml')
            with patch('importlib.util.find_spec', return_value=object()) as find_spec:
                self.assertTrue(availability(ctx)['osint_domains'])
                find_spec.assert_called_once_with('yaml')
            self.assertEqual(fixture.records(), [])
            self.assertFalse((fixture.repo / 'scans').exists())

    def test_no_data_reads_or_environment_authority(self):
        with patch('builtins.open', side_effect=AssertionError('data read forbidden')), \
                patch.object(Path, 'open', side_effect=AssertionError('data read forbidden')), \
                patch.dict('os.environ', {'SQLMAP_SI': '1', 'SQLMAP_ENUMERAR': '1',
                                          'SQLMAP_TABLA': 'db.table', 'BASH_ENV': '/untrusted',
                                          'PYTHONPATH': '/untrusted', 'PATH': '/untrusted'}):
            self.assertEqual(validate('path', '/unreadable/a file.req'), Path('/unreadable/a file.req'))
            self.assertEqual(validate('target', 'EXAMPLE.TEST.'), 'example.test')
            self.assertEqual(get_action('sqlmap_request').gates, GATES['sqlmap_request'])
            self.assertFalse(any(availability(RuntimeContext(SOURCES.framework, SOURCES.repo,
                                                            Path(sys.executable), '')).values()))

    def test_product_rejects_comment_metacharacter(self):
        with self.assertRaises(PlanError):
            validate('product', 'Apache #comment')


class AutomationFixtureContext(AutomationFixture):
    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


if __name__ == '__main__':
    unittest.main()
