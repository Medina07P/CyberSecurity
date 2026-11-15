"""Task2: effect-free plans and bounded, closed-schema workflows."""
import atexit
import builtins
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from automation_fixture import AutomationFixture, preserve

SOURCES = AutomationFixture()
atexit.register(SOURCES.close)
sys.path.insert(0, str(SOURCES.framework / '00_Config/lib'))
from automation.model import Plan, PlanError, RuntimeContext, Step
from automation.planner import build_plan, render_plan, validate_plan
from automation.workflows import load_workflow


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.fixture = AutomationFixture()
        self.addCleanup(self.fixture.close)
        self.path = self.fixture.repo / 'workflow.yaml'
        self.ctx = RuntimeContext(self.fixture.framework, self.fixture.repo,
                                  Path(sys.executable), str(self.fixture.bin))

    def workflow(self, text, defaults=None):
        preserve(self.path)
        self.path.write_text(text, encoding='utf-8')
        return load_workflow(self.path, defaults or {'target': '192.0.2.1'})

    def test_profiles_exact_actions(self):
        for selector, actions, timeout in [
                ('quick', ('ping', 'scan_basic'), 600),
                ('full', ('ping', 'scan_basic', 'db_versions'), 3600),
                ('recon', ('ping', 'scan_basic'), 600),
                ('scan', ('scan_basic',), 600),
                ('enum', ('ssh_enum', 'smb_shares', 'db_versions'), 600),
                ('web', ('web_tech', 'web_scan'), 600)]:
            inputs = {'target': '192.0.2.1'}
            if selector == 'web':
                inputs['url'] = 'https://192.0.2.1/'
            plan = build_plan(selector, inputs)
            self.assertEqual(tuple(s.action for s in plan.steps), actions)
            self.assertEqual(plan.timeout, timeout)
        self.assertEqual(build_plan('quick', inputs).steps[1].depends_on, ('ping',))
        full = build_plan('full', {'target': '192.0.2.1', 'domain': 'example.test',
                                  'url': 'https://192.0.2.1', 'include_config': True,
                                  'report_input': '/unread/scans'})
        self.assertEqual(tuple(s.action for s in full.steps),
                         ('config_check', 'osint_domains', 'ping', 'scan_basic',
                          'db_versions', 'web_tech', 'report'))
        self.assertEqual(build_plan('enum', {'target': '192.0.2.1'}).steps[0].inputs['port'], 22)
        self.assertEqual(build_plan('post', {}).steps, ())
        for selector in ('exploit', 'unknown'):
            with self.assertRaises(PlanError):
                build_plan(selector, {})

    def test_strict_yaml(self):
        base = 'name: test\nversion: 1\ntimeout: 600\nsteps:\n  - id: ping\n    action: ping\n'
        invalid = [base + 'parallel: false\n', base + 'extra: 1\n',
                   base.replace('action: ping', 'action: ping\n    script: x'),
                   base.replace('600', 'true'), base.replace('version: 1', 'version: true'),
                   base.replace('version: 1', 'version: 1.0'),
                   base + 'name: duplicate\n', base.replace('name: test', 'name: !!str test'),
                   base.replace('name: test', 'name: &a test') + 'other: *a\n',
                   base.replace('action: ping', 'action: ping\n    inputs: {target: a, target: b}'),
                   base.replace('action: ping', 'action: ping\n    inputs: {env: x}'),
                   base.replace('action: ping', 'action: ping\n    depends_on: [ping]'),
                   base.replace('action: ping', 'action: ping\n    depends_on: [missing]'),
                   base + '  - id: ping\n    action: ping\n',
                   base.replace('name: test', 'name: ' + '[' * 13 + 'x' + ']' * 13),
                   'x' * 65537,
                   'name: test\nversion: 1\ntimeout: 600\nsteps:\n' + ''.join(
                       f'  - id: p{i}\n    action: ping\n' for i in range(65)),
                   base.replace('inputs:', 'inputs:') + 'permissions: [all]\n']
        for text in invalid:
            with self.subTest(text=text[:100]), self.assertRaises(PlanError):
                self.workflow(text)
        self.assertEqual(self.workflow(base).steps[0].inputs['target'], '192.0.2.1')

    def test_literal_nul_is_plan_error(self):
        text = 'name: t\x00\nversion: 1\ntimeout: 600\nsteps: [{id: a, action: ping}]\n'
        with self.assertRaisesRegex(PlanError, 'YAML inválido'):
            self.workflow(text)

    def test_stable_topology_and_defaults(self):
        plan = self.workflow('''name: test
version: 1
timeout: 600
steps:
  - {id: c, action: ping, depends_on: [a]}
  - {id: b, action: ping, inputs: {target: example.test}}
  - {id: a, action: ping}
''')
        self.assertEqual(tuple(s.id for s in plan.steps), ('b', 'a', 'c'))
        self.assertEqual(plan.steps[0].inputs['target'], 'example.test')
        with self.assertRaisesRegex(PlanError, 'Texto vacío o con controles'):
            self.workflow('name: t\nversion: 1\ntimeout: 600\nsteps: [{id: a, action: ping, inputs: {target: null}}]',
                          {'target': 'example.test'})

    def test_paths_relative_to_yaml(self):
        req = self.fixture.repo / 'dir con espacios/a.req'
        req.parent.mkdir()
        req.write_text('DO NOT READ')
        link = req.parent / 'link.req'
        link.symlink_to(req)
        text = '''name: test
version: 1
timeout: 600
steps:
  - id: sql
    action: sqlmap_request
    inputs: {request_file: "dir con espacios/a.req", scheme: https}
'''
        plan = self.workflow(text)
        self.assertEqual(plan.steps[0].inputs['request_file'], req)
        plan = self.workflow(text.replace('a.req', 'link.req'))
        self.assertEqual(plan.steps[0].inputs['request_file'], link)
        self.assertIn('enlace inválido', render_plan(plan, self.ctx))
        self.assertIn('sqlmap_probe', render_plan(plan, self.ctx))

    def test_plan_has_no_data_reads(self):
        before = set(self.fixture.repo.rglob('*'))
        with patch('builtins.open', side_effect=AssertionError('no content reads')), \
                patch.object(Path, 'open', side_effect=AssertionError('no content reads')), \
                patch.object(Path, 'resolve', side_effect=AssertionError('no resolve')), \
                patch('subprocess.Popen', side_effect=AssertionError('no processes')):
            for selector, inputs in [
                    ('full', {'target': '192.0.2.1', 'include_config': True, 'report_input': '/unread/scans'}),
                    ('sqlmap_request', {'target': '192.0.2.1', 'scheme': 'https', 'request_file': '/unread/a.req'}),
                    ('ssh_attempts', {'target': '192.0.2.1', 'account': 'test', 'wordlist': '/unread/words',
                                      'max_attempts': 2, 'max_seconds': 1})]:
                rendered = render_plan(build_plan(selector, inputs), self.ctx)
                self.assertIn('preflight', rendered)
        self.assertEqual(before, set(self.fixture.repo.rglob('*')))
        self.assertEqual(self.fixture.records(), [])

    def test_only_yaml_content_is_read(self):
        self.path.write_text('name: t\nversion: 1\ntimeout: 600\nsteps: [{id: r, action: report}]\n')
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertEqual(path, self.path)
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            plan = load_workflow(self.path, {'target': '192.0.2.1', 'report_input': '/unread/scans'})
        self.assertEqual(plan.steps[0].inputs['report_input'], Path('/unread/scans'))

    def test_without_pyyaml(self):
        original = builtins.__import__
        def blocked(name, *args, **kwargs):
            if name == 'yaml':
                raise ImportError('synthetic')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=blocked):
            self.assertEqual(len(build_plan('quick', {'target': '192.0.2.1'}).steps), 2)
            with self.assertRaisesRegex(PlanError, 'PyYAML'):
                load_workflow(self.path, {})

    def test_bundled_workflows(self):
        for filename, selector in [('quick_scan', 'quick'), ('full_audit', 'full')]:
            path = self.fixture.framework / f'09_Automation/workflows/{filename}.yaml'
            loaded = load_workflow(path, {'target': '192.0.2.1'})
            built = build_plan(selector, {'target': '192.0.2.1'})
            self.assertEqual(loaded.steps, built.steps)
            self.assertEqual(loaded.timeout, built.timeout)

    def test_limits_and_no_templates(self):
        base = 'name: t\nversion: 1\ntimeout: 86400\nsteps: [{id: a, action: ping}]\n'
        self.assertEqual(self.workflow(base + '#' + 'x' * (65536 - len(base) - 1)).timeout, 86400)
        for value in ('0', '86401', '1.0', '"600"', 'false'):
            with self.subTest(value=value), self.assertRaises(PlanError):
                self.workflow(base.replace('86400', value))
        with self.assertRaises(PlanError):
            self.workflow(base.replace('action: ping', 'action: ping, inputs: {target: "{target}"}'))
        with self.assertRaises(PlanError):
            self.workflow(base.replace('action: ping', 'action: ping, inputs: {target: "${TARGET}"}'))
        cyclic = '''name: t
version: 1
timeout: 600
steps:
  - {id: a, action: ping, depends_on: [b]}
  - {id: b, action: ping, depends_on: [a]}
'''
        with self.assertRaises(PlanError):
            self.workflow(cyclic)

    def test_typed_defaults_preserve_explicit_inputs(self):
        text = '''name: t
version: 1
timeout: 600
steps:
  - {id: s, action: services, inputs: {ports: [443]}}
  - {id: r, action: report, inputs: {report_input: "dir con espacios/scans"}}
'''
        plan = self.workflow(text, {'target': 'EXAMPLE.TEST.', 'ports': (22, 80),
                                    'report_input': Path('/cli/scans'), 'unrelated': 'ignored'})
        self.assertEqual(plan.steps[0].inputs['ports'], (443,))
        self.assertEqual(plan.steps[0].inputs['target'], 'example.test')
        self.assertEqual(plan.steps[1].inputs['report_input'], self.path.parent / 'dir con espacios/scans')
        text = text.replace('inputs: {report_input: "dir con espacios/scans"}', 'inputs: {}')
        self.assertEqual(self.workflow(text, {'target': 'a', 'report_input': Path('/cli/scans')})
                         .steps[1].inputs['report_input'], Path('/cli/scans'))

    def test_invalid_inputs_and_cross_fields(self):
        for selector, inputs in [
                ('ping', {}), ('ping', {'target': 'a', 'env': {}}),
                ('web', {'target': 'a.test', 'url': 'https://b.test'}),
                ('sqlmap_request', {'target': 'a', 'scheme': 'https', 'request_file': 'x', 'table': 't'}),
                ('quick', {'target': 'a', 'include_config': 'false'}),
                ('scan_vuln', {'target': 'a'})]:
            with self.subTest(selector=selector), self.assertRaises(PlanError):
                build_plan(selector, inputs)
        with self.assertRaises(PlanError):
            validate_plan(Plan('test', (Step('bad-id', 'ping', {'target': 'a'}, ()),), 600))
        plan = build_plan('services', {'target': 'a', 'ports': '22,80-81'})
        self.assertEqual(plan.steps[0].inputs['ports'], (22, 80, 81))
        self.assertIn('3 puertos', render_plan(plan, self.ctx))


if __name__ == '__main__':
    unittest.main()
