"""Static Docker contracts only: no daemon, build, network or real data inventory."""
import fnmatch
import json
from pathlib import Path
import re
import unittest

import yaml

from automation_fixture import AutomationFixture


def pattern_matches(pattern, path):
    """Docker's slash-separated patterns, including ** and parent matches.

    Parent matching matters: !directory/ also re-includes its descendants
    unless a subsequent rule denies them again. No host files are enumerated.
    """
    pattern = pattern.strip('/')

    def segments_match(parts, names):
        if not parts:
            return not names
        if parts[0] == '**':
            # A trailing '/**' requires the separator and a descendant;
            # unlike a middle '**/', it does not match the directory itself.
            if len(parts) == 1:
                return bool(names)
            return any(segments_match(parts[1:], names[i:])
                       for i in range(len(names) + 1))
        return bool(names and fnmatch.fnmatchcase(names[0], parts[0])
                    and segments_match(parts[1:], names[1:]))

    names = path.strip('/').split('/')
    return any(segments_match(pattern.split('/'), names[:i])
               for i in range(1, len(names) + 1))


def included(path, rules):
    result = True
    for rule in rules:
        if pattern_matches(rule.lstrip('!'), path):
            result = rule.startswith('!')
    return result


class DockerContracts(unittest.TestCase):
    def setUp(self):
        self.fixture = AutomationFixture()
        self.addCleanup(self.fixture.close)
        self.docker = self.fixture.framework / '09_Automation/docker'
        origin = Path(__file__).resolve().parents[1] / '09_Automation/docker'
        ignore = origin / 'Dockerfile.dockerignore'
        if ignore.is_file():
            (self.docker / ignore.name).write_text(ignore.read_text())
        self.compose = yaml.safe_load((self.docker / 'docker-compose.yml').read_text())
        self.dockerfile = (self.docker / 'Dockerfile').read_text()

    def test_compose_minimum_privileges(self):
        service = self.compose['services']['ctf-toolkit']
        for key in ('volumes', 'volumes_from', 'cap_add', 'devices', 'entrypoint',
                    'command', 'extends', 'env_file', 'develop', 'configs', 'secrets'):
            self.assertNotIn(key, service)
        self.assertFalse(service.get('privileged', False))
        self.assertNotEqual(service.get('network_mode'), 'host')
        self.assertNotEqual(service.get('pid'), 'host')
        self.assertNotEqual(service.get('ipc'), 'host')
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertIn('no-new-privileges:true', service['security_opt'])
        self.assertEqual(service['user'], 'toolkit')
        self.assertTrue(service['stdin_open'])
        self.assertTrue(service['tty'])
        self.assertEqual(service['build'], {
            'context': '../..', 'dockerfile': '09_Automation/docker/Dockerfile'})
        context = (self.docker / service['build']['context']).resolve()
        self.assertEqual(context, self.fixture.framework)
        self.assertEqual(context / service['build']['dockerfile'], self.docker / 'Dockerfile')
        self.assertNotIn('volumes', self.compose)
        self.assertNotIn('include', self.compose)
        self.assertNotIn('docker.sock', str(self.compose))

    def test_context_allowlist(self):
        ignore = self.docker / 'Dockerfile.dockerignore'
        self.assertTrue(ignore.is_file(), 'Dockerfile-specific deny-by-default filter missing')
        rules = [line.strip() for line in ignore.read_text().splitlines()
                 if line.strip() and not line.startswith('#')]
        self.assertEqual(rules[0], '**')
        exact = [r[1:] for r in rules if r.startswith('!') and not r.endswith('/')]
        self.assertTrue(exact)
        for rule in rules[1:]:
            if rule.startswith('!'):
                self.assertFalse(any(char in rule for char in '*?[]'))
            else:
                self.assertTrue(rule.endswith('/**'), rule)
        required = ('09_Automation/python/orchestrator.py',
                    '00_Config/lib/automation/cli.py',
                    '03_Scanners/network_scanners/nmap/nmap_smart.sh',
                    '11_Reports/report_engine.py',
                    '09_Automation/workflows/quick_scan.yaml',
                    '09_Automation/workflows/full_audit.yaml')
        self.assertIn('09_Automation/USE.md', exact)
        self.assertFalse(included('09_Automation/USE-private.md', rules))
        for path in required:
            self.assertIn(path, exact)
        forbidden = ['00_Config/scope.yaml', '00_Config/targets.txt',
                     '00_Config/.session', '11_Reports/.report_profile',
                     '09_Automation/report.json', '09_Automation/report.html',
                      '00_Config/wordlists/users.txt', '.git/config']
        forbidden += ['tests/' + name for name in (
            'automation_sandbox_launch.py', 'automation_sandbox_prepare.py',
            'automation_sandbox_policy.py', 'automation_sandbox_inside.py',
            'automation_suite_selection.py', 'automation_sandbox_sources.json')]
        forbidden += ['docs/AUTOMATION-TEST-ISOLATION-2026-11-13.md',
                      '09_Automation/USE-private.md']
        for directory in ('scans', 'loot', 'credentials', 'analysis', 'logs', '__pycache__'):
            for prefix in ('', '00_Config/', '09_Automation/', '06_PostExploitation/', '08_Forensics/'):
                forbidden.extend(prefix + directory + '/secret' + suffix
                                 for suffix in ('.py', '.sh', '.yaml', '.log', '.pyc'))
        # Sibling files under EVERY reopened ancestor catch inherited inclusion.
        for rule in rules:
            if rule.startswith('!') and rule.endswith('/'):
                forbidden.extend(rule[1:] + name for name in
                                 ('secret.py', 'secret.sh', '.session', 'report.html'))
        for path in forbidden:
            self.assertFalse(included(path, rules), 'private candidate admitted: ' + path)
        tree = self.fixture.repo / 'synthetic-context'
        for path in set(exact + forbidden):
            candidate = tree / path
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_text('synthetic only\n')
        accepted = {p.relative_to(tree).as_posix() for p in tree.rglob('*')
                    if p.is_file() and included(p.relative_to(tree).as_posix(), rules)}
        self.assertEqual(accepted, set(exact))
        for path in exact:
            self.assertFalse(set(Path(path).parts) & {
                'loot', 'scans', 'credentials', 'analysis', 'logs', '__pycache__',
                'wordlists', 'captures', 'recovered', 'final_report'}, path)
            self.assertTrue(path.endswith(('.py', '.sh', '.bash', '.ps1', '.md'))
                            or path in required[-2:] or path == '00_Config/lib/dangerous.txt', path)
            for parent in Path(path).parents:
                if str(parent) != '.':
                    self.assertTrue(included(parent.as_posix(), rules), str(parent))

    def test_nonroot_and_dependencies(self):
        text = self.dockerfile
        self.assertIn('FROM kalilinux/kali-rolling:', text)
        self.assertNotRegex(text, r'\bpip[3]?\b')
        packages = re.search(r'apt-get install\s+.*?\\\n(.*?)&&', text, re.S)
        self.assertIsNotNone(packages)
        names = packages[1].replace('\\', '').split()
        self.assertEqual(len(names), len(set(names)), 'duplicate packages')
        for name in ('netcat-openbsd', 'python3-yaml', 'python3-requests',
                     'python3-bs4', 'python3-scapy', 'python3-shodan', 'hydra'):
            self.assertIn(name, names)
        self.assertNotIn('netcat', names)
        self.assertRegex(text, r'useradd[^\n]*--create-home[^\n]*toolkit')
        self.assertRegex(text, r'chmod 700 /home/toolkit')
        users = re.findall(r'^USER\s+(.+)$', text, re.M)
        self.assertEqual(users[-1:], ['toolkit'])
        self.assertIn('COPY --chown=toolkit:toolkit', text)
        self.assertNotRegex(text, r'(?m)^COPY\s+(?:--\S+\s+)*\.\s+\.')
        self.assertNotRegex(text, r'(?m)^VOLUME\b')
        entries = re.findall(r'^ENTRYPOINT\s+(.+)$', text, re.M)
        self.assertEqual(json.loads(entries[-1]), ['/bin/bash', '--noprofile', '--norc'])
        self.assertNotRegex(text, r'(?m)^CMD\b')
        self.assertNotRegex(text.split('USER toolkit')[-1], r'(?m)^RUN\b')

    def test_matcher_parent_and_recursive_semantics(self):
        self.assertTrue(included('a/private/secret.py', ['**', '!a/']))
        self.assertFalse(included('a/private/secret.py', ['**', '!a/', 'a/**']))
        self.assertTrue(included('a/public.py', ['**', '!a/', 'a/**', '!a/public.py']))
        self.assertTrue(pattern_matches('**/*.py', 'a/b/file.py'))
        self.assertTrue(pattern_matches('**/*.py', 'file.py'))
        self.assertFalse(pattern_matches('a/**', 'a'))
        self.assertTrue(included('a', ['**', '!a/', 'a/**']))


if __name__ == '__main__':
    unittest.main()
