import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

FW = Path(__file__).resolve().parents[1]


class EnumerationFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='enumeration-test-', dir='/tmp/opencode')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = self.root/'framework with spaces'/'CyberSecurity-Framework'
        shutil.copytree(FW/'04_Enumeration', self.fw/'04_Enumeration')
        shutil.copytree(FW/'00_Config/lib', self.fw/'00_Config/lib', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(FW/'11_Reports/lib', self.fw/'11_Reports/lib', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copy2(FW/'cyber_framework.sh', self.fw/'cyber_framework.sh')
        (self.fw/'00_Config/scope.yaml').write_text('targets: {ips: [], domains: []}\n')
        (self.fw/'00_Config/targets.txt').write_text('')
        self.scans = self.fw.parent/'scans'
        self.bin = self.root/'bin'; self.bin.mkdir()
        for name in ('bash', 'env', 'timeout', 'dirname', 'basename', 'mkdir', 'mktemp', 'date',
                     'cat', 'rm', 'rmdir', 'mv', 'cp', 'sort', 'awk', 'sed', 'cut', 'grep',
                     'tr', 'head', 'tail', 'find', 'chmod', 'python3', 'wc', 'tee'):
            tool = shutil.which(name)
            if tool: (self.bin/name).symlink_to(tool)
        for name in ('nmap', 'nc', 'ftp', 'ldapsearch', 'rpcclient', 'smbclient', 'enum4linux',
                     'mysql', 'psql', 'curl', 'whatweb', 'ffuf'):
            shutil.copy2(FW/'tests/fixtures/enumeration_tools.py', self.bin/name)
            (self.bin/name).chmod(0o755)
        for name in ('clear', 'sleep'):
            (self.bin/name).write_text('#!/bin/bash\nexit 0\n'); (self.bin/name).chmod(0o755)
        self.home = self.root/'home'; self.home.mkdir()
        self.calls = self.root/'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin), HOME=str(self.home), TERM='dumb',
                        ENUM_CALLS=str(self.calls), PYTHONDONTWRITEBYTECODE='1',
                        SESSION_FILE=str(self.root/'session'), SESSION_SCOPE_FILE=str(self.fw/'00_Config/scope.yaml'),
                        SESSION_TARGETS_FILE=str(self.fw/'00_Config/targets.txt'))
        for key in list(self.env):
            if key.startswith(('FAKE_', 'ENUM_TEST_', 'CURL_')):
                self.env.pop(key)

    def shell(self, text, inputs='', **env):
        return subprocess.run(['bash', '-c', text], input=inputs, cwd=self.root,
                              env=dict(self.env, **env), text=True, capture_output=True, timeout=25)

    def leaf(self, path, *args, **env):
        return subprocess.run(['bash', str(self.fw/'04_Enumeration'/path), *args],
                              cwd=self.root, env=dict(self.env, **env), text=True,
                              capture_output=True, timeout=25)

    def invoked(self, tool=None):
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []
        return [c for c in calls if tool is None or c['tool'] == tool]

    def metas(self, service):
        return [json.loads(p.read_text()) for p in (self.scans/service).glob('*.meta.json')]
