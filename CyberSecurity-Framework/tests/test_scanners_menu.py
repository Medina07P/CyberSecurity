"""Ejecuta fuentes reales en un árbol sintético; solo las herramientas son falsas."""
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

FW = Path(__file__).resolve().parents[1]
LEAVES = {
    'smart': ('network_scanners/nmap/nmap_smart.sh', ['example.invalid']),
    'aggressive': ('network_scanners/nmap/nmap_aggressive.sh', ['example.invalid']),
    'nse': ('network_scanners/nmap/nmap_scripts.sh', ['example.invalid', '8080']),
    'masscan': ('network_scanners/masscan/masscan_scan.sh', ['192.0.2.1', '80']),
    'rustscan': ('network_scanners/rustscan/rustscan_scan.sh', ['example.invalid']),
    'nikto': ('web_scanners/nikto/nikto_scan.sh', ['https://example.invalid:9443/ruta']),
    'nuclei': ('web_scanners/nuclei/nuclei_scan.sh', ['https://example.invalid:9443/ruta']),
    'cves': ('web_scanners/nuclei/nuclei_cves.sh', ['https://example.invalid', 'critical']),
}

STUB = r'''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f:
    f.write(json.dumps([name, *args]) + '\n')
if name == 'id':
    print(os.environ.get('FAKE_UID', '0')); sys.exit(0)
if os.environ.get('FAIL_TOOL') in ('all', name):
    print('fallo simulado', file=sys.stderr); sys.exit(7)
if os.environ.get('WARN_TOOL') == name:
    print('aviso informativo', file=sys.stderr)
body = os.environ.get('PORT_LINES', '8080/tcp open http\n8443/tcp open https\n')
if name == 'nmap':
    if '-oA' in args:
        base = args[args.index('-oA')+1]
        for ext in ('.nmap', '.gnmap', '.xml'):
            Path(base+ext).write_text(body)
    elif '-oN' in args:
        Path(args[args.index('-oN')+1]).write_text(body)
    print(body)
elif name == 'nikto':
    Path(args[args.index('-o')+1]+'.txt').write_text('Nikto: ejecución terminada\n')
    mode = os.environ.get('NIKTO_RESULT', 'ok')
    if mode == 'zero':
        print('+ ERROR: Unable to connect to example.invalid:443\n+ 0 host(s) tested')
    elif mode == 'partial':
        print('+ ERROR: Error limit reached for host, giving up.\n+ Scan terminated: 20 errors and 0 items reported on the remote host\n+ 1 host(s) tested')
    else:
        print('+ 100 requests: 0 errors and 0 items reported on the remote host\n+ End Time: 2026-11-09\n+ 1 host(s) tested')
elif name == 'nuclei':
    if '-json' in args:
        sys.exit('flag obsoleto: -json')
    content = ''
    if os.environ.get('NUCLEI_HIT'):
        if '-jsonl' in args:
            content = json.dumps({'template-id': 'CVE-2021-44228', 'info': {'name': 'Fixture', 'severity': 'critical'}, 'matched-at': 'https://example.invalid/'})+'\n'
        else:
            content = '[CVE-2021-44228] [http] [critical] https://example.invalid/\n'
    Path(args[args.index('-o')+1]).write_text(content)
elif name == 'rustscan':
    if '-o' in args:
        sys.exit('RustScan no guarda salida con -o')
    print('Open example.invalid:8080')
elif name == 'masscan':
    formats = [x for x in args if x in ('-oJ', '-oG', '-oL')]
    if len(formats) != 1:
        sys.exit('masscan solo admite un formato de salida')
    Path(args[args.index(formats[0])+1]).write_text('[]\n')
'''


class ScannersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='scanners-test-', dir='/tmp/opencode')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = self.root/'CyberSecurity-Framework'
        shutil.copytree(FW/'03_Scanners', self.fw/'03_Scanners')
        shutil.copytree(FW/'00_Config/lib', self.fw/'00_Config/lib')
        shutil.copy2(FW/'cyber_framework.sh', self.fw/'cyber_framework.sh')
        (self.fw/'00_Config/scope.yaml').write_text('targets: {ips: [], domains: []}\n')
        (self.fw/'00_Config/targets.txt').write_text('')
        self.bin = self.root/'bin'; self.bin.mkdir()
        # PATH is closed: a missing stub can never fall through to a real scanner.
        for command in ('bash', 'dirname', 'mkdir', 'grep', 'cut', 'tr', 'sed', 'head',
                        'tail', 'cat', 'wc', 'date', 'mktemp', 'mv', 'rm', 'rmdir', 'cp',
                        'python3', 'awk', 'sort', 'find', 'chmod', 'basename', 'tee'):
            tool = shutil.which(command)
            if tool:
                (self.bin/command).symlink_to(tool)
        for command in ('nmap', 'nuclei', 'nikto', 'masscan', 'rustscan', 'burpsuite', 'id'):
            path = self.bin/command; path.write_text(STUB); path.chmod(0o755)
        for command in ('clear', 'sleep'):
            path = self.bin/command; path.write_text('#!/bin/bash\nexit 0\n'); path.chmod(0o755)
        self.calls = self.root/'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin), CALLS=str(self.calls),
                        HOME=str(self.root/'home'), TERM='dumb',
                        SESSION_FILE=str(self.root/'session'),
                        SESSION_SCOPE_FILE=str(self.fw/'00_Config/scope.yaml'),
                        SESSION_TARGETS_FILE=str(self.fw/'00_Config/targets.txt'))
        for key in ('FAIL_TOOL', 'WARN_TOOL', 'PORT_LINES', 'FAKE_UID'):
            self.env.pop(key, None)

    def run_script(self, name, args=None, **env):
        path, defaults = LEAVES[name]
        return subprocess.run(['bash', str(self.fw/'03_Scanners'/path),
                               *(defaults if args is None else args)],
                              env=dict(self.env, **env), cwd=self.root,
                              text=True, capture_output=True, timeout=15)

    def invocations(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def run_all(self, target='example.invalid', **env):
        return subprocess.run(['bash', str(self.fw/'03_Scanners/run_all_scanners.sh'), target],
                              env=dict(self.env, **env), cwd=self.root, text=True,
                              capture_output=True, timeout=15)

    def menu(self, inputs, target='example.invalid'):
        if target:
            Path(self.env['SESSION_FILE']).write_text(target+'\n')
        result = subprocess.run(['bash', str(self.fw/'cyber_framework.sh')], input=inputs,
                                env=self.env, cwd=self.root, text=True,
                                capture_output=True, timeout=15)
        result.stdout = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', result.stdout)
        return result

    def test_menu_local_checks_do_not_invoke_tools(self):
        result = self.menu('03\n1\n\n0\nQ\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('COMPROBACIÓN LOCAL', result.stdout)
        self.assertIn('example.invalid', result.stdout)
        self.assertIn('root', result.stdout)
        self.assertEqual(self.invocations(), [])

    def test_menu_basic_is_limited_and_confirmed(self):
        result = self.menu('03\n2\n\ns\n\n0\nQ\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.invocations()
        self.assertEqual(len(calls), 1, result.stdout+result.stderr)
        call = calls[0]
        self.assertEqual(call[0], 'nmap')
        self.assertEqual(call[call.index('--top-ports')+1], '100')
        self.assertIn('example.invalid', call)
        self.assertIn('--version-light', call)
        self.assertNotIn('--script', call)
        self.assertNotIn('-p-', call)
        self.assertNotIn('-O', call)

    def test_menu_cancel_and_eof_never_execute(self):
        for inputs in ('03\n2\n', '03\n2\n\n', '03\n2\n\nn\n0\nQ\n',
                       '03\n2\n!\n0\nQ\n', '03\n3\n1\n',
                       '03\n3\n1\nhttps://example.invalid\n', '03\n4\nn\n0\nQ\n'):
            with self.subTest(inputs=inputs):
                result = self.menu(inputs)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.invocations(), [], result.stdout+result.stderr)

    def test_menu_web_preserves_explicit_url(self):
        for choice, tool, flag in [('1', 'nikto', '-h'), ('2', 'nuclei', '-u')]:
            with self.subTest(tool=tool):
                if self.calls.exists(): self.calls.unlink()
                result = self.menu('03\n3\n'+choice+'\nhttps://example.invalid:9443/ruta\ns\n\n0\nQ\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.invocations()
                self.assertEqual(len(calls), 1, result.stdout+result.stderr)
                self.assertEqual(calls[0][0], tool)
                self.assertEqual(calls[0][calls[0].index(flag)+1], 'https://example.invalid:9443/ruta')

    def test_menu_no_session_has_no_example_target_default(self):
        result = self.menu('03\n2\n\n0\nQ\n', target=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.invocations(), [])
        self.assertIn('sin definir', result.stdout)

    def test_menu_invalid_choice_and_advanced_navigation(self):
        result = self.menu('03\n99\n5\n0\n0\nQ\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('no válida', result.stdout)
        self.assertIn('10 scripts', result.stdout)
        self.assertIn('[intrusiva]', result.stdout)
        self.assertEqual(self.invocations(), [])

    def test_smart_basic_profile_and_invalid_profile(self):
        result = self.run_script('smart', ['example.invalid', 'basico'])
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(len(self.invocations()), 1)
        call = self.invocations()[0]
        self.assertIn('--top-ports', call)
        self.calls.unlink()
        result = self.run_script('smart', ['example.invalid', 'bogus'])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.invocations(), [])

    def test_orchestrator_partial_failure_is_not_success(self):
        result = self.run_all(FAIL_TOOL='nikto')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('Fallidas: 2', result.stdout)
        self.assertNotIn('✅ ESCANEOS COMPLETADOS', result.stdout)

    def test_orchestrator_discovery_failure_stops_web(self):
        result = self.run_all(FAIL_TOOL='nmap')
        self.assertEqual(result.returncode, 1)
        self.assertFalse(any(call[0] in ('nikto', 'nuclei') for call in self.invocations()))
        self.assertIn('NO DETERMINADO', result.stdout+result.stderr)

    def test_orchestrator_optional_masscan_omission_is_explicit(self):
        result = self.run_all('192.0.2.1', FAKE_UID='1000', PORT_LINES='80/tcp closed http\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('Omitidas: 1', result.stdout)
        self.assertIn('root', result.stdout)
        self.assertFalse(any(call[0] == 'masscan' for call in self.invocations()))

    def test_orchestrator_missing_required_script_fails(self):
        (self.fw/'03_Scanners'/LEAVES['smart'][0]).unlink()
        result = self.run_all(PORT_LINES='80/tcp closed http\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn('no encontrado', result.stdout)

    def test_orchestrator_preserves_ports_and_never_shows_old_logs(self):
        log = self.root/'scans/unrelated/errores.log'; log.parent.mkdir(parents=True)
        log.write_text('error ajeno antiguo\n')
        result = self.run_all()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        calls = self.invocations()
        urls = [call[call.index('-h')+1] for call in calls if call[0] == 'nikto']
        self.assertEqual(urls, ['http://example.invalid:8080', 'https://example.invalid:8443'])
        self.assertNotIn(str(log), result.stdout)
        self.assertIn('heurística', result.stdout)

    def test_each_leaf_propagates_failure(self):
        for name in LEAVES:
            with self.subTest(name=name):
                result = self.run_script(name, FAIL_TOOL='all')
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn('✅', result.stdout)

    def test_smart_does_not_reuse_stale_ports_after_failure(self):
        output = self.root/'scans/nmap'; output.mkdir(parents=True)
        old = output/'smart_ports_example.invalid.nmap'
        old.write_text('22/tcp open ssh\n')
        result = self.run_script('smart', FAIL_TOOL='nmap')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(old.read_text(), '22/tcp open ssh\n')

    def test_smart_only_uses_open_tcp_ports(self):
        result = self.run_script('smart', PORT_LINES='53/udp open domain\n80/tcp open|filtered http\n8080/tcp open http\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        phases = self.invocations()[1:]
        self.assertEqual(len(phases), 2)
        for call in phases:
            self.assertEqual(call[call.index('-p')+1], '8080')

    def test_empty_scan_is_success_not_a_finding(self):
        result = self.run_script('smart', PORT_LINES='80/tcp closed http\n')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(self.invocations()), 1)
        self.assertIn('No se encontraron puertos', result.stdout)

    def test_missing_tool_fails_before_creating_results(self):
        (self.bin/'nuclei').unlink()
        result = self.run_script('cves')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no instalado', result.stdout+result.stderr)

    def test_invalid_input_never_reaches_tool(self):
        cases = [('smart', ['--script=vuln']), ('smart', ['https://example.invalid']),
                 ('smart', ['999.1.1.1']), ('smart', ['192.0.2.0/24']),
                 ('nikto', ['https://user:password@example.invalid/']),
                 ('nuclei', ['file:///etc/passwd']),
                 ('nse', ['example.invalid', '0,70000']),
                 ('nse', ['example.invalid', '100-1']),
                 ('cves', ['https://example.invalid', '--debug'])]
        for name, args in cases:
            with self.subTest(name=name, args=args):
                if self.calls.exists(): self.calls.unlink()
                result = self.run_script(name, args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.invocations(), [])

    def test_log_preserves_previous_run_and_stderr_warning_is_not_failure(self):
        log = self.root/'scans/nuclei/errores.log'; log.parent.mkdir(parents=True)
        log.write_text('error anterior\n')
        result = self.run_script('nuclei', WARN_TOOL='nuclei')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('error anterior', log.read_text())
        self.assertIn('aviso informativo', log.read_text())

    def test_cli_formats_and_requested_nse_ports(self):
        for name in ('rustscan', 'masscan', 'cves', 'nse'):
            with self.subTest(name=name):
                if self.calls.exists(): self.calls.unlink()
                result = self.run_script(name)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                if name == 'nse':
                    for call in self.invocations():
                        self.assertEqual(call[call.index('-p')+1], '8080')
                        self.assertNotIn('smb-enum', call)

    def test_web_url_is_preserved_and_ssl_only_for_https(self):
        for url, ssl in [('http://example.invalid:8080/path', False),
                         ('https://example.invalid:9443/ruta', True)]:
            result = self.run_script('nikto', [url])
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            call = self.invocations()[-1]
            self.assertEqual(call[call.index('-h')+1], url)
            self.assertEqual('-ssl' in call, ssl)

    def test_cve_output_is_consumed_by_report_engine(self):
        shutil.copytree(FW/'11_Reports/lib', self.fw/'11_Reports/lib')
        result = self.run_script('cves', NUCLEI_HIT='1')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        script = '''import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from lib.engine import collect
root = Path(sys.argv[2])
result = collect(root/'scans', root, 'example.invalid')
assert len(result.findings) == 1, (result.findings, result.no_evaluable)
assert result.findings[0].cve == 'CVE-2021-44228'
'''
        result = subprocess.run(['python3', '-c', script, str(self.fw/'11_Reports'), str(self.root)],
                                env=self.env, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_nikto_rejects_comma_host_lists_in_path_and_query(self):
        for url in ('https://example.invalid/path,other.invalid',
                    'https://example.invalid/?q=a,other.invalid'):
            with self.subTest(url=url):
                result = self.run_script('nikto', [url])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.invocations(), [])

    def test_nikto_zero_exit_without_evaluation_is_failure(self):
        for mode in ('zero', 'partial'):
            with self.subTest(mode=mode):
                result = self.run_script('nikto', NIKTO_RESULT=mode)
                self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertNotIn('✅', result.stdout)
                self.assertIn('NO DETERMINADO', result.stdout+result.stderr)

    def test_nikto_partial_failure_is_counted_by_orchestrator(self):
        result = self.run_all(NIKTO_RESULT='zero')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('Fallidas: 2', result.stdout)

    def test_ipv6_network_targets_rejected_before_invoking_any_tool(self):
        for name in ('smart', 'aggressive', 'nse', 'rustscan'):
            with self.subTest(name=name):
                result = self.run_script(name, ['2001:db8::1'])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.invocations(), [])
        result = self.run_all('2001:db8::1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.invocations(), [])

    def test_rustscan_failure_preserves_previous_evidence(self):
        output = self.root/'scans/rustscan/rustscan_example.invalid.txt'
        output.parent.mkdir(parents=True)
        output.write_text('Evidencia anterior\n')
        result = self.run_script('rustscan', FAIL_TOOL='rustscan')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), 'Evidencia anterior\n')


if __name__ == '__main__':
    unittest.main()
