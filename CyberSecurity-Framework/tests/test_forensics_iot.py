"""IoT/portable contracts: synthetic trees, closed PATH, loopback provider only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from forensics_fixture import load_evidence, runtime_environment, sandbox

FRAMEWORK = Path(__file__).resolve().parents[1]
LEAVES = {'acquire': 'iot/iot_acquire.sh', 'triage': 'iot/iot_triage.sh',
          'lookup': 'iot/iot_vt_lookup.sh', 'sterilize': 'iot/iot_sterilize.sh'}
LIBRARIES = ('forensics_evidence.py', 'forensics_runtime.bash',
             'forensics_iot.bash', 'forensics_iot.py')
KEY = 'synthetic-vt-key-0123456789'
PNG = b'\x89PNG\r\n\x1a\n' + b'synthetic image body'
ZIP = b'PK\x03\x04' + b'synthetic archive body'


def tree_inventory(base):
    result = {}
    for path in sorted(base.rglob('*')):
        info = path.lstat()
        key = str(path.relative_to(base))
        if path.is_symlink():
            result[key] = ('link', os.readlink(path))
        elif path.is_dir():
            result[key] = ('dir', info.st_mode & 0o777)
        else:
            result[key] = ('file', hashlib.sha256(path.read_bytes()).hexdigest(),
                           info.st_mode & 0o777)
    return result


class Provider(BaseHTTPRequestHandler):
    """Loopback VirusTotal v3 stand-in; records headers, answers by hash."""

    def do_GET(self):
        self.server.calls.append((self.path, self.headers.get('x-apikey')))
        digest = self.path.rsplit('/', 1)[-1]
        if digest in self.server.answers:
            body = json.dumps({'data': {'attributes': {
                'last_analysis_stats': self.server.answers[digest],
                'last_analysis_date': 946684800}}}).encode()
            self.send_response(200)
        else:
            body = b'{"error": {"code": "NotFoundError"}}'
            self.send_response(404)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class IoTTests(unittest.TestCase):
    def setUp(self):
        self.ctx = sandbox()
        self.root = self.ctx.__enter__()
        self.addCleanup(self.ctx.__exit__, None, None, None)
        self.env = runtime_environment(self.root)
        self.env['FORENSICS_ANALYSIS_ROOT'] = str(self.root / 'outputs')
        self.env['FORENSICS_RECOVERED_ROOT'] = str(self.root / 'recovered')
        self.framework = self.root / 'code'
        for relative in [*(Path('00_Config/lib') / name for name in LIBRARIES),
                         *(Path('08_Forensics') / path for path in LEAVES.values())]:
            destination = self.framework / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(FRAMEWORK / relative, destination)
        self.helper_path = self.framework / '00_Config/lib/forensics_iot.py'
        self.e = load_evidence()

    def stub(self, name, body):
        path = self.root / 'bin' / name
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o700)

    def invoke(self, kind, *args, input='', env=None):
        return subprocess.run(['/bin/bash', str(self.framework / '08_Forensics' / LEAVES[kind]),
                               *map(str, args)], env=env or self.env, input=input,
                              capture_output=True, text=True, timeout=60)

    def helper(self, *args, env=None):
        return subprocess.run([sys.executable, '-B', str(self.helper_path), *map(str, args)],
                              env=env or self.env, capture_output=True, text=True, timeout=60)

    def runs(self, operation=None):
        found = []
        for path in sorted((self.root / 'outputs').rglob('run.json')):
            data = self.e.read_run(path)
            if operation is None or data['operation'] == operation:
                found.append(path)
        return found

    def read(self, operation=None):
        runs = self.runs(operation)
        self.assertTrue(runs, 'no attributable private run')
        return self.e.read_run(runs[-1])

    def triage_tree(self, files=None):
        tree = self.root / 'sources' / 'recuperados'
        tree.mkdir(parents=True)
        for name, body in (files or {'foto.png': PNG, 'nota.txt': b'hola sintetica\n',
                                     'sub/copia.png': PNG}).items():
            target = tree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        return tree

    # --- triage -------------------------------------------------------

    def test_triage_private_report_classifies_and_keeps_original_tree(self):
        tree = self.triage_tree()
        before = tree_inventory(tree)
        result = self.invoke('triage', tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        run = self.read('triage')
        self.assertEqual((run['mode'], run['state'], run['complete']), ('offline', 'COMPLETADO', True))
        analysis = Path(run['artifact_roots']['analysis'])
        report = json.loads((analysis / 'report.json').read_text())
        self.assertEqual(report['resumen']['total'], 3)
        self.assertEqual(report['resumen']['por_familia'], {'documento': 1, 'imagen': 2})
        rows = {row['ruta']: row for row in report['archivos']}
        self.assertEqual(rows['foto.png']['familia'], 'imagen')
        self.assertEqual(rows['foto.png']['firma'], 'PNG')
        self.assertEqual(rows['nota.txt']['familia'], 'documento')
        self.assertEqual(rows['nota.txt']['firma'], 'EXTENSION')
        self.assertEqual(rows['sub/copia.png']['duplicado_de'], 'foto.png')
        self.assertIn('Duplicados exactos', (analysis / 'report.md').read_text())
        self.assertEqual(tree_inventory(tree), before)
        products = [p for p in (self.root / 'outputs').rglob('*') if p.is_file()]
        self.assertTrue(products)
        for product in products:
            self.assertEqual(product.stat().st_mode & 0o777, 0o600, product)
        for directory in (self.root / 'outputs').rglob('*'):
            if directory.is_dir():
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700, directory)
        published = [ref['path'] for step in run['steps'] for ref in step['artifacts']]
        self.assertIn('report.json', published)
        self.assertIn('report.md', published)

    def test_empty_tree_is_not_a_useful_triage(self):
        tree = self.root / 'sources' / 'vacio'
        tree.mkdir(parents=True)
        result = self.invoke('triage', tree)
        self.assertEqual(result.returncode, 1)
        run = self.read('triage')
        self.assertFalse(run['complete'])
        states = {step['name']: step['state'] for step in run['steps']}
        self.assertEqual(states.get('triage'), 'NO_EVALUABLE')
        report = json.loads((Path(run['artifact_roots']['analysis']) / 'report.json').read_text())
        self.assertEqual(report['resumen']['total'], 0)

    def test_tree_with_symlink_is_rejected_before_any_report(self):
        tree = self.triage_tree({'real.png': PNG})
        (tree / 'escape.png').symlink_to(self.root / 'never-readable')
        result = self.invoke('triage', tree)
        self.assertEqual(result.returncode, 1)
        run = self.read('triage')
        self.assertTrue(run['dependents_blocked'])
        self.assertEqual(run['state'], 'FALLIDO')
        self.assertFalse((Path(run['artifact_roots']['analysis']) / 'report.json').exists())

    def test_exiftool_absent_is_a_precondition_and_failure_is_not_fatal(self):
        tree = self.triage_tree({'solo.png': PNG})
        result = self.invoke('triage', tree, '--exiftool')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.runs(), [])
        self.stub('exiftool', 'printf "synthetic metadata" >&2; exit 99')
        result = self.invoke('triage', tree, '--exiftool')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((Path(self.read('triage')['artifact_roots']['analysis'])
                             / 'report.json').read_text())
        self.assertNotIn('metadatos', report['archivos'][0])

    def test_exiftool_limit_writes_warning_and_metadata_in_markdown_report(self):
        tree = self.triage_tree({'a.png': PNG, 'b.png': PNG + b'2'})
        self.stub('exiftool', 'printf \'[{"MIMEType": "image/png", "ImageWidth": 64}]\\n\'')
        result = self.invoke('triage', tree, '--exiftool', '--exiftool-limit', '1')
        self.assertEqual(result.returncode, 0, result.stderr)
        run = self.read('triage')
        self.assertEqual(run['state'], 'COMPLETADO')
        analysis = Path(run['artifact_roots']['analysis'])
        report = json.loads((analysis / 'report.json').read_text())
        self.assertEqual(len(report['advertencias']), 1)
        self.assertIn('Metadatos limitados a 1 archivos', report['advertencias'][0])
        self.assertEqual(sum(1 for row in report['archivos'] if 'metadatos' in row), 1)
        markdown = (analysis / 'report.md').read_text()
        self.assertIn('## Advertencias', markdown)
        self.assertIn('Metadatos limitados a 1 archivos', markdown)
        self.assertIn('## Metadatos (exiftool, subconjunto)', markdown)

    # --- VirusTotal v3 -------------------------------------------------

    def server(self, answers):
        httpd = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
        httpd.answers = answers
        httpd.calls = []
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return httpd

    def test_lookup_sends_only_hashes_to_loopback_and_records_origin(self):
        tree = self.triage_tree({'limpio.txt': b'texto sintetico\n', 'malo.bin': ZIP})
        self.assertEqual(self.invoke('triage', tree).returncode, 0)
        triage = self.read('triage')
        report = Path(triage['artifact_roots']['analysis']) / 'report.json'
        digests = [row['sha256'] for row in json.loads(report.read_text())['archivos']]
        self.assertEqual(len(digests), 2)
        httpd = self.server({digests[0]: {'malicious': 4, 'suspicious': 1, 'harmless': 50,
                                          'undetected': 5, 'timeout': 0},
                             digests[1]: {'malicious': 0, 'suspicious': 0, 'harmless': 0,
                                          'undetected': 0, 'timeout': 0}})
        env = dict(self.env, VT_API_KEY=KEY)
        run_dir = self.runs('triage')[-1].parent
        result = self.invoke('lookup', run_dir, '--api-base',
                             'http://127.0.0.1:%d/api/v3' % httpd.server_address[1],
                             '--delay', '0', '--limit', '0',
                             input='CONSULTAR_VIRUSTOTAL\n', env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        lookup = self.read('lookup')
        self.assertEqual((lookup['operation'], lookup['mode']), ('lookup', 'network'))
        analysis = Path(lookup['artifact_roots']['analysis'])
        data = json.loads((analysis / 'vt.json').read_text())
        self.assertEqual(data['consultados'], 2)
        self.assertEqual(data['origen']['run'], run_dir.name)
        self.assertEqual(data['origen']['report_sha256'],
                         hashlib.sha256(report.read_bytes()).hexdigest())
        states = {row['sha256']: row['estado'] for row in data['resultados']}
        self.assertEqual(states, {digests[0]: 'MALICIOSO', digests[1]: 'SIN_ANALISIS'})
        self.assertEqual(len(httpd.calls), 2)
        for path, key in httpd.calls:
            self.assertTrue(path.startswith('/api/v3/files/'))
            self.assertIn(path.rsplit('/', 1)[-1], digests)
            self.assertEqual(key, KEY)
        for path in (self.root / 'outputs').rglob('*'):
            if path.is_file():
                self.assertNotIn(KEY.encode(), path.read_bytes(), path)

    def test_lookup_requires_key_valid_triage_run_and_token(self):
        tree = self.triage_tree({'uno.txt': b'texto\n'})
        self.assertEqual(self.invoke('triage', tree).returncode, 0)
        run_dir = self.runs('triage')[-1].parent
        self.assertEqual(self.invoke('lookup', run_dir).returncode, 2)
        env = dict(self.env, VT_API_KEY=KEY)
        self.assertEqual(self.invoke('lookup', self.root / 'sources' / 'missing',
                                     env=env).returncode, 2)
        self.assertEqual(self.invoke('lookup', run_dir, env=env,
                                     input='NO\n').returncode, 2)
        self.assertEqual(self.runs('lookup'), [])

    def test_lookup_refuses_non_loopback_plaintext_provider(self):
        tree = self.triage_tree({'uno.txt': b'texto\n'})
        self.assertEqual(self.invoke('triage', tree).returncode, 0)
        run_dir = self.runs('triage')[-1].parent
        env = dict(self.env, VT_API_KEY=KEY)
        result = self.invoke('lookup', run_dir, '--api-base', 'http://example.test/api/v3',
                             '--delay', '0', '--limit', '1',
                             input='CONSULTAR_VIRUSTOTAL\n', env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn('solo se envía a VirusTotal por HTTPS', result.stderr)
        self.assertEqual(self.runs('lookup'), [])

    def test_lookup_and_vt_check_reject_spoofed_virustotal_suffixes(self):
        for bad_url in ('https://evilvirustotal.com/api/v3',
                        'https://virustotal.com.evil.test/api/v3',
                        'https://.virustotal.com/api/v3'):
            with self.subTest(url=bad_url):
                check = self.helper('vt-check', '--api-base', bad_url, '--delay', '16')
                self.assertEqual(check.returncode, 2)
                self.assertIn('solo se envía a VirusTotal por HTTPS', check.stderr)
        for good_url in ('https://www.virustotal.com/api/v3',
                         'https://virustotal.com/api/v3'):
            with self.subTest(url=good_url):
                check = self.helper('vt-check', '--api-base', good_url, '--delay', '16')
                self.assertEqual(check.returncode, 0, check.stderr)
        tree = self.triage_tree({'uno.txt': b'texto\n'})
        self.assertEqual(self.invoke('triage', tree).returncode, 0)
        run_dir = self.runs('triage')[-1].parent
        env = dict(self.env, VT_API_KEY=KEY)
        result = self.invoke('lookup', run_dir, '--api-base', 'https://evilvirustotal.com/api/v3',
                             '--delay', '16', '--limit', '1',
                             input='CONSULTAR_VIRUSTOTAL\n', env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn('solo se envía a VirusTotal por HTTPS', result.stderr)
        self.assertEqual(self.runs('lookup'), [])

    # --- acquire / sterilize: consent and privilege, nothing else ------

    def test_acquire_requires_token_and_never_escalates(self):
        self.stub('sha256sum', 'exit 99')
        device = self.root / 'sources' / 'fake-device'
        device.write_bytes(b'synthetic')
        self.assertEqual(self.invoke('acquire', device).returncode, 2)
        self.assertEqual(self.invoke('acquire', device, input='NO\n').returncode, 2)
        result = self.invoke('acquire', device, input='ADQUIRIR_SOPORTE\n')
        self.assertEqual(result.returncode, 2)
        self.assertIn('sin escalada automática', result.stderr)
        self.assertEqual(self.runs(), [])

    def test_sterilize_requires_token_and_never_escalates(self):
        device = self.root / 'sources' / 'fake-device'
        device.write_bytes(b'synthetic')
        self.assertEqual(self.invoke('sterilize', device).returncode, 2)
        result = self.invoke('sterilize', device, '--size-mib', '1',
                             input='ESTERILIZAR_SOPORTE\n')
        self.assertEqual(result.returncode, 2)
        self.assertIn('sin escalada automática', result.stderr)
        self.assertFalse((self.framework / '08_Forensics/analysis/sterilizations').exists())
        self.assertEqual(list((self.root / 'outputs').rglob('run.json')), [])

    # --- helper guard rails -------------------------------------------

    def test_device_guard_rejects_non_block_sources(self):
        regular = self.root / 'sources' / 'regular'
        regular.write_bytes(b'not a device')
        for source in (regular, '/dev/null'):
            with self.subTest(source=str(source)):
                result = self.helper('device-guard', '--source', source, '--mode', 'acquire')
                self.assertEqual(result.returncode, 2)
                self.assertIn('dispositivo de bloque', result.stderr)

    def test_fs_check_reads_signature_and_refuses_unknown(self):
        boot = self.root / 'sources' / 'boot.bin'
        payload = bytearray(512)
        payload[82:90] = b'FAT32   '
        boot.write_bytes(bytes(payload))
        result = self.helper('fs-check', '--source', boot, '--expected', 'vfat')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'observado': 'vfat32'})
        boot.write_bytes(bytes(512))
        self.assertEqual(self.helper('fs-check', '--source', boot,
                                     '--expected', 'vfat').returncode, 2)

    def test_zero_check_detects_nonzero_tail(self):
        clean = self.root / 'sources' / 'clean.bin'
        clean.write_bytes(bytes(8192))
        self.assertEqual(self.helper('zero-check', '--source', clean).returncode, 0)
        dirty = self.root / 'sources' / 'dirty.bin'
        dirty.write_bytes(bytes(8191) + b'\x01')
        self.assertEqual(self.helper('zero-check', '--source', dirty).returncode, 2)

    def test_private_paths_refuse_existing_symlink_and_wide_modes(self):
        wide = self.root / 'sources' / 'wide'
        wide.mkdir(mode=0o755)
        self.assertEqual(self.helper('mkdir', '--path', wide).returncode, 2)
        target = self.root / 'sources' / 'exists'
        target.write_text('synthetic')
        self.assertEqual(self.helper('reserve', '--path', target).returncode, 2)
        link = self.root / 'sources' / 'link'
        link.symlink_to(target)
        self.assertEqual(self.helper('reserve', '--path', link).returncode, 2)

    def test_report_path_only_resolves_finished_triage(self):
        tree = self.triage_tree({'uno.txt': b'texto\n'})
        self.assertEqual(self.invoke('triage', tree).returncode, 0)
        run_dir = self.runs('triage')[-1].parent
        result = self.helper('report-path', '--run', run_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()),
                         run_dir / 'analysis' / 'report.json')
        self.assertEqual(self.helper('report-path', '--run',
                                     self.root / 'sources').returncode, 2)


if __name__ == '__main__':
    unittest.main()
