"""SSTI real contra fixture local y copia de fuentes/configuración sintéticas."""
import csv
import html
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer


FW = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ssti_http_fixture', FW / 'tests/fixtures/http_target.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class Handler(fixture.Manejador):
    def do_GET(self):
        if self.path.startswith('/ssti49?'):
            value = self._valor()
            result = '49' if '{{7*7}}' in value else html.escape(value)
            self._responder(200, '<html>49 resultados; reflejo: %s</html>' % result)
        else:
            super().do_GET()


class SstiBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = self.root / 'fw'
        shutil.copytree(FW / '00_Config/lib', self.fw / '00_Config/lib')
        self.script = self.fw / '05_Exploitation/web/http_inject.sh'
        self.script.parent.mkdir(parents=True)
        shutil.copy2(FW / '05_Exploitation/web/http_inject.sh', self.script)
        self.config = self.fw / '00_Config'
        (self.config / 'scope.yaml').write_text('targets:\n  ips: [127.0.0.1]\n')
        (self.config / 'targets.txt').write_text('127.0.0.1|80|HTTP|Fixture|B\n')
        (self.root / 'home').mkdir()

    def check_endpoint(self, endpoint, seed, expected):
        port = self.server.server_port
        request = self.root / 'input.req'
        request.write_text(f'GET /{endpoint}?name=x HTTP/1.1\nHost: 127.0.0.1:{port}\n\n')
        env = {'PATH':os.environ['PATH'], 'HOME':str(self.root / 'home'),
               'LC_ALL':'C.UTF-8', 'HTTP_INJECT_SI':'1', 'HTTP_INJECT_RETARDO':'0',
               'HTTP_INJECT_UMBRAL':'.5', 'SESSION_CONFIG_DIR':str(self.config),
               'SESSION_SCOPE_FILE':str(self.config / 'scope.yaml'),
               'SESSION_TARGETS_FILE':str(self.config / 'targets.txt'),
               'SESSION_FILE':str(self.root / 'session')}
        result = subprocess.run(['bash', '-c', 'RANDOM=$1; shift; source "$@"',
                                 'probe', str(seed), str(self.script), str(request), '127.0.0.1'],
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        path = self.root / f'scans/web/http_inject_127.0.0.1_{port}.tsv'
        with path.open() as stream:
            rows = list(csv.DictReader(stream, delimiter='\t', quoting=csv.QUOTE_NONE))
        confirmed = [r for r in rows if r['nivel'] == 'CONFIRMADO' and r['clase'] == 'ssti']
        self.assertEqual(len(confirmed), expected, rows)
        if expected:
            self.assertEqual(confirmed[0]['payload'], '{{7*7}}')

    def test_ssti_without_token_collision(self):
        self.check_endpoint('ssti', 1, 1)

    def test_ssti_token_containing_49_does_not_hide_evaluation(self):
        self.check_endpoint('ssti', 5, 1)

    def test_real_49_in_baseline_still_vetoes_confirmation(self):
        for seed in (1, 5):
            with self.subTest(seed=seed):
                self.check_endpoint('mostrar49', seed, 0)

    def test_real_49_next_to_reflected_token_still_vetoes_confirmation(self):
        for seed in (1, 5):
            with self.subTest(seed=seed):
                self.check_endpoint('ssti49', seed, 0)

    def test_echo_of_token_containing_49_is_not_evaluation(self):
        self.check_endpoint('echo', 5, 0)


if __name__ == '__main__':
    unittest.main()
