"""OSINT: fixtures locales; nunca usar red externa ni credenciales reales."""
import io
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

LIB = Path(__file__).resolve().parents[1] / '00_Config/lib'
sys.path.insert(0, str(LIB))

try:
    from osint.model import Evidence, Limits, Run, SourceResult
    from osint.runtime import HttpClient, SourceError, exit_code, run_tool, write_run
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


class Response(io.BytesIO):
    def __init__(self, status=200, body=b'{}', headers=None, url='https://example.test/'):
        super().__init__(body)
        self.status, self.headers, self.url = status, headers or {}, url

    def geturl(self):
        return self.url


class Clock:
    def __init__(self):
        self.now, self.waits = 0., []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(AVAILABLE, 'Falta el núcleo OSINT compartido')
        self.network = patch.object(socket, 'create_connection', side_effect=AssertionError('red real prohibida'))
        self.network.start()
        self.addCleanup(self.network.stop)

    def test_failed_sources_exit_one(self):
        for state in ('failed', 'blocked', 'timeout'):
            self.assertEqual(exit_code([SourceResult('web', state, [])]), 1)

    def test_only_skipped_exit_one(self):
        self.assertEqual(exit_code([SourceResult('brave', 'skipped', [])]), 1)
        self.assertEqual(exit_code([]), 1)

    def test_empty_success_exits_zero(self):
        self.assertEqual(exit_code([SourceResult('web', 'empty', []), SourceResult('brave', 'skipped', [])]), 0)

    def test_runs_do_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = [Run('Example Corp', Path(tmp), Limits()) for _ in range(2)]
            for run in runs:
                run.secrets.append('secret-fixture')
                run.results.append(SourceResult('web', 'failed', [], 'error secret-fixture'))
            paths = [write_run(run) for run in runs]
            self.assertNotEqual(paths[0], paths[1])
            for path in paths:
                text = (path/'resultados.json').read_text()
                self.assertNotIn('secret-fixture', text)
                self.assertEqual(json.loads(text)['version'], 1)
                self.assertIn('[REDACTADO]', (path/'errores.log').read_text())
                self.assertTrue((path/'resumen.txt').exists())

    def test_limits_reject_increase(self):
        for kwargs in ({'api_calls': 11}, {'dns_qps': 6}, {'request_seconds': 16}, {'dns_candidates': 1001}, {'dns_workers': 3}, {'tool_seconds': 121}):
            with self.assertRaises(ValueError):
                Limits(**kwargs)

    def test_blocked_response_is_not_data(self):
        client = HttpClient(opener=lambda *a, **k: Response(403, b'login'))
        with self.assertRaises(SourceError) as cm:
            client.request('web', 'https://example.test/')
        self.assertEqual(cm.exception.status, 'blocked')

    def test_retry_after_seconds_and_date(self):
        for header in ('2', 'Thu, 01 Jan 1970 00:00:02 GMT'):
            clock = Clock()
            replies = iter([Response(429, headers={'Retry-After': header}), Response()])
            client = HttpClient(opener=lambda *a, **k: next(replies), clock=clock, sleep=clock.sleep, wall_clock=lambda: 0)
            self.assertEqual(client.request('brave', 'https://example.test/').status, 200)
            self.assertEqual(clock.waits, [2])

    def test_retry_after_over_budget_stops_without_sleep(self):
        clock = Clock()
        calls = []
        def opener(*a, **k):
            calls.append(1)
            return Response(503, headers={'Retry-After': '9999'})
        client = HttpClient(opener=opener, clock=clock, sleep=clock.sleep)
        with self.assertRaises(SourceError):
            client.request('web', 'https://example.test/')
        self.assertEqual(calls, [1])
        self.assertEqual(clock.waits, [])

    def test_persistent_429_503_stop_after_one_retry(self):
        for code in (429, 503):
            calls = []
            def opener(*a, **k):
                calls.append(1)
                return Response(code)
            with self.assertRaises(SourceError):
                HttpClient(opener=opener, sleep=lambda _: None).request('web', 'https://example.test/')
            self.assertEqual(len(calls), 2)

    def test_api_budget_counts_retries(self):
        calls = []
        def opener(*a, **k):
            calls.append(1)
            return Response(429 if len(calls) == 1 else 200)
        client = HttpClient(opener=opener, sleep=lambda _: None)
        for _ in range(9):
            client.request('github', 'https://example.test/')
        with self.assertRaises(SourceError):
            client.request('github', 'https://example.test/')
        self.assertEqual(len(calls), 10)

    def test_http_timeout_and_body_limit(self):
        with self.assertRaises(SourceError) as cm:
            HttpClient(opener=lambda *a, **k: (_ for _ in ()).throw(TimeoutError())).request('web', 'https://example.test/')
        self.assertEqual(cm.exception.status, 'timeout')
        with self.assertRaises(SourceError):
            HttpClient(opener=lambda *a, **k: Response(body=b'x' * (2*1024*1024+1))).request('web', 'https://example.test/')

    def test_tool_failure_and_missing_command(self):
        with self.assertRaises(SourceError):
            run_tool(['/nonexistent/osint-tool'], 1)
        with self.assertRaises(SourceError):
            run_tool([sys.executable, '-c', 'raise SystemExit(7)'], 1)
        with self.assertRaises(SourceError) as cm:
            run_tool([sys.executable, '-c', 'import time;time.sleep(2)'], .01)
        self.assertEqual(cm.exception.status, 'timeout')


class SourcesTests(unittest.TestCase):
    def setUp(self):
        RuntimeTests.setUp(self)
        self.assertTrue((LIB/'osint/credentials.py').exists(), 'Falta lectura de claves OSINT')
        from osint import credentials, sources
        self.credentials, self.sources = credentials, sources
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run = Run('example.test', self.root, Limits())

    def test_registry_precedence_without_writes(self):
        reg, one, two = self.root/'keys.yaml', self.root/'one', self.root/'two'
        one.mkdir(); two.mkdir()
        reg.write_text('theharvester:\n  brave:\n    key: registry-key\n')
        (one/'api-keys.yaml').write_text('apikeys:\n  brave:\n    key: old-key\n  github:\n    key: github-key\n')
        (two/'api-keys.yaml').write_text('apikeys:\n  hunter:\n    key: ignored-key\n')
        before = {p: p.read_bytes() for p in (reg, one/'api-keys.yaml', two/'api-keys.yaml')}
        self.assertEqual(self.credentials.load_credentials(reg, [one, two]), {'brave': 'registry-key', 'github': 'github-key'})
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_missing_keys_skip(self):
        self.assertEqual(self.credentials.load_credentials(self.root/'none', []), {})

    def test_corrupt_yaml_no_secret_leak(self):
        reg = self.root/'bad.yaml'
        reg.write_text('secret-fixture: [oops')
        with self.assertRaises(ValueError) as cm:
            self.credentials.load_credentials(reg, [])
        self.assertNotIn('secret-fixture', str(cm.exception))

    def test_crtsh_invalid_json_fails(self):
        client = HttpClient(opener=lambda *a, **k: Response(body=b'<html>blocked</html>'))
        result = self.sources.collect_certificates(self.run, client, 'example.test')
        self.assertEqual(result.status, 'failed')
        self.assertEqual(result.evidence, [])

    def test_certificate_scope_boundary(self):
        body = json.dumps([{'name_value': 'www.example.test\n*.example.test\nexampleXtest\nbadexample.test\nexample.test.attacker.test'}]).encode()
        result = self.sources.collect_certificates(self.run, HttpClient(opener=lambda *a, **k: Response(body=body)), 'example.test')
        self.assertEqual([(e.kind, e.value) for e in result.evidence], [('subdomain', 'www.example.test')])

    def test_shared_collection_once(self):
        calls = []
        def opener(*a, **k):
            calls.append(1)
            return Response(body=b'<a href="https://github.com/acme">GitHub</a>')
        client = HttpClient(opener=opener)
        first = self.sources.collect_site(self.run, client, 'https://example.test/')
        second = self.sources.collect_site(self.run, client, 'https://example.test/')
        self.assertIs(first, second)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(self.run.results), 1)
        self.assertIn('github.com/acme', self.run.cache['site:html'])

    def test_harvester_selected_sources(self):
        # El wrapper no debe esconder fallos/reintentos opacos de terceros.
        with patch('osint.sources.run_tool', side_effect=AssertionError('No ejecutar all')):
            result = self.sources.collect_tool(self.run, 'theHarvester', 'example.test')
        self.assertEqual(result.status, 'skipped')
        self.assertIn('presupuesto', result.error)

    def test_provider_error_redacted(self):
        self.run.secrets.append('secret-fixture')
        result = self.sources.collect_site(self.run, HttpClient(opener=lambda *a, **k: (_ for _ in ()).throw(OSError('secret-fixture'))), 'https://example.test/')
        self.assertEqual(result.status, 'failed')
        self.assertNotIn('secret-fixture', result.error)


if __name__ == '__main__':
    unittest.main()
