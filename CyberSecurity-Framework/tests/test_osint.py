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


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        RuntimeTests.setUp(self)
        self.assertTrue((LIB/'osint/discovery.py').exists(), 'Falta descubrimiento real de perfiles')
        from osint import discovery
        self.d = discovery
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.run = Run('example.test', Path(self.tmp.name), Limits())

    def test_no_generated_profile_urls(self):
        self.assertEqual(self.d.extract_profiles('Example Corp', 'https://example.test/', True), [])

    def test_official_link_not_ownership(self):
        evidence = self.d.extract_profiles('<a href="https://github.com/example">Org</a>', 'https://example.test/', True)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].attribution, 'vinculado_desde_sitio')

    def test_name_match_is_candidate(self):
        evidence = self.d.extract_profiles('<a href="https://github.com/example">Org</a>', 'https://search.test/', False)
        self.assertEqual(evidence[0].attribution, 'candidato')

    def test_social_host_and_route_validation(self):
        urls = ['https://github.com.attacker.test/example', 'javascript:alert(1)', 'https://github.com/search?q=example',
                'https://facebook.com/sharer.php?u=x', 'https://instagram.com/p/post', 'https://x.com/login',
                'https://github.com/login?return_to=example', 'https://github.com@example.test/acme']
        self.assertEqual(self.d.extract_profiles(''.join(f'<a href="{u}">x</a>' for u in urls), 'https://example.test/', True), [])
        good = ['https://www.linkedin.com/company/acme', 'https://x.com/acme', 'https://github.com/acme',
                'https://instagram.com/acme/', 'https://www.facebook.com/acme', 'https://www.tiktok.com/@acme']
        self.assertEqual(len(self.d.extract_profiles(''.join(f'<a href="{u}">x</a>' for u in good), 'https://example.test/', True)), 6)

    def test_mailto_normalized(self):
        rows = self.d.extract_emails('<a href="mailto:Info%40example.test?subject=Hi">Info</a> info@example.test', 'example.test', 'site')
        self.assertEqual([e.value for e in rows], ['info@example.test'])

    def test_email_domain_boundary(self):
        rows = self.d.extract_emails('ok@example.test bad@example.test.attacker.test other@badexample.test', 'example.test', 'site')
        self.assertEqual([e.value for e in rows], ['ok@example.test'])

    def test_github_login_not_email(self):
        client = HttpClient(opener=lambda *a, **k: Response(body=b'{"total_count":1,"incomplete_results":false,"items":[{"login":"acme","html_url":"https://github.com/acme","type":"Organization"}]}'))
        results = self.d.discover_social(self.run, client, 'Acme', None, {})
        self.assertEqual([e.kind for r in results for e in r.evidence], ['profile'])
        self.assertEqual([e.value for r in results for e in r.evidence], ['https://github.com/acme'])

    def test_api_missing_coverage_visible(self):
        results = self.d.discover_social(self.run, HttpClient(opener=lambda *a, **k: Response(body=b'{"items":[],"total_count":0,"incomplete_results":false}')), 'Acme', None, {})
        self.assertTrue(any(r.source == 'brave' and r.status == 'skipped' for r in results))

    def test_hunter_header_and_real_emails(self):
        requests = []
        def opener(req, **kwargs):
            requests.append(req)
            if 'hunter.io' in req.full_url:
                return Response(body=b'{"data":{"emails":[{"value":"info@example.test","sources":[{"uri":"https://example.test/contact"}]}]},"meta":{"results":1}}')
            return Response(body=b'<html>contact info@example.test</html>', url='https://example.test/')
        self.run.secrets.append('hunter-fixture-key')
        results = self.d.discover_emails(self.run, HttpClient(opener=opener), 'example.test', {'hunter':'hunter-fixture-key'})
        hunter = next(r for r in results if r.source == 'hunter')
        self.assertEqual([e.value for e in hunter.evidence], ['info@example.test'])
        request = next(req for req in requests if 'hunter.io' in req.full_url)
        self.assertNotIn('hunter-fixture-key', request.full_url)
        self.assertEqual(request.get_header('X-api-key'), 'hunter-fixture-key')

    def test_malformed_api_shape_fails(self):
        results = self.d.discover_social(self.run, HttpClient(opener=lambda *a, **k: Response(body=b'{"error":"denied"}')), 'Acme', None, {'brave':'key'})
        self.assertTrue(all(r.status == 'failed' for r in results))

    def test_redirected_official_site_does_not_attribute(self):
        def opener(req, **kwargs):
            if 'api.github' in req.full_url:
                return Response(body=b'{"items":[],"total_count":0,"incomplete_results":false}')
            return Response(body=b'<a href="https://github.com/other">Other</a>', url='https://unrelated.test/')
        results = self.d.discover_social(self.run, HttpClient(opener=opener), 'Acme', 'example.test', {})
        rows = [e for r in results for e in r.evidence if e.kind == 'profile']
        self.assertEqual(rows[0].attribution, 'candidato')


if __name__ == '__main__':
    unittest.main()
