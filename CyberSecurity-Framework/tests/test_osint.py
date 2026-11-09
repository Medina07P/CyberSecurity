"""OSINT: fixtures locales; nunca usar red externa ni credenciales reales."""
import io
import http.client
import json
import os
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import ProxyHandler, build_opener
import socket
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

LIB = Path(__file__).resolve().parents[1] / '00_Config/lib'
REAL_CREATE_CONNECTION = socket.create_connection
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

    def test_json_escaped_secret_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Run('example.test', Path(tmp), Limits())
            run.secrets.append('key"with\\escape')
            run.results.append(SourceResult('web', 'failed', [], 'provider echoed key"with\\escape'))
            path = write_run(run)
            data = json.loads((path/'resultados.json').read_text())
            self.assertNotIn('key"with\\escape', data['sources'][0]['error'])

    def test_drip_response_obeys_absolute_deadline(self):
        class Drip(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '20')
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b'x'); self.wfile.flush()
                        time.sleep(.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Drip)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.01), daemon=True)
        thread.start()
        try:
            # Única excepción a la guarda de red: servidor propio en loopback.
            with patch.object(socket, 'create_connection', REAL_CREATE_CONNECTION):
                client = HttpClient(Limits(request_seconds=.05, tool_seconds=.12), opener=build_opener(ProxyHandler({})).open)
                started = time.monotonic()
                with self.assertRaises(SourceError) as cm:
                    client.request('web', f'http://127.0.0.1:{server.server_port}/')
                self.assertEqual(cm.exception.status, 'timeout')
                self.assertLess(time.monotonic()-started, .20)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=1)


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

    def test_protocol_error_redacted_and_recorded(self):
        self.run.secrets.append('secret-fixture')
        def opener(*args, **kwargs):
            raise http.client.BadStatusLine('provider echoed secret-fixture')
        result = self.sources.collect_site(self.run, HttpClient(opener=opener), 'https://example.test/')
        self.assertEqual(result.status, 'failed')
        self.assertEqual(result.evidence, [])
        self.assertNotIn('secret-fixture', result.error)

    def test_whatweb_exit_zero_stderr_failure(self):
        self.run.secrets.append('secret-fixture')
        output = subprocess.CompletedProcess([], 0, '', 'ERROR Opening: Connection refused secret-fixture')
        with patch('osint.sources.run_tool', return_value=output):
            result = self.sources.collect_tool(self.run, 'whatweb', 'example.test')
        self.assertEqual(result.status, 'failed')
        self.assertEqual(result.evidence, [])
        self.assertIn('Connection refused', result.error)
        self.assertNotIn('secret-fixture', result.error)
        self.assertEqual(exit_code(self.run.results), 1)


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

    def test_special_routes_are_not_profiles(self):
        for url in ('https://facebook.com/l.php?u=https%3A%2F%2Felsewhere.test',
                    'https://facebook.com/profile.php', 'https://github.com/topics',
                    'https://github.com/collections', 'https://github.com/orgs'):
            self.assertIsNone(self.d.profile_url(url), url)

    def test_facebook_numeric_profile_preserves_identity(self):
        self.assertEqual(self.d.profile_url('https://www.facebook.com/profile.php?id=1234&tracking=foo'),
                         'https://facebook.com/profile.php?id=1234')
        self.assertIsNone(self.d.profile_url('https://facebook.com/profile.php?id=1234&id=5678'))

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


class DnsTests(unittest.TestCase):
    def setUp(self):
        RuntimeTests.setUp(self)
        self.assertTrue((LIB/'osint/dns.py').exists(), 'Falta DNS acotado')
        from osint import dns
        self.dns = dns
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run = Run('example.test', self.root, Limits())
        self.wordlist = self.root/'words.txt'
        self.wordlist.write_text('www\nmail\n')

    def test_domain_normalization(self):
        self.assertEqual(self.dns.normalize_domain('ÉXAMPLE.test.'), 'xn--xample-9ua.test')
        for value in ('127.0.0.1', '-bad.test', 'https://example.test/', 'example.test:443', 'bad..test', 'a'*64+'.test'):
            with self.assertRaises(ValueError):
                self.dns.normalize_domain(value)

    def test_active_requires_confirmation(self):
        with patch('osint.dns.resolve_name', side_effect=AssertionError('No DNS sin permiso')):
            with self.assertRaises(ValueError):
                self.dns.enumerate_dns(self.run, 'example.test', self.wordlist, None, False)

    def test_wordlist_limit_1000(self):
        self.wordlist.write_text('\n'.join(f'host{i}' for i in range(1001)))
        with patch('osint.dns.resolve_name', side_effect=AssertionError('Validar antes de consultar')):
            with self.assertRaises(ValueError):
                self.dns.enumerate_dns(self.run, 'example.test', self.wordlist, None, True)

    def test_wordlist_deduplicates_and_rejects_invalid(self):
        self.wordlist.write_text('www\nWWW\n# comment\nmail\n')
        self.assertEqual(self.dns.load_wordlist(self.wordlist, 'example.test', 1000), ['www.example.test', 'mail.example.test'])
        self.wordlist.write_text('www;touch-file\n')
        with self.assertRaises(ValueError):
            self.dns.load_wordlist(self.wordlist, 'example.test', 1000)

    def test_dns_nxdomain_not_failure(self):
        clock = Clock()
        with patch('osint.dns.run_tool', return_value=subprocess.CompletedProcess([], 0, ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n', '')):
            result = self.dns.resolve_name('missing.example.test', None, self.dns.DnsLimiter(clock=clock, sleep=clock.sleep))
        self.assertEqual(result.status, 'absent')

    def test_dns_servfail_not_absence(self):
        with patch('osint.dns.run_tool', return_value=subprocess.CompletedProcess([], 0, ';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n', '')):
            result = self.dns.resolve_name('www.example.test', None, self.dns.DnsLimiter())
        self.assertEqual(result.status, 'failed')

    def test_wildcard_ambiguous(self):
        with patch('osint.dns.resolve_name', side_effect=lambda name, *args: self.dns.DnsAnswer(name, 'resolved', {'A':['192.0.2.1']})):
            result = self.dns.enumerate_dns(self.run, 'example.test', self.wordlist, None, True)
        self.assertEqual([e.attribution for e in result.evidence], ['ambiguo_wildcard', 'ambiguo_wildcard'])

    def test_rotating_wildcard_not_confirmed(self):
        count = 0
        def resolve(name, *args):
            nonlocal count
            count += 1
            return self.dns.DnsAnswer(name, 'resolved', {'A':[f'192.0.2.{count}']})
        with patch('osint.dns.resolve_name', side_effect=resolve):
            result = self.dns.enumerate_dns(self.run, 'example.test', self.wordlist, None, True)
        self.assertTrue(all(e.attribution == 'ambiguo_wildcard' for e in result.evidence))

    def test_global_qps_includes_controls(self):
        clock = Clock()
        limiter = self.dns.DnsLimiter(clock=clock, sleep=clock.sleep)
        queried = []
        def tool(argv, timeout):
            queried.append((clock(), argv))
            return subprocess.CompletedProcess(argv, 0, ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nwww.example.test. 60 IN A 192.0.2.1\n', '')
        with patch('osint.dns.run_tool', side_effect=tool):
            for name in ('random1.example.test', 'random2.example.test', 'random3.example.test', 'www.example.test'):
                self.dns.resolve_name(name, None, limiter)
        self.assertEqual(len(queried), 12)
        self.assertTrue(all(b[0]-a[0] >= .199999 for a,b in zip(queried, queried[1:])))
        self.assertTrue(all('+tries=1' in argv for _,argv in queried))
        self.assertTrue(all(not any(arg.startswith('@') for arg in argv) for _,argv in queried))

    def test_dns_workers_at_most_two(self):
        import threading
        active, peak = 0, 0
        lock = threading.Lock()
        def resolve(name, *args):
            nonlocal active, peak
            with lock:
                active += 1; peak = max(peak, active)
            with lock:
                active -= 1
            return self.dns.DnsAnswer(name, 'absent', {})
        with patch('osint.dns.resolve_name', side_effect=resolve):
            result = self.dns.enumerate_dns(self.run, 'example.test', self.wordlist, None, True)
        self.assertLessEqual(peak, 2)
        self.assertEqual(result.status, 'empty')

    def test_persistent_failures_stop(self):
        self.wordlist.write_text('\n'.join(f'host{i}' for i in range(10)))
        names = []
        def resolve(name, *args):
            names.append(name)
            return self.dns.DnsAnswer(name, 'absent' if name.startswith('osint-control-') else 'failed', {})
        with patch('osint.dns.resolve_name', side_effect=resolve):
            result = self.dns.enumerate_dns(self.run, 'example.test', self.wordlist, None, True)
        self.assertEqual(result.status, 'failed')
        self.assertEqual(len(names), 6)  # tres controles + tres candidatos fallidos


class CliTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((LIB/'osint/cli.py').exists(), 'Falta integrar OSINT con las entradas del gestor')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = self.root/'framework'
        source = LIB.parents[1]
        shutil.copytree(source/'01_OSINT/scripts', self.fw/'01_OSINT/scripts')
        shutil.copy2(source/'01_OSINT/run_all_osint.sh', self.fw/'01_OSINT/run_all_osint.sh')
        shutil.copytree(LIB/'osint', self.fw/'00_Config/lib/osint', ignore=shutil.ignore_patterns('__pycache__'))
        bin_dir = self.root/'bin'; bin_dir.mkdir()
        for tool in ('whois', 'whatweb', 'file', 'pdfinfo', 'exiftool', 'strings', 'dig'):
            path = bin_dir/tool
            text = '#!/bin/bash\nprintf "%s\\n" "'+tool+' $*" >> "$OSINT_TOOL_LOG"\n'
            if tool == 'dig':
                text += 'echo ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1"\n'
            elif tool == 'file':
                text += 'echo application/pdf\n'
            elif tool == 'pdfinfo':
                text += '[[ "$OSINT_FIXTURE_MODE" == "metadata-fail" ]] && exit 7\necho "Author: fixture"\n'
            else:
                text += 'echo "fixture '+tool+' output"\n'
            path.write_text(text); path.chmod(0o755)
        fixture_path = Path(__file__).parent/'fixtures/osint'
        (self.root/'sitecustomize.py').write_text('from osint_http_fixture import install\ninstall()\n')
        self.env = dict(os.environ, HOME=str(self.root/'home'), KEYS_FILE=str(self.root/'keys.yaml'),
                        KEYS_HARVESTER_DIRS=str(self.root/'keys'), PYTHONDONTWRITEBYTECODE='1',
                        PYTHONPATH=os.pathsep.join([str(self.root), str(fixture_path)]),
                        PATH=str(bin_dir)+os.pathsep+os.environ['PATH'], OSINT_FIXTURE_LOG=str(self.root/'http.log'),
                        OSINT_TOOL_LOG=str(self.root/'tools.log'), OSINT_FIXTURE_MODE='normal')
        self.cwd = self.root/'caller'; self.cwd.mkdir()

    def launch(self, script, *args, stdin=''):
        return subprocess.run(['bash', str(self.fw/'01_OSINT'/script), *map(str,args)], cwd=self.cwd,
                              env=self.env, input=stdin, capture_output=True, text=True, timeout=15)

    def artifacts(self):
        return sorted(self.root.rglob('resultados.json'))

    def test_all_relative_file_and_shared_sources(self):
        (self.cwd/'document with spaces.pdf').write_bytes(b'%PDF-1.4 fixture')
        result = self.launch('run_all_osint.sh', 'example.test', 'document with spaces.pdf', 'Example Corp')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(self.artifacts()[0].read_text())
        self.assertEqual(data['target'], 'example.test')
        self.assertTrue(any(r['source'] == 'metadata' and r['status'] == 'ok' for r in data['sources']))
        requests = (self.root/'http.log').read_text().splitlines()
        self.assertEqual(requests.count('https://example.test/'), 1)
        self.assertEqual(sum('crt.sh' in row for row in requests), 1)
        self.assertFalse((self.cwd/'domains').exists())

    def test_all_partial_is_not_success(self):
        self.env['OSINT_FIXTURE_MODE'] = 'blocked'
        result = self.launch('run_all_osint.sh', 'example.test')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn('✅ OSINT completado', result.stdout)
        self.assertIn('BLOQUEADA', result.stdout)
        self.assertIn('HTTP 403', next(self.root.rglob('errores.log')).read_text())

    def test_metadata_extractor_failure(self):
        self.env['OSINT_FIXTURE_MODE'] = 'metadata-fail'
        file = self.cwd/'doc.pdf'; file.write_bytes(b'%PDF')
        result = self.launch('scripts/metadata_extractor.sh', 'doc.pdf', self.root/'output')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('FALLIDA', result.stdout)

    def test_all_does_not_bruteforce(self):
        result = self.launch('run_all_osint.sh', 'example.test')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        data = json.loads(self.artifacts()[0].read_text())
        self.assertFalse(any(r['source'] == 'dns_bruteforce' for r in data['sources']))
        self.assertNotIn('AXFR', (self.root/'tools.log').read_text())

    def test_menu_slots_and_confirm(self):
        wordlist = self.cwd/'words'; wordlist.write_text('www\n')
        result = self.launch('scripts/subdomain_finder.sh', 'example.test', self.root/'out', wordlist, stdin='NO\n')
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root/'http.log').exists())
        self.assertFalse((self.root/'tools.log').exists())
        result = self.launch('scripts/subdomain_finder.sh', 'example.test', self.root/'out', wordlist, stdin='DNS_SI\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('dns_bruteforce', self.artifacts()[0].read_text())

    def test_company_spaces_external_output_no_overwrite(self):
        output = self.root/'custom output'
        for _ in range(2):
            result = self.launch('scripts/social_media_search.sh', 'Example Corp', output)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('puede no estar ignorada', result.stderr)
        artifacts = sorted(output.rglob('resultados.json'))
        self.assertEqual(len(artifacts), 2)
        data = json.loads(artifacts[0].read_text())
        self.assertEqual(data['target'], 'Example Corp')
        self.assertIn('q=Example+Corp', (self.root/'http.log').read_text())

    def test_invalid_arguments_exit_two_without_requests(self):
        for args in ((), ('127.0.0.1',), ('example.test', 'missing.pdf')):
            result = self.launch('run_all_osint.sh', *args)
            self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertFalse((self.root/'http.log').exists())

    def test_menu_preserves_empty_middle_slot(self):
        fw = LIB.parents[1]
        code = 'source "$1/00_Config/lib/params.bash"; source "$1/00_Config/lib/prompt.bash"; session_target() { :; }; prompt_for_slots "$1/01_OSINT/run_all_osint.sh" 01_OSINT/run_all_osint.sh'
        result = subprocess.run(['bash', '-c', code, 'test', str(fw)], input='example.test\n\nExample Corp\n', capture_output=True, text=True, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'example.test\n\nExample Corp\n')

    def test_wrappers_directly_executable(self):
        module = LIB.parents[1]/'01_OSINT'
        for script in [module/'run_all_osint.sh', *(module/'scripts').glob('*.sh')]:
            self.assertTrue(os.access(script, os.X_OK), f'No ejecutable: {script.name}')


if __name__ == '__main__':
    unittest.main()
