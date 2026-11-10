import json
from enumeration_fixture import EnumerationFixture


class HttpTests(EnumerationFixture):
    def test_api_keeps_all_endpoints_methods_and_documents(self):
        result = self.leaf('api/enum_api.sh', 'example.invalid', '8080')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        calls = self.invoked('curl')
        methods = {c['args'][c['args'].index('-X')+1] for c in calls if '-X' in c['args']}
        self.assertEqual(methods, {'GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'})
        urls = {c['args'][c['args'].index('--url')+1] for c in calls if '--url' in c['args']}
        for endpoint in ('/api','/v1','/v2','/rest','/graphql','/swagger','/docs','/openapi','/apidocs','/api/v1','/api/v2','/api/rest','/swagger.json','/openapi.json','/api-docs'):
            self.assertIn('http://example.invalid:8080'+endpoint, urls)
        self.assertTrue(list((self.scans/'api').glob('methods_*.tsv')))

    def test_web_capabilities_and_explicit_url_are_preserved(self):
        result = self.leaf('web/enum_web.sh', '--url', 'https://example.invalid:9443/base?x=1')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(len(self.invoked('whatweb')), 1)
        self.assertEqual(len(self.invoked('ffuf')), 1)
        curls = self.invoked('curl')
        urls = [c['args'][c['args'].index('--url')+1] for c in curls]
        self.assertIn('https://example.invalid:9443/base?x=1', urls)
        self.assertTrue(any('/base/robots.txt?x=1' in u for u in urls))
        self.assertTrue(any('/base/sitemap.xml?x=1' in u for u in urls))
        self.assertTrue(list((self.scans/'web').glob('ffuf_*.json')))

    def test_advanced_web_keeps_ports_and_sensitive_paths(self):
        result = self.leaf('web/enum_web_advanced.sh', 'example.invalid')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        urls = [c['args'][c['args'].index('--url')+1] for c in self.invoked('curl')]
        for port in (80,443,8080,8443,8000,8888,9000):
            self.assertTrue(any(':'+str(port)+'/' in url for url in urls))
        for path in ('.env','.git/config','backup.zip','config.php','wp-config.php','.htaccess','admin.php'):
            self.assertTrue(any('/'+path in url for url in urls))

    def test_catchall_not_reported_as_api_methods_or_sensitive_files(self):
        result = self.leaf('api/enum_api.sh', 'example.invalid', CURL_MODE='catchall')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        methods = list((self.scans/'api').glob('methods_*.tsv'))
        self.assertTrue(methods)
        self.assertNotIn('RESPUESTA_2XX', methods[0].read_text())
        self.assertIn('CATCH_ALL', methods[0].read_text())

    def test_http_transport_failure_is_not_a_clean_result(self):
        for path in ('api/enum_api.sh','web/enum_web.sh','web/enum_web_advanced.sh'):
            with self.subTest(path=path):
                result = self.leaf(path, 'example.invalid', CURL_MODE='down')
                self.assertEqual(result.returncode, 1, result.stdout+result.stderr)

    def test_429_stops_method_batch_after_one_retry(self):
        result = self.leaf('api/enum_api.sh', 'example.invalid', CURL_MODE='block', CURL_BLOCK_METHOD='POST')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        methods = [c['args'][c['args'].index('-X')+1] for c in self.invoked('curl')]
        self.assertEqual(methods.count('POST'), 2)
        self.assertNotIn('PUT', methods)
        self.assertNotIn('DELETE', methods)
        self.assertFalse(list((self.scans/'api').glob('methods_*.tsv')))

    def test_fuzzing_block_is_failure_not_a_finding(self):
        result = self.leaf('web/enum_web.sh', 'example.invalid', FAKE_FFUF_BLOCK='1')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertFalse(list((self.scans/'web').glob('ffuf_*.json')))

    def test_long_url_uses_bounded_names_without_changing_network_url(self):
        url = 'https://example.invalid:9443/'+('x'*280)+'?q=1'
        result = self.leaf('api/enum_api.sh', '--url', url)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(any(url in c['args'] for c in self.invoked('curl')))
        for path in self.scans.rglob('*'):
            self.assertLessEqual(len(path.name.encode()), 240)

    def test_failed_http_rerun_invalidates_old_evidence_without_truncating(self):
        result = self.leaf('api/enum_api.sh','example.invalid')
        self.assertEqual(result.returncode,0,result.stderr)
        path = next((self.scans/'api').glob('methods_*.tsv'))
        old = path.read_bytes()
        result = self.leaf('api/enum_api.sh','example.invalid',CURL_MODE='down')
        self.assertEqual(result.returncode,1)
        self.assertEqual(path.read_bytes(),old)
        self.assertEqual(json.loads(__import__('pathlib').Path(str(path)+'.attempt.json').read_text())['estado'],'NO_DETERMINADO')
