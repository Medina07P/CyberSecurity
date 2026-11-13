import json
from enumeration_fixture import EnumerationFixture


class ReportTests(EnumerationFixture):
    def collect(self, host):
        script = '''import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from lib.engine import collect
r=collect(Path(sys.argv[2])/'scans',Path(sys.argv[2]),sys.argv[3])
print(json.dumps({'findings':[{'type':f.rule,'host':f.activo,'key':f.key} for f in r.findings],'no_evaluable':r.no_evaluable}))
'''
        return self.shell(f'python3 -c {__import__("shlex").quote(script)} "{self.fw}/11_Reports" "{self.fw.parent}" {host}')

    def test_new_ssh_and_database_findings_belong_to_correct_target(self):
        for host in ('example.invalid','other.invalid'):
            self.assertEqual(self.leaf('ssh/enum_ssh.sh',host).returncode,0)
            self.assertEqual(self.leaf('database/enum_mysql.sh',host).returncode,0)
        result = self.collect('example.invalid')
        self.assertEqual(result.returncode,0,result.stderr)
        findings = json.loads(result.stdout)['findings']
        self.assertEqual(len(findings),2, findings)
        self.assertTrue(all(f['host'] == 'example.invalid' for f in findings))

    def test_failed_attempt_does_not_reuse_prior_mysql_access(self):
        self.assertEqual(self.leaf('database/enum_mysql.sh','example.invalid').returncode,0)
        self.assertNotEqual(self.leaf('database/enum_mysql.sh','example.invalid',FAKE_FAIL='mysql').returncode,0)
        result = self.collect('example.invalid')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['findings'],[])
        self.assertTrue(json.loads(result.stdout)['no_evaluable'])

    def test_viewer_filters_exact_host_and_labels_unattributed_legacy(self):
        for host in ('example.invalid','other.invalid'):
            self.assertEqual(self.leaf('database/enum_mysql.sh',host).returncode,0)
        result = self.leaf('show_results.sh','example.invalid')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('example.invalid',result.stdout)
        self.assertNotIn('other.invalid',result.stdout)
        legacy = self.scans/'database/anon.txt'; legacy.write_text('legacy sin host\n')
        result = self.leaf('show_results.sh')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('sin atribución',result.stdout)

    def test_long_host_is_attributed_by_metadata(self):
        host = '.'.join(['a'*60]*3+['invalid'])
        result = self.leaf('database/enum_mysql.sh',host)
        self.assertEqual(result.returncode,0,result.stderr)
        result = self.collect(host)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(json.loads(result.stdout)['findings']),1)

    def test_api_method_observation_requires_matching_url_and_not_catchall(self):
        folder = self.scans/'api'; folder.mkdir(parents=True)
        path = folder/'methods_example.invalid_8080.tsv'
        path.write_text('metodo\tcodigo\turl\tclasificacion\nPUT\t204\thttp://example.invalid:8080/api\tRESPUESTA_2XX\nDELETE\t200\thttp://example.invalid:8080/api\tCATCH_ALL\nPATCH\t204\thttp://other.invalid/api\tRESPUESTA_2XX\n')
        Path = __import__('pathlib').Path
        Path(str(path)+'.meta.json').write_text(json.dumps({'version':1,'host':'example.invalid','puerto':8080,'estado':'EJECUTADO'}))
        result = self.collect('example.invalid')
        self.assertEqual(result.returncode,0,result.stderr)
        findings = json.loads(result.stdout)['findings']
        self.assertEqual(len(findings),1)
        self.assertEqual(findings[0]['host'],'example.invalid')
