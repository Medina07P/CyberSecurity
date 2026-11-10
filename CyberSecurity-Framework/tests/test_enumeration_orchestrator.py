from pathlib import Path
from enumeration_fixture import EnumerationFixture

CHILDREN = ('ssh/enum_ssh.sh','ftp/enum_ftp.sh','smb/enum_smb_advanced.sh',
            'ldap/enum_ldap.sh','web/enum_web.sh','database/enum_mysql.sh',
            'database/enum_postgres.sh','database/enum_redis.sh')


class OrchestratorTests(EnumerationFixture):
    def stub_children(self):
        for name in CHILDREN:
            path = self.fw/'04_Enumeration'/name
            path.write_text('''#!/bin/bash
python3 - "$0" "$@" <<'PY'
import json,os,sys
with open(os.environ['ENUM_CALLS'],'a') as f:
 f.write(json.dumps({'tool':'child','args':sys.argv[1:]})+'\\n')
PY
exit "${FAKE_CHILD_RC:-0}"
''')
            path.chmod(0o755)

    def test_orchestrator_discovery_failure_never_uses_old_result(self):
        self.stub_children()
        self.scans.mkdir(parents=True)
        (self.scans/'enum_services_example.invalid.gnmap').write_text('Ports: 22/open/tcp//ssh///\n')
        result = self.leaf('run_all_enum.sh','example.invalid',FAKE_FAIL='nmap')
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertEqual(self.invoked('child'),[])

    def test_all_original_children_and_8443_in_one_discovery(self):
        self.stub_children()
        result = self.leaf('run_all_enum.sh','example.invalid')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        calls = self.invoked('nmap')
        self.assertEqual(len(calls),1)
        self.assertIn('8443',calls[0]['args'][calls[0]['args'].index('-p')+1].split(','))
        children = self.invoked('child')
        self.assertEqual(len(children),11)
        self.assertTrue(all(c['args'][1] == 'example.invalid' for c in children))

    def test_child_failure_missing_script_and_invalid_timeout_are_failures(self):
        self.stub_children()
        result = self.leaf('run_all_enum.sh','example.invalid',FAKE_CHILD_RC='7')
        self.assertEqual(result.returncode,1)
        self.assertIn('Fallidas: 11',result.stdout)
        (self.fw/'04_Enumeration/ssh/enum_ssh.sh').unlink()
        result = self.leaf('run_all_enum.sh','example.invalid')
        self.assertEqual(result.returncode,1)
        result = self.leaf('run_all_enum.sh','example.invalid',ENUM_TIMEOUT='oops')
        self.assertEqual(result.returncode,1)

    def test_closed_and_filtered_are_distinct_and_not_executed(self):
        self.stub_children()
        for state in ('closed','filtered','open|filtered'):
            result = self.leaf('run_all_enum.sh','example.invalid',FAKE_PORT_STATE=state)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn(state,result.stdout)
        self.assertEqual(self.invoked('child'),[])

    def test_generators_keep_payloads_and_run_only_inside_fixture(self):
        expected = (self.fw/'04_Enumeration/web/enum_web.sh').read_bytes()
        result = self.leaf('web/deepseeenum_web.sh')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual((self.fw/'04_Enumeration/web/enum_web.sh').read_bytes(), expected)
        result = self.leaf('smb/enum_smb.sh')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.invoked(),[])
        result = self.leaf('smb/enum_smb.sh','example.invalid')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        args = [' '.join(c['args']) for c in self.invoked('smbclient')]
        for share in ('ADMIN$','IPC$','C$','public','share','documents','backup'):
            self.assertTrue(any('//example.invalid/'+share in a for a in args),share)
        self.assertTrue(self.invoked('enum4linux'))
        self.assertTrue(self.invoked('rpcclient'))
