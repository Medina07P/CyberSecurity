import hashlib
import re
from enumeration_fixture import EnumerationFixture


class MenuTests(EnumerationFixture):
    def menu(self, inputs, target='example.invalid'):
        if target: __import__('pathlib').Path(self.env['SESSION_FILE']).write_text(target+'\n')
        result = self.shell(f'bash "{self.fw}/cyber_framework.sh"', inputs)
        result.stdout = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', result.stdout)
        return result

    def test_local_checks_and_all_sixteen_entries_remain_available(self):
        result = self.menu('04\n1\n\n11\n0\n0\nQ\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('COMPROBACIÓN LOCAL',result.stdout)
        self.assertIn('16 scripts',result.stdout)
        self.assertIn('[generador]',result.stdout)
        self.assertEqual(self.invoked(),[])

    def test_ssh_guided_parameters_reach_all_original_operations(self):
        result = self.menu('04\n2\n\n\ns\n\n0\nQ\n')
        self.assertEqual(result.returncode,0,result.stderr)
        calls = self.invoked('nmap')
        self.assertTrue(calls,result.stdout+result.stderr)
        args = [' '.join(c['args']) for c in calls]
        self.assertTrue(any('--script ssh-enum-users' in a for a in args))
        self.assertTrue(all('example.invalid' in c['args'] for c in calls if '--script-help' not in c['args']))

    def test_api_menu_keeps_modifying_methods_after_confirmation(self):
        result = self.menu('04\n8\nhttps://example.invalid:9443/base\ns\n\n0\nQ\n')
        self.assertEqual(result.returncode,0,result.stderr)
        methods = {c['args'][c['args'].index('-X')+1] for c in self.invoked('curl')}
        self.assertEqual(methods,{'GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'},result.stdout+result.stderr)
        self.assertIn('DELETE',result.stdout)

    def test_cancellation_eof_and_generator_denial_have_no_effects(self):
        for inputs in ('04\n2\n','04\n2\n!\n0\nQ\n','04\n2\n\n\nn\n0\nQ\n',
                       '04\n8\nhttps://example.invalid\n','04\n8\nhttps://example.invalid\nn\n0\nQ\n',
                       '04\n9\n!\n0\nQ\n','04\n11\n12\nn\n0\n0\nQ\n',
                       '04\n11\n14\nn\n0\n0\nQ\n'):
            with self.subTest(inputs=inputs):
                initial = {str(p): hashlib.sha256(p.read_bytes()).digest() for p in (self.fw/'04_Enumeration').rglob('*.sh')}
                result = self.menu(inputs)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(self.invoked(),[],result.stdout+result.stderr)
                self.assertEqual(initial,{str(p): hashlib.sha256(p.read_bytes()).digest() for p in (self.fw/'04_Enumeration').rglob('*.sh')})

    def test_no_session_does_not_use_example_target(self):
        result = self.menu('04\n2\n\n0\nQ\n',target=None)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.invoked(),[])
        self.assertIn('sin definir',result.stdout)
