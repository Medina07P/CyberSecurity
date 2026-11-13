from enumeration_fixture import EnumerationFixture

LEAVES = {'ssh': 'ssh/enum_ssh.sh', 'ftp': 'ftp/enum_ftp.sh',
          'ftp_anon': 'ftp/ftp_anonymous.sh', 'smb': 'smb/enum_smb_advanced.sh',
          'ldap': 'ldap/enum_ldap.sh', 'ldap_anon': 'ldap/ldap_anonymous.sh',
          'mysql': 'database/enum_mysql.sh', 'postgres': 'database/enum_postgres.sh',
          'redis': 'database/enum_redis.sh'}


class ServiceTests(EnumerationFixture):
    def test_every_leaf_propagates_failure(self):
        for name, path in LEAVES.items():
            with self.subTest(name=name):
                result = self.leaf(path, 'example.invalid', FAKE_FAIL='all')
                self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertNotIn('✅', result.stdout)

    def test_all_service_capabilities_remain_executable(self):
        for name, path in LEAVES.items():
            with self.subTest(name=name):
                result = self.leaf(path, 'example.invalid')
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        nmap_args = [' '.join(c['args']) for c in self.invoked('nmap')]
        for script in ('ssh-auth-methods', 'ssh-enum-users', 'ssh2-enum-algos',
                       'ftp-*', 'smb-enum*,smb-os-discovery,smb-security-mode', 'mysql-info'):
            self.assertTrue(any('--script '+script in a for a in nmap_args), script)
        self.assertTrue(any('--version-all' in a for a in nmap_args))
        self.assertTrue(self.invoked('rpcclient'))
        self.assertTrue(self.invoked('enum4linux'))
        self.assertTrue(self.invoked('smbclient'))
        self.assertTrue(any('(objectClass=user)' in c['args'] for c in self.invoked('ldapsearch')))
        self.assertTrue(any('USER anonymous' in c['stdin'] for c in self.invoked('ftp')))
        self.assertTrue(any('KEYS *' in c['stdin'] for c in self.invoked('nc')))
        self.assertTrue(any('INFO' in c['stdin'] for c in self.invoked('nc')))
        self.assertTrue(any('SELECT version();' in c['args'] for c in self.invoked('mysql')))
        self.assertTrue(any('\\l' in c['args'] for c in self.invoked('psql')))

    def test_denied_is_not_a_confirmed_access_or_transport_failure(self):
        for name, tool, service in [('ftp','ftp','ftp'), ('ldap','ldapsearch','ldap'),
                                    ('smb','rpcclient','smb'), ('mysql','mysql','database'),
                                    ('postgres','psql','database'), ('redis','nc','database')]:
            with self.subTest(name=name):
                result = self.leaf(LEAVES[name], 'example.invalid', FAKE_DENY=tool)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                states = self.metas(service)
                self.assertTrue(any(m['estado'] == 'DENEGADO' for m in states))
                # Distinct leaf prefixes must not overwrite each other's evidence.
                if name in ('mysql','postgres','redis'):
                    prefix = {'mysql':'anon_', 'postgres':'postgres_info_', 'redis':'redis_info_'}[name]
                    import json
                    own = [json.loads(p.read_text()) for p in (self.scans/service).glob(prefix+'*.meta.json')]
                    self.assertTrue(own)
                    self.assertFalse(any(m['estado'] == 'CONFIRMADO' for m in own))

    def test_database_identity_ignores_ambient_credentials(self):
        result = self.leaf(LEAVES['mysql'], 'example.invalid', MYSQL_PWD='should-not-use')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        mysql = self.invoked('mysql')[0]
        self.assertIsNone(mysql['env']['MYSQL_PWD'])
        self.assertEqual(mysql['args'][0], '--no-defaults')
        self.assertIn('--skip-password', mysql['args'])
        result = self.leaf(LEAVES['postgres'], 'example.invalid', PGPASSWORD='wrong-ambient', PGSERVICE='other-target', PGHOSTADDR='192.0.2.99')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        for call in self.invoked('psql'):
            self.assertEqual(call['env']['PGPASSWORD'], 'postgres')
            self.assertIsNone(call['env']['PGSERVICE'])
            self.assertIsNone(call['env']['PGHOSTADDR'])
            self.assertEqual(call['env']['PGPASSFILE'], '/dev/null')
            self.assertIn('-X', call['args'])
            self.assertIn('-w', call['args'])

    def test_auxiliary_ports_and_ldaps_are_preserved(self):
        result = self.leaf(LEAVES['ldap_anon'], 'example.invalid')
        self.assertEqual(result.returncode, 0, result.stderr)
        urls = [c['args'][c['args'].index('-H')+1] for c in self.invoked('ldapsearch')]
        self.assertEqual(urls, ['ldap://example.invalid:389','ldaps://example.invalid:636',
                                'ldap://example.invalid:3268','ldaps://example.invalid:3269'])
        result = self.leaf(LEAVES['ftp_anon'], 'example.invalid')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c['args'][-1] for c in self.invoked('ftp')], ['21','2121','2221'])
        self.assertTrue(all('-v' in c['args'] for c in self.invoked('ftp')), 'FTP debe imprimir códigos también fuera de TTY')

    def test_missing_user_nse_is_explicit_not_silently_removed(self):
        result = self.leaf(LEAVES['ssh'], 'example.invalid', FAKE_NSE_MISSING='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('ssh-enum-users', result.stdout+result.stderr)
        self.assertIn('NO_DETERMINADO', result.stdout+result.stderr)

    def test_invalid_ports_and_hosts_never_invoke_tool(self):
        for args in [('--script=vuln',), ('example.invalid','70000'), ('example.invalid','22,23')]:
            result = self.leaf(LEAVES['ssh'], *args)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.invoked(), [])
