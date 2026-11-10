import json
from enumeration_fixture import EnumerationFixture


class RuntimeTests(EnumerationFixture):
    def runtime(self, body, **env):
        lib = self.fw/'00_Config/lib/enumeration_runtime.bash'
        return self.shell(f'source "{lib}" || exit 1\n'+body, **env)

    def test_invalid_target_never_runs_tool(self):
        result = self.runtime('enum_init ssh --script=vuln 22 && enum_capture version nmap x')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.invoked(), [])

    def test_capture_failure_preserves_existing_evidence(self):
        result = self.runtime('enum_init ssh example.invalid 22 || exit 1\nenum_capture version nmap example.invalid || exit 1\nenum_publish version EJECUTADO')
        self.assertEqual(result.returncode, 0, result.stderr)
        files = list((self.scans/'ssh').glob('version_*.txt'))
        self.assertEqual(len(files), 1)
        old = files[0].read_bytes()
        result = self.runtime('enum_init ssh example.invalid 22 || exit 1\nenum_capture version nmap example.invalid || exit 1\nenum_publish version EJECUTADO', FAKE_FAIL='nmap')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files[0].read_bytes(), old)

    def test_two_targets_and_ports_are_distinct(self):
        for host, port in [('example.invalid', '22'), ('other.invalid', '22'), ('example.invalid', '2222')]:
            result = self.runtime(f'enum_init ssh {host} {port} || exit 1\nenum_capture version nmap {host} || exit 1\nenum_publish version EJECUTADO')
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(list((self.scans/'ssh').glob('version_*.txt'))), 3)
        self.assertEqual({(m['host'], m['puerto']) for m in self.metas('ssh')}, {('example.invalid',22),('other.invalid',22),('example.invalid',2222)})

    def test_long_identity_is_bounded_and_value_stdout_is_pure(self):
        host = '.'.join(['a'*60]*4)
        result = self.runtime(f'enum_init ssh "{host}" 2222 || exit 1\nenum_capture version nmap "{host}" || exit 1\nenum_publish version EJECUTADO')
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in (self.scans/'ssh').iterdir():
            self.assertLessEqual(len(path.name.encode()), 240)
