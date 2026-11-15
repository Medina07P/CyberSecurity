"""Lectura de puertos desde archivos sintéticos, sin escáneres ni DNS."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / '11_Reports'))
from lib.engine import collect
from lib.render import write_reports, to_json


class PortsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scans = self.root / 'scans'

    def put(self, relative, text):
        path = self.scans / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def masscan(self, ports=None, host='192.0.2.10'):
        return {'ip': host, 'ports': ports if ports is not None else [{'port': 80, 'proto': 'tcp', 'status': 'open'}]}

    def result(self, host='192.0.2.10'):
        return collect(self.scans, self.root, host)

    def test_masscan_open_ports_are_observations(self):
        record = self.masscan([{'port': 80, 'proto': 'tcp', 'status': 'open'}, {'port': 53, 'proto': 'udp', 'status': 'open'}])
        self.put('masscan/masscan_192.0.2.10.json', json.dumps([record]))
        result = self.result()
        self.assertEqual(len(result.findings), 2)
        self.assertEqual({f.key for f in result.findings}, {'nmap.open_port:tcp:192.0.2.10:80', 'nmap.open_port:udp:192.0.2.10:53'})
        self.assertTrue(all((f.severidad, f.confianza, f.cve) == ('info', 'observacion', None) for f in result.findings))
        self.assertTrue(all(f.tecnica == 'masscan' and f.evidencia for f in result.findings))

    def test_masscan_types_and_truncation_are_not_guessed(self):
        for value in ([self.masscan([{'port': p, 'proto': 'tcp', 'status': 'open'}])] for p in (True, 0, 65536)):
            self.put('masscan/masscan_192.0.2.10.json', json.dumps(value))
            self.assertEqual(self.result().findings, [])
            self.assertTrue(self.result().no_evaluable)
        for value in ([self.masscan(host='bad ip')], [self.masscan(ports='oops')], {}, '[{"ip":'):
            self.put('masscan/masscan_192.0.2.10.json', value if isinstance(value, str) else json.dumps(value))
            self.assertEqual(self.result().findings, [])
            self.assertTrue(self.result().no_evaluable)

    def test_masscan_nonopen_does_not_become_open(self):
        for status in ('closed', 'filtered', 'bogus'):
            self.put('masscan/masscan_192.0.2.10.json', json.dumps([self.masscan([{'port': 80, 'proto': 'tcp', 'status': status}])]))
            self.assertEqual(self.result().findings, [])
            self.assertTrue(self.result().no_evaluable)

    def test_masscan_other_host_never_leaks(self):
        other = dict(self.masscan(host='192.0.2.99'), banner='SECRET-BANNER CVE-2021-44228')
        for records in ([other], [other, self.masscan()]):
            self.put('masscan/masscan_192.0.2.10.json', json.dumps(records))
            result = self.result()
            self.assertEqual(len(result.findings), 1 if len(records) == 2 else 0)
            out = self.root / 'reports'
            write_reports(result, {}, out, ['tecnico', 'cliente'])
            text = json.dumps(to_json(result, {})) + ''.join(p.read_text() for p in out.iterdir())
            self.assertNotIn('192.0.2.99', text)
            self.assertNotIn('SECRET-BANNER', text)

    def test_empty_sources_do_not_claim_clean_scan(self):
        for rel, content in (('masscan/masscan_192.0.2.10.json', '[]'),
                             ('rustscan/rustscan_192.0.2.10.txt', ''),
                             ('rustscan/rustscan_192.0.2.10.txt', '192.0.2.10 -> []')):
            self.put(rel, content)
            result = self.result()
            self.assertFalse(result.evaluado)
            self.assertEqual(result.findings, [])
            self.assertTrue(result.no_evaluable)

    def test_rustscan_exact_formats_and_sgr(self):
        for text, host, ports in (
            ('Open 192.0.2.10:8080', '192.0.2.10', [8080]),
            ('example.invalid -> [80, 443]', 'example.invalid', [80, 443]),
            ('Open [2001:db8::10]:443', '2001:db8::10', [443]),
            ('\x1b[32mOpen 192.0.2.10:80\x1b[0m', '192.0.2.10', [80]),
        ):
            with self.subTest(text=text):
                self.put('rustscan/rustscan_192.0.2.10.txt', text)
                result = self.result(host)
                self.assertEqual(len(result.findings), len(ports))
                self.assertEqual(sorted(p['puerto'] for p in result.activos[host]['puertos']), ports)
                self.assertTrue(all(f.confianza == 'observacion' for f in result.findings))

    def test_rustscan_control_and_mixed_lines(self):
        self.put('rustscan/rustscan_192.0.2.10.txt', 'banner open SECRET\nOpen 2001:db8::10:443\n\x1b[2JOpen 192.0.2.10:81\n192.0.2.10 -> [80]\n')
        result = self.result()
        self.assertEqual([f.key for f in result.findings], ['nmap.open_port:tcp:192.0.2.10:80'])
        self.assertTrue(result.no_evaluable)
        self.assertNotIn('SECRET', repr(result))

    def test_repeated_ports_are_deduplicated(self):
        self.put('masscan/masscan_192.0.2.10.json', json.dumps([self.masscan(), self.masscan()]))
        self.put('rustscan/rustscan_192.0.2.10.txt', 'Open 192.0.2.10:80\nOpen 192.0.2.10:80\n')
        self.put('nmap/nmap_192.0.2.10.xml', '<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="TestServer"/></port></ports></host></nmaprun>')
        result = self.result()
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.id, '30f6a241126cc83439a7a545deae8b0fd817974f')
        self.assertEqual(finding.tecnica, 'nmap')
        self.assertEqual(len({e.archivo for e in finding.evidencia}), 3)
        self.assertEqual(result.activos['192.0.2.10']['puertos'][0]['producto'], 'TestServer')

    def test_reading_ports_does_not_claim_last_attempt(self):
        self.put('rustscan/rustscan_192.0.2.10.txt', '192.0.2.10 -> [80]')
        self.put('rustscan/errores.log', 'later failure')
        result = self.result()
        self.assertEqual(len(result.findings), 1)
        self.assertIn('finalización y actualidad no acreditadas', result.cobertura[0]['motivo'])

    def test_other_host_open_does_not_evaluate_requested_host_without_open_ports(self):
        self.put('masscan/masscan_192.0.2.10.json', json.dumps([
            self.masscan([{'port': 80, 'proto': 'tcp', 'status': 'closed'}]),
            self.masscan(host='192.0.2.99'),
        ]))
        result = self.result()
        self.assertEqual(result.findings, [])
        self.assertFalse(result.evaluado)
        self.assertTrue(result.no_evaluable)

    def test_rustscan_non_linebreak_controls_cannot_create_valid_records(self):
        for control in ('\x0b', '\x0c', '\x85', '\r', '\x1c'):
            with self.subTest(control=repr(control)):
                self.put('rustscan/rustscan_192.0.2.10.txt', 'SECRET' + control + 'Open 192.0.2.10:80\n')
                self.assertEqual(self.result().findings, [])
        self.put('rustscan/rustscan_192.0.2.10.txt', 'Open 192.0.2.10:80\r\n')
        self.assertEqual(len(self.result().findings), 1)


if __name__ == '__main__':
    unittest.main()
