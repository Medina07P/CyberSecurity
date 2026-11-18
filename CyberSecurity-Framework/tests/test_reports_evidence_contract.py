"""Contratos de informes: solo fixtures; ejecutar con run_reports_evidence.sh."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / '11_Reports'))
import report_engine
from reports_fixture import latest_run
from lib.engine import collect
from lib.parsers.exploitation import parse as parse_exploitation
from lib.parsers.nmap import parse as parse_nmap
from lib.parsers.nikto import parse as parse_nikto
from lib.parsers.nuclei import parse_txt as parse_nuclei
from lib.sources import discover
from lib.catalog import build
from lib.model import merge_findings
from lib.render import to_json, from_json, write_reports


def put(root, relative, content):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
    return path


def xml(host='192.0.2.10'):
    return (f'<nmaprun><host><status state="up"/><address addr="{host}" '
            'addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
            '<state state="open"/></port></ports></host></nmaprun>')


class Sandbox(unittest.TestCase):
    @property
    def generated(self):
        return latest_run(self.out)
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='reports-contract-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / 'out'
        self.scans = self.root / 'scans'
        self.session = self.root / 'session'
        self.env = patch.dict(os.environ, {
            'REPORT_SCANS_DIR': str(self.scans), 'REPORT_OUT_DIR': str(self.out),
            'REPORT_PROFILE': str(self.root / 'profile'),
            'SESSION_FILE': str(self.session), 'HOME': str(self.root / 'home'),
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = report_engine.run(list(args))
        return rc, stdout.getvalue(), stderr.getvalue()

    def valid_json(self):
        put(self.root, 'scans/nmap/a.xml', xml())
        self.assertEqual(self.run_cli('--objetivo', '192.0.2.10')[0], 0)
        return json.loads((self.generated / 'findings.json').read_text())


class ScopeAndCliTests(Sandbox):
    def test_missing_target_never_enables_all_or_creates_output(self):
        put(self.root, 'scans/nmap/a.xml', xml())
        rc, _, error = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertFalse(self.out.exists())
        self.assertIn('objetivo', error.lower())

    def test_session_override_is_used_without_fallback(self):
        self.session.write_text('192.0.2.10\n')
        put(self.root, 'scans/nmap/a.xml', xml())
        self.assertEqual(self.run_cli()[0], 0)
        data = json.loads((self.generated / 'findings.json').read_text())
        self.assertEqual(data['meta']['objetivo'], '192.0.2.10')
        self.assertEqual(data['meta']['modo'], 'objetivo')

    def test_explicit_all_remains_available(self):
        put(self.root, 'scans/nmap/a.xml', xml())
        put(self.root, 'scans/nmap/b.xml', xml('192.0.2.99'))
        self.assertEqual(self.run_cli('--todos')[0], 0)
        data = json.loads((self.generated / 'findings.json').read_text())
        self.assertEqual(len(data['hallazgos']), 2)

    def test_empty_or_invalid_target_rejected_before_writes(self):
        for value in ('', ' ', 'http://[bad', 'https://u:p@example.invalid/'):
            with self.subTest(value=value):
                self.assertEqual(self.run_cli('--objetivo', value)[0], 1)
                self.assertFalse(self.out.exists())

    def test_json_for_another_target_is_rejected_without_writes(self):
        data = self.valid_json()
        source = put(self.root, 'input.json', json.dumps(data))
        destination = self.root / 'rerender'
        rc, _, _ = self.run_cli('--desde-json', str(source), '--objetivo', '192.0.2.99', '--salida', str(destination))
        self.assertEqual(rc, 1)
        self.assertFalse(destination.exists())

    def test_json_internal_target_mismatch_is_rejected(self):
        data = self.valid_json()
        data['hallazgos'][0]['activo'] = '192.0.2.99:80'
        source = put(self.root, 'input.json', json.dumps(data))
        destination = self.root / 'rerender'
        self.assertEqual(self.run_cli('--desde-json', str(source), '--objetivo', '192.0.2.10', '--salida', str(destination))[0], 1)
        self.assertFalse(destination.exists())

    def test_json_invalid_shapes_have_diagnostic_and_no_outputs(self):
        valid = self.valid_json()
        for number, data in enumerate(([], None, {'meta': []}, dict(valid, evaluado='false'),
                                       dict(valid, activos=[]), dict(valid, hallazgos=[{}]))):
            with self.subTest(data=data):
                source = put(self.root, 'input.json', json.dumps(data))
                destination = self.root / f'bad-{number}'
                rc, _, error = self.run_cli('--desde-json', str(source), '--objetivo', '192.0.2.10', '--salida', str(destination))
                self.assertEqual(rc, 1)
                self.assertTrue(error)
                self.assertFalse(destination.exists())

    def test_json_uses_its_own_identity_when_no_cli_target(self):
        data = self.valid_json()
        source = put(self.root, 'input.json', json.dumps(data))
        destination = self.root / 'rerender'
        self.assertEqual(self.run_cli('--desde-json', str(source), '--salida', str(destination))[0], 0)
        self.assertEqual(json.loads((latest_run(destination) / 'findings.json').read_text())['meta']['objetivo'], '192.0.2.10')

    def test_json_not_evaluated_does_not_become_success(self):
        data = self.valid_json()
        data.update(evaluado=False, hallazgos=[], activos={})
        source = put(self.root, 'input.json', json.dumps(data))
        self.assertEqual(self.run_cli('--desde-json', str(source), '--objetivo', '192.0.2.10')[0], 3)

    def test_wrapper_preserves_option_values_that_look_like_types(self):
        put(self.root, 'scans/nmap/a.xml', xml())
        for value in ('cliente', 'tecnico', 'ambos'):
            with self.subTest(value=value):
                result = subprocess.run(['bash', str(FW / '11_Reports/report_generator.sh'),
                                         '--cliente', value, '--objetivo', '192.0.2.10'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((self.generated / 'findings.json').read_text())['meta']['cliente'], value)


class EvidenceTrustTests(Sandbox):
    def manifest(self, name='first', port=443, state='CONFIRMADO', rc=0, kind='web_sqli', date='2026-11-13T10:01:00+00:00'):
        directory = self.scans / 'web' / ('exploitation_' + name)
        data = {'version': 1, 'module': '05', 'run_id': directory.name,
                'host': '192.0.2.10', 'puerto': port, 'url': '', 'herramienta': 'web',
                'started': '2026-11-13T10:00:00+00:00', 'fecha': date,
                'complete': True, 'estado': state, 'rc': rc,
                'steps': [{'name': 'sqli', 'estado': state, 'rc': rc}]}
        path = put(directory, 'run.json', json.dumps(data))
        meta = {k: v for k, v in data.items() if k not in ('steps', 'complete', 'started')}
        meta['kind'] = kind
        put(directory, 'sqli.meta.json', json.dumps(meta))
        put(directory, 'sqli.stdout', 'PRIVATE-CREDENTIAL-MARKER')
        return path, data, meta

    def test_failed_or_incomplete_05_never_confirms(self):
        path, data, _ = self.manifest()
        for changes in ({'complete': False}, {'estado': 'NO_DETERMINADO', 'rc': 1},
                        {'steps': []}, {'version': True}, {'puerto': True}):
            with self.subTest(changes=changes):
                path.write_text(json.dumps({**data, **changes}))
                result = parse_exploitation(path, self.root)
                self.assertFalse(result.evaluado)
                self.assertEqual(result.findings, [])
                self.assertTrue(result.no_evaluable)

    def test_05_requires_consistent_sidecar(self):
        path, _, meta = self.manifest()
        sidecar = path.parent / 'sqli.meta.json'
        for changes in ({'host': 'other.invalid'}, {'rc': 1}, {'kind': 'command'}, {'module': '06'}):
            with self.subTest(changes=changes):
                sidecar.write_text(json.dumps({**meta, **changes}))
                self.assertFalse(parse_exploitation(path, self.root).evaluado)
        sidecar.unlink()
        self.assertFalse(parse_exploitation(path, self.root).evaluado)

    def test_validated_05_retains_port_and_never_reads_body(self):
        path, _, _ = self.manifest()
        result = parse_exploitation(path, self.root)
        self.assertTrue(result.evaluado)
        self.assertEqual(result.findings[0].activo, '192.0.2.10:443')
        self.assertNotIn('PRIVATE-CREDENTIAL-MARKER', repr(result))

    def test_executed_sqli_is_not_an_unproven_differential(self):
        path, _, _ = self.manifest(state='EJECUTADO')
        self.assertEqual(parse_exploitation(path, self.root).findings[0].confianza, 'observacion')

    def test_reflection_is_not_confirmed_xss(self):
        path, _, _ = self.manifest(kind='web_xss')
        self.assertEqual(parse_exploitation(path, self.root).findings[0].confianza, 'candidato')

    def test_ports_are_not_collapsed_by_latest_selection(self):
        first, _, _ = self.manifest('first', port=443)
        second, _, _ = self.manifest('second', port=8443)
        selected = [s.path for s in discover(self.scans) if s.kind == 'exploitation']
        self.assertEqual(set(selected), {first, second})

    def test_latest_failed_05_does_not_revive_success(self):
        self.manifest()
        self.manifest('later', state='NO_DETERMINADO', rc=1, date='2026-11-13T11:00:00+00:00')
        self.assertEqual(collect(self.scans, self.root, '192.0.2.10').findings, [])

    def test_invalid_identity_blocks_previous_success_conservatively(self):
        self.manifest()
        put(self.scans, 'web/exploitation_bad/run.json', '[]')
        result = collect(self.scans, self.root, '192.0.2.10')
        self.assertEqual(result.findings, [])
        self.assertTrue(result.no_evaluable)

    def test_latest_uses_instants_not_lexicographic_timezone(self):
        self.manifest('first', date='2026-11-13T12:00:00+02:00')
        later, _, _ = self.manifest('later', state='NO_DETERMINADO', rc=1, date='2026-11-13T11:00:00+00:00')
        self.assertEqual([s.path for s in discover(self.scans) if s.kind == 'exploitation'], [later])

    def test_unordered_manifest_cannot_restore_previous_success(self):
        self.manifest()
        later, data, _ = self.manifest('later')
        data['fecha'] = []
        later.write_text(json.dumps(data))
        self.assertEqual(collect(self.scans, self.root, '192.0.2.10').findings, [])

    def test_nmap_cve_reference_is_candidate_not_confirmed(self):
        doc = '<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><hostscript><script id="banner" output="Documentation CVE-2021-44228; no test performed"/></hostscript></host></nmaprun>'
        result = parse_nmap(put(self.root, 'reference.xml', doc), self.root)
        self.assertFalse(any(f.confianza == 'confirmado' for f in result.findings))
        self.assertEqual(result.findings[0].confianza, 'candidato')

    def test_merge_never_demotes_confirmed_to_candidate_on_severity(self):
        candidate = build('nmap.cve', key='same', activo='192.0.2.10', evidencia=[], confianza='candidato', severidad='alta')
        confirmed = build('nuclei.template', key='same', activo='192.0.2.10', evidencia=[], confianza='confirmado', severidad='media')
        result = merge_findings([candidate, confirmed])[0]
        self.assertEqual(result.confianza, 'confirmado')
        self.assertEqual(result.rule, 'nuclei.template')


class PriorEvidenceTests(Sandbox):
    def setUp(self):
        super().setUp()
        self.prior = self.root / 'framework'
        os.environ['REPORT_FRAMEWORK_ROOT'] = str(self.prior)

    def osint(self, target='example.invalid', status='ok'):
        return put(self.prior, f'01_OSINT/domains/osint_{target}_one/resultados.json', json.dumps({
            'version': 1, 'target': target, 'timestamp': '2026-11-13T10:00:00+00:00',
            'run_id': 'a' * 32, 'exit_code': 0 if status in ('ok', 'empty') else 1,
            'sources': [{'source': 'dns', 'status': status, 'error': '',
                         'evidence': [{'kind': 'subdomain', 'value': 'www.' + target,
                                       'source': 'dns', 'attribution': 'resuelto', 'detail': ''}]}],
        }))

    def test_osint_context_is_included_without_inventing_vulnerabilities(self):
        self.osint()
        self.assertEqual(self.run_cli('--objetivo', 'example.invalid')[0], 0)
        data = json.loads((self.generated / 'findings.json').read_text())
        self.assertEqual(data['hallazgos'], [])
        entry = next(c for c in data['cobertura'] if c['modulo'] == '01')
        self.assertEqual((entry['objetivo'], entry['estado']), ('example.invalid', 'contexto'))
        self.assertIn('1', entry['motivo'])

    def test_osint_other_target_is_not_in_json_or_reports(self):
        self.osint()
        self.osint('other.invalid')
        self.run_cli('--objetivo', 'example.invalid')
        self.assertNotIn('other.invalid', '\n'.join(p.read_text() for p in self.generated.iterdir()))

    def test_osint_failed_and_empty_are_distinct(self):
        for status, expected in (('empty', 'contexto'), ('failed', 'no_evaluable')):
            with self.subTest(status=status):
                self.osint(status=status)
                self.run_cli('--objetivo', 'example.invalid')
                data = json.loads((self.generated / 'findings.json').read_text())
                self.assertEqual(next(c for c in data['cobertura'] if c['modulo'] == '01')['estado'], expected)

    def test_unknown_scan_source_is_reported_not_silently_discarded(self):
        put(self.root, 'scans/nmap/a.xml', xml())
        put(self.root, 'scans/masscan/masscan_192.0.2.10.json', '[]')
        self.run_cli('--objetivo', '192.0.2.10')
        data = json.loads((self.generated / 'findings.json').read_text())
        self.assertTrue(any(c['estado'] == 'no_evaluable' and 'masscan' in c['fuente'] for c in data['cobertura']))
        for name in ('informe_cliente.md', 'informe_cliente.html'):
            text = (self.generated / name).read_text()
            self.assertNotIn('Todas las pruebas se completaron', text)
            self.assertIn('cobertura', text.lower())

    def test_recon_legacy_is_context_not_proof_of_success(self):
        put(self.prior, '02_Recon/fingerprinting/nmap_192.0.2.10.txt', 'SECRET-BODY-CVE-2021-44228')
        self.run_cli('--objetivo', '192.0.2.10')
        data = json.loads((self.generated / 'findings.json').read_text())
        self.assertEqual(data['hallazgos'], [])
        self.assertTrue(any(c['modulo'] == '02' and c['estado'] == 'contexto' for c in data['cobertura']))
        self.assertNotIn('SECRET-BODY', repr(data))

    def test_forensics_without_target_is_not_labeled_with_session(self):
        put(self.prior, '08_Forensics/analysis/runs/run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/run.json', json.dumps({
            'version': 1, 'module': '08', 'run_id': 'run-' + 'a' * 32, 'operation': 'strings',
            'mode': 'offline', 'identity': None, 'inputs': [], 'started': '2026-11-13T10:00:00+00:00',
            'finished': '2026-11-13T10:01:00+00:00', 'state': 'COMPLETADO', 'complete': True,
            'rc': 0, 'steps': [], 'artifact_roots': {}, 'dependents_blocked': False,
        }))
        self.run_cli('--objetivo', '192.0.2.10')
        data = json.loads((self.generated / 'findings.json').read_text())
        self.assertEqual(data['hallazgos'], [])
        entry = next(c for c in data['cobertura'] if c['modulo'] == '08')
        self.assertEqual(entry['objetivo'], '')
        self.assertEqual(entry['estado'], 'no_evaluable')

    def test_evidence_metadata_never_opens_payload_or_treats_label_as_finding(self):
        identifier = 'aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa'
        path = put(self.prior, f'10_Evidence/findings/vulnerabilities/{identifier}/evidence.json', json.dumps({
            'schema_version': 1, 'id': identifier, 'type': 'finding',
            'original_name': 'SECRET-NAME', 'stored_name': 'artifact', 'size': 4,
            'sha256': 'a' * 64, 'created_at': '2026-11-13T10:00:00Z',
            'description': 'SECRET-DESCRIPTION CONFIRMADO CVE-2021-44228',
            'origin': 'import', 'target': '192.0.2.10', 'run_id': None, 'method': None,
        }))
        payload = put(path.parent, 'artifact', 'SECRET-PAYLOAD')
        original = Path.open
        def forbid_payload(p, *args, **kwargs):
            if p == payload:
                raise AssertionError('report must not open private evidence')
            return original(p, *args, **kwargs)
        with patch.object(Path, 'open', forbid_payload):
            self.run_cli('--objetivo', '192.0.2.10')
        data = json.loads((self.generated / 'findings.json').read_text())
        self.assertEqual(data['hallazgos'], [])
        self.assertTrue(any(c['modulo'] == '10' and c['estado'] == 'contexto' for c in data['cobertura']))
        self.assertNotIn('SECRET-', repr(data))

    def test_symlink_scan_is_never_consumed_as_evidence(self):
        source = put(self.root, 'outside.xml', xml())
        path = self.scans / 'nmap/nmap_192.0.2.10.xml'
        path.parent.mkdir(parents=True)
        path.symlink_to(source)
        self.run_cli('--objetivo', '192.0.2.10')
        data = json.loads((self.generated / 'findings.json').read_text())
        self.assertEqual(data['hallazgos'], [])
        self.assertTrue(any(c['estado'] == 'no_evaluable' for c in data['cobertura']))

    def test_coverage_roundtrip_and_legacy_json_default(self):
        self.osint()
        self.run_cli('--objetivo', 'example.invalid')
        data = report_engine._load_json(self.generated / 'findings.json')
        collected, meta = from_json(data)
        self.assertTrue(collected.cobertura)
        self.assertEqual(to_json(collected, meta)['cobertura'], data['cobertura'])
        del data['cobertura']
        self.assertEqual(from_json(data)[0].cobertura, [])

    def test_coverage_is_visible_in_both_technical_formats(self):
        self.osint()
        self.run_cli('--objetivo', 'example.invalid')
        for name in ('informe_tecnico.md', 'informe_tecnico.html'):
            self.assertIn('Cobertura', (self.generated / name).read_text())
            self.assertIn('resultados.json', (self.generated / name).read_text())


class ReportIntegrationTests(Sandbox):
    def test_eof_during_profile_cancels_without_saving_or_generating(self):
        self.session.write_text('192.0.2.10\n')
        put(self.root, 'scans/nmap/a.xml', xml())
        for answers in ('1\n', '1\nSynthetic\n'):
            with self.subTest(answers=answers):
                result = subprocess.run(['bash', '-c', 'source "$1"; quick_report', 'reports-test', str(FW / 'cyber_framework.sh')],
                                        input=answers, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0)
                self.assertFalse(self.out.exists())
                self.assertFalse((self.root / 'profile').exists())

    def quick(self, answers):
        bindir = self.root / 'bin'
        bindir.mkdir(exist_ok=True)
        opener = put(bindir, 'xdg-open', '#!/bin/bash\nprintf "%s" "$1" > "$REPORT_OPEN_LOG"\n')
        opener.chmod(0o700)
        put(bindir, 'clear', '#!/bin/bash\nexit 0\n').chmod(0o700)
        put(self.root, 'profile', 'cliente=Synthetic\nauditor=Test\n')
        env = dict(os.environ, PATH=str(bindir) + ':' + os.environ['PATH'], REPORT_OPEN_LOG=str(self.root / 'opened'))
        return subprocess.run(['bash', '-c', 'source "$1"; quick_report', 'reports-test', str(FW / 'cyber_framework.sh')],
                              input=answers, capture_output=True, text=True, env=env, timeout=10)

    def test_quick_report_opens_only_new_requested_type_at_custom_output(self):
        self.session.write_text('192.0.2.10\n')
        put(self.root, 'scans/nmap/a.xml', xml())
        put(self.out, 'informe_cliente.html', 'OLD-CUSTOM')
        put(FW / '11_Reports', 'generated/192.0.2.10/informe_cliente.html', 'OLD-DEFAULT')
        result = self.quick('1\ns\n\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'opened').read_text(), str(self.generated / 'informe_tecnico.html'))
        self.assertNotIn('informe_cliente.html', result.stdout)

    def test_quick_report_failure_never_offers_old_html(self):
        self.session.write_text('192.0.2.10\n')
        put(self.root, 'scans/nmap/a.xml', xml())
        self.out.write_text('blocked-output-directory')
        put(FW / '11_Reports', 'generated/192.0.2.10/informe_cliente.html', 'OLD-DEFAULT')
        result = self.quick('1\ns\n\n')
        self.assertFalse((self.root / 'opened').exists())
        self.assertNotIn('¿Abrir informe HTML?', result.stdout)

    def test_quick_report_eof_does_nothing(self):
        self.assertEqual(self.quick('').returncode, 0)
        self.assertFalse(self.out.exists())
        self.assertFalse((self.root / 'opened').exists())

    def test_json_summary_lists_only_files_from_this_generation(self):
        put(self.root, 'scans/nmap/a.xml', xml())
        put(self.out, 'informe_cliente.html', 'OLD-REPORT')
        rc, output, _ = self.run_cli('--objetivo', '192.0.2.10', '--tipo', 'tecnico', '--json')
        self.assertEqual(rc, 0)
        self.assertEqual({Path(p).name for p in json.loads(output)['archivos']},
                         {'findings.json', 'informe_tecnico.md', 'informe_tecnico.html', 'run.json'})
        self.assertEqual((self.out / 'informe_cliente.html').read_text(), 'OLD-REPORT')

    def test_rc3_still_has_receipt_but_failure_does_not(self):
        rc, output, _ = self.run_cli('--objetivo', '192.0.2.10', '--json')
        self.assertEqual(rc, 3)
        self.assertEqual(len(json.loads(output)['archivos']), 6)
        self.assertEqual(self.run_cli('--objetivo', '', '--json')[1], '')

    def test_phase_does_not_package_or_list_other_targets(self):
        put(self.root, 'scans/nmap/a.xml', xml())
        # Real phase wrapper, stub only the operational packaging dependency.
        import shutil
        fw = self.root / 'framework'
        directory = fw / '11_Reports'
        directory.mkdir(parents=True)
        for name in ('run_all_reports.sh', 'report_generator.sh', 'report_engine.py'):
            shutil.copy2(FW / '11_Reports' / name, directory / name)
        shutil.copytree(FW / '11_Reports/lib', directory / 'lib', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(FW / '00_Config/lib/ai', fw / '00_Config/lib/ai', ignore=shutil.ignore_patterns('__pycache__'))
        stub = put(fw, '10_Evidence/evidence_manager.sh', '#!/bin/bash\nprintf called > "${0%/*}/CALLED"\n')
        stub.chmod(0o700)
        put(directory, 'generated/other.invalid/informe_cliente.html', 'OLD')
        result = subprocess.run(['bash', str(directory / 'run_all_reports.sh'), '192.0.2.10'], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((stub.parent / 'CALLED').exists())
        self.assertNotIn('other.invalid', result.stdout)
        self.assertIn(str(self.generated / 'informe_tecnico.html'), result.stdout)

    def test_phase_failure_does_not_present_old_reports(self):
        put(FW / '11_Reports', 'generated/invalid/informe_cliente.html', 'OLD')
        result = subprocess.run(['bash', str(FW / '11_Reports/run_all_reports.sh'), ''], text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('informe_cliente.html', result.stdout)
        self.assertNotIn('COMPLETADOS', result.stdout)


class FinalReviewTests(Sandbox):
    def test_http_context_symlink_cannot_attribute_confirmation(self):
        path = put(self.root, 'scans/web/http_inject_192.0.2.10.tsv',
                   'nivel\tparam\tclase\tpayload\tcodigo\ttamano\tms\tevidencia\nCONFIRMADO\tid\tsqli\tx\t200\t10\t1\tdemo\n')
        outside = put(self.root, 'private-context', 'host=192.0.2.99\n')
        context = path.parent / path.stem / 'contexto.txt'
        context.parent.mkdir()
        context.symlink_to(outside)
        result = collect(self.scans, self.root, '192.0.2.10')
        self.assertEqual(result.findings, [])
        self.assertTrue(result.no_evaluable)

    def test_rate_limit_paired_symlink_is_not_read(self):
        path = put(self.root, 'scans/web/rate_limit_192.0.2.10.txt',
                   '- Objetivo: 192.0.2.10\n- Veredicto: SIN FRENO\n')
        outside = put(self.root, 'private-tsv', 'attempt\tcode\nSECRET\t200\n')
        path.with_suffix('.tsv').symlink_to(outside)
        result = collect(self.scans, self.root, '192.0.2.10')
        self.assertEqual(result.findings, [])
        self.assertNotIn('SECRET', repr(result))

    def test_postexploitation_sidecar_symlink_rejects_run(self):
        from lib.parsers.postexploitation import parse
        directory = self.scans / 'inventory/postexploitation_one'
        data = {'version': 1, 'module': '06', 'run_id': directory.name,
                'host': '192.0.2.10', 'puerto': 443, 'url': '', 'herramienta': 'inventory',
                'started': '2026-11-13T10:00:00+00:00', 'fecha': '2026-11-13T10:01:00+00:00',
                'complete': True, 'estado': 'EJECUTADO', 'rc': 0,
                'steps': [{'name': 'inventory', 'estado': 'EJECUTADO', 'rc': 0}]}
        path = put(directory, 'run.json', json.dumps(data))
        meta = {k: v for k, v in data.items() if k not in ('steps', 'complete', 'started')}
        meta['kind'] = 'command'
        outside = put(self.root, 'private-meta', json.dumps(meta))
        (directory / 'inventory.meta.json').symlink_to(outside)
        self.assertFalse(parse(path, self.root).evaluado)

    def test_output_symlink_does_not_overwrite_unrelated_file(self):
        put(self.root, 'scans/nmap/a.xml', xml())
        sentinel = put(self.root, 'sentinel', 'DO-NOT-CHANGE')
        self.out.mkdir()
        (self.out / 'findings.json').symlink_to(sentinel)
        rc, output, _ = self.run_cli('--objetivo', '192.0.2.10', '--json')
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(output)['run_id'])
        self.assertEqual(sentinel.read_text(), 'DO-NOT-CHANGE')
        self.assertFalse((self.out / 'informe_tecnico.html').exists())

    def test_new_reports_and_directories_are_private(self):
        put(self.root, 'scans/nmap/a.xml', xml())
        self.assertEqual(self.run_cli('--objetivo', '192.0.2.10')[0], 0)
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.generated.stat().st_mode & 0o777, 0o700)
        for path in self.generated.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_coverage_schema_rejected_before_writing(self):
        data = self.valid_json()
        source = put(self.root, 'input.json', json.dumps(dict(data, cobertura=[{}])))
        destination = self.root / 'rerender'
        self.assertEqual(self.run_cli('--desde-json', str(source), '--salida', str(destination))[0], 1)
        self.assertFalse(destination.exists())

    def test_ambiguous_json_findings_keys_are_rejected(self):
        data = self.valid_json()
        data['findings'] = []
        source = put(self.root, 'input.json', json.dumps(data))
        destination = self.root / 'rerender'
        self.assertEqual(self.run_cli('--desde-json', str(source), '--salida', str(destination))[0], 1)
        self.assertFalse(destination.exists())

    def test_sidecar_symlink_is_not_consumed(self):
        source = put(self.root, 'scans/ssh/auth_methods_192.0.2.10.txt', '| ssh-auth-methods:\n|_ password\n')
        outside = put(self.root, 'outside.json', json.dumps({'version': 1, 'host': '192.0.2.10', 'puerto': 22, 'estado': 'EJECUTADO'}))
        Path(str(source) + '.meta.json').symlink_to(outside)
        original = Path.open
        def safe(p, *args, **kwargs):
            if p == outside or p.is_symlink():
                raise AssertionError('must not open symlinked metadata')
            return original(p, *args, **kwargs)
        with patch.object(Path, 'open', safe):
            result = collect(self.scans, self.root, '192.0.2.10')
        self.assertEqual(result.findings, [])
        self.assertTrue(result.no_evaluable or result.cobertura)

    def test_paired_headers_symlink_never_supplies_success(self):
        source = put(self.root, 'scans/web/security_headers_192.0.2.10.txt', '')
        outside = put(self.root, 'outside.txt', 'HTTP/1.1 200 OK\n')
        (source.parent / 'headers_192.0.2.10.txt').symlink_to(outside)
        self.assertEqual(collect(self.scans, self.root, '192.0.2.10').findings, [])

    def test_nikto_reference_is_candidate_not_proven_vulnerability(self):
        path = put(self.root, 'nikto_192.0.2.10.txt', '+ /docs: CVE-2021-44228 reference only\n')
        self.assertEqual(parse_nikto(path, self.root).findings[0].confianza, 'candidato')

    def test_nuclei_information_is_observation_not_vulnerability(self):
        path = put(self.root, 'nuclei_192.0.2.10.txt', '[tech-detect] [http] [info] https://192.0.2.10/\n')
        result = parse_nuclei(path, self.root)
        self.assertEqual(result.findings[0].confianza, 'observacion')
        self.assertNotIn('vulnerabilidad conocida', result.findings[0].titulo.lower())

    def test_unknown_unattributed_source_remains_visible_as_limit(self):
        put(self.root, 'scans/masscan/result.json', '[]')
        self.run_cli('--objetivo', '192.0.2.10')
        data = json.loads((self.generated / 'findings.json').read_text())
        self.assertTrue(any(c['estado'] == 'no_soportada' for c in data['cobertura']))

    def test_no_sources_never_claims_all_findings_evaluated(self):
        self.run_cli('--objetivo', '192.0.2.10')
        self.assertNotIn('Todos los hallazgos pudieron evaluarse', (self.generated / 'informe_tecnico.md').read_text())


if __name__ == '__main__':
    unittest.main()
