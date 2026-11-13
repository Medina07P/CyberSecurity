"""Explicit acquisition contracts; only synthetic artifacts and closed PATH stubs."""
import importlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tarfile
import unittest
import warnings
from unittest import mock

from evidence_fixture import sandbox, copy_sources, closed_env, snapshot


class CaptureTests(unittest.TestCase):
    def setUp(self):
        context = sandbox()
        self.base = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.framework = copy_sources(self.base)
        self.root = self.base / 'evidence-data'
        for name in list(sys.modules):
            if name == 'evidence' or name.startswith('evidence.'):
                del sys.modules[name]
        sys.path.insert(0, str(self.framework / '00_Config/lib'))
        self.addCleanup(sys.path.pop, 0)
        self.c = importlib.import_module('evidence.capture')
        self.model = importlib.import_module('evidence.model')
        self.inv = importlib.import_module('evidence.inventory')
        warning_context = warnings.catch_warnings()
        warning_context.__enter__()
        self.addCleanup(warning_context.__exit__, None, None, None)
        warnings.filterwarnings('ignore', message='LEDGER DIAGNÓSTICO EXCLUIDO: .*', category=UserWarning)
        patch = mock.patch.dict(os.environ, closed_env(self.base), clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def plan(self, **kw):
        self.assertTrue(hasattr(self.c, 'CapturePlan'), 'CapturePlan missing')
        return self.c.CapturePlan(**kw)

    def invalid(self, **kw):
        before = snapshot(self.base)
        self.assertTrue(hasattr(self.c, 'capture'), 'capture missing')
        with self.assertRaises(self.model.UsageError):
            self.c.capture(self.root, self.plan(**kw))
        self.assertEqual(snapshot(self.base), before)

    def test_no_action_no_network_or_file_side_effects(self):
        self.invalid()

    def test_network_requires_authorize_before_tool_or_ledger(self):
        for kw in ({'web': 'https://example.test/'},
                   {'traffic': 'localhost', 'interface': 'lo'},
                   {'scan': '127.0.0.1', 'scan_profile': 'basic'}):
            self.invalid(**kw)

    def test_duration_packet_bounds_and_required_pairs(self):
        for kw in ({'traffic': 'localhost'}, {'interface': 'lo'},
                   {'scan': 'localhost'}, {'scan_profile': 'basic'},
                   {'scan': 'localhost', 'scan_profile': 'bad'},
                   {'system': True, 'duration': 1}, {'system': True, 'packet_limit': 1}):
            self.invalid(authorize_network=True, **kw)
        for duration in (0, 301, True, 1.5, '10'):
            self.invalid(traffic='localhost', interface='lo', duration=duration, authorize_network=True)
        for count in (0, 10001, True, 1.5):
            self.invalid(traffic='localhost', interface='lo', packet_limit=count, authorize_network=True)
        for duration, count in ((1, 1), (300, 10000)):
            self.c.validate_plan(self.plan(traffic='localhost', interface='lo', duration=duration,
                                          packet_limit=count, authorize_network=True))

    def test_host_url_interface_reject_option_filter_and_path_injection(self):
        for host in ('-oX', 'a/b', 'a b', 'a\n', '*.test', '10.0.0.0/8',
                     'host;id', '::1%lo', 'é.test', 'a..b', 'a_b', 'x or y', ''):
            self.invalid(scan=host, scan_profile='basic', authorize_network=True)
        for url in ('example.test', 'ftp://a', 'http://a:0', 'http://a:65536',
                    'http://u:p@a', 'http://a/#x', 'http://a/#', 'http://a\\b',
                    'http://a/ a', 'http://a\n', 'http://[::1%lo]/', 'http://a:',
                    'http://[::1]evil/', 'http://[::1]443/'):
            self.invalid(web=url, authorize_network=True)
        for iface in ('', '-i', 'a b', 'a\t', 'a' * 16, 'a/b'):
            self.invalid(traffic='localhost', interface=iface, authorize_network=True)

    def test_https_port_path_and_ipv6_are_preserved(self):
        self.assertTrue(hasattr(self.c, 'validate_plan'), 'validate_plan missing')
        for host in ('localhost', 'example.test', '127.0.0.1', '2001:db8::1'):
            self.c.validate_plan(self.plan(scan=host, scan_profile='basic', authorize_network=True))
        self.c.validate_plan(self.plan(web='https://[2001:db8::1]:8443/a?q=b', authorize_network=True))

    def test_nmap_ipv4_ranges_rejected_before_ledger_or_backend(self):
        for host in ('127.0.0.1-2', '0-255.0-255.13.37', '1-2.3.4.5',
                     '1.2-3.4.5', '1.2.3-4.5'):
            with self.subTest(host=host):
                with mock.patch.object(self.c, 'run_child', side_effect=AssertionError('backend invoked')) as child:
                    self.invalid(scan=host, scan_profile='basic', authorize_network=True)
                    child.assert_not_called()

    def test_single_hosts_and_hyphenated_domains_remain_valid(self):
        for host in ('127.0.0.1', '2001:db8::1', '::1', 'localhost',
                     'example.test', 'api-2.example.test', '127-0-0-1.example.test',
                     '0-255.0-255.example.test', '1-2', 'a-b.c-d.e-f.g-h'):
            with self.subTest(host=host):
                self.c.validate_plan(self.plan(scan=host, scan_profile='basic', authorize_network=True))

    def stub(self, name, data, rc=0):
        code = ('import json,sys\nfrom pathlib import Path\na=sys.argv[1:]\n'
                f'p=Path({str(self.base / "calls")!r})\n'
                'with p.open("a") as f: f.write(json.dumps(a)+"\\n")\n')
        if name == 'cutycapt':
            code += 'out=next(x[6:] for x in a if x.startswith("--out="))\n'
        else:
            code += f'out=a[a.index({"-w" if name == "tcpdump" else "-oN"!r})+1]\n'
        code += f'Path(out).write_bytes({data!r})\nprint("private diagnostic")\nprint("private error",file=sys.stderr)\nsys.exit({rc})\n'
        path = self.base / 'bin' / name
        path.write_text('#!' + sys.executable + '\n' + code)
        path.chmod(0o700)

    def calls(self):
        return [json.loads(s) for s in (self.base / 'calls').read_text().splitlines()]

    def run_plan(self, **kw):
        self.assertTrue(hasattr(self.c, 'capture'), 'capture missing')
        return self.c.capture(self.root, self.plan(authorize_network=True, **kw))

    def ledger(self):
        paths = list((self.root / 'logs/runs').iterdir())
        self.assertEqual(len(paths), 1)
        return self.c.read_run(paths[0]), paths[0]

    @staticmethod
    def pcap(endian='<', nano=False, packets=1):
        magic = (b'\x4d\x3c\xb2\xa1' if nano else b'\xd4\xc3\xb2\xa1') if endian == '<' else (b'\xa1\xb2\x3c\x4d' if nano else b'\xa1\xb2\xc3\xd4')
        return magic + struct.pack(endian + 'HHiIII', 2, 4, 0, 0, 65535, 1) + (struct.pack(endian + 'IIII', 1, 0, 4, 4) + b'data') * packets

    def test_system_is_operator_not_target(self):
        self.assertEqual(self.run_plan(system=True), 0)
        records = self.inv.scan(self.root).records
        self.assertEqual(len(records), 1)
        data = json.loads(records[0].payload.read_text())
        self.assertEqual(data['scope'], 'OPERADOR')
        self.assertEqual(set(data), {'scope', 'utc', 'user', 'hostname', 'uname'})
        meta = json.loads(records[0].metadata.read_text())
        self.assertIsNone(meta['target'])
        self.assertEqual((meta['origin'], meta['method']), ('capture', 'system'))
        self.assertTrue(self.inv.verify(self.root).ok)

    def test_system_never_spawns_even_platform_processor_probe(self):
        import platform
        # A fresh uname cache exposes platform's lazy `uname -p` fallback.
        with mock.patch.object(platform, '_uname_cache', None), mock.patch('subprocess.Popen', side_effect=AssertionError('system spawned a tool')):
            self.assertEqual(self.run_plan(system=True), 0)

    def test_cutycapt_failure_or_non_png_never_imports(self):
        for data, rc in ((b'\x89PNG\r\n\x1a\nextra', 1), (b'not png', 0), (b'\x89PNG\r\n\x1a\n', 0)):
            with self.subTest(data=data, rc=rc):
                self.root = self.base / ('data-' + str(len(list(self.base.iterdir()))))
                self.stub('cutycapt', data, rc)
                self.assertEqual(self.run_plan(web='https://localhost:8443/path?q=1'), 1)
                self.assertEqual(self.inv.scan(self.root).records, [])

    def test_web_success_preserves_url_and_private_outputs(self):
        self.stub('cutycapt', b'\x89PNG\r\n\x1a\nextra')
        self.assertEqual(self.run_plan(web='https://[::1]:8443/path?q=1'), 0)
        args = self.calls()[0]
        self.assertIn('--url=https://[::1]:8443/path?q=1', args)
        run, path = self.ledger()
        self.assertEqual(run['actions'][0]['status'], 'success')
        self.assertIn('private error', (path / 'web.stderr').read_text())
        self.assertTrue(self.inv.verify(self.root).ok)
        for p in self.root.rglob('*'):
            self.assertEqual(p.stat().st_mode & 0o777, 0o700 if p.is_dir() else 0o600)

    def test_pcap_endian_micro_nano_and_streamed_lengths(self):
        self.assertTrue(hasattr(self.c, 'pcap_packet_count'), 'pcap_packet_count missing')
        path = self.base / 'input.pcap'
        for endian in ('<', '>'):
            for nano in (False, True):
                path.write_bytes(self.pcap(endian, nano, 2))
                self.assertEqual(self.c.pcap_packet_count(path), 2)
        for data in (b'', b'wrong' * 9, self.pcap()[:-1], self.pcap() + b'x',
                     self.pcap(packets=0)[:16] + struct.pack('<I', 0) + self.pcap(packets=0)[20:],
                     self.pcap(packets=0) + struct.pack('<IIII', 1, 0, 8, 4) + b'12345678'):
            path.write_bytes(data)
            with self.assertRaises(self.model.EvidenceError):
                self.c.pcap_packet_count(path)

    def test_tcpdump_clean_interval_zero_packets_is_no_traffic(self):
        process = importlib.import_module('evidence.process')
        def interval(argv, stdout, stderr, **kw):
            self.assertEqual(kw, {'timeout': 1, 'interval_stop': True})
            self.assertEqual(argv[1:7], ['-U', '-n', '-c', '1', '-i', 'lo'])
            self.assertEqual(argv[-2:], ['host', '::1'])
            Path(argv[argv.index('-w') + 1]).write_bytes(self.pcap(packets=0))
            return process.ProcessResult(-signal.SIGINT, True, 'SIGINT')
        with mock.patch.object(self.c, 'run_child', side_effect=interval, create=True):
            self.assertEqual(self.run_plan(traffic='::1', interface='lo', duration=1, packet_limit=1), 0)
        self.assertEqual(self.ledger()[0]['actions'][0]['status'], 'no-traffic')
        self.assertEqual(self.inv.scan(self.root).records, [])

    def test_tcpdump_valid_packets_are_imported(self):
        self.stub('tcpdump', self.pcap())
        self.assertEqual(self.run_plan(traffic='localhost', interface='lo', duration=300, packet_limit=10000), 0)
        self.assertEqual(self.calls()[0][:6], ['-U', '-n', '-c', '10000', '-i', 'lo'])
        self.assertTrue(self.inv.verify(self.root).ok)

    def test_truncated_or_wrong_pcap_is_failed(self):
        self.stub('tcpdump', self.pcap()[:-1])
        self.assertEqual(self.run_plan(traffic='localhost', interface='lo'), 1)
        self.assertEqual(self.ledger()[0]['actions'][0]['status'], 'failed')
        self.assertEqual(self.inv.scan(self.root).records, [])

    def nmap_data(self, host='localhost'):
        return (f'# Nmap 7.95 scan initiated Thu Nov 13 as: nmap -oN out {host}\n'
                f'Nmap scan report for {host}\n80/tcp open http\n'
                '# Nmap done at Thu Nov 13 10:00:00 2026 -- 1 IP address (1 host up) scanned in 0.01 seconds\n').encode()

    def test_nmap_basic_has_100_ports_no_nse_or_version(self):
        self.stub('nmap', self.nmap_data('::1'))
        self.assertEqual(self.run_plan(scan='::1', scan_profile='basic'), 0)
        args = self.calls()[0]
        self.assertEqual(args[:5], ['-6', '-n', '-sT', '--top-ports', '100'])
        self.assertEqual(args[-1], '::1')
        self.assertEqual(len(args), 8)
        self.assertTrue(self.inv.verify(self.root).ok)

    def test_nmap_full_has_all_ports_version_no_min_rate(self):
        self.stub('nmap', self.nmap_data())
        self.assertEqual(self.run_plan(scan='localhost', scan_profile='full'), 0)
        args = self.calls()[0]
        self.assertEqual(args[:4], ['-n', '-sT', '-sV', '-p-'])
        self.assertEqual(len(args), 7)

    def test_nmap_rc_or_missing_completion_never_imports(self):
        for data, rc in ((self.nmap_data(), 1), (b'echo Nmap done\n', 0),
                         (self.nmap_data().replace(b'# Nmap done at', b'echo # Nmap done at'), 0)):
            self.root = self.base / ('data-' + str(len(list(self.base.iterdir()))))
            self.stub('nmap', data, rc)
            self.assertEqual(self.run_plan(scan='localhost', scan_profile='basic'), 1)
            self.assertEqual(self.inv.scan(self.root).records, [])

    def test_forced_writer_cleanup_and_deadline_never_publish(self):
        process = importlib.import_module('evidence.process')
        for action in ('web', 'scan', 'traffic'):
            for stopped, timeout in (('SIGTERM', False), ('SIGKILL', True), (None, True)):
                self.root = self.base / f'data-{action}-{stopped}-{timeout}'
                def forced(argv, stdout, stderr, **kw):
                    out = next((a[6:] for a in argv if a.startswith('--out=')), None)
                    if out is None:
                        out = argv[argv.index('-oN' if action == 'scan' else '-w') + 1]
                    Path(out).write_bytes({'web': b'\x89PNG\r\n\x1a\nextra', 'scan': self.nmap_data(), 'traffic': self.pcap()}[action])
                    return process.ProcessResult(0, timeout, stopped)
                options = {'web': {'web': 'https://localhost'}, 'scan': {'scan': 'localhost', 'scan_profile': 'basic'},
                           'traffic': {'traffic': 'localhost', 'interface': 'lo'}}[action]
                with mock.patch.object(self.c, 'run_child', side_effect=forced, create=True):
                    self.assertEqual(self.run_plan(**options), 1)
                self.assertEqual(self.inv.scan(self.root).records, [])

    def test_partial_run_is_rc1_and_only_successes_published(self):
        self.stub('cutycapt', b'not png')
        self.stub('nmap', self.nmap_data())
        self.assertEqual(self.run_plan(web='https://localhost', traffic='localhost', interface='lo',
                                       scan='localhost', scan_profile='basic', system=True), 1)
        run, path = self.ledger()
        self.assertEqual([a['status'] for a in run['actions']], ['failed', 'failed', 'success', 'success'])
        self.assertEqual(len(self.inv.scan(self.root).records), 2)
        self.assertTrue(self.inv.verify(self.root).ok)

    def test_interrupt_does_not_publish_active_step(self):
        process = importlib.import_module('evidence.process')
        for sig in (signal.SIGINT, signal.SIGTERM):
            self.root = self.base / str(sig)
            def interrupt(*args, **kwargs):
                raise process.CaptureInterrupted(sig)
            with mock.patch.object(self.c, 'run_child', side_effect=interrupt, create=True):
                self.assertEqual(self.run_plan(web='https://localhost', system=True), 128 + sig)
            run, _ = self.ledger()
            self.assertEqual([a['status'] for a in run['actions']], ['interrupted', 'not-run'])
            self.assertEqual(self.inv.scan(self.root).records, [])

    def test_real_parent_only_signals_reap_active_stub_and_return_signal_rc(self):
        path = self.base / 'bin/cutycapt'
        for sig in (signal.SIGINT, signal.SIGTERM):
            self.root = self.base / str(sig)
            pidfile = self.base / 'child-pid'
            path.write_text('#!' + sys.executable + '\nimport os,signal,time\nfrom pathlib import Path\n'
                            f'Path({str(pidfile)!r}).write_text(str(os.getpid()))\n'
                            f'os.kill(os.getppid(), {int(sig)})\ntime.sleep(60)\n')
            path.chmod(0o700)
            code = ('import sys\nfrom pathlib import Path\n'
                    f'sys.path.insert(0, {str(self.framework / "00_Config/lib")!r})\n'
                    'from evidence.capture import capture,CapturePlan\n'
                    f'sys.exit(capture(Path({str(self.root)!r}), CapturePlan(web="https://localhost", system=True, authorize_network=True)))')
            result = subprocess.run([sys.executable, '-B', '-c', code], env=dict(os.environ),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 128 + sig, result.stderr)
            self.assertFalse(Path('/proc/' + pidfile.read_text()).exists())
            self.assertEqual([a['status'] for a in self.ledger()[0]['actions']], ['interrupted', 'not-run'])
            self.assertEqual(self.inv.scan(self.root).records, [])

    def test_system_interrupt_restores_handlers_and_never_imports(self):
        previous = signal.getsignal(signal.SIGINT)
        def interrupt():
            os.kill(os.getpid(), signal.SIGINT)
        with mock.patch.object(self.c.getpass, 'getuser', side_effect=interrupt):
            self.assertEqual(self.run_plan(system=True), 130)
        self.assertIs(signal.getsignal(signal.SIGINT), previous)
        self.assertEqual(self.inv.scan(self.root).records, [])

    def test_capture_then_package_excludes_failed_diagnostics(self):
        self.stub('cutycapt', b'private broken artifact')
        self.assertEqual(self.run_plan(web='https://localhost', system=True), 1)
        package = importlib.import_module('evidence.package')
        archive = package.create(self.root)
        package.check_archive(archive)
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                self.assertNotIn('runs', member.name)
                self.assertNotIn('work', member.name)
                self.assertNotIn(b'private broken artifact', tar.extractfile(member).read())

    def test_ledger_preserves_backend_failure_rc(self):
        self.stub('cutycapt', b'\x89PNG\r\n\x1a\nextra', 17)
        self.assertEqual(self.run_plan(web='https://localhost'), 1)
        self.assertEqual(self.ledger()[0]['actions'][0]['rc'], 17)

    def test_backend_deadlines_are_fixed(self):
        process = importlib.import_module('evidence.process')
        for action, profile, deadline in (('web', None, 60), ('scan', 'basic', 120), ('scan', 'full', 1800)):
            self.root = self.base / f'{action}-{profile}'
            def expired(argv, stdout, stderr, **kw):
                self.assertEqual(kw, {'timeout': deadline, 'interval_stop': False})
                return process.ProcessResult(-15, True, 'SIGTERM')
            kw = {'web': 'https://localhost'} if action == 'web' else {'scan': 'localhost', 'scan_profile': profile}
            with mock.patch.object(self.c, 'run_child', side_effect=expired):
                self.assertEqual(self.run_plan(**kw), 1)

    def test_format_validators_reject_links_and_nonregular_files(self):
        path = self.base / 'input'
        path.symlink_to(self.base / 'missing')
        for validate in (self.c.validate_png, self.c.pcap_packet_count, lambda p: self.c.validate_nmap(p, 'localhost')):
            with self.assertRaises(self.model.EvidenceError):
                validate(path)
            with self.assertRaises(self.model.EvidenceError):
                validate(self.base)

    def test_nmap_footer_not_echo_or_trailing_partial(self):
        path = self.base / 'input'
        for data in (self.nmap_data() + b'more scanning\n', self.nmap_data().replace(b'1 IP address', b'0 IP addresses')):
            path.write_bytes(data)
            with self.assertRaises(self.model.EvidenceError):
                self.c.validate_nmap(path, 'localhost')
