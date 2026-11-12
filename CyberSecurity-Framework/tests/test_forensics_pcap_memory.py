"""Offline adapters: synthetic inputs, closed PATH, no forensic binaries."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from forensics_fixture import load_evidence, runtime_environment, sandbox

FRAMEWORK = Path(__file__).resolve().parents[1]
SECRET = 'synthetic-password-PRIVATE'
LEAVES = {'pcap': 'pcaps/pcap_analyzer.sh', 'memory': 'memory/volatility_analysis.sh'}

# Realistic help/table fragments. Unknown options fail rather than silently pass.
BACKEND = r'''
import json, os, pathlib, sys
a = sys.argv[1:]; name = pathlib.Path(sys.argv[0]).name
root = pathlib.Path(os.environ['ROOT'])
with (root/'calls').open('a') as f:
    f.write(json.dumps([name, a, os.environ.get('HOME'), os.environ.get('XDG_CACHE_HOME')])+'\n')
def out(s): print(s)
def fail(rc=7):
    print('synthetic-password-PRIVATE backend error', file=sys.stderr); sys.exit(rc)
if name == 'capinfos':
    if os.environ.get('CAPFAIL'): fail()
    if len(a)!=1 or not pathlib.Path(a[0]).is_relative_to(root/'outputs'): fail(91)
    out('File type: Wireshark/tcpdump/... - pcap\nNumber of packets: '+os.environ.get('PACKETS','3')); sys.exit()
if name == 'tshark':
    if a == ['--version']:
        out('TShark (Wireshark) 4.2.0' if not os.environ.get('BADVERSION') else 'unrelated executable'); sys.exit()
    if a == ['-z','help']:
        text = 'tshark: The available statistics for the "-z" option are:\n     io,phs\n     conv,tcp\n     conv,udp' if not os.environ.get('BADHELP') else 'unknown'
        print(text, file=sys.stderr if os.environ.get('HELP_STDERR') else sys.stdout); sys.exit()
    if '-r' not in a or '-n' not in a or '-i' in a: fail(92)
    if not pathlib.Path(a[a.index('-r')+1]).is_relative_to(root/'outputs'): fail(93)
    if '-z' in a and a[a.index('-z')+1] not in ('io,phs','conv,tcp','conv,udp'): fail(94)
    if '-Y' in a:
        fields = a[a.index('-Y'):]
        supported = [
            ['-Y','dns.flags.response==0','-T','fields','-e','dns.qry.name'],
            ['-Y','http.request','-T','fields','-e','http.request.uri','-e','http.host'],
            ['-Y','http.request.method == "POST"','-T','fields','-e','http.request.uri','-e','http.host','-e','http.request.uri.query'],
            ['-Y','http.response','-T','fields','-e','http.file_data','-e','http.content_type']]
        if fields not in supported: fail(89)
    if os.environ.get('TSFAIL'): fail(8)
    if os.environ.get('NONMATCH'): out('opaque-sensitive-credential-value harmless')
    elif not os.environ.get('EMPTY'): out('synthetic-password-PRIVATE login')
    sys.exit()
family = os.environ.get('FAMILY','v2')
if a == ['-h']:
    if os.environ.get('BANNER_STDERR'):
        print('Volatility Foundation Volatility Framework 2.6.1',file=sys.stderr)
        out(' --profile=PROFILE\n imageinfo pslist pstree netscan dlllist cmdscan consoles'); sys.exit()
    if family == 'v2': out('Volatility Foundation Volatility Framework 2.6.1\n --profile=PROFILE\n --cache-directory=CACHE_DIRECTORY\n imageinfo pslist pstree netscan dlllist cmdscan consoles')
    elif family == 'v3':
        out('Volatility 3 Framework 2.26.2\n --offline --symbol-dirs SYMBOL_DIRS --cache-path CACHE_PATH\n windows.info.Info windows.pslist.PsList windows.pstree.PsTree windows.netscan.NetScan windows.dlllist.DllList'+(' windows.cmdscan.CmdScan windows.consoles.Consoles' if os.environ.get('COMMANDS') else ''))
    else: out('unrelated utility')
    sys.exit()
if '-f' not in a or not pathlib.Path(a[a.index('-f')+1]).is_relative_to(root/'outputs'): fail(95)
if not pathlib.Path(os.environ['HOME']).is_relative_to(root/'outputs'): fail(96)
if family == 'v3':
    if '--offline' not in a or any(x.startswith('--profile') for x in a): fail(97)
    if '--symbol-dirs' not in a or '--cache-path' not in a: fail(98)
    if not pathlib.Path(a[a.index('--symbol-dirs')+1]).is_relative_to(root/'outputs'): fail(99)
    plugin = a[-1]
    if plugin == 'windows.info.Info':
        if os.environ.get('INFOFAIL'): fail(6)
        if os.environ.get('LINUX'): out('Linux version 6.1'); sys.exit()
        out('Variable Value\nNTBuildLab 19041.1.amd64fre.vb_release\nMajor/Minor 10.0'); sys.exit()
else:
    plugin = a[-1]
    if plugin == 'imageinfo':
        if os.environ.get('INFOFAIL'): fail(6)
        if os.environ.get('UNSATISFIED') == plugin:
            out('Unsatisfied requirement: Windows kernel symbols'); sys.exit()
        out('Suggested Profile(s) : '+('LinuxUbuntu_5_4' if os.environ.get('LINUX') else 'No suggestion' if os.environ.get('NOSUGGEST') else 'Win7SP1x64, Win7SP0x64')); sys.exit()
    if not any(x.startswith('--profile=Win') for x in a): fail(90)
if os.environ.get('VOLFAIL') == plugin: fail(9)
if os.environ.get('UNSATISFIED') == plugin:
    out('Unsatisfied requirement plugins.PsList.kernel.symbol_table_name: Windows kernel symbols'); sys.exit()
out('synthetic-password-PRIVATE process table')
'''


class PcapMemoryTests(unittest.TestCase):
    def setUp(self):
        self.ctx = sandbox(); self.root = self.ctx.__enter__()
        self.addCleanup(self.ctx.__exit__, None, None, None)
        self.env = runtime_environment(self.root)
        self.env['FORENSICS_ANALYSIS_ROOT'] = str(self.root/'outputs')
        self.code = self.root/'code'
        for rel in [*(Path('08_Forensics')/v for v in LEAVES.values()),
                    *(Path('00_Config/lib')/v for v in ('forensics_evidence.py', 'forensics_runtime.bash', 'forensics_volatility.bash'))]:
            if (FRAMEWORK/rel).exists():
                dst = self.code/rel; dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(FRAMEWORK/rel, dst)
        for name in ('dirname', 'sort', 'grep', 'mkdir'):
            p = self.root/'bin'/name
            p.symlink_to('/usr/bin/'+name)
        for name in ('capinfos', 'tshark', 'volatility'):
            self.stub(name, '#!'+sys.executable+'\n'+BACKEND)
        for name in ('curl', 'wget', 'nc', 'sudo', 'mount', 'pip', 'apt', 'tcpdump'):
            self.stub(name, '#!/bin/bash\nprintf denied >> "$ROOT/network"\nexit 99\n')
        self.source = self.root/'sources'/'--input with spaces'
        self.source.write_text(SECRET)
        self.symbols = self.root/'sources'/'local symbols'
        self.symbols.mkdir(); (self.symbols/'fixture.json').write_text('{}')
        self.e = load_evidence()

    def stub(self, name, body):
        p = self.root/'bin'/name
        if p.exists() or p.is_symlink(): p.unlink()
        p.write_text(body); p.chmod(0o700)

    def invoke(self, kind='pcap', *args):
        before = {str(p): (p.lstat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
                  for p in (self.root/'sources').rglob('*') if p.is_file() and not p.is_symlink()}
        r = subprocess.run(['/bin/bash', str(self.code/'08_Forensics'/LEAVES[kind]), *map(str, args or [self.source])],
                           env=self.env, cwd=self.source.parent, capture_output=True, text=True, timeout=55)
        self.assertNotIn(SECRET, r.stdout+r.stderr)
        self.assertEqual(r.stdout,'', 'leaf leaked backend/control output')
        self.assertFalse((self.root/'network').exists(), 'network/privilege attempt')
        for p, record in before.items():
            self.assertEqual((Path(p).lstat().st_mode, hashlib.sha256(Path(p).read_bytes()).hexdigest()), record)
        return r

    def runs(self): return sorted((self.root/'outputs').rglob('run.json'))

    def run_data(self):
        self.assertTrue(self.runs(), 'missing private run')
        return self.e.read_run(self.runs()[-1])

    def calls(self):
        p = self.root/'calls'
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def steps(self): return {s['name']: s for s in self.run_data()['steps']}

    def test_pcap_all_operations_copy_only_private_unique(self):
        for _ in range(2): self.assertEqual(self.invoke().returncode, 0)
        self.assertEqual(len(self.runs()), 2)
        self.assertTrue({'capinfos', 'tshark_help', 'protocols', 'conversations_tcp', 'conversations_udp', 'dns_queries', 'http_requests', 'credentials', 'files'} <= set(self.steps()))
        copies = []
        for path in self.runs():
            run = self.e.read_run(path); self.assertEqual(run['state'], 'COMPLETADO')
            copies.append(run['inputs'][0]['work_path'])
            for p in path.parent.rglob('*'):
                self.assertEqual(p.stat().st_mode & 0o777, 0o700 if p.is_dir() else 0o600)
        self.assertNotEqual(*copies)
        for name, args, *_ in self.calls():
            if name == 'tshark' and '-r' in args:
                self.assertIn('-n', args); self.assertNotIn(str(self.source), args)

    def test_pcap_corrupt_stops_before_tshark(self):
        self.env['CAPFAIL']='1'
        self.assertEqual(self.invoke().returncode, 1)
        self.assertEqual(self.steps()['capinfos']['rc'], 7)
        self.assertEqual([c[0] for c in self.calls()], ['capinfos'])

    def test_pcap_valid_zero_packets_and_empty_tables_complete(self):
        self.env.update(PACKETS='0', EMPTY='1')
        self.assertEqual(self.invoke().returncode, 0)
        self.assertEqual(self.run_data()['state'], 'COMPLETADO')

    def test_pcap_no_indicator_matches_is_success(self):
        self.env['EMPTY']='1'
        self.assertEqual(self.invoke().returncode, 0)
        self.assertEqual(self.steps()['credentials']['rc'], 0)

    def test_pcap_pipeline_producer_failure_not_hidden(self):
        self.env['TSFAIL']='1'
        self.assertEqual(self.invoke().returncode, 1)
        for name in ('dns_queries', 'http_requests', 'credentials'):
            self.assertEqual(self.steps()['raw_'+name]['rc'], 8)
            self.assertEqual(self.steps()['raw_'+name]['state'], 'FALLIDO')
            self.assertEqual(self.steps()[name]['state'], 'NO_EVALUABLE')

    def test_pcap_full_producer_output_preserved_before_filter(self):
        self.env['NONMATCH']='1'
        self.assertEqual(self.invoke().returncode,0)
        analysis=self.runs()[-1].parent/'analysis'
        self.assertIn('opaque-sensitive-credential-value',(analysis/'raw_credentials.stdout').read_text())
        self.assertEqual((analysis/'credentials.stdout').read_text(),'')

    def test_tshark_real_statistics_help_can_be_stderr(self):
        self.env['HELP_STDERR']='1'
        self.assertEqual(self.invoke().returncode,0)
        self.assertEqual(self.steps()['protocols']['state'],'COMPLETADO')

    def test_tshark_unknown_version_blocks_statistics(self):
        self.env['BADVERSION']='1'
        self.assertEqual(self.invoke().returncode,1)
        self.assertEqual(self.steps()['protocols']['state'],'NO_EVALUABLE')

    def test_pcap_unknown_statistics_not_silent_success(self):
        self.env['BADHELP']='1'
        self.assertEqual(self.invoke().returncode, 1)
        self.assertNotEqual(self.run_data()['state'], 'COMPLETADO')
        self.assertFalse(any('-z' in c[1] and '-r' in c[1] for c in self.calls()))

    def test_missing_pcap_tools_is_precondition(self):
        for name in ('tshark', 'capinfos'):
            with self.subTest(name=name):
                p=self.root/'bin'/name; body=p.read_bytes(); p.unlink()
                self.assertEqual(self.invoke().returncode, 2)
                self.assertEqual(self.runs(), [])
                p.write_bytes(body); p.chmod(0o700)

    def test_v2_seven_plugins_and_detected_profile(self):
        self.assertEqual(self.invoke('memory').returncode, 0)
        calls=[c for c in self.calls() if '-f' in c[1]]
        self.assertEqual([c[1][-1] for c in calls], ['imageinfo','pslist','pstree','netscan','dlllist','cmdscan','consoles'])
        self.assertEqual(self.run_data()['state'], 'COMPLETADO')

    def test_v2_banner_on_stderr_still_recognized_privately(self):
        self.env['BANNER_STDERR']='1'
        self.assertEqual(self.invoke('memory').returncode,0)
        self.assertEqual(len([c for c in self.calls() if '-f' in c[1]]),7)

    def test_plugins_and_options_on_stderr_are_recognized(self):
        self.env.update(FAMILY='v3', COMMANDS='1')
        self.stub('volatility', '#!'+sys.executable+'\n'+BACKEND.replace(
            'def out(s): print(s)', "def out(s): print(s, file=sys.stderr if a == ['-h'] else sys.stdout)"))
        self.assertEqual(self.invoke('memory', self.source, '--symbols', self.symbols).returncode, 0)
        self.assertEqual(self.steps()['consoles']['state'], 'COMPLETADO')

    def test_relative_path_still_resolves_after_private_cwd_change(self):
        self.env['PATH'] = '../bin'
        self.assertEqual(self.invoke('memory').returncode, 0)
        self.assertEqual(self.steps()['pslist']['state'], 'COMPLETADO')

    def test_library_source_uses_zsh_fallback(self):
        # Test library location only: the Task2 operational runtime is Bash-only.
        runtime = self.code/'00_Config/lib/forensics_runtime.bash'
        runtime.write_text('_FORENSICS_HELPER="${0%/*}/forensics_evidence.py"\n')
        r = subprocess.run(['/usr/bin/zsh', '-c', 'source "$1"; print -r -- "$_FORENSICS_HELPER"',
                            'zsh', str(self.code/'00_Config/lib/forensics_volatility.bash')],
                           env=self.env, cwd=self.source.parent, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stderr, '')
        self.assertEqual(r.stdout.strip(), str(self.code/'00_Config/lib/forensics_evidence.py'))

    def test_backend_home_cache_and_temporary_files_confined(self):
        self.stub('volatility', '#!'+sys.executable+'\n'+BACKEND.replace("out('synthetic-password-PRIVATE process table')", "pathlib.Path(os.environ['TMPDIR'],'temporary').write_text('private'); pathlib.Path(os.environ['XDG_CONFIG_HOME'],'config').write_text('private'); out('synthetic-password-PRIVATE process table')"))
        self.assertEqual(self.invoke('memory').returncode,0)
        for _, _, home, cache in self.calls():
            self.assertTrue(Path(home).is_relative_to(self.root/'outputs'))
            self.assertTrue(Path(cache).is_relative_to(self.root/'outputs'))
        self.assertFalse((self.root/'home'/'temporary').exists())

    def test_v2_explicit_profile_is_preserved(self):
        self.assertEqual(self.invoke('memory', self.source, '--profile','Win10x64_19041').returncode, 0)
        self.assertEqual(len([c for c in self.calls() if '-f' in c[1]]),7)
        for c in self.calls():
            if '-f' in c[1] and c[1][-1]!='imageinfo': self.assertIn('--profile=Win10x64_19041',c[1])

    def test_v2_explicit_profile_allows_no_suggestion_not_linux(self):
        self.env['NOSUGGEST']='1'
        self.assertEqual(self.invoke('memory',self.source,'--profile','Win7SP1x64').returncode,0)

    def test_v2_no_suggestion_without_profile_blocks_dependents(self):
        self.env['NOSUGGEST']='1'
        self.assertEqual(self.invoke('memory').returncode,1)
        self.assertEqual([c[1][-1] for c in self.calls() if '-f' in c[1]],['imageinfo'])

    def test_v2_identification_error_preserves_rc_and_blocks_dependents(self):
        self.env['INFOFAIL'] = '1'
        self.assertEqual(self.invoke('memory').returncode, 1)
        self.assertEqual(self.steps()['imageinfo']['rc'], 6)
        self.assertEqual([c[1][-1] for c in self.calls() if '-f' in c[1]], ['imageinfo'])

    def test_v2_explicit_profile_cannot_override_unsatisfied_requirements(self):
        self.env['UNSATISFIED'] = 'imageinfo'
        self.assertEqual(self.invoke('memory', self.source, '--profile', 'Win7SP1x64').returncode, 1)
        self.assertEqual(self.steps()['imageinfo']['state'], 'NO_EVALUABLE')
        self.assertEqual([c[1][-1] for c in self.calls() if '-f' in c[1]], ['imageinfo'])

    def test_v2_explicit_profile_does_not_override_linux_identification(self):
        self.env['LINUX']='1'
        self.assertEqual(self.invoke('memory',self.source,'--profile','Win7SP1x64').returncode,1)
        self.assertEqual([c[1][-1] for c in self.calls() if '-f' in c[1]],['imageinfo'])

    def test_v2_linux_is_not_reinterpreted(self):
        self.env['LINUX']='1'
        self.assertEqual(self.invoke('memory').returncode, 1)
        self.assertEqual([c[1][-1] for c in self.calls() if '-f' in c[1]], ['imageinfo'])
        self.assertNotEqual(self.run_data()['state'], 'COMPLETADO')

    def test_v3_offline_symbols_copy_no_profile_missing_commands_partial(self):
        self.env['FAMILY']='v3'
        self.assertEqual(self.invoke('memory',self.source,'--symbols',self.symbols).returncode, 1)
        steps=self.steps()
        self.assertEqual(steps['pslist']['state'],'COMPLETADO')
        self.assertEqual(steps['cmdscan']['state'],'NO_EVALUABLE')
        self.assertEqual(steps['consoles']['state'],'NO_EVALUABLE')
        for c in self.calls():
            if '-f' in c[1]: self.assertIn('--offline',c[1]); self.assertFalse(any(x.startswith('--profile') for x in c[1]))

    def test_v3_available_commands_complete(self):
        self.env.update(FAMILY='v3',COMMANDS='1')
        self.assertEqual(self.invoke('memory',self.source,'--symbols',self.symbols,'--backend','v3').returncode,0)
        self.assertEqual(len([c for c in self.calls() if '-f' in c[1]]),7)

    def test_v3_profile_is_explicit_error_not_ignored(self):
        self.env['FAMILY']='v3'
        r=self.invoke('memory',self.source,'--profile','Win7SP1x64','--symbols',self.symbols)
        self.assertEqual(r.returncode,1); self.assertIn('profile',r.stderr)
        self.assertFalse(any('-f' in c[1] for c in self.calls()))

    def test_v3_missing_symbols_no_analysis(self):
        self.env['FAMILY']='v3'
        self.assertEqual(self.invoke('memory').returncode,1)
        self.assertFalse(any('-f' in c[1] for c in self.calls()))
        self.assertNotEqual(self.run_data()['state'],'COMPLETADO')

    def test_v3_empty_symbol_tree_no_analysis(self):
        self.env['FAMILY']='v3'
        (self.symbols/'fixture.json').unlink()
        self.assertEqual(self.invoke('memory',self.source,'--symbols',self.symbols).returncode,1)
        self.assertFalse(any('-f' in c[1] for c in self.calls()))

    def test_v3_identification_tool_error_blocks_dependents(self):
        self.env.update(FAMILY='v3',INFOFAIL='1')
        self.assertEqual(self.invoke('memory',self.source,'--symbols',self.symbols).returncode,1)
        self.assertEqual(self.steps()['imageinfo']['rc'],6)
        self.assertEqual([c[1][-1] for c in self.calls() if '-f' in c[1]],['windows.info.Info'])

    def test_v3_empty_tables_are_not_tool_failure(self):
        self.env.update(FAMILY='v3',COMMANDS='1')
        self.stub('volatility','#!'+sys.executable+'\n'+BACKEND.replace("out('synthetic-password-PRIVATE process table')",'sys.exit()'))
        self.assertEqual(self.invoke('memory',self.source,'--symbols',self.symbols).returncode,0)
        self.assertEqual(self.steps()['pslist']['state'],'COMPLETADO')

    def test_absent_volatility_is_precondition_without_run(self):
        for name in ('volatility','vol','vol.py'):
            p=self.root/'bin'/name
            if p.exists(): p.unlink()
        self.assertEqual(self.invoke('memory').returncode,2)
        self.assertEqual(self.runs(),[])

    def test_sort_and_grep_read_errors_are_not_empty_success(self):
        self.stub('sort','#!/bin/bash\nexit 12\n')
        self.stub('grep','#!/bin/bash\nexit 13\n')
        self.assertEqual(self.invoke().returncode,1)
        self.assertEqual(self.steps()['dns_queries']['rc'],12)
        self.assertEqual(self.steps()['credentials']['rc'],13)

    def test_v3_linux_info_blocks_windows_plugins(self):
        self.env.update(FAMILY='v3',LINUX='1')
        self.assertEqual(self.invoke('memory',self.source,'--symbols',self.symbols).returncode,1)
        self.assertEqual([c[1][-1] for c in self.calls() if '-f' in c[1]],['windows.info.Info'])

    def test_v3_tool_failure_rc_and_stderr_preserved(self):
        self.env.update(FAMILY='v3',VOLFAIL='windows.pslist.PsList',COMMANDS='1')
        self.assertEqual(self.invoke('memory',self.source,'--symbols',self.symbols).returncode,1)
        self.assertEqual(self.steps()['pslist']['rc'],9)
        self.assertEqual(self.steps()['pslist']['state'],'FALLIDO')
        self.assertIn(SECRET,(self.runs()[-1].parent/'analysis/pslist.stderr').read_text())

    def test_v3_unsatisfied_symbols_with_zero_rc_not_success(self):
        self.env.update(FAMILY='v3',UNSATISFIED='windows.pslist.PsList',COMMANDS='1')
        self.assertEqual(self.invoke('memory',self.source,'--symbols',self.symbols).returncode,1)
        self.assertEqual(self.steps()['pslist']['state'],'NO_EVALUABLE')
        self.assertEqual(self.steps()['pslist']['rc'],0)

    def test_unknown_backend_never_guesses_plugins(self):
        self.env['FAMILY']='unknown'
        self.assertEqual(self.invoke('memory').returncode,1)
        self.assertFalse(any('-f' in c[1] for c in self.calls()))

    def test_real_family_not_command_name(self):
        (self.root/'bin'/'volatility').rename(self.root/'bin'/'vol.py')
        self.assertEqual(self.invoke('memory').returncode,0)

    def test_requested_backend_mismatch_no_analysis(self):
        self.assertEqual(self.invoke('memory',self.source,'--backend','v3','--symbols',self.symbols).returncode,1)
        self.assertFalse(any('-f' in c[1] for c in self.calls()))

    def test_invalid_cli_and_input_preconditions_no_run(self):
        for kind,args in [('pcap',[self.source,'extra']),('memory',[self.source,'--backend','bad']),
                          ('memory',[self.source,'--unknown']),('pcap',[self.source.parent]),
                          ('memory',[self.source,'--symbols',self.source])]:
            with self.subTest(kind=kind,args=args):
                self.assertEqual(self.invoke(kind,*args).returncode,2)
                self.assertEqual(self.runs(),[])

    def test_symlink_sources_rejected_before_tools(self):
        link=self.source.parent/'link'; link.symlink_to(self.source)
        for kind in LEAVES:
            self.assertEqual(self.invoke(kind,link).returncode,2)
        self.assertEqual(self.calls(),[])

    def test_relative_leading_dash_input_normalized(self):
        self.assertEqual(self.invoke('pcap',self.source.name).returncode,0)

    def test_symbols_symlink_tree_never_starts_probe(self):
        (self.symbols/'link').symlink_to(self.source)
        self.assertEqual(self.invoke('memory',self.source,'--symbols',self.symbols).returncode,1)
        self.assertEqual(self.calls(),[])


if __name__ == '__main__': unittest.main()
