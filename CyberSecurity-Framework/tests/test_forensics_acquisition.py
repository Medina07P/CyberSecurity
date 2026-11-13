"""Acquisition/install boundaries: copied code, synthetic files, closed stubs only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
import ctypes
import signal
import socket
import time
from forensics_fixture import sandbox, runtime_environment

FRAMEWORK=Path(__file__).resolve().parents[1]
BACKEND=r'''#!PYTHON
import json, os, pathlib, sys
p=pathlib.Path; root=p(os.environ['ROOT']); name=p(sys.argv[0]).name; a=sys.argv[1:]
with (root/'calls').open('a') as f: f.write(json.dumps([name,a])+'\n')
if os.environ.get('BLOCK_PREFLIGHT')==name:
 import signal, socket
 child=os.fork()
 if child==0:
  signal.signal(signal.SIGTERM,signal.SIG_IGN)
  signal.signal(signal.SIGINT,signal.SIG_IGN)
  while True: signal.pause()
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 signal.signal(signal.SIGINT,signal.SIG_IGN)
 with socket.socket(socket.AF_UNIX) as ready:
  ready.connect(str(root/'ready.sock'))
  ready.sendall(json.dumps([os.getpid(),child]).encode())
 while True: signal.pause()
if name=='sudo':
 if os.environ.get('NO_PRIVILEGE'): sys.exit(1)
 if a and a[0]=='-n': a=a[1:]
 if a==['true']: sys.exit(0)
 os.execv(str(root/'bin'/a[0]),a)
if name=='apt': sys.exit(int(os.environ.get('APT_RC','0')))
if name=='uname': print('SYNTHETIC KERNEL'); sys.exit(int(os.environ.get('UNAME_RC','0')))
if name=='cat':
 if a!=['/etc/os-release']: sys.exit(96)
 print('SYNTHETIC OS'); sys.exit(int(os.environ.get('CAT_RC','0')))
if name in ('avml','lime','dd'):
 if '--help' in a:
  if os.environ.get('UNKNOWN_'+name.upper()): print('unrelated module'); sys.exit(0)
  print('AVML Linux memory acquisition\nUsage: avml [OPTIONS] <FILENAME>' if name=='avml' else 'LiME prepared CLI\nUsage: lime -o <OUTPUT>')
  sys.exit(int(os.environ.get('HELP_RC','0')))
 out=p(next(x[3:] for x in a if x.startswith('of='))) if name=='dd' else p(a[-1])
 if not out.is_file() or out.stat().st_mode&0o777!=0o600: sys.exit(95)
 if os.environ.get('ABSENT'): out.unlink(missing_ok=True)
 elif os.environ.get('SYMLINK_RAM'): out.unlink(); out.symlink_to(root/'sources/sentinel')
 elif not os.environ.get('EMPTY'): out.write_bytes(b'SYNTHETIC RAM')
 sys.exit(int(os.environ.get('RAM_RC','0')))
sys.exit(98)
'''

class AcquisitionTests(unittest.TestCase):
 def setUp(self):
  self.box=sandbox(); self.root=self.box.__enter__(); self.addCleanup(self.box.__exit__,None,None,None)
  self.fw=self.root/'code'
  for relative in ('00_Config/lib','08_Forensics/memory'):
   target=self.fw/relative; target.mkdir(parents=True)
   for src in (FRAMEWORK/relative).iterdir():
    if src.is_file(): shutil.copy2(src,target/src.name)
  shutil.copy2(FRAMEWORK/'08_Forensics/requirements.sh',self.fw/'08_Forensics/requirements.sh')
  self.env=runtime_environment(self.root)
  for name in ('dirname','mkdir','date','grep','sed'):
   (self.root/'bin'/name).symlink_to('/usr/bin/'+name)
  for name in ('sudo','apt','avml','lime','dd','uname','cat'):
   path=self.root/'bin'/name
   if path.exists(): path.unlink()
   path.write_text(BACKEND.replace('PYTHON',sys.executable,1)); path.chmod(0o700)
  self.env.update(FORENSICS_ANALYSIS_ROOT=str(self.root/'outputs/analysis'),FORENSICS_MEMORY_ROOT=str(self.root/'outputs/memory'))
  # Only copied sources replace the root boundary; production has no bypass.
  path=self.fw/'08_Forensics/memory/memory_dump.sh'
  path.write_text(path.read_text().replace('(( EUID == 0 ))','[[ ${FIXTURE_ROOT:-0} = 1 ]]'))
 def test_direct_executable_entrypoints_preserve_cancel_and_check_contracts(self):
  for relative,args,expected in (('memory/memory_dump.sh',[],2),('requirements.sh',['--check'],0)):
   path=self.fw/'08_Forensics'/relative
   self.assertTrue(os.access(path,os.X_OK),'original executable leaf must remain executable')
   r=subprocess.run([str(path),*args],input='',env=self.env,text=True,capture_output=True,timeout=35)
   self.assertEqual(r.returncode,expected,r.stderr)
  self.assertEqual(self.calls(),[])
 def leaf(self,name,*args,input='',**env):
  return subprocess.run(['/bin/bash',str(self.fw/'08_Forensics'/name),*map(str,args)],env={**self.env,**env},input=input,text=True,capture_output=True,timeout=35)
 def calls(self):
  path=self.root/'calls'
  return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
 def runs(self):
  return sorted((self.root/'outputs/analysis/runs').glob('*/run.json'),key=lambda p:json.loads(p.read_text())['started'])
 def data(self): return json.loads(self.runs()[-1].read_text())
 def ram(self,*args,**kwargs): return self.leaf('memory/memory_dump.sh',*args,**kwargs)
 def test_denied_and_eof_never_probe_acquire_or_create(self):
  for answer in ('','no\n'):
   r=self.ram(input=answer); self.assertEqual(r.returncode,2,r.stderr)
   self.assertEqual(self.calls(),[]); self.assertEqual(list((self.root/'outputs').iterdir()),[])
 def blocked_preflight_cancel(self,backend,signum):
  """Signals go only to the leaf; cleanup uses pinned pidfds of fixture children."""
  libc=ctypes.CDLL(None,use_errno=True)
  previous=ctypes.c_int()
  self.assertEqual(libc.prctl(37,ctypes.byref(previous),0,0,0),0) # GET_CHILD_SUBREAPER
  self.assertEqual(libc.prctl(36,1,0,0,0),0)
  handles=[]; pids=[]; leaf=None
  sentinel=subprocess.Popen([sys.executable,'-B','-c','import signal; signal.pause()'],env=self.env)
  sentinel_fd=os.pidfd_open(sentinel.pid)
  try:
   with socket.socket(socket.AF_UNIX) as ready:
    ready.bind(str(self.root/'ready.sock')); ready.listen(1); ready.settimeout(8)
    with (self.root/'wrapper.stdout').open('w') as out,(self.root/'wrapper.stderr').open('w') as err:
     leaf=subprocess.Popen(['/bin/bash',str(self.fw/'08_Forensics/memory/memory_dump.sh')],
       env={**self.env,'BLOCK_PREFLIGHT':backend,'FIXTURE_ROOT':'1' if backend=='avml' else '0'},
       stdin=subprocess.PIPE,stdout=out,stderr=err,text=True)
     leaf.stdin.write('ADQUIRIR_MEMORIA\n'); leaf.stdin.close()
     connection,_=ready.accept()
     with connection: pids=json.loads(connection.recv(4096))
     handles=[os.pidfd_open(pid) for pid in pids]
     started=time.monotonic()
     if signum is not None: leaf.send_signal(signum)
     try: leaf.wait(timeout=2 if signum is not None else 12); completed=True
     except subprocess.TimeoutExpired: completed=False
     self.assertIsNone(sentinel.poll(),'unrelated sentinel was signaled')
     self.assertTrue(completed,'leaf remained blocked after cancellation or compatibility deadline')
     self.assertFalse(any(Path('/proc',str(pid)).exists() for pid in pids),
                      'preflight child/descendant survived or was not reaped')
     self.assertEqual(leaf.returncode,1 if signum is not None else 2)
     if signum is None: self.assertGreaterEqual(time.monotonic()-started,9.5)
     self.assertEqual(self.runs(),[])
     self.assertFalse(any(n in ('dd','uname','cat') or n=='avml' and a!=['--help'] for n,a in self.calls()))
  finally:
   for fd in handles:
    try: signal.pidfd_send_signal(fd,signal.SIGKILL)
    except ProcessLookupError: pass
    os.close(fd)
   if leaf is not None:
    if leaf.poll() is None: leaf.kill()
    leaf.wait(timeout=5)
   for pid in pids:
    try: os.waitpid(pid,0)
    except ChildProcessError: pass
   signal.pidfd_send_signal(sentinel_fd,signal.SIGKILL); sentinel.wait(timeout=5); os.close(sentinel_fd)
   self.assertEqual(libc.prctl(36,previous.value,0,0,0),0)
 def test_preflight_help_cancel_sigterm_reaps_child_and_descendant(self):
  self.blocked_preflight_cancel('avml',signal.SIGTERM)
 def test_preflight_help_cancel_sigint_reaps_child_and_descendant(self):
  self.blocked_preflight_cancel('avml',signal.SIGINT)
 def test_preflight_sudo_cancel_sigterm_reaps_child_and_descendant(self):
  self.blocked_preflight_cancel('sudo',signal.SIGTERM)
 def test_preflight_sudo_cancel_sigint_reaps_child_and_descendant(self):
  self.blocked_preflight_cancel('sudo',signal.SIGINT)
 def test_preflight_help_deadline_ten_seconds_without_acquisition(self):
  self.blocked_preflight_cancel('avml',None)
 def test_auto_never_falls_back_to_dd_or_unrecognized_lime(self):
  (self.root/'bin/avml').unlink()
  r=self.ram(input='ADQUIRIR_MEMORIA\n',UNKNOWN_LIME='1')
  self.assertEqual(r.returncode,2,r.stderr)
  self.assertIn('NO_EVALUABLE',r.stdout+r.stderr)
  self.assertFalse(any(n in ('dd','uname','cat') for n,a in self.calls()))
 def test_avml_success_has_private_new_products_and_structured_limits(self):
  for _ in range(2):
   r=self.ram(input='ADQUIRIR_MEMORIA\n'); self.assertEqual(r.returncode,0,r.stderr)
  self.assertEqual(len(self.runs()),2)
  for run in self.runs():
   d=json.loads(run.read_text()); self.assertEqual(d['mode'],'local'); self.assertEqual(d['state'],'COMPLETADO')
   root=Path(d['artifact_roots']['captures']); self.assertEqual(root.stat().st_mode&0o777,0o700)
   meta=json.loads((root/'memory.json').read_text())
   self.assertEqual(meta,dict(method='avml',bytes=13,completitud_memoria='no_verificada',sample=False))
   self.assertEqual((root/'memory.raw').read_bytes(),b'SYNTHETIC RAM')
   self.assertTrue(any(a['root']=='captures' for s in d['steps'] for a in s['artifacts']))
   for s in d['steps']: self.assertEqual(set(s['coverage']),{'code','complete','requested'})
   for p in root.iterdir(): self.assertEqual(p.stat().st_mode&0o777,0o600)
  self.assertNotIn('SYNTHETIC',r.stdout+r.stderr)
 def test_backend_failure_missing_and_empty_are_not_memory_success(self):
  for env in ({'RAM_RC':'7'},{'ABSENT':'1'},{'EMPTY':'1'}):
   with self.subTest(env=env):
    r=self.ram('--method','avml',input='ADQUIRIR_MEMORIA\n',**env)
    self.assertEqual(r.returncode,1,r.stderr); self.assertNotIn('COMPLETADO',self.data()['state'])
    if 'RAM_RC' in env: self.assertEqual(next(s['rc'] for s in self.data()['steps'] if s['name']=='acquire'),7)
 def test_dd_is_explicit_bounded_and_always_partial(self):
  r=self.ram('--method','dd',input='ADQUIRIR_MEMORIA\n'); self.assertEqual(r.returncode,1,r.stderr)
  call=next(a for n,a in self.calls() if n=='dd')
  self.assertEqual(call[0],'if=/dev/mem'); self.assertEqual(call[-2:],['bs=1M','count=1024'])
  self.assertEqual(self.data()['state'],'PARCIAL')
  root=Path(self.data()['artifact_roots']['captures']); self.assertTrue(json.loads((root/'memory.json').read_text())['sample'])
 def test_lime_prepared_cli_and_no_module_loading(self):
  r=self.ram('--method','lime',input='ADQUIRIR_MEMORIA\n'); self.assertEqual(r.returncode,0,r.stderr)
  self.assertTrue(any(n=='lime' and a[0]=='-o' for n,a in self.calls()))
  self.assertFalse(any(n in ('insmod','apt') for n,a in self.calls()))
 def test_missing_privileges_prevents_backend_and_system_reads(self):
  r=self.ram(input='ADQUIRIR_MEMORIA\n',NO_PRIVILEGE='1')
  self.assertEqual(r.returncode,2,r.stderr)
  self.assertFalse(any(n in ('avml','lime','dd','uname','cat') for n,a in self.calls()))
 def test_external_root_symlinks_and_collision_do_not_overwrite(self):
  parent=self.root/'outputs/external'; parent.mkdir(mode=0o700)
  sentinel=parent/'keep'; sentinel.write_bytes(b'KEEP')
  r=self.ram(parent,input='ADQUIRIR_MEMORIA\n'); self.assertEqual(r.returncode,0,r.stderr)
  self.assertEqual(Path(self.data()['artifact_roots']['captures']).parent,parent)
  self.assertEqual(sentinel.read_bytes(),b'KEEP')
  alias=self.root/'alias'; alias.symlink_to(parent,target_is_directory=True)
  r=self.ram(alias,input='ADQUIRIR_MEMORIA\n'); self.assertEqual(r.returncode,1,r.stderr)
  self.assertEqual(sentinel.read_bytes(),b'KEEP')
 def test_system_failure_is_separate_and_does_not_claim_full_success(self):
  r=self.ram(input='ADQUIRIR_MEMORIA\n',UNAME_RC='9'); self.assertEqual(r.returncode,1,r.stderr)
  self.assertEqual(next(s['rc'] for s in self.data()['steps'] if s['name']=='system_information'),9)
 def test_os_release_failure_preserves_exact_rc(self):
  r=self.ram(input='ADQUIRIR_MEMORIA\n',CAT_RC='17'); self.assertEqual(r.returncode,1,r.stderr)
  self.assertEqual(next(s['rc'] for s in self.data()['steps'] if s['name']=='system_information'),17)
 def test_symlink_product_is_not_published_or_followed(self):
  sentinel=self.root/'sources/sentinel'; sentinel.write_bytes(b'PRIVATE SOURCE')
  r=self.ram(input='ADQUIRIR_MEMORIA\n',SYMLINK_RAM='1'); self.assertEqual(r.returncode,1,r.stderr)
  self.assertEqual(sentinel.read_bytes(),b'PRIVATE SOURCE')
  self.assertFalse(any(a['path']=='memory.raw' for s in self.data()['steps'] for a in s['artifacts']))
 def test_root_uses_no_sudo_and_failed_avml_never_switches_method(self):
  r=self.ram(input='ADQUIRIR_MEMORIA\n',FIXTURE_ROOT='1',RAM_RC='23')
  self.assertEqual(r.returncode,1,r.stderr)
  self.assertFalse(any(n in ('sudo','lime','dd') for n,a in self.calls()))
  self.assertEqual(next(s['rc'] for s in self.data()['steps'] if s['name']=='acquire'),23)
 def test_failed_help_is_precondition_not_acquisition(self):
  r=self.ram('--method','avml',input='ADQUIRIR_MEMORIA\n',HELP_RC='8')
  self.assertEqual(r.returncode,2,r.stderr)
  self.assertTrue(all(n=='sudo' or a==['--help'] for n,a in self.calls()))
  self.assertEqual(self.runs(),[])
 def test_registered_root_collision_keeps_existing_product(self):
  # Introduce collision ONLY at the copied helper's registration boundary.
  helper=self.fw/'00_Config/lib/forensics_evidence.py'
  text=helper.read_text()
  marker='def register_artifact_root('
  start=text.index(marker); body=text.index('\n',start)
  # Force the root parent to contain this run id at registration time.
  # Instrument only the boundary, not the collision validation.
  injection='''
    collision = Path(parent) / Path(run_dir).name
    collision.mkdir(parents=True, mode=0o700)
    (collision / 'keep').write_bytes(b'KEEP')
'''
  helper.write_text(text[:body+1]+injection+text[body+1:])
  r=self.ram(input='ADQUIRIR_MEMORIA\n'); self.assertEqual(r.returncode,1,r.stderr)
  self.assertFalse(any(n in ('avml','lime','dd') and a!=['--help'] for n,a in self.calls()))
  self.assertEqual(next((self.root/'outputs/memory').glob('*/keep')).read_bytes(),b'KEEP')
 def test_capture_receipt_failure_never_announces_completed_memory(self):
  helper=self.fw/'00_Config/lib/forensics_evidence.py'
  helper.write_text(helper.read_text().replace("elif command == 'capture-result':", "elif command == 'capture-result':\n            raise OSError('synthetic receipt failure')"))
  r=self.ram(input='ADQUIRIR_MEMORIA\n')
  self.assertEqual(r.returncode,1,r.stderr)
  self.assertNotIn('RAM: COMPLETADO',r.stdout+r.stderr)
  self.assertEqual(self.data()['state'],'FALLIDO')
 def test_invalid_usage_does_nothing(self):
  for args in (('--method','unknown'),('--method',),('--install',),('one','two')):
   r=self.ram(*args,input='ADQUIRIR_MEMORIA\n'); self.assertEqual(r.returncode,2,r.stderr)
  self.assertEqual(self.calls(),[])
 def test_requirements_default_and_check_only_resolve_commands(self):
  for args in ((),('--check',)):
   r=self.leaf('requirements.sh',*args); self.assertEqual(r.returncode,0,r.stderr)
   self.assertIn('volatility',r.stdout); self.assertEqual(self.calls(),[])
  self.assertEqual(self.runs(),[])
 def test_install_denied_or_eof_has_no_effect(self):
  for answer in ('','no\n'):
   r=self.leaf('requirements.sh','--install',input=answer); self.assertEqual(r.returncode,2,r.stderr)
   self.assertEqual(self.calls(),[]); self.assertEqual(self.runs(),[])
 def test_install_preserves_historical_packages_and_real_apt_rc(self):
  for rc,want in (('0',0),('42',1)):
   r=self.leaf('requirements.sh','--install',input='INSTALAR_DEPENDENCIAS\n',APT_RC=rc)
   self.assertEqual(r.returncode,want,r.stderr)
   call=[a for n,a in self.calls() if n=='apt'][-1]
   self.assertEqual(call,['install','-y','volatility','autopsy','foremost','scalpel','tcpdump','wireshark'])
   self.assertEqual(next(s['rc'] for s in self.data()['steps'] if s['name']=='install'),int(rc))
 def test_generic_listing_marks_all_sensitive_routes_dangerous(self):
  paths=['08_Forensics/'+p for p in ('memory/memory_dump.sh','requirements.sh','disk/disk_forensics.sh','disk/file_carving.sh','timeline/timeline_creator.sh','run_all_forensics.sh')]
  lib=self.fw/'00_Config/lib/params.bash'
  r=subprocess.run(['/bin/bash','-c','source "$1"; shift; for p; do params_is_dangerous "$p" || exit 8; done','test',str(lib),*paths],env=self.env,text=True,capture_output=True)
  self.assertEqual(r.returncode,0,r.stderr)
