"""Task7 boundaries: copied manager/flow, synthetic metadata, closed backends."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import signal
import subprocess
import sys
import unittest
from forensics_fixture import sandbox, runtime_environment, load_evidence, inventory

FRAMEWORK = Path(__file__).resolve().parents[1]
LEAF = r'''#!PYTHON
import json, os, pathlib, sys, types
p=pathlib.Path; root=p(os.environ['ROOT']); name=p(sys.argv[0]).with_suffix('.sh').name
with (root/'calls').open('a') as f: f.write(json.dumps([name,sys.argv[1:]])+'\n')
if name=='memory_dump.sh':
 if sys.stdin.readline().strip()!='ADQUIRIR_MEMORIA': sys.exit(2)
 if os.environ.get('RAM_FAIL'): sys.exit(1)
 lib=p(sys.argv[0]).parents[2]/'00_Config/lib/forensics_evidence.py'
 e=types.ModuleType('e'); e.__file__=str(lib); exec(compile(lib.read_bytes(),str(lib),'exec'),e.__dict__)
 run=e.start_run(p(os.environ['FORENSICS_ANALYSIS_ROOT'])/'runs','memory','local',[])
 dest=e.register_artifact_root(run,'captures',root/'outputs/ram')
 raw=dest/'memory.raw'; raw.touch(mode=0o600); raw.write_bytes(b'SYNTHETIC NEW RAM')
 meta=dest/'memory.json'; meta.touch(mode=0o600)
 meta.write_text(json.dumps(dict(method='avml',bytes=17,completitud_memoria='no_verificada',sample=False)))
 cov=dict(code='memory_structure_checked',complete=True,requested=True)
 e.record_step(run,'acquire',0,'COMPLETADO',cov,[],tool='avml')
 e.record_step(run,'memory_product',0,'COMPLETADO',dict(code='memory_metadata',complete=True,requested=True),[raw,meta],tool='memory_product')
 e.finish_run(run)
 if os.environ.get('RAM_TAMPER'): raw.write_bytes(b'TAMPER')
sys.exit(int(os.environ.get('FAIL_'+name.replace('.','_'),'0')))
'''

class MenuFlowTests(unittest.TestCase):
 def setUp(self):
  self.box=sandbox(); self.root=self.box.__enter__(); self.addCleanup(self.box.__exit__,None,None,None)
  self.fw=self.root/'code'; self.fw.mkdir()
  for rel in ('00_Config/lib','08_Forensics'):
   shutil.copytree(FRAMEWORK/rel,self.fw/rel,ignore=shutil.ignore_patterns('__pycache__','analysis','recovered'))
  shutil.copy2(FRAMEWORK/'cyber_framework.sh',self.fw/'cyber_framework.sh')
  self.env=runtime_environment(self.root)
  for name in ('dirname','grep','sed','tr','wc','awk','find','sort','head','basename'):
   (self.root/'bin'/name).symlink_to('/usr/bin/'+name)
  for name in ('clear','sleep'):
   path=self.root/'bin'/name; path.write_text('#!/bin/bash\nexit 0\n'); path.chmod(0o700)
  self.env.update(FORENSICS_ANALYSIS_ROOT=str(self.root/'outputs/analysis'),SESSION_FILE=str(self.root/'session'),SESSION_SCOPE_FILE=str(self.fw/'00_Config/scope.yaml'),SESSION_TARGETS_FILE=str(self.fw/'00_Config/targets.txt'))
  (self.fw/'00_Config/scope.yaml').write_text('targets: {ips: [], domains: [example.test]}\n')
  (self.fw/'00_Config/targets.txt').write_text('# synthetic\n')
  (self.root/'session').write_text('198.51.100.99\n')
  self.configs={p:p.read_bytes() for p in (self.root/'session',self.fw/'00_Config/scope.yaml',self.fw/'00_Config/targets.txt')}
  self.addCleanup(self.config_guard)
 def config_guard(self):
  for p,body in self.configs.items(): self.assertEqual(p.read_bytes(),body)
 def source(self,name,body='SYNTHETIC SECRET BODY'):
  p=self.root/'sources'/name; p.write_text(body); return p
 def stub_leaves(self):
  for p in (self.fw/'08_Forensics').rglob('*.sh'):
   if p.name in ('run_all_forensics.sh','show_results.sh'): continue
   backend=p.with_suffix('.fixture')
   backend.write_text(LEAF.replace('PYTHON',sys.executable,1)); backend.chmod(0o700)
   # Real leaves are Bash entrypoints. Preserve that boundary in the double.
   p.write_text('#!/bin/bash\nexec '+sys.executable+' -B "${BASH_SOURCE[0]%.sh}.fixture" "$@"\n'); p.chmod(0o700)
 def calls(self):
  p=self.root/'calls'; return [json.loads(s) for s in p.read_text().splitlines()] if p.exists() else []
 def cancellation_case(self,signum,*,local_stage=None,boundary=None,parent_only=False):
  """Only own session receives signals; pipes hold cleanup until released."""
  import ctypes
  libc=ctypes.CDLL(None,use_errno=True); previous=ctypes.c_int()
  self.assertEqual(libc.prctl(37,ctypes.byref(previous),0,0,0),0)
  self.assertEqual(libc.prctl(36,1,0,0,0),0)
  self.stub_leaves()
  target='memory_dump.sh' if local_stage=='memory' else 'strings_analysis.sh'
  if boundary is None:
   fixture=next(p for p in (self.fw/'08_Forensics').rglob('*.fixture') if p.with_suffix('.sh').name==target)
   block=r'''
if name==os.environ['BLOCK_LEAF']:
 import signal
 ready=int(os.environ['READY_FD']); release=int(os.environ['RELEASE_FD'])
 def cancelled(signum,frame):
  os.write(ready,b'S')
  os.read(release,1)
  fd=os.open(root/'leaf-cleanup.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as f: json.dump(dict(signal=signum,rc=1,cleanup=True),f)
  print('LEAF_PRIVATE_CLEANUP',flush=True)
  sys.exit(1)
 signal.signal(signal.SIGINT,cancelled); signal.signal(signal.SIGTERM,cancelled)
 (root/'leaf-pid').write_text(str(os.getpid()))
 os.write(ready,b'R')
 while True: signal.pause()
'''
   fixture.write_text(fixture.read_text().replace("if name=='memory_dump.sh':",block+"\nif name=='memory_dump.sh':",1))
  else:
   # Instrument only the copied shell boundary, never production test hooks.
   flow=self.fw/'08_Forensics/run_all_forensics.sh'
   hook='    printf R >&"$READY_FD"\n    IFS= read -r -u "$RELEASE_FD" boundary_release\n'
   text=flow.read_text()
   anchor='    flow_leaf "$module_dir/$leaf" "$@"\n' if boundary=='invoke' and 'flow_leaf ' in text else ('    bash "$module_dir/$leaf" "$@" >>"$log" 2>&1\n' if boundary=='invoke' else '    status=$?\n')
   self.assertIn(anchor,text)
   flow.write_text(text.replace(anchor,hook+anchor if boundary=='invoke' else anchor+hook,1))
  # Preserve fixture pipes ONLY in the disposable supervisor copy. Production
  # child fd policy stays closed except for its gate and selected stdin.
  helper=self.fw/'00_Config/lib/forensics_evidence.py'
  helper.write_text(helper.read_text().replace('pass_fds=(gate_read,),',
   "pass_fds=(gate_read, *[int(os.environ[k]) for k in ('READY_FD','RELEASE_FD') if k in os.environ]),"))
  ready_r,ready_w=os.pipe(); release_r,release_w=os.pipe()
  sentinel=subprocess.Popen([sys.executable,'-B','-c','import signal; signal.pause()'],env=self.env,start_new_session=True)
  sentinel_fd=os.pidfd_open(sentinel.pid); proc=None; owner_fd=None; leaf_fd=None; leaf_pid=None
  try:
   args=['--local'] if local_stage else ['--memory',str(self.source('first source')), '--log',str(self.source('second source'))]
   proc=subprocess.Popen(['/bin/bash',str(self.fw/'08_Forensics/run_all_forensics.sh'),*args],
    env={**self.env,'READY_FD':str(ready_w),'RELEASE_FD':str(release_r),'BLOCK_LEAF':target},
    cwd=self.root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
    pass_fds=(ready_w,release_r),start_new_session=True)
   owner_fd=os.pidfd_open(proc.pid)
   os.close(ready_w); ready_w=None; os.close(release_r); release_r=None
   if local_stage: proc.stdin.write('FLUJO_LOCAL\nADQUIRIR_MEMORIA\nLEER_LOG_LOCAL\nLOCAL_SI\n'); proc.stdin.flush()
   self.assertTrue(select.select([ready_r],[],[],8)[0],'readiness pipe not signaled')
   self.assertEqual(os.read(ready_r,1),b'R')
   if boundary is None:
    leaf_pid=int((self.root/'leaf-pid').read_text()); leaf_fd=os.pidfd_open(leaf_pid)
   self.assertIsNone(proc.poll())
   if parent_only: signal.pidfd_send_signal(owner_fd,signum)
   else: os.killpg(proc.pid,signum)  # pinned live owner, separate session from sentinel
   if boundary is None:
    self.assertTrue(select.select([ready_r],[],[],4)[0],'active leaf did not receive cancellation')
    self.assertEqual(os.read(ready_r,1),b'S')
    self.assertFalse(select.select([owner_fd],[],[],0.15)[0],'owner exited before active leaf cleanup')
    os.write(release_w,b'x\n')
   out,err=proc.communicate(timeout=8)
   self.assertEqual(proc.returncode,1,err)
   self.assertIsNone(sentinel.poll(),'unrelated sentinel was signaled')
   expected=[] if boundary=='invoke' else ['strings_analysis.sh']
   if local_stage: expected=['memory_dump.sh']+(['strings_analysis.sh'] if local_stage=='strings' else [])
   self.assertEqual([c[0] for c in self.calls()],expected,err)
   self.assertNotIn('Lectura del log del host',err)
   self.assertNotIn('LEER_LOG_LOCAL',err); self.assertNotIn('LOCAL_SI',err)
   self.assertEqual(out,''); self.assertNotIn('LEAF_PRIVATE_CLEANUP',err)
   logs=list((self.root/'outputs').rglob('workflow.log')); self.assertEqual(len(logs),1)
   self.assertIn('workflow_cancelled wrapper_signal='+str(signum),logs[0].read_text())
   if boundary is None:
    self.assertEqual(json.loads((self.root/'leaf-cleanup.json').read_text()),dict(signal=signum,rc=1,cleanup=True))
    self.assertIn('LEAF_PRIVATE_CLEANUP',logs[0].read_text())
  finally:
   try: os.write(release_w,b'x\n')
   except BrokenPipeError: pass
   if proc is not None:
    if proc.poll() is None: os.killpg(proc.pid,signal.SIGKILL)
    proc.communicate(timeout=5)
   if leaf_fd is not None:
    if not select.select([leaf_fd],[],[],3)[0]: signal.pidfd_send_signal(leaf_fd,signal.SIGKILL)
    try: os.waitpid(leaf_pid,0)
    except ChildProcessError: pass
    os.close(leaf_fd)
   signal.pidfd_send_signal(sentinel_fd,signal.SIGKILL); sentinel.wait(timeout=5); os.close(sentinel_fd)
   for fd in (ready_r,ready_w,release_r,release_w,owner_fd):
    if fd is not None: os.close(fd)
   self.assertEqual(libc.prctl(36,previous.value,0,0,0),0)
 def test_workflow_cancellation_group_sigint_waits_cleanup_no_second_source(self):
   self.cancellation_case(signal.SIGINT)
 def test_workflow_parent_only_sigint_waits_cleanup_no_second_source(self):
  self.cancellation_case(signal.SIGINT,parent_only=True)
 def test_workflow_parent_only_sigterm_waits_cleanup_no_second_source(self):
  self.cancellation_case(signal.SIGTERM,parent_only=True)
 def test_workflow_parent_only_local_acquisition_sigterm_no_new_prompts(self):
  self.cancellation_case(signal.SIGTERM,parent_only=True,local_stage='memory')
 def test_workflow_cancellation_group_sigterm_waits_cleanup_no_second_source(self):
  self.cancellation_case(signal.SIGTERM)
 def test_workflow_cancellation_local_memory_sigint_no_new_prompts_or_reads(self):
  self.cancellation_case(signal.SIGINT,local_stage='memory')
 def test_workflow_cancellation_local_memory_sigterm_no_new_prompts_or_reads(self):
  self.cancellation_case(signal.SIGTERM,local_stage='memory')
 def test_workflow_cancellation_local_strings_sigint_no_new_prompts_or_reads(self):
  self.cancellation_case(signal.SIGINT,local_stage='strings')
 def test_workflow_cancellation_local_strings_sigterm_no_new_prompts_or_reads(self):
  self.cancellation_case(signal.SIGTERM,local_stage='strings')
 def test_workflow_cancellation_before_invocation_sigint_never_launches(self):
  self.cancellation_case(signal.SIGINT,boundary='invoke')
 def test_workflow_cancellation_before_invocation_sigterm_never_launches(self):
  self.cancellation_case(signal.SIGTERM,boundary='invoke')
 def test_workflow_cancellation_after_wait_sigint_never_launches_next(self):
  self.cancellation_case(signal.SIGINT,boundary='returned')
 def test_workflow_cancellation_after_wait_sigterm_never_launches_next(self):
  self.cancellation_case(signal.SIGTERM,boundary='returned')
 def test_workflow_cancellation_not_inferred_from_ordinary_rc_1_130_143(self):
  self.stub_leaves(); a=self.source('ordinary error'); b=self.source('independent source')
  for rc in (1,130,143):
   (self.root/'calls').unlink(missing_ok=True)
   r=self.flow('--memory',a,'--log',b,FAIL_strings_analysis_sh=str(rc))
   self.assertEqual(r.returncode,1,r.stderr)
   self.assertEqual([c[0] for c in self.calls()],['strings_analysis.sh','log_analyzer.sh'])
   self.assertIn('ejecutadas=2 fallidas=1',r.stderr)
 def run_shell(self,code,input='',**env):
  return subprocess.run(['/bin/bash','-c',code],input=input,text=True,capture_output=True,cwd=self.root,env={**self.env,**env},timeout=45)
 def manager(self,code='module_forensics',input=''):
  return self.run_shell('source "'+str(self.fw/'cyber_framework.sh')+'"; '+code,input)
 def flow(self,*args,input='',**env):
  return subprocess.run(['/bin/bash',str(self.fw/'08_Forensics/run_all_forensics.sh'),*map(str,args)],input=input,text=True,capture_output=True,cwd=self.root,env={**self.env,**env},timeout=60)
 def viewer(self,*args):
  return subprocess.run(['/bin/bash',str(self.fw/'08_Forensics/show_results.sh'),*map(str,args)],text=True,capture_output=True,cwd=self.root,env=self.env,timeout=30)
 def test_file_slot_types_preserve_previous_contracts(self):
  r=self.manager('for t in DISK_IMAGE MEMORY_FILE LOG_FILE PCAP_FILE IP URL IP/RANGO OUTPUT_DIR; do params_type_of "$t"; done')
  self.assertEqual(r.stdout.splitlines(),['FICHERO']*4+['IP','URL','TEXTO','FICHERO'])
 def test_menu_eof_cancel_invalid_never_dispatch(self):
  self.stub_leaves()
  for inp in ('','0\n','!\n','999\n0\n','2\n','2\n!\n0\n','2\n0\n0\n'):
   r=self.manager(input=inp); self.assertEqual(r.returncode,0,r.stderr)
   self.assertEqual(self.calls(),[]); self.assertEqual(r.stdout,'')
   self.assertIn('FORENSE',r.stderr)
 def test_dependencies_only_check(self):
  self.stub_leaves(); r=self.manager(input='1\n0\n')
  self.assertEqual(self.calls(),[['requirements.sh',['--check']]],r.stderr)
 def test_manager_entry_from_external_cwd_and_eof_are_passive(self):
  self.stub_leaves()
  for inp in ('08\n0\nQ\n','08\n'):
   r=subprocess.run(['/bin/bash',str(self.fw/'cyber_framework.sh')],input=inp,text=True,capture_output=True,cwd=self.root,env=self.env,timeout=30)
   self.assertEqual(r.returncode,0,r.stderr); self.assertEqual(self.calls(),[])
   self.assertIn('FORENSE',r.stderr)
 def test_original_run_all_does_not_claim_all_leaves(self):
  self.stub_leaves()
  r=self.manager(input='11\n1\n!\n0\n0\n')
  self.assertEqual(self.calls(),[],r.stderr)
  self.assertNotIn('TODOS los scripts',r.stderr)
 def test_original_list_never_discovers_scripts_from_evidence(self):
  self.stub_leaves()
  recovered=self.fw/'08_Forensics/recovered'; recovered.mkdir(mode=0o700)
  (recovered/'untrusted_evidence.sh').write_text('#!/bin/bash\nexit 97\n')
  r=self.manager(input='11\n0\n0\n')
  self.assertIn('11 scripts',r.stderr)
  self.assertNotIn('untrusted_evidence',r.stderr)
  self.assertEqual(self.calls(),[])
  r=self.manager('execute_script 08_Forensics/recovered/untrusted_evidence.sh 08_Forensics --prepared')
  self.assertEqual(r.returncode,2,r.stderr)
 def test_selected_file_spaces_one_argument_and_no_target(self):
  self.stub_leaves(); p=self.source('RAM with spaces.raw')
  r=self.manager(input='2\n'+str(p)+'\n0\n')
  self.assertEqual(self.calls(),[['strings_analysis.sh',[str(p)]]],r.stderr)
  self.assertNotIn('198.51.100.99',r.stdout+r.stderr)
  self.assertNotIn(str(p),r.stdout+r.stderr)
 def test_viewer_and_original_list_distinct(self):
  self.stub_leaves()
  r=self.manager(input='10\n0\n'); self.assertEqual(self.calls(),[]); self.assertIn('Sin ejecuciones',r.stderr)
  r=self.manager(input='11\n0\n0\n'); self.assertEqual(self.calls(),[])
  self.assertIn('11 scripts',r.stderr); self.assertIn('show_results.sh',r.stderr); self.assertIn('memory_dump.sh',r.stderr)
 def test_original_list_sensitive_denied_does_not_dispatch(self):
  self.stub_leaves()
  # Sorted original list: run_all, disk x2, logs, memory_dump, strings, volatility,
  # pcaps, requirements, show_results, timeline.
  r=self.manager(input='11\n5\nno\n0\n0\n')
  self.assertEqual(self.calls(),[],r.stderr); self.assertIn('autorizado',r.stderr)
 def test_original_list_file_does_not_inherit_session_or_echo_arguments(self):
  self.stub_leaves(); p=self.source('log private.txt')
  r=self.manager(input='11\n4\n'+str(p)+'\n0\n0\n')
  self.assertEqual(self.calls(),[['log_analyzer.sh',[str(p)]]],r.stderr)
  self.assertNotIn(str(p),r.stdout+r.stderr)
 def test_offline_selection_eof_cancels_whole_selection(self):
  self.stub_leaves(); p=self.source('RAM.raw')
  r=self.manager(input='9\n'+str(p)+'\n')
  self.assertEqual(self.calls(),[],r.stderr)
 def test_empty_and_invalid_cli_no_work_or_false_run(self):
  self.stub_leaves()
  for args in ((),('--bad',),('--memory',),('--log','missing'),('--log',''),('--local','--local')):
   r=self.flow(*args); self.assertEqual(r.returncode,2,r.stderr); self.assertEqual(self.calls(),[])
  self.assertEqual(list((self.root/'outputs').iterdir()),[])
 def test_offline_exact_two_sources_and_private_log(self):
  self.stub_leaves(); ram=self.source('chosen ram.raw'); log=self.source('chosen log.txt')
  self.source('unselected.pcap')
  before={p:p.read_bytes() for p in (ram,log)}
  r=self.flow('--memory',ram,'--log',log)
  self.assertEqual(r.returncode,0,r.stderr)
  self.assertEqual(self.calls(),[['strings_analysis.sh',[str(ram)]],['log_analyzer.sh',[str(log)]]])
  self.assertIn('ejecutadas=2 fallidas=0',r.stderr); self.assertEqual(r.stdout,'')
  self.assertNotIn('SYNTHETIC SECRET BODY',r.stdout+r.stderr)
  for p,b in before.items(): self.assertEqual(p.read_bytes(),b)
  logs=list((self.root/'outputs').rglob('workflow.log')); self.assertEqual(len(logs),1)
  self.assertEqual(logs[0].stat().st_mode&0o777,0o600); self.assertEqual(logs[0].parent.stat().st_mode&0o777,0o700)
 def test_independent_failure_continues_and_returns_partial(self):
  self.stub_leaves(); a=self.source('memory'); b=self.source('packets')
  r=self.flow('--memory',a,'--pcap',b,FAIL_strings_analysis_sh='7')
  self.assertEqual(r.returncode,1,r.stderr)
  self.assertEqual([c[0] for c in self.calls()],['strings_analysis.sh','pcap_analyzer.sh'])
  self.assertIn('ejecutadas=2 fallidas=1',r.stderr)
 def test_all_leaf_preconditions_return_two_without_fake_run(self):
  self.stub_leaves(); a=self.source('memory')
  r=self.flow('--memory',a,FAIL_strings_analysis_sh='2')
  self.assertEqual(r.returncode,2,r.stderr)
  self.assertEqual(list((self.root/'outputs').rglob('run.json')),[])
 def test_mixed_precondition_and_success_returns_partial(self):
  self.stub_leaves(); a=self.source('memory'); b=self.source('log')
  r=self.flow('--memory',a,'--log',b,FAIL_strings_analysis_sh='2')
  self.assertEqual(r.returncode,1,r.stderr)
 def test_invalid_source_blocks_itself_not_independent_valid_source(self):
  self.stub_leaves(); a=self.source('valid'); link=self.root/'sources/link'; link.symlink_to(a)
  fifo=self.root/'sources/fifo'; os.mkfifo(fifo)
  for bad in (link,fifo,self.root/'sources',self.root/'missing'):
   (self.root/'calls').unlink(missing_ok=True)
   r=self.flow('--memory',a,'--log',bad)
   self.assertEqual(r.returncode,1,r.stderr)
   self.assertEqual(self.calls(),[['strings_analysis.sh',[str(a)]]])
 def test_all_invalid_sources_no_work_no_run(self):
  self.stub_leaves(); p=self.root/'sources/missing'
  r=self.flow('--memory',p,'--log',p)
  self.assertEqual(r.returncode,2,r.stderr); self.assertEqual(self.calls(),[])
  self.assertEqual(list((self.root/'outputs').iterdir()),[])
 def test_shell_metacharacters_are_data_not_commands(self):
  self.stub_leaves(); p=self.source('$(touch NEVER); memory.raw')
  r=self.flow('--memory',p); self.assertEqual(r.returncode,0,r.stderr)
  self.assertEqual(self.calls(),[['strings_analysis.sh',[str(p)]]])
  self.assertFalse((self.root/'NEVER').exists())
 def test_menu_volatility_quoted_symbols_and_advanced_cancellation(self):
  self.stub_leaves(); p=self.source('Windows RAM'); symbols=self.root/'symbols local'; symbols.mkdir()
  r=self.manager(input='5\n'+str(p)+'\n--backend v3 --symbols "'+str(symbols)+'"\n0\n')
  self.assertEqual(self.calls(),[['volatility_analysis.sh',[str(p),'--backend','v3','--symbols',str(symbols)]]],r.stderr)
  (self.root/'calls').unlink()
  r=self.manager(input='5\n'+str(p)+'\n'); self.assertEqual(self.calls(),[],r.stderr)
 def test_original_sensitive_actions_keep_dangerous_gate(self):
  self.stub_leaves(); p=self.source('image')
  for number,arguments in ((2,str(p)+'\n\n'),(3,str(p)+'\n\n'),(9,'2\n'),(11,'auth\n'+str(p)+'\n\n')):
   r=self.manager(input='11\n'+str(number)+'\n'+arguments+'no\n0\n0\n')
   self.assertEqual(self.calls(),[],r.stderr); self.assertIn('autorizado',r.stderr)
 def test_real_offline_leaves_once_private_copies_and_viewer_no_bodies(self):
  # Only extraction is stubbed; stage, runtime, filters, integrity and metadata
  # are the actual shipped implementations.
  path=self.root/'bin/strings'
  path.write_text('#!'+sys.executable+'\nimport json,os,pathlib,sys\np=pathlib.Path\nwith (p(os.environ["ROOT"])/"calls").open("a") as f: f.write(json.dumps(["strings",sys.argv[1:]])+"\\n")\nprint("password=SYNTHETIC_PRIVATE_VALUE")\n')
  path.chmod(0o700)
  ram=self.source('real-leaf RAM'); log=self.source('real-leaf log','Jan  1 00:00:00 synthetic sshd: Failed password synthetic\n')
  r=self.flow('--memory',ram,'--log',log)
  self.assertEqual(r.returncode,0,r.stderr); self.assertEqual(len(self.calls()),1)
  self.assertNotEqual(self.calls()[0][1][-1],str(ram))
  runs=list((self.root/'outputs/analysis/runs').glob('*/run.json'))
  self.assertEqual(len(runs),2)
  self.assertEqual({json.loads(p.read_text())['operation'] for p in runs},{'strings','logs'})
  before=inventory(self.root/'outputs'); r=self.viewer()
  self.assertEqual(r.returncode,0,r.stderr)
  self.assertNotIn('SYNTHETIC_PRIVATE_VALUE',r.stdout+r.stderr)
  self.assertEqual(inventory(self.root/'outputs'),before)
 def test_real_acquisition_leaf_exact_reference_consumed_by_real_strings(self):
  from test_forensics_acquisition import BACKEND
  for name in ('sudo','avml','lime','dd','uname','cat'):
   path=self.root/'bin'/name
   if path.exists(): path.unlink()
   path.write_text(BACKEND.replace('PYTHON',sys.executable,1)); path.chmod(0o700)
  path=self.root/'bin/strings'; path.unlink()
  path.write_text('#!/bin/bash\nprintf "synthetic strings\\n"\n'); path.chmod(0o700)
  # Test-only root instrumentation, as in Task6. No production bypass.
  path=self.fw/'08_Forensics/memory/memory_dump.sh'
  path.write_text(path.read_text().replace('(( EUID == 0 ))','[[ ${FIXTURE_ROOT:-0} = 1 ]]'))
  r=self.flow('--local',input='FLUJO_LOCAL\nADQUIRIR_MEMORIA\nno\n',FIXTURE_ROOT='1')
  self.assertEqual(r.returncode,1,r.stderr)
  self.assertEqual([c[0] for c in self.calls()],['avml','avml','uname','cat'])
  runs=list((self.root/'outputs/analysis').rglob('run.json'))
  self.assertEqual(len(runs),2)
  data=[json.loads(p.read_text()) for p in runs]
  self.assertEqual({d['operation'] for d in data},{'memory','strings'})
  self.assertTrue(all(d['complete'] for d in data))
  viewed=self.viewer()
  self.assertEqual(viewed.returncode,0,viewed.stderr)
  self.assertIn('"operation": "memory"',viewed.stdout)
  self.assertIn('"operation": "strings"',viewed.stdout)
 def test_workflow_parent_only_real_acquisition_cancels_nested_capture_before_host_reads(self):
  import time
  from test_forensics_acquisition import BACKEND
  for name in ('sudo','avml','lime','dd','uname','cat'):
   path=self.root/'bin'/name
   if path.exists(): path.unlink()
   body=BACKEND.replace('PYTHON',sys.executable,1)
   body=body.replace(" sys.exit(int(os.environ.get('RAM_RC','0')))",
    " (root/'acquiring').write_text(str(os.getpid()))\n __import__('signal').pause()")
   path.write_text(body); path.chmod(0o700)
  path=self.fw/'08_Forensics/memory/memory_dump.sh'
  path.write_text(path.read_text().replace('(( EUID == 0 ))','[[ ${FIXTURE_ROOT:-0} = 1 ]]'))
  proc=subprocess.Popen(['/bin/bash',str(self.fw/'08_Forensics/run_all_forensics.sh'),'--local'],
   env={**self.env,'FIXTURE_ROOT':'1'},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
  owner=os.pidfd_open(proc.pid); backend=None
  try:
   proc.stdin.write('FLUJO_LOCAL\nADQUIRIR_MEMORIA\nLEER_LOG_LOCAL\nLOCAL_SI\n'); proc.stdin.flush()
   deadline=time.monotonic()+12
   while not (self.root/'acquiring').exists() and proc.poll() is None and time.monotonic()<deadline: time.sleep(.01)
   self.assertTrue((self.root/'acquiring').exists())
   backend=os.pidfd_open(int((self.root/'acquiring').read_text()))
   signal.pidfd_send_signal(owner,signal.SIGTERM)
   out,err=proc.communicate(timeout=15)
   self.assertEqual(proc.returncode,1,err)
   self.assertTrue(select.select([backend],[],[],1)[0],'nested acquisition backend survived')
   self.assertNotIn('LEER_LOG_LOCAL',err); self.assertNotIn('LOCAL_SI',err)
   data=json.loads(next((self.root/'outputs/analysis').rglob('run.json')).read_text())
   self.assertIsNotNone(data['finished']); self.assertEqual(data['state'],'CANCELADO')
   self.assertEqual(next(s['signal'] for s in data['steps'] if s['name']=='acquire'),15)
   self.assertEqual([c[0] for c in self.calls()],['avml','avml'])
  finally:
   if proc.poll() is None: signal.pidfd_send_signal(owner,signal.SIGKILL); proc.communicate(timeout=5)
   if backend is not None:
    if not select.select([backend],[],[],0)[0]: signal.pidfd_send_signal(backend,signal.SIGKILL)
    os.close(backend)
   os.close(owner)
 def test_all_selected_routes_absolute_from_external_cwd(self):
  self.stub_leaves(); a=self.source('a')
  r=self.flow('--pcap',a,'--disk',a,'--timeline-auth',a)
  self.assertEqual(r.returncode,0,r.stderr)
  self.assertEqual(self.calls(),[['pcap_analyzer.sh',[str(a)]],['disk_forensics.sh',[str(a)]],['timeline_creator.sh',['--auth',str(a)]]])
 def test_direct_local_denied_or_eof_has_no_effects(self):
  self.stub_leaves()
  for inp in ('','no\n'):
   r=self.flow('--local',input=inp); self.assertEqual(r.returncode,2,r.stderr)
   self.assertEqual(self.calls(),[]); self.assertEqual(list((self.root/'outputs').iterdir()),[])
 def test_direct_ram_denial_blocks_hostlogs_and_timeline(self):
  self.stub_leaves()
  for inp in ('FLUJO_LOCAL\n','FLUJO_LOCAL\nno\nLEER_LOG_LOCAL\nLOCAL_SI\n'):
   (self.root/'calls').unlink(missing_ok=True)
   r=self.flow('--local',input=inp); self.assertNotEqual(r.returncode,0,r.stderr)
   self.assertEqual([c[0] for c in self.calls()],['memory_dump.sh'])
   self.assertNotIn('COMPLETADO',r.stderr)
 def test_local_ram_failure_blocks_only_local_dependents(self):
  self.stub_leaves(); log=self.source('offline log')
  r=self.flow('--local','--log',log,input='FLUJO_LOCAL\nADQUIRIR_MEMORIA\nLEER_LOG_LOCAL\nLOCAL_SI\n',RAM_FAIL='1')
  self.assertEqual(r.returncode,1,r.stderr)
  self.assertEqual([c[0] for c in self.calls()],['memory_dump.sh','log_analyzer.sh'])
  self.assertIn('omitidas=',r.stderr)
 def test_local_new_ram_validated_exact_no_windows_assumption(self):
  self.stub_leaves(); self.source('old.raw')
  r=self.flow('--local',input='FLUJO_LOCAL\nADQUIRIR_MEMORIA\nno\n')
  self.assertEqual(r.returncode,1,r.stderr)
  calls=self.calls(); self.assertEqual([c[0] for c in calls],['memory_dump.sh','strings_analysis.sh'])
  raw=Path(calls[1][1][0]); self.assertEqual(raw.read_bytes(),b'SYNTHETIC NEW RAM')
  self.assertTrue(str(raw).startswith(str(self.root/'outputs/ram')))
 def test_local_tampered_ram_reference_not_consumed(self):
  self.stub_leaves()
  r=self.flow('--local',input='FLUJO_LOCAL\nADQUIRIR_MEMORIA\nLEER_LOG_LOCAL\nLOCAL_SI\n',RAM_TAMPER='1')
  self.assertEqual(r.returncode,1,r.stderr)
  self.assertEqual([c[0] for c in self.calls()],['memory_dump.sh'])
 def make_run(self,state='COMPLETADO',operation='strings',root=None):
  e=load_evidence(); src=self.source('viewer-source')
  run=e.start_run(root or self.root/'outputs/analysis/runs',operation,'offline',[])
  e.stage_input(run,src,'file')
  e.record_step(run,'analysis',0 if state=='COMPLETADO' else 7,state,dict(code='test_coverage',complete=state=='COMPLETADO',requested=True),[],tool='fixture')
  e.finish_run(run); return run
 def test_viewer_readonly_current_failed_history_and_filters(self):
  a=self.make_run(); b=self.make_run('FALLIDO')
  before=inventory(self.root/'outputs'); code=inventory(self.fw)
  r=self.viewer('--operation','strings')
  self.assertEqual(r.returncode,0,r.stderr)
  self.assertIn('ACTUAL',r.stdout); self.assertIn('HISTORICO',r.stdout)
  self.assertIn('FALLIDO',r.stdout); self.assertIn('test_coverage',r.stdout)
  self.assertNotIn('SYNTHETIC SECRET BODY',r.stdout+r.stderr)
  self.assertNotIn('198.51.100.99',r.stdout+r.stderr)
  self.assertEqual(inventory(self.root/'outputs'),before); self.assertEqual(inventory(self.fw),code)
  sha=hashlib.sha256(b'SYNTHETIC SECRET BODY').hexdigest()
  self.assertIn(sha,self.viewer('--input',sha).stdout)
 def test_viewer_invalid_blocks_previous_current_and_is_diagnostic(self):
  a=self.make_run(); b=self.make_run('FALLIDO'); (b/'run.json').write_text('{}')
  r=self.viewer(); self.assertEqual(r.returncode,1,r.stderr)
  self.assertNotIn('ACTUAL',r.stdout); self.assertIn('NO_EVALUABLE',r.stdout+r.stderr)
  self.assertIn('HISTORICO',r.stdout)
 def test_viewer_staging_failures_and_preidentity_incomplete_block_history(self):
   import contextlib, io
   import errno
   from unittest.mock import patch
   with contextlib.redirect_stderr(io.StringIO()): old=self.make_run()
   e=load_evidence(); src=self.root/'sources/viewer-source'
   digest=hashlib.sha256(src.read_bytes()).hexdigest()
   for fault in ('enospc','mutation','incomplete'):
    with self.subTest(fault=fault):
     with contextlib.redirect_stderr(io.StringIO()): attempt=e.start_run(old.parent,'strings','offline',[])
     if fault!='incomplete':
      copy=e._copy
      def fail(*args):
       if fault=='enospc': raise OSError(errno.ENOSPC,'synthetic')
       copy(*args); Path(args[1]).write_bytes(b'CORRUPT')
      with patch.object(e,'_copy',side_effect=fail),self.assertRaises(ValueError): e.stage_input(attempt,src)
      e.finish_run(attempt)
     for flags in ((),('--input',digest)):
      before=inventory(self.root/'outputs')
      result=self.viewer(*flags)
      self.assertNotIn('ACTUAL ',result.stdout)
      self.assertIn(old.name,result.stdout)
      self.assertIn('HISTORICO ',result.stdout)
      self.assertEqual(inventory(self.root/'outputs'),before)
 def test_viewer_external_only_explicit_and_never_reopens_source(self):
  external=self.make_run(root=self.root/'external')
  (self.root/'sources/viewer-source').unlink()
  r=self.viewer(); self.assertNotIn(external.name,r.stdout)
  r=self.viewer('--run',external/'run.json'); self.assertEqual(r.returncode,0,r.stderr)
  self.assertIn(external.name,r.stdout)
 def test_viewer_rejects_bad_filters_and_external_parent(self):
  for args in (('--input','198.51.100.99'),('--operation','BAD'),('--run',self.root/'outputs'),('--run','missing'),('--bad',)):
   r=self.viewer(*args); self.assertEqual(r.returncode,2,r.stderr)
 def test_viewer_symlink_and_tampered_sidecar_fail_closed(self):
  a=self.make_run(); link=self.root/'linked-run'; link.symlink_to(a,target_is_directory=True)
  self.assertEqual(self.viewer('--run',link).returncode,2)
  sidecar=next((a/'steps').iterdir()); sidecar.write_text('{}')
  r=self.viewer('--run',a); self.assertEqual(r.returncode,1,r.stderr)
  self.assertNotIn('ACTUAL',r.stdout); self.assertIn('NO_EVALUABLE',r.stderr)

if __name__=='__main__': unittest.main()
