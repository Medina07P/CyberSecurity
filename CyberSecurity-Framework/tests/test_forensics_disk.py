"""Disk contracts on copied sources and synthetic stubs; no kernel devices."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import unittest

from forensics_fixture import sandbox, runtime_environment, inventory

FRAMEWORK = Path(__file__).resolve().parents[1]
BACKEND = r'''#!PYTHON
import json, os, pathlib, sys
p = pathlib.Path
root = p(os.environ['ROOT'])
name = p(sys.argv[0]).name
a = sys.argv[1:]
with (root/'calls').open('a') as f: f.write(json.dumps([name, a])+'\n')
statefile=root/'kernel.json'
s=json.loads(statefile.read_text()) if statefile.exists() else {}
def save(): statefile.write_text(json.dumps(s))
if name == 'sudo': sys.exit(98)
if name == 'file': print('synthetic filesystem'); sys.exit(int(os.environ.get('FILE_RC','0')))
if name == 'fdisk': print('synthetic partition metadata'); sys.exit(int(os.environ.get('FDISK_RC','0')))
if name == 'blkid': print(os.environ.get('FS','ext4')); sys.exit(int(os.environ.get('BLKID_RC','0')))
if name == 'losetup':
 if '--find' in a:
  s.update(loop='/dev/loop900', copy=a[-1], offset=int(a[a.index('--offset')+1]) if '--offset' in a else 0,
           length=int(a[a.index('--sizelimit')+1]) if '--sizelimit' in a else 0)
  save(); print(s['loop']); sys.exit(int(os.environ.get('LOOP_RC','0')))
 if '--json' in a:
  rows=[{'name':s.get('loop'), 'back-file':s.get('copy'),
   'ro':not bool(os.environ.get('WRITABLE_LOOP')), 'offset':s.get('offset'), 'sizelimit':s.get('length')}] if s.get('loop') else []
  print(json.dumps({'loopdevices':rows})); sys.exit(0)
 if '--detach' in a:
  if s.get('mounted') or a[-1]!=s.get('loop'): sys.exit(88)
  if os.environ.get('DETACH_LIES'): sys.exit(0)
  s['loop']=None; save(); sys.exit(0)
if name == 'mount':
 s.update(point=a[-1], mounted=True, fs=a[a.index('-t')+1], options=a[a.index('-o')+1]); save()
 sys.exit(int(os.environ.get('MOUNT_RC','0')))
if name == 'findmnt':
 if '--list' in a:
  if os.environ.get('ABSENCE_FAIL'): sys.exit(2)
  rows=[{'source':s.get('loop'),'target':s.get('point')}] if s.get('mounted') else []
  print(json.dumps({'filesystems':rows})); sys.exit(0)
 if not s.get('mounted'): sys.exit(1)
 source='/dev/foreign' if os.environ.get('FOREIGN_MOUNT') else s.get('loop')
 print(json.dumps({'filesystems':[{'source':source,'target':s.get('point'),'fstype':s.get('fs'),'options':s.get('options')}]})); sys.exit(0)
if name == 'umount':
 if os.environ.get('UMOUNT_FAIL'): sys.exit(32)
 if a[-1]!=s.get('point'): sys.exit(88)
 s['mounted']=False; save(); sys.exit(0)
if name in ('foremost','scalpel'):
 out=p(a[a.index('-o')+1]); out.mkdir(mode=0o700,exist_ok=True)
 if not os.environ.get('ZERO_RECOVERED'): (out/'SECRET.bin').write_bytes(b'SECRET-CONTENT')
 if os.environ.get('WAIT_BACKEND'):
  (root/'started').touch()
  signal=__import__('signal'); signal.pause()
 sys.exit(int(os.environ.get('CARVE_RC','0')))
if name=='ddrescue':
 image,mapfile=map(p,a[-2:]); image.write_bytes(b'X'*1024)
 mode=os.environ.get('MAP','complete')
 if mode!='absent':
  text={'complete':'0x0 + 1\n0x0 0x400 +\n',
        'bad':'0x0 + 1\n0x0 0x200 +\n0x200 0x200 -\n',
        'pending':'0x0 ? 1\n0x0 0x400 ?\n',
        'unknown':'0x0 + 1\n0x0 0x400 Z\n',
        'gap':'0x0 + 1\n0x200 0x200 +\n'}[mode]
  mapfile.write_text('# synthetic ddrescue map\n'+text)
 sys.exit(int(os.environ.get('DD_RC','0')))
sys.exit(97)
'''


class DiskTests(unittest.TestCase):
    def setUp(self):
        self.box = sandbox()
        self.root = self.box.__enter__()
        self.addCleanup(self.box.__exit__, None, None, None)
        self.framework = self.root / 'code'
        for relative in ('00_Config/lib', '08_Forensics/disk'):
            target = self.framework / relative
            target.mkdir(parents=True)
            for src in (FRAMEWORK / relative).iterdir():
                if src.is_file() and (src.name.startswith('forensics_') or relative.endswith('/disk')):
                    shutil.copyfile(src, target / src.name)
        self.env = runtime_environment(self.root)
        library=self.framework/'00_Config/lib/forensics_disk.bash'
        self.real_disk_library=library.read_text() if library.exists() else None
        if library.exists():
            # Stub only the privilege boundary in this disposable source copy.
            with library.open('a') as stream:
                stream.write('\n_forensics_disk_privilege() { return 0; }\n')
        for name in ('dirname','mkdir','tee','date'):
            (self.root/'bin'/name).symlink_to('/usr/bin/'+name)
        self.env.update(FORENSICS_ANALYSIS_ROOT=str(self.root/'outputs'/'analysis'),
                        FORENSICS_RECOVERED_ROOT=str(self.root/'outputs'/'recovered'),
                        FORENSICS_MEMORY_ROOT=str(self.root/'outputs'/'memory'))
        for name in ('file','fdisk','blkid','losetup','mount','findmnt','umount','sudo','foremost','scalpel','ddrescue'):
            path = self.root / 'bin' / name
            if path.exists(): path.unlink()
            path.write_text(BACKEND.replace('PYTHON',sys.executable,1))
            path.chmod(0o700)
        self.source=self.root/'sources'/'image with spaces'
        self.source.write_bytes(b'A'*1024)
        self.source.chmod(0o640)
        self.original=inventory(self.root/'sources')

    def leaf(self, name, *args, input='', **env):
        result = subprocess.run(['/bin/bash', str(self.framework/'08_Forensics/disk'/name),
                                 *map(str,args)], env={**self.env,**env}, input=input,
                                text=True,capture_output=True,timeout=40)
        self.assertEqual(inventory(self.root/'sources'),self.original)
        self.assertNotIn('SECRET-CONTENT',result.stdout+result.stderr)
        return result

    def calls(self):
        p=self.root/'calls'
        return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []

    def manifests(self):
        return sorted([json.loads(p.read_text()) for p in (self.root/'outputs'/'analysis').glob('runs/*/run.json')],key=lambda d:d['started'])

    def physical_device(self):
        helper=self.framework/'00_Config/lib/forensics_evidence.py'
        injection="""
_real_observation = _device_observation
_real_identity = _device_identity
def _device_identity(source):
    if str(source) == os.environ.get('SYNTHETIC_DEVICE'):
        return dict(dev=1, ino=2, rdev=3, mode=384)
    return _real_identity(source)
def _device_observation(source):
    if str(source) == os.environ.get('SYNTHETIC_DEVICE'):
        return dict(dev=1, ino=2, rdev=3, mode=384, size=1024)
    return _real_observation(source)
"""
        helper.write_text(helper.read_text().replace("if __name__ == '__main__':",injection+"\nif __name__ == '__main__':"))
        return helper

    def test_physical_observation_metadata_error_is_operational_one_not_usage_two(self):
        helper=self.physical_device()
        helper.write_text(helper.read_text().replace("elif command == 'observe-device':", """elif command == 'observe-device':
            raise OSError('synthetic persistence failure')"""))
        result=self.leaf('file_carving.sh',self.source,'--physical',input='RECUPERAR_FISICO\n',
                         SYNTHETIC_DEVICE=str(self.source))
        self.assertEqual(result.returncode,1,result.stderr)
        self.assertEqual(self.manifests()[0]['state'],'FALLIDO')
        self.assertEqual(self.calls(),[])

    def test_disk_default_is_copy_metadata_only_and_rc_is_real(self):
        result=self.leaf('disk_forensics.sh',self.source,FDISK_RC='7')
        self.assertEqual(result.returncode,1,result.stderr)
        calls=self.calls()
        self.assertEqual({name for name,_ in calls},{'file','fdisk','blkid'})
        for _,args in calls: self.assertNotIn(str(self.source),args)
        data=self.manifests()[0]
        self.assertEqual(next(s['rc'] for s in data['steps'] if s['tool']=='fdisk'),7)

    def test_bash_bare_filename_from_leaf_directory_self_locates(self):
        for name in ('disk_forensics.sh','file_carving.sh'):
            with self.subTest(leaf=name):
                result=subprocess.run(['/bin/bash',name,str(self.source)],
                    cwd=self.framework/'08_Forensics/disk',env=self.env,
                    capture_output=True,text=True,timeout=40)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(inventory(self.root/'sources'),self.original)

    def test_mount_library_rejects_original_even_when_caller_bypasses_leaf(self):
        library=self.framework/'00_Config/lib/forensics_disk.bash'
        result=subprocess.run(['/bin/bash','-c',r'''
source "$1"
forensics_begin disk offline || exit $?
copy=$(forensics_stage "$2") || exit $?
forensics_disk_mount "$2"
status=$?
forensics_disk_release || :
exit "$status"
''','fixture',str(library),str(self.source)],env=self.env,capture_output=True,text=True,timeout=40)
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertEqual(self.calls(),[])
        self.assertEqual(inventory(self.root/'sources'),self.original)

    def test_mount_filesystem_options_readonly_loop_and_release(self):
        for fs,options in [('ext2','ro'),('ext3','ro,noload'),('ext4','ro,noload'),('xfs','ro,norecovery')]:
            with self.subTest(fs=fs):
                result=self.leaf('disk_forensics.sh',self.source,'--mount-copy',input='MONTAR_COPIA\n',FS=fs)
                self.assertEqual(result.returncode,0,result.stderr)
                calls=self.calls()
                mount=[args for name,args in calls if name=='mount'][-1]
                self.assertEqual(mount[mount.index('-o')+1],options)
                loop=[args for name,args in calls if name=='losetup' and '--find' in args][-1]
                self.assertIn('--read-only',loop)
                self.assertNotEqual(loop[-1],str(self.source))
                state=json.loads((self.root/'kernel.json').read_text())
                self.assertIsNone(state['loop'])
                self.assertFalse(state['mounted'])
                self.assertFalse(Path(state['point']).exists())

    def test_mount_eof_and_bad_ranges_do_not_allocate_resources(self):
        for args in [('--mount-copy',),('--mount-copy','--offset','-1','--length','1'),
                     ('--mount-copy','--offset','512','--length','1024'),
                     ('--mount-copy','--offset','0')]:
            result=self.leaf('disk_forensics.sh',self.source,*args)
            self.assertEqual(result.returncode,2,result.stderr)
        self.assertFalse(any(n in ('mount','losetup') for n,_ in self.calls()))

    def test_unsupported_and_ambiguous_filesystems_never_mount(self):
        for fs in ('','ntfs'):
            result=self.leaf('disk_forensics.sh',self.source,'--mount-copy',input='MONTAR_COPIA\n',FS=fs)
            self.assertEqual(result.returncode,1,result.stderr)
        self.assertFalse(any(n=='mount' for n,_ in self.calls()))

    def test_mount_selected_range_reaches_loop_and_invalid_source_is_never_listed(self):
        result=self.leaf('disk_forensics.sh',self.source,'--mount-copy','--offset','512','--length','512',
                         input='MONTAR_COPIA\n',FOREIGN_MOUNT='1')
        self.assertEqual(result.returncode,1,result.stderr)
        loop=next(a for n,a in self.calls() if n=='losetup' and '--find' in a)
        self.assertEqual(loop[loop.index('--offset')+1],'512')
        self.assertEqual(loop[loop.index('--sizelimit')+1],'512')
        self.assertFalse(any(n=='umount' for n,_ in self.calls()),'must not unmount foreign source')
        self.assertFalse(any(n=='losetup' and '--detach' in a for n,a in self.calls()))
        self.assertFalse(any(s['name']=='filelist' for s in self.manifests()[0]['steps']))

    def test_unmount_failure_keeps_loop_point_and_private_manual_diagnostic(self):
        result=self.leaf('disk_forensics.sh',self.source,'--mount-copy',input='MONTAR_COPIA\n',UMOUNT_FAIL='1')
        self.assertEqual(result.returncode,1,result.stderr)
        state=json.loads((self.root/'kernel.json').read_text())
        self.assertIsNotNone(state['loop'])
        self.assertTrue(Path(state['point']).exists())
        self.assertFalse(any(n=='losetup' and '--detach' in a for n,a in self.calls()))
        self.assertIn('manual',result.stderr.lower())
        self.assertNotEqual(self.manifests()[0]['state'],'COMPLETADO')

    def test_loop_readwrite_or_mount_failure_preserves_truthful_manifest(self):
        for key in ('WRITABLE_LOOP','MOUNT_RC'):
            result=self.leaf('disk_forensics.sh',self.source,'--mount-copy',
                             input='MONTAR_COPIA\n',**{key:'7'})
            self.assertEqual(result.returncode,1,result.stderr)
            self.assertNotEqual(self.manifests()[-1]['state'],'COMPLETADO')

    def test_complete_map_cannot_certify_truncated_image(self):
        backend=self.root/'bin'/'ddrescue'
        backend.write_text(backend.read_text().replace("b'X'*1024","b'X'*512"))
        result=self.leaf('file_carving.sh',self.source)
        self.assertEqual(result.returncode,1,result.stderr)
        step=next(s for s in self.manifests()[0]['steps'] if s['name']=='ddrescue')
        self.assertEqual(step['state'],'NO_EVALUABLE')

    def test_empty_success_and_external_parent_mode(self):
        parent=self.root/'external'
        parent.mkdir(mode=0o755)
        result=self.leaf('file_carving.sh',self.source,parent,ZERO_RECOVERED='1')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(parent.stat().st_mode & 0o777,0o755)
        self.assertEqual(len(list(parent.glob('run-*'))),1)

    def test_unprivileged_mount_is_precondition_without_sudo(self):
        if self.real_disk_library is None: self.fail('missing disk library')
        library=self.framework/'00_Config/lib/forensics_disk.bash'
        library.write_text(self.real_disk_library)
        # Exercise the real privilege condition, independent of runner uid.
        library.write_text(library.read_text().replace('(( EUID == 0 ))','(( 12345 == 0 ))'))
        result=self.leaf('disk_forensics.sh',self.source,'--mount-copy',input='MONTAR_COPIA\n')
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertEqual(self.calls(),[])

    def test_physical_mount_refused_and_offline_nonregular_is_precondition(self):
        result=self.leaf('disk_forensics.sh',self.source,'--physical','--mount-copy')
        self.assertEqual(result.returncode,2,result.stderr)
        pipe=self.root/'pipe'; os.mkfifo(pipe)
        result=self.leaf('disk_forensics.sh',pipe)
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertEqual(self.calls(),[])

    def test_confirmed_physical_regular_file_rejected_before_run_creation(self):
        result=self.leaf('file_carving.sh',self.source,'--physical',input='RECUPERAR_FISICO\n')
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertEqual(self.manifests(),[])
        self.assertEqual(self.calls(),[])

    def test_resource_metadata_failure_blocks_success_even_after_cleanup(self):
        helper=self.framework/'00_Config/lib/forensics_evidence.py'
        text=helper.read_text().replace("elif command == 'step':", """elif command == 'step':
            if args.name == 'disk_resources': raise ValueError('synthetic persistence failure')""")
        helper.write_text(text)
        result=self.leaf('disk_forensics.sh',self.source,'--mount-copy',input='MONTAR_COPIA\n')
        self.assertEqual(result.returncode,1,result.stderr)
        self.assertEqual(self.manifests()[0]['state'],'FALLIDO')
        self.assertNotIn('Traceback',result.stdout+result.stderr)

    def test_cleanup_requires_actual_absence_not_only_umount_and_detach_rc(self):
        for key in ('ABSENCE_FAIL','DETACH_LIES'):
            with self.subTest(key=key):
                result=self.leaf('disk_forensics.sh',self.source,'--mount-copy',input='MONTAR_COPIA\n',**{key:'1'})
                self.assertEqual(result.returncode,1,result.stderr)
                self.assertNotEqual(self.manifests()[-1]['state'],'COMPLETADO')
                state=json.loads((self.root/'kernel.json').read_text())
                self.assertTrue(Path(state['point']).exists())

    def test_replaced_point_never_listed_removed_or_unmounted(self):
        backend=self.root/'bin'/'findmnt'
        backend.write_text(backend.read_text().replace("if name == 'findmnt':", """if name == 'findmnt':
 if not (root/'replaced').exists():
  point=p(s['point']); point.rename(point.with_name('owned-old-point'))
  point.mkdir(mode=0o700); (point/'foreign-sentinel').write_text('intact')
  (root/'replaced').touch()
"""))
        result=self.leaf('disk_forensics.sh',self.source,'--mount-copy',input='MONTAR_COPIA\n')
        self.assertEqual(result.returncode,1,result.stderr)
        state=json.loads((self.root/'kernel.json').read_text())
        self.assertEqual((Path(state['point'])/'foreign-sentinel').read_text(),'intact')
        self.assertFalse(any(s['name']=='filelist' for s in self.manifests()[0]['steps']))
        self.assertFalse(any(n=='umount' for n,_ in self.calls()))

    def test_cancel_inside_mount_capture_reaps_before_releasing(self):
        backend=self.root/'bin'/'mount'
        backend.write_text(backend.read_text().replace("sys.exit(int(os.environ.get('MOUNT_RC','0')))","""
 (root/'started').touch()
 import signal
 signal.pause()
"""))
        script=self.framework/'08_Forensics/disk/disk_forensics.sh'
        process=subprocess.Popen(['/bin/bash',str(script),str(self.source),'--mount-copy'],env=self.env,
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        process.stdin.write('MONTAR_COPIA\n'); process.stdin.close(); process.stdin=None
        try:
            deadline=time.monotonic()+20
            while not (self.root/'started').exists() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertTrue((self.root/'started').exists())
            process.send_signal(signal.SIGINT)
            out,err=process.communicate(timeout=20)
            self.assertEqual(process.returncode,1,err)
            data=self.manifests()[0]
            self.assertEqual(data['state'],'CANCELADO')
            step=next(s for s in data['steps'] if s['name']=='mount_copy')
            self.assertEqual(step['signal'],2)
            self.assertEqual(step['rc'],137)
            state=json.loads((self.root/'kernel.json').read_text())
            self.assertFalse(state['mounted'])
            self.assertIsNone(state['loop'])
        finally:
            if process.poll() is None:
                process.terminate(); process.communicate(timeout=20)

    def test_mount_signal_releases_only_owned_resources_and_waits_backend(self):
        backend=self.root/'bin'/'findmnt'
        backend.write_text(backend.read_text().replace("if name == 'findmnt':", """if name == 'findmnt':
 if os.environ.get('PAUSE_PROBE') and not (root/'started').exists():
  (root/'started').touch()
  import time
  while not (root/'continue').exists(): time.sleep(.01)
"""))
        # Probe runs synchronously outside the capture group. Signal delivery to
        # the owner must not remove resources while this child is still running.
        script=self.framework/'08_Forensics/disk/disk_forensics.sh'
        process=subprocess.Popen(['/bin/bash',str(script),str(self.source),'--mount-copy'],
                env={**self.env,'PAUSE_PROBE':'1'},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        process.stdin.write('MONTAR_COPIA\n'); process.stdin.close(); process.stdin=None
        try:
            deadline=time.monotonic()+20
            while not (self.root/'started').exists() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertTrue((self.root/'started').exists())
            process.send_signal(signal.SIGTERM)
            (self.root/'continue').touch()
            out,err=process.communicate(timeout=20)
            self.assertEqual(process.returncode,1,err)
            state=json.loads((self.root/'kernel.json').read_text())
            self.assertFalse(state['mounted'])
            self.assertIsNone(state['loop'])
            self.assertFalse(Path(state['point']).exists())
            self.assertNotIn('SECRET-CONTENT',out+err)
            self.assertEqual(self.manifests()[0]['state'],'CANCELADO')
        finally:
            (self.root/'continue').touch(exist_ok=True)
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=20)

    def test_carving_products_unique_private_and_three_backends_preserved(self):
        first=self.leaf('file_carving.sh',self.source)
        self.assertEqual(first.returncode,0,first.stderr)
        old=inventory(self.root/'outputs'/'recovered')
        second=self.leaf('file_carving.sh',self.source)
        self.assertEqual(second.returncode,0,second.stderr)
        now=inventory(self.root/'outputs'/'recovered')
        self.assertTrue(all(now[k]==v for k,v in old.items()))
        self.assertEqual(len(self.manifests()),2)
        for name,args in self.calls():
            if name in ('foremost','scalpel','ddrescue'):
                self.assertNotIn(str(self.source),args)
        for data in self.manifests():
            self.assertEqual({s['tool'] for s in data['steps']} & {'foremost','scalpel','ddrescue'},
                             {'foremost','scalpel','ddrescue'})
            self.assertEqual(data['state'],'COMPLETADO')
        for path in (self.root/'outputs'/'recovered').rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777,0o700 if path.is_dir() else 0o600)

    def test_ddrescue_map_not_rc_or_nonempty_image_controls_coverage(self):
        for mode,state in [('bad','PARCIAL'),('pending','PARCIAL'),('unknown','NO_EVALUABLE'),
                           ('absent','NO_EVALUABLE'),('gap','NO_EVALUABLE')]:
            with self.subTest(mode=mode):
                result=self.leaf('file_carving.sh',self.source,MAP=mode)
                self.assertEqual(result.returncode,1,result.stderr)
                step=next(s for s in self.manifests()[-1]['steps'] if s['name']=='ddrescue')
                self.assertEqual(step['rc'],0)
                self.assertEqual(step['state'],state)

    def test_missing_error_and_zero_carving_not_silent_success(self):
        for name in ('foremost','scalpel','ddrescue'): (self.root/'bin'/name).unlink()
        result=self.leaf('file_carving.sh',self.source)
        self.assertEqual(result.returncode,1,result.stderr)
        self.assertTrue(all(s['state']=='OMITIDO' for s in self.manifests()[0]['steps']))

    def test_error_rc_preserved_zero_recovered_is_valid_empty_result(self):
        result=self.leaf('file_carving.sh',self.source,ZERO_RECOVERED='1',CARVE_RC='9',DD_RC='8')
        self.assertEqual(result.returncode,1,result.stderr)
        data=self.manifests()[0]
        self.assertEqual(next(s['rc'] for s in data['steps'] if s['name']=='foremost'),9)
        self.assertEqual(next(s['rc'] for s in data['steps'] if s['name']=='ddrescue'),8)

    def test_physical_requires_block_source_explicit_permission_and_never_offline_backends(self):
        # No synthetic kernel nodes: instrument only observation boundary of the copied helper.
        self.physical_device()
        result=self.leaf('file_carving.sh',self.source,'--physical')
        self.assertEqual(result.returncode,2,result.stderr)
        result=self.leaf('file_carving.sh',self.source,'--physical',input='RECUPERAR_FISICO\n',
                         SYNTHETIC_DEVICE=str(self.source))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual({n for n,_ in self.calls()},{'ddrescue'})
        data=self.manifests()[-1]
        self.assertEqual(data['inputs'],[])
        self.assertEqual(data['observed_devices'][0]['rdev'],3)
        self.assertNotIn('sha256',data['observed_devices'][0])
        self.assertEqual(next(a for n,a in self.calls() if n=='ddrescue')[0],str(self.source))


if __name__ == '__main__':
    unittest.main()
