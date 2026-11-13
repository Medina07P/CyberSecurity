import json
import os
from pathlib import Path
import signal
import subprocess
import time
import test_enumeration_reports
from enumeration_fixture import EnumerationFixture


class FreshnessReviewTests(EnumerationFixture):
    collect = test_enumeration_reports.ReportTests.collect
    def test_invalid_attempt_metadata_never_crashes_or_restores_finding(self):
        self.assertEqual(self.leaf('ssh/enum_ssh.sh','example.invalid').returncode,0)
        path=next((self.scans/'ssh').glob('auth_methods_*.txt.attempt.json'))
        for invalid in ([],{}, {'version':1,'host':'example.invalid','estado':'CONFIRMADO'}):
            path.write_text(json.dumps(invalid))
            result=self.collect('example.invalid')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['findings'],[])
            self.assertTrue(json.loads(result.stdout)['no_evaluable'])

    def test_missing_ffuf_marks_previous_results_omitted(self):
        self.assertEqual(self.leaf('web/enum_web.sh','example.invalid').returncode,0)
        path=next((self.scans/'web').glob('ffuf_*.json.attempt.json'))
        (self.bin/'ffuf').unlink()
        self.assertEqual(self.leaf('web/enum_web.sh','example.invalid').returncode,0)
        self.assertEqual(json.loads(path.read_text())['estado'],'OMITIDO')

    def test_failed_advanced_probe_invalidates_history_and_returns_failure(self):
        self.assertEqual(self.leaf('web/enum_web_advanced.sh','example.invalid').returncode,0)
        paths=list((self.scans/'web').glob('sensitive_files_*.txt.attempt.json'))
        result=self.leaf('web/enum_web_advanced.sh','example.invalid',FAKE_FAIL='nc')
        self.assertEqual(result.returncode,1)
        self.assertTrue(paths)
        self.assertTrue(all(json.loads(p.read_text())['estado']=='NO_DETERMINADO' for p in paths))


class ProcessReviewTests(EnumerationFixture):
    def test_sigterm_stops_separate_ffuf_process_group(self):
        pidfile=self.root/'ffuf.pid'
        (self.bin/'ffuf').write_text(f'''#!/usr/bin/python3
import os,time
open({str(pidfile)!r},'w').write(str(os.getpid()))
time.sleep(30)
''')
        process=subprocess.Popen(['bash',str(self.fw/'04_Enumeration/web/enum_web.sh'),'example.invalid'],env=self.env,cwd=self.root,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        ffuf_pid=None
        try:
            deadline=time.monotonic()+8
            while not pidfile.exists() and time.monotonic()<deadline:
                time.sleep(.05)
            self.assertTrue(pidfile.exists())
            ffuf_pid=int(pidfile.read_text())
            os.killpg(process.pid,signal.SIGTERM)
            process.wait(timeout=5)
            deadline=time.monotonic()+3
            while Path(f'/proc/{ffuf_pid}').exists() and time.monotonic()<deadline:
                time.sleep(.05)
            self.assertFalse(Path(f'/proc/{ffuf_pid}').exists(),'ffuf sobrevivió a SIGTERM')
        finally:
            if process.poll() is None: os.killpg(process.pid,signal.SIGKILL); process.wait()
            if ffuf_pid and Path(f'/proc/{ffuf_pid}').exists():
                os.kill(ffuf_pid,signal.SIGKILL)
