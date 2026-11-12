"""Runtime contracts using only synthetic sources and harmless local processes."""
import json
import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from forensics_fixture import sandbox, runtime_environment, load_evidence, inventory


RUNTIME = Path(__file__).resolve().parents[1] / '00_Config/lib/forensics_runtime.bash'


class RuntimeTests(unittest.TestCase):
    def environment(self, root):
        env = runtime_environment(root)
        env['RUNTIME'] = str(RUNTIME)
        return env

    def run_shell(self, root, body, env=None):
        return subprocess.run(['/bin/bash', '-c', 'source "$RUNTIME" || exit 90\n' + body],
                              env=env or self.environment(root), capture_output=True,
                              text=True, timeout=15)

    def manifest(self, root):
        files = list((root / 'outputs').glob('run-*/run.json'))
        self.assertEqual(len(files), 1)
        return json.loads(files[0].read_text())

    def test_cancel_before_launch_and_before_registration_never_starts_backend(self):
        for boundary in ('launch', 'registration', 'authorization'):
            with self.subTest(boundary=boundary), sandbox() as root:
                env = self.environment(root)
                env['BOUNDARY'] = boundary
                result = self.run_shell(root, r'''
trap 'printf prior >> "$ROOT/prior"' TERM
forensics_begin strings offline "$ROOT/outputs" || exit
backend() { printf forbidden > "$ROOT/backend-started"; }
injected=0
inject_cancel() {
    [[ $BASHPID = $$ && $injected = 0 ]] || return 0
    case "$BOUNDARY:$BASH_COMMAND" in
        launch:setsid\ bash*|launch:_forensics_start_supervisor*) ;;
        registration:'_FORENSICS_ACTIVE_PID=$!') ;;
        authorization:'_forensics_send GO') ;;
        *) return 0 ;;
    esac
    injected=1
    kill -TERM "$$"
    kill -TERM "$$"
}
set -T
trap inject_cancel DEBUG
forensics_capture interrupted backend
trap - DEBUG
[[ $injected = 1 ]] || exit 80
[[ $(trap -p TERM) = *'printf prior'* ]] || exit 81
forensics_finish
''', env)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse((root / 'backend-started').exists(), 'backend ran after cancellation')
                self.assertEqual((root / 'prior').read_text(), 'prior')
                data = self.manifest(root)
                self.assertEqual(data['state'], 'CANCELADO')
                self.assertEqual(data['steps'][0]['rc'], 0)
                self.assertIsNone(data['steps'][0]['signal'])

    def test_bash_never_signals_a_numeric_group_after_wait(self):
        with sandbox() as root:
            result = self.run_shell(root, r'''
forensics_begin strings offline "$ROOT/outputs" || exit
kill() {
    printf '%s\n' "$*" >> "$ROOT/signal-calls"
    builtin kill "$@"
}
forensics_capture done printf okay || exit
forensics_complete_step done COMPLETADO checked || exit
forensics_finish
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / 'signal-calls').exists(), 'Bash still signals a reusable numeric PGID')

    def test_pidfd_failure_never_executes_tool_even_after_go(self):
        for failure in ('ENOSYS', 'EPERM', 'CHILD_EPERM'):
            with self.subTest(failure=failure), sandbox() as root:
                env = self.environment(root)
                copied = root / 'lib'
                copied.mkdir(mode=0o700)
                for name in ('forensics_runtime.bash', 'forensics_evidence.py'):
                    (copied / name).write_bytes(RUNTIME.with_name(name).read_bytes())
                    (copied / name).chmod(0o600)
                env['RUNTIME'] = str(copied / 'forensics_runtime.bash')
                env['FAILURE'] = failure
                injector = root / 'sources/injector.py'
                injector.write_text('''import errno, os, subprocess, sys
from pathlib import Path
namespace = {'__name__': 'injected_evidence', '__file__': sys.argv[1]}
exec(compile(Path(sys.argv[1]).read_bytes(), sys.argv[1], 'exec'), namespace)
real_open, real_popen = os.pidfd_open, subprocess.Popen
failure = os.environ['FAILURE']
if failure == 'CHILD_EPERM':
    handle = real_open(os.getpid())
    os.close(handle)
    Path(os.environ['ROOT']+'/self-probe-ok').write_text('ok')
def opening(pid, flags=0):
    if failure == 'CHILD_EPERM' and pid == os.getpid():
        return real_open(pid, flags)
    Path(os.environ['ROOT']+'/pidfd-attempt').write_text('child' if pid != os.getpid() else 'self')
    raise OSError(errno.ENOSYS if failure == 'ENOSYS' else errno.EPERM, 'injected pidfd failure')
def scheduled(argv, **kwargs):
    child = real_popen(argv, **kwargs)
    # Make the original unsafe direct-Bash launch finish its innocuous marker
    # before returning Popen. Never wait for a gated interpreter to be released.
    if argv[0] == 'bash':
        child.wait()
    return child
os.pidfd_open, subprocess.Popen = opening, scheduled
sys.exit(namespace['main'](sys.argv[2:]))
''')
                injector.chmod(0o600)
                result = self.run_shell(root, r'''
_forensics_helper() {
    if [[ $1 = supervise ]]; then
        python3 -B "$ROOT/sources/injector.py" "$_FORENSICS_HELPER" "$@"
    else
        python3 -B "$_FORENSICS_HELPER" "$@"
    fi
}
forensics_begin strings offline "$ROOT/outputs" || exit
backend() { printf forbidden > "$ROOT/tool-started"; }
forensics_capture failed backend
capture_status=$?
[[ $capture_status = 1 ]] || exit 80
forensics_finish
''', env)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse((root / 'tool-started').exists(), 'tool ran without an effective concrete pidfd')
                self.assertEqual(result.stdout, '')
                self.assertIn('Error forense', result.stderr)
                self.assertEqual((root / 'pidfd-attempt').read_text(), 'child')
                if failure == 'CHILD_EPERM':
                    self.assertEqual((root / 'self-probe-ok').read_text(), 'ok')
                data = self.manifest(root)
                self.assertEqual((data['state'], data['rc'], data['complete']), ('FALLIDO', 1, False))
                self.assertTrue(data['dependents_blocked'])
                self.assertEqual(data['steps'][0]['state'], 'PARCIAL')
                self.assertEqual(data['steps'][0]['coverage']['code'], 'runtime_pending')

    def test_streams_and_delayed_publication_preserve_each_rc(self):
        with sandbox() as root:
            result = self.run_shell(root, '''
forensics_begin strings offline "$ROOT/outputs" || exit
bad() { printf 'partial'; printf 'diagnostic' >&2; return 7; }
forensics_capture failed bad
test "$FORENSICS_STEP_RC" = 7 || exit 80
forensics_capture good printf okay
forensics_complete_step good COMPLETADO analyzed || exit
forensics_complete_step failed FALLIDO analyzed
forensics_finish
''')
            self.assertEqual(result.returncode, 1, result.stderr)
            data = self.manifest(root)
            failed_step = next(s for s in data['steps'] if s['name'] == 'failed')
            self.assertEqual(failed_step['rc'], 7)
            self.assertEqual(failed_step['state'], 'FALLIDO')
            run = next((root / 'outputs').iterdir())
            self.assertEqual((run / 'analysis/failed.stdout').read_text(), 'partial')
            self.assertEqual((run / 'analysis/failed.stderr').read_text(), 'diagnostic')
            self.assertEqual(result.stdout, '')

    def test_missing_command_127_and_tool_exit_143_not_invented_signal(self):
        for command, expected in [('absent_backend', 127), ('exit143', 143)]:
            with self.subTest(command=command), sandbox() as root:
                result = self.run_shell(root, f'''
forensics_begin strings offline "$ROOT/outputs" || exit
exit143() {{ return 143; }}
forensics_capture failed {command}
forensics_complete_step failed FALLIDO analyzed
forensics_finish
''')
                self.assertEqual(result.returncode, 1, result.stderr)
                step = self.manifest(root)['steps'][0]
                self.assertEqual(step['rc'], expected)
                self.assertIsNone(step['signal'])

    def test_empty_and_pending_runs_never_succeed(self):
        for action in ['', 'forensics_capture pending printf hello']:
            with self.subTest(action=action), sandbox() as root:
                result = self.run_shell(root, f'''
forensics_begin strings offline "$ROOT/outputs" || exit
{action}
forensics_finish
''')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(self.manifest(root)['state'], 'PARCIAL')

    def test_stderr_with_rc_zero_and_idempotent_finish(self):
        with sandbox() as root:
            result = self.run_shell(root, '''
forensics_begin strings offline "$ROOT/outputs" || exit
warn() { printf warning >&2; }
forensics_capture warn warn || exit
forensics_complete_step warn COMPLETADO analyzed || exit
forensics_finish || exit
forensics_finish
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.manifest(root)['state'], 'COMPLETADO')

    def test_pipeline_producer_failure_is_not_hidden(self):
        with sandbox() as root:
            result = self.run_shell(root, '''
forensics_begin strings offline "$ROOT/outputs" || exit
producer() { printf bytes; return 7; }
consumer() { while IFS= read -r -n 1 c; do printf '%s' "$c"; done; }
pipeline() { producer | consumer; }
forensics_capture pipe pipeline
test "$FORENSICS_STEP_RC" = 7 || exit 80
forensics_complete_step pipe FALLIDO analyzed
forensics_finish
''')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(self.manifest(root)['steps'][0]['rc'], 7)

    def test_job_control_cannot_detach_the_owned_process(self):
        with sandbox() as root:
            result = self.run_shell(root, '''
forensics_begin strings offline "$ROOT/outputs" || exit
set -m
forensics_capture job python3 -B -c 'import time; time.sleep(.2); print("finished")' || exit
[[ $- = *m* ]] || exit 80
IFS= read -r content < "$FORENSICS_STEP_OUT"
[[ $content = finished ]] || exit 81
forensics_complete_step job COMPLETADO checked || exit
forensics_finish
''')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_stage_stdout_only_and_failure_blocks_tool(self):
        with sandbox() as root:
            (root / 'sources/input').write_text('synthetic')
            result = self.run_shell(root, '''
forensics_begin strings offline "$ROOT/outputs" || exit
copy=$(forensics_stage "$ROOT/sources/input") || exit
test -f "$copy" || exit 81
forensics_stage "$ROOT/sources/missing"
forensics_capture forbidden printf should-not-run
forensics_finish
''')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(self.manifest(root)['steps'], [])
            self.assertEqual(result.stdout, '')

    def test_modified_source_blocks_dependent_execution(self):
        with sandbox() as root:
            (root / 'sources/input').write_text('synthetic')
            result = self.run_shell(root, '''
forensics_begin strings offline "$ROOT/outputs" || exit
forensics_stage "$ROOT/sources/input" > "$ROOT/copy-path" || exit
printf changed > "$ROOT/sources/input"
forensics_capture forbidden printf should-not-run
forensics_finish
''')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue(self.manifest(root)['dependents_blocked'])
            self.assertEqual(self.manifest(root)['steps'], [])

    def test_privacy_from_command_start(self):
        with sandbox() as root:
            result = self.run_shell(root, '''
umask 000
forensics_begin strings offline "$ROOT/outputs" || exit
private() {
 python3 -B -c 'import os,stat; from pathlib import Path; r=Path(os.environ["FORENSICS_RUN_DIR"]); assert all(stat.S_IMODE(p.stat().st_mode)==(448 if p.is_dir() else 384) for p in [r,*r.rglob("*")])'
}
forensics_capture private private || exit
forensics_complete_step private COMPLETADO checked || exit
forensics_finish
''')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_metadata_failure_is_visible_even_with_tool_rc_zero(self):
        with sandbox() as root:
            result = self.run_shell(root, '''
forensics_begin strings offline "$ROOT/outputs" || exit
break_metadata() { printf '{' > "$FORENSICS_RUN_DIR/run.json"; }
forensics_capture broken break_metadata
status=$?
test "$FORENSICS_STEP_RC" = 0 || exit 81
test "$status" != 0 || exit 82
forensics_finish
''')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('Error forense', result.stderr)

    def test_require_does_not_execute_and_skip_is_partial(self):
        with sandbox() as root:
            env = self.environment(root)
            (root / 'bin/backend').write_text('#!/bin/bash\nprintf forbidden\n')
            (root / 'bin/backend').chmod(0o700)
            result = self.run_shell(root, '''
forensics_begin dependencies offline "$ROOT/outputs" || exit
forensics_require backend || exit
forensics_require absent && exit 80
forensics_skip optional unavailable
forensics_finish
''', env)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(self.manifest(root)['steps'][0]['state'], 'OMITIDO')

    def test_failed_skip_publication_cannot_leave_successful_finish(self):
        with sandbox() as root:
            result = self.run_shell(root, '''
forensics_begin strings offline "$ROOT/outputs" || exit
forensics_capture done printf okay || exit
forensics_complete_step done COMPLETADO checked || exit
forensics_skip done unavailable
forensics_finish
''')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('Error forense', result.stderr)
            self.assertEqual(self.manifest(root)['state'], 'FALLIDO')

    def test_explicitly_ignored_and_existing_traps_are_restored(self):
        for setup in ["trap '' INT TERM PIPE", "trap 'printf previous >&2' INT TERM PIPE"]:
            with self.subTest(setup=setup), sandbox() as root:
                result = self.run_shell(root, f'''
{setup}
before=$(trap -p INT TERM PIPE)
forensics_begin strings offline "$ROOT/outputs" || exit
forensics_capture good printf okay || exit
after=$(trap -p INT TERM PIPE)
test "$before" = "$after" || exit 81
forensics_complete_step good COMPLETADO checked || exit
forensics_finish
''')
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_json_parser_errors_are_not_swallowed(self):
        with sandbox() as root:
            result = self.run_shell(root, '''
_forensics_helper() { printf 'not-json'; }
forensics_begin strings offline "$ROOT/outputs"
''')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotEqual(result.stderr, '')

    def test_root_override_and_readonly_cli_do_not_create_bytecode(self):
        with sandbox() as root:
            env = self.environment(root)
            env['FORENSICS_ANALYSIS_ROOT'] = str(root / 'outputs')
            result = self.run_shell(root, '''
forensics_begin dependencies offline || exit
forensics_skip optional unavailable
forensics_finish
''', env)
            self.assertEqual(result.returncode, 1, result.stderr)
            run = next((root / 'outputs/runs').iterdir())
            code = RUNTIME.parent
            before_code, before_run = inventory(code), inventory(run)
            for command in ('validate', 'list'):
                flag = '--root' if command == 'list' else '--run'
                probe = subprocess.run([sys.executable, str(code / 'forensics_evidence.py'),
                                        command, flag, str(run)], env=env, capture_output=True)
                self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertEqual(inventory(code), before_code)
            self.assertEqual(inventory(run), before_run)

    def test_signals_preserve_partial_streams_and_unrelated_process(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig), sandbox() as root:
                env = self.environment(root)
                unrelated = subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(30)'])
                child = subprocess.Popen(['/bin/bash', '-c', '''
source "$RUNTIME" || exit 90
trap 'printf prior > "$ROOT/prior"' INT TERM
forensics_begin strings offline "$ROOT/outputs" || exit
long() { trap '' TERM; python3 -B -c 'import os,time; from pathlib import Path; print("partial",flush=True); print("error",file=__import__("sys").stderr,flush=True); Path(os.environ["ROOT"]+"/ready").write_text(str(os.getpid())); time.sleep(30)'; }
forensics_capture interrupted long
forensics_finish
'''], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 8
                    while not (root / 'ready').exists() and child.poll() is None and time.monotonic() < deadline:
                        time.sleep(.02)
                    self.assertTrue((root / 'ready').exists(), child.communicate(timeout=1) if child.poll() is not None else 'not ready')
                    child.send_signal(sig)
                    stdout, stderr = child.communicate(timeout=8)
                    self.assertEqual(child.returncode, 1, stderr)
                    self.assertEqual(stdout, '')
                    data = self.manifest(root)
                    self.assertEqual(data['state'], 'CANCELADO')
                    # The owned shell ignores TERM, so forced teardown really
                    # exits 137. Do not replace that observed rc with 128+sig.
                    self.assertEqual(data['steps'][0]['rc'], 137)
                    self.assertEqual(data['steps'][0]['signal'], sig)
                    run = next((root / 'outputs').iterdir())
                    self.assertIn('partial', (run / 'analysis/interrupted.stdout').read_text())
                    self.assertIn('error', (run / 'analysis/interrupted.stderr').read_text())
                    self.assertTrue((root / 'prior').exists())
                    self.assertIsNone(unrelated.poll())
                    pid = int((root / 'ready').read_text())
                    if Path(f'/proc/{pid}/stat').exists():
                        self.assertEqual(Path(f'/proc/{pid}/stat').read_text().split()[2], 'Z')
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.communicate()
                    unrelated.terminate()
                    unrelated.wait()


class CaptureApiTests(unittest.TestCase):
    def start(self, api, root):
        with contextlib.redirect_stderr(io.StringIO()):
            return api.start_run(root / 'outputs', 'strings', 'offline', [])

    def test_capture_receipt_cannot_be_replaced_or_completed_with_wrong_rc(self):
        with sandbox() as root:
            api = load_evidence()
            run = self.start(api, root)
            self.assertTrue(hasattr(api, 'prepare_capture'), 'capture API missing')
            streams = api.prepare_capture(run, 'bad', 'bash')
            self.assertEqual(api.finish_run(run)['rc'], 1)
            with self.assertRaises(ValueError):
                api.capture_result(run, 'bad', 7)
        with sandbox() as root:
            api = load_evidence()
            run = self.start(api, root)
            api.prepare_capture(run, 'bad', 'bash')
            with self.assertRaises(ValueError):
                api.complete_capture(run, 'bad', 'COMPLETADO', 'checked')
            api.capture_result(run, 'bad', 7)
            with self.assertRaises(ValueError):
                api.complete_capture(run, 'bad', 'COMPLETADO', 'checked')
            api.complete_capture(run, 'bad', 'FALLIDO', 'checked')
            with self.assertRaises(ValueError):
                api.complete_capture(run, 'bad', 'FALLIDO', 'changed')
            with self.assertRaises(ValueError):
                api.capture_result(run, 'bad', 0)
            self.assertEqual(api.read_run(run)['steps'][0]['rc'], 7)

    def test_sealed_capture_checks_signal_rc_and_stream_integrity(self):
        with sandbox() as root:
            api = load_evidence()
            run = self.start(api, root)
            streams = api.prepare_capture(run, 'one', 'bash')
            with self.assertRaises(ValueError):
                api.capture_result(run, 'one', 0, signal=15)
            api.capture_result(run, 'one', 7)
            with self.assertRaises(ValueError):
                api.capture_result(run, 'one', 0)
            Path(streams['stdout']).write_text('altered')
            with self.assertRaises(ValueError):
                api.complete_capture(run, 'one', 'FALLIDO', 'checked')

    def test_all_staging_precedes_captures_and_each_run_is_independent(self):
        with sandbox() as root:
            api = load_evidence()
            source = root / 'sources/input'
            source.write_text('synthetic')
            run = self.start(api, root)
            first = api.stage_input(run, source)
            api.prepare_capture(run, 'one', 'bash')
            with self.assertRaises(ValueError):
                api.stage_input(run, source)
            second_run = self.start(api, root)
            second = api.stage_input(second_run, source)
            self.assertNotEqual(first['work_path'], second['work_path'])

    def test_pending_receipt_cannot_claim_completed_in_metadata(self):
        with sandbox() as root:
            api = load_evidence()
            run = self.start(api, root)
            api.prepare_capture(run, 'one', 'bash')
            data = json.loads((run / 'run.json').read_text())
            step = data['steps'][0]
            step['state'] = 'COMPLETADO'
            step['coverage']['complete'] = True
            (run / 'steps/0000-one.json').write_text(json.dumps(step))
            (run / 'run.json').write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                api.read_run(run)
            with self.assertRaises(ValueError):
                api.finish_run(run)

    def test_cancellation_after_command_exit_keeps_zero_rc_without_fake_signal(self):
        with sandbox() as root:
            api = load_evidence()
            run = self.start(api, root)
            api.prepare_capture(run, 'one', 'bash')
            step = api.capture_result(run, 'one', 0, cancelled=True)
            self.assertEqual(step['rc'], 0)
            self.assertIsNone(step['signal'])
            self.assertEqual(api.finish_run(run)['state'], 'CANCELADO')

    def test_group_teardown_precedes_anchor_reap_no_signal_after_release(self):
        api = load_evidence()
        self.assertTrue(hasattr(api, '_OwnedProcessGroup'), 'owned anchor protocol missing')
        events = []
        anchor, unrelated = 43210, 54321
        released = False

        def kill_group(pid, sig):
            self.assertFalse(released, 'signalling after ownership release')
            self.assertEqual(pid, anchor)
            self.assertNotEqual(pid, unrelated)
            events.append(('signal', pid, sig))

        def reap(pid, flags):
            nonlocal released
            self.assertTrue(events and events[-1][0] == 'signal')
            self.assertEqual((pid, flags), (anchor, 0))
            events.append(('reap', pid))
            released = True
            return pid, 9

        with patch.object(api.os, 'fork', return_value=anchor), \
             patch.object(api.os, 'setpgid') as grouping, \
             patch.object(api.os, 'killpg', side_effect=kill_group), \
             patch.object(api.os, 'waitpid', side_effect=reap):
            group = api._OwnedProcessGroup()
            grouping.assert_called_once_with(anchor, anchor)
            group.stop()
            group.close()
            before = list(events)
            group.stop()
            group.close()
            self.assertEqual(events, before)
        self.assertEqual(events[-1], ('reap', anchor))

    def test_supervisor_private_protocol_is_not_backend_stdin_and_repeated_cancel(self):
        with sandbox() as root:
            api = load_evidence()
            run = self.start(api, root)
            streams = api.prepare_capture(run, 'job', 'python3')
            env = runtime_environment(root)
            script = ('import os,signal,sys,time; from pathlib import Path; '
                      'assert sys.stdin.read()==""; '
                      'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                      'print("partial",flush=True); print("error",file=sys.stderr,flush=True); '
                      'Path(os.environ["ROOT"]+"/ready").write_text("ready"); time.sleep(30)')
            worker = subprocess.Popen(
                [sys.executable, '-B', str(RUNTIME.with_name('forensics_evidence.py')),
                 'supervise', '--run', str(run), '--name', 'job', '--tool', 'python3',
                 '--', '-B', '-c', script], env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(worker.stdout.readline(), 'READY\n')
                worker.stdin.write('GO\n')
                worker.stdin.flush()
                deadline = time.monotonic() + 3
                while not (root / 'ready').exists() and worker.poll() is None and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue((root / 'ready').exists(), 'backend stdin is not isolated from control pipe')
                worker.stdin.write('CANCEL 2\nCANCEL 15\n')
                worker.stdin.flush()
                import select
                self.assertTrue(select.select([worker.stdout], [], [], 5)[0], 'cancel did not complete')
                line = worker.stdout.readline()
                self.assertTrue(line.startswith('RESULT '), line)
                result = json.loads(line.removeprefix('RESULT '))
                self.assertEqual(result, dict(rc=137, terminating_signal=9,
                                             cancellation_wrapper_signal=2, started=True,
                                             worker_created=True))
                worker.stdin.write('RELEASE\n')
                worker.stdin.flush()
                stdout, stderr = worker.communicate(timeout=5)
                self.assertEqual((worker.returncode, stdout, stderr), (0, '', ''))
                step = api.capture_result(run, 'job', result['rc'], signal=2, cancelled=True)
                self.assertEqual(step['rc'], 137)
                self.assertEqual(api.finish_run(run)['state'], 'CANCELADO')
                self.assertEqual(Path(streams['stdout']).read_text(), 'partial\n')
                self.assertEqual(Path(streams['stderr']).read_text(), 'error\n')
            finally:
                if worker.poll() is None:
                    worker.stdin.close()  # EOF forces owned group teardown
                    worker.stdin = None
                worker.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
