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
        for setup in ["trap '' INT TERM", "trap 'printf previous >&2' INT TERM"]:
            with self.subTest(setup=setup), sandbox() as root:
                result = self.run_shell(root, f'''
{setup}
before=$(trap -p INT TERM)
forensics_begin strings offline "$ROOT/outputs" || exit
forensics_capture good printf okay || exit
after=$(trap -p INT TERM)
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


if __name__ == '__main__':
    unittest.main()
