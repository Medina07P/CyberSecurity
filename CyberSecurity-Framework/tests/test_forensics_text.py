"""Task3 consumer contracts, exclusively synthetic inputs and closed PATH."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import unittest

from forensics_fixture import load_evidence, runtime_environment, sandbox

FRAMEWORK = Path(__file__).resolve().parents[1]
LEAVES = {'strings': 'memory/strings_analysis.sh', 'logs': 'logs/log_analyzer.sh',
          'timeline': 'timeline/timeline_creator.sh'}
SECRET = 'SYNTHETIC-password-token-SECRET'


class TextTests(unittest.TestCase):
    def setUp(self):
        self.ctx = sandbox()
        self.root = self.ctx.__enter__()
        self.addCleanup(self.ctx.__exit__, None, None, None)
        self.env = runtime_environment(self.root)
        self.framework = self.root / 'code'
        for relative in [*(Path('08_Forensics') / p for p in LEAVES.values()),
                         *(Path('00_Config/lib') / p for p in
                           ('forensics_evidence.py', 'forensics_runtime.bash', 'forensics_timeline.py'))]:
            src = FRAMEWORK / relative
            if src.exists():
                dst = self.framework / relative
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
        for name in ('dirname', 'wc', 'strings', 'mkdir', 'basename', 'cut'):
            p = self.root / 'bin' / name
            if p.exists():
                p.unlink()
            p.symlink_to('/usr/bin/' + name)
        self.stub('grep', '[[ ${@: -1} = "$ROOT"/* ]] || exit 98\nexec /usr/bin/grep "$@"')
        for name in ('last', 'find', 'head', 'tail', 'date'):
            self.stub(name, 'exit 98')
        self.env['FORENSICS_ANALYSIS_ROOT'] = str(self.root / 'outputs')
        self.source = self.root / 'sources' / 'input with spaces'
        self.source.write_text(SECRET + ' user@fixture.invalid https://fixture.invalid\n'
                               'ERROR sshd authentication 192.0.2.1\n')
        self.e = load_evidence()

    def stub(self, name, body):
        p = self.root / 'bin' / name
        if p.exists() or p.is_symlink():
            p.unlink()
        p.write_text('#!/bin/bash\n' + body + '\n')
        p.chmod(0o700)

    def invoke(self, kind, *args, input=''):
        def sources():
            return {str(p.relative_to(self.root)): (p.lstat().st_mode,
                    os.readlink(p) if p.is_symlink() else
                    hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
                    for p in (self.root / 'sources').rglob('*')}
        before = sources()
        result = subprocess.run(['/bin/bash', str(self.framework / '08_Forensics' / LEAVES[kind]),
                                 *map(str, args)], env=self.env, input=input,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(sources(), before)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        return result

    def runs(self, root=None):
        return sorted((root or self.root / 'outputs').rglob('run.json'))

    def read(self, root=None):
        runs = self.runs(root)
        self.assertTrue(runs, 'no attributable private run')
        return self.e.read_run(runs[-1])

    def events(self, run):
        return [json.loads(line) for line in
                (Path(run['artifact_roots']['analysis']) / 'events.jsonl').read_text().splitlines()]

    def test_strings_private_filters_independent_runs_and_duplicate_basename(self):
        for _ in range(2):
            result = self.invoke('strings', self.source)
            self.assertEqual(result.returncode, 0, result.stderr)
        other = self.source.parent / 'other'
        other.mkdir()
        duplicate = other / self.source.name
        duplicate.write_text('other nonsecret string\n')
        self.assertEqual(self.invoke('strings', duplicate).returncode, 0)
        self.assertEqual(len(self.runs()), 3)
        copies = []
        for path in self.runs():
            run = self.e.read_run(path)
            copies.append(run['inputs'][0]['work_path'])
            self.assertEqual(run['state'], 'COMPLETADO')
            for product in path.parent.rglob('*'):
                self.assertEqual(product.stat().st_mode & 0o777, 0o700 if product.is_dir() else 0o600)
        self.assertEqual(len(set(copies)), 3)
        contents = '\n'.join(p.read_text() for p in (self.runs()[0].parent / 'analysis').glob('*.stdout'))
        self.assertTrue(contents)

    def test_empty_and_no_hits_are_complete_for_both_analyzers(self):
        for content in ('', 'unremarkable alphabetic text\n'):
            self.source.write_text(content)
            for kind in ('strings', 'logs'):
                with self.subTest(content=content, kind=kind):
                    result = self.invoke(kind, self.source)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.read()['rc'], 0)

    def test_log_filters_preserved_and_counted_without_console_bodies(self):
        self.assertEqual(self.invoke('logs', self.source).returncode, 0)
        run = self.read()
        analysis = Path(run['artifact_roots']['analysis'])
        self.assertIn('ERROR sshd', (analysis / 'levels.stdout').read_text())
        self.assertIn('192.0.2.1', (analysis / 'ips.stdout').read_text())
        self.assertIn(SECRET, (analysis / 'auth.stdout').read_text())
        counts = json.loads((analysis / 'summary.stdout').read_text())
        self.assertEqual(counts['counts']['errors'], 1)
        self.assertEqual(counts['counts']['lines'], 2)

    def test_tool_failure_and_grep_error_not_empty_success(self):
        for tool, kind, rc in (('strings', 'strings', 7), ('grep', 'logs', 2)):
            with self.subTest(tool=tool):
                self.stub(tool, f'printf "{SECRET}" >&2; exit {rc}')
                result = self.invoke(kind, self.source)
                self.assertEqual(result.returncode, 1)
                runs = [self.e.read_run(p) for p in self.runs()]
                failed = [r for r in runs if r['state'] == 'FALLIDO']
                self.assertTrue(failed)
                self.assertTrue(any(s['rc'] == rc for r in failed for s in r['steps']))

    def test_invalid_file_precondition_no_run(self):
        for kind in ('strings', 'logs'):
            self.assertEqual(self.invoke(kind, self.source.parent / 'missing').returncode, 2)
        self.assertEqual(self.runs(), [])

    def test_timeline_no_sources_and_local_eof_do_not_query_host(self):
        self.assertEqual(self.invoke('timeline').returncode, 2)
        self.assertEqual(self.invoke('timeline', '--local').returncode, 2)
        self.assertEqual(self.runs(), [])

    def test_timeline_mixed_sources_utc_unresolved_and_original_tree_time(self):
        journal = self.root / 'sources' / 'journal'
        journal.write_text(json.dumps({'__REALTIME_TIMESTAMP': '946684800000000', 'MESSAGE': SECRET}) + '\n')
        auth = self.root / 'sources' / 'auth'
        auth.write_text('Jan  1 01:00:00 host sshd ' + SECRET + '\nnot a dated line\n')
        dpkg = self.root / 'sources' / 'dpkg'
        dpkg.write_text('2000-01-01 01:00:00 install synthetic\n')
        tree = self.root / 'sources' / 'tree'
        tree.mkdir()
        leaf = tree / 'old'
        leaf.write_text('synthetic')
        os.utime(leaf, ns=(946684800000000000, 946684800000000000))
        external = self.root / 'external output'
        result = self.invoke('timeline', external, '--journal', journal, '--auth', auth,
                             '--dpkg', dpkg, '--tree', tree, '--year', '2000', '--timezone', 'Europe/Madrid')
        self.assertEqual(result.returncode, 0, result.stderr)
        run = self.read(external)
        events = self.events(run)
        resolved = [e for e in events if e['timestamp_utc'] == '2000-01-01T00:00:00Z']
        self.assertEqual({e['source_type'] for e in resolved}, {'journal', 'auth', 'dpkg', 'tree'})
        self.assertTrue(any(e['section'] == 'unresolved' for e in events))
        self.assertTrue(all(e['origin'] for e in events))
        self.assertTrue(any(e['category'] == 'archivos_modificados' for e in events))
        self.assertEqual(external.stat().st_mode & 0o777, 0o700)

    def test_timeline_without_year_zone_does_not_guess(self):
        self.source.write_text('Jan  1 01:00:00 host sshd synthetic\n')
        result = self.invoke('timeline', '--auth', self.source)
        self.assertEqual(result.returncode, 0, result.stderr)
        event = self.events(self.read())[0]
        self.assertIsNone(event['timestamp_utc'])
        self.assertEqual(event['section'], 'unresolved')

    def test_timeline_wtmp_explicit_archive_and_source_failure_partial(self):
        self.stub('last', '[[ $1 = -f && $2 = "$ROOT"/*/work/* ]] || exit 97\nprintf "user pts/0 host Sat Jan  1 00:00:00 2000 synthetic\\n"')
        result = self.invoke('timeline', '--wtmp', self.source, '--timezone', 'UTC')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.events(self.read()))
        self.source.write_text('bad JSON\n')
        other = self.source.parent / 'valid auth'
        other.write_text('Jan  1 00:00:00 host synthetic\n')
        result = self.invoke('timeline', '--journal', self.source, '--auth', other)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any(self.e.read_run(p)['state'] == 'PARCIAL' for p in self.runs()))

    def test_tree_symlink_outside_rejected_without_target_read(self):
        tree = self.source.parent / 'links'
        tree.mkdir()
        (tree / 'escape').symlink_to(self.root / 'never-readable-target')
        self.assertNotEqual(self.invoke('timeline', '--tree', tree).returncode, 0)
        self.assertFalse(any(self.e.read_run(p)['complete'] for p in self.runs()))

    def test_local_requires_confirmation_and_remains_fragmentary(self):
        self.stub('journalctl', 'printf \'{"__REALTIME_TIMESTAMP":"946684800000000","MESSAGE":"synthetic"}\\n\'')
        self.stub('last', 'printf "synthetic session\\n"')
        self.stub('find', '[[ $1 = / ]] || exit 97; printf "946684800.000000000 /synthetic\\n"')
        # Local log requests are synthetic stubs too, never host-file reads.
        self.stub('grep', 'printf "Jan  1 00:00:00 synthetic sshd install\\n"')
        result = self.invoke('timeline', '--local', input='LOCAL_SI\n')
        self.assertEqual(result.returncode, 1, result.stderr)
        run = self.read()
        self.assertEqual(run['mode'], 'local')
        self.assertEqual(run['state'], 'PARCIAL')
        self.assertFalse(run['complete'])
        self.assertTrue(self.events(run))

    def test_local_historical_output_limits_are_not_total_coverage(self):
        self.stub('journalctl', '[[ $1 = --since && $2 = "24 hours ago" && $3 = -o && $4 = json ]] || exit 97\nfor ((i=0;i<105;i++)); do printf \'{"__REALTIME_TIMESTAMP":"946684800000000","MESSAGE":"synthetic"}\\n\'; done')
        self.stub('last', '[[ $# = 1 && $1 = -a ]] || exit 97\nfor ((i=0;i<25;i++)); do printf "synthetic session\\n"; done')
        self.stub('find', '[[ $1 = / && $2 = -type && $3 = f && $4 = -mtime && $5 = -1 && $6 = -printf ]] || exit 97\nfor ((i=0;i<25;i++)); do printf "946684800.000000000 /synthetic\\n"; done')
        self.stub('grep', '[[ $1 = sshd && $2 = /var/log/auth.log || $1 = install && $2 = /var/log/dpkg.log ]] || exit 97\nfor ((i=0;i<25;i++)); do printf "Jan  1 00:00:00 synthetic sshd install\\n"; done')
        self.assertEqual(self.invoke('timeline', '--local', input='LOCAL_SI\n').returncode, 1)
        counts = {}
        for event in self.events(self.read()):
            counts[event['source_type']] = counts.get(event['source_type'], 0) + 1
        self.assertEqual(counts, {'journal': 100, 'wtmp': 20, 'auth': 20, 'tree': 20, 'dpkg': 10})

    def test_tree_future_timestamp_not_replaced_with_current_copy_time(self):
        tree = self.source.parent / 'future'
        tree.mkdir()
        leaf = tree / 'future file'
        leaf.write_text('synthetic')
        os.utime(leaf, ns=(4102444800123456789, 4102444800123456789))
        self.assertEqual(self.invoke('timeline', '--tree', tree).returncode, 0)
        event = self.events(self.read())[0]
        self.assertEqual(event['timestamp_utc'], '2100-01-01T00:00:00.123456789Z')

    def test_ambiguous_and_nonexistent_wall_times_unresolved(self):
        self.source.write_text('2026-10-25 02:30:00 ambiguous\n2026-03-29 02:30:00 missing\n')
        self.assertEqual(self.invoke('timeline', '--auth', self.source, '--timezone', 'Europe/Madrid').returncode, 0)
        self.assertTrue(all(e['timestamp_utc'] is None for e in self.events(self.read())))

    def test_original_tree_mtime_change_during_work_blocks_success(self):
        tree = self.source.parent / 'tree'
        tree.mkdir()
        leaf = tree / 'old'
        leaf.write_text('synthetic')
        os.utime(leaf, ns=(946684800000000000, 946684800000000000))
        self.stub('last', 'python3 -B -c \'import os; p=os.environ["ROOT"]+"/sources/tree/old"; os.utime(p, ns=(946684800000000001,946684800000000001))\'\nprintf "synthetic\\n"')
        self.assertEqual(self.invoke('timeline', '--wtmp', self.source, '--tree', tree).returncode, 1)
        run = self.read()
        self.assertEqual(run['state'], 'FALLIDO')
        self.assertTrue(run['dependents_blocked'])
        self.assertEqual(leaf.stat().st_mtime_ns, 946684800000000001)

    def test_legacy_tree_metadata_stays_unresolved(self):
        # Historical run metadata lacks original mtime: do not consult either
        # source or work stat to manufacture a timestamp.
        tree = self.source.parent / 'tree'
        tree.mkdir()
        (tree / 'file').write_text('synthetic')
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            run = self.e.start_run(self.root / 'outputs', 'timeline', 'offline', [])
        item = self.e.stage_input(run, tree, 'tree')
        metadata = json.loads((run / 'run.json').read_text())
        for snapshot in ('original', 'work'):
            metadata['inputs'][0][snapshot].pop('temporal')
        (run / 'run.json').write_text(json.dumps(metadata))
        result = subprocess.run([sys.executable, '-B', str(self.framework / '00_Config/lib/forensics_timeline.py'),
                                 'source', '--run', str(run), '--kind', 'tree', '--work', item['work_path']],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        event = json.loads(result.stdout)
        self.assertEqual(event['section'], 'unresolved')
        self.assertEqual(event['reason'], 'original_mtime_not_observed')

    def test_existing_output_parent_preserved_and_overlap_rejected(self):
        parent = self.root / 'external'
        parent.mkdir(mode=0o750)
        (parent / 'keep').write_text('synthetic keep')
        self.assertEqual(self.invoke('timeline', parent, '--auth', self.source).returncode, 0)
        self.assertEqual(parent.stat().st_mode & 0o777, 0o750)
        self.assertEqual((parent / 'keep').read_text(), 'synthetic keep')
        self.assertNotEqual(self.invoke('timeline', self.source.parent, '--auth', self.source).returncode, 0)

    def test_missing_wtmp_backend_is_precondition_before_run(self):
        (self.root / 'bin' / 'last').unlink()
        self.assertEqual(self.invoke('timeline', '--wtmp', self.source).returncode, 2)
        self.assertEqual(self.runs(), [])

    def test_empty_journal_is_valid_and_corrupt_only_source_fails(self):
        self.source.write_text('')
        self.assertEqual(self.invoke('timeline', '--journal', self.source).returncode, 0)
        self.assertEqual(self.events(self.read()), [])
        self.source.write_text('not JSON\n')
        self.assertEqual(self.invoke('timeline', '--journal', self.source).returncode, 1)
        self.assertTrue(any(self.e.read_run(p)['state'] == 'FALLIDO' for p in self.runs()))

    def test_journal_control_data_stays_private_escaped_and_not_executed(self):
        self.source.write_text(json.dumps({'__REALTIME_TIMESTAMP': '946684800000000',
                                          'MESSAGE': SECRET + '\x1b[31m$(touch never)'}) + '\n')
        result = self.invoke('timeline', '--journal', self.source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('\x1b', result.stdout + result.stderr)
        run = self.read()
        self.assertIn('$(touch never)', self.events(run)[0]['body'])
        raw = (Path(run['artifact_roots']['analysis']) / 'events.jsonl').read_bytes()
        self.assertNotIn(b'\x1b', raw)

    def test_wtmp_display_timezone_matches_explicit_interpretation(self):
        self.stub('last', '[[ $1 = -f && $TZ = Europe/Madrid ]] || exit 97\nprintf "user pts/0 host Sat Jan  1 01:00:00 2000 synthetic\\n"')
        result = self.invoke('timeline', '--wtmp', self.source, '--timezone', 'Europe/Madrid')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(self.read())[0]['timestamp_utc'], '2000-01-01T00:00:00Z')

    def test_failed_wtmp_retains_partial_records_without_claiming_success(self):
        self.stub('last', 'printf "user pts/0 host Sat Jan  1 00:00:00 2000 partial\\n"\nprintf "synthetic error" >&2\nexit 7')
        result = self.invoke('timeline', '--wtmp', self.source, '--timezone', 'UTC')
        self.assertEqual(result.returncode, 1)
        run = self.read()
        self.assertEqual(run['state'], 'FALLIDO')
        self.assertEqual(run['steps'][0]['rc'], 7)
        self.assertIn('partial', self.events(run)[0]['body'])

    def test_relative_option_like_filename_is_data_for_all_three_leaves(self):
        source = self.root / 'sources' / '--synthetic-file'
        source.write_text('Jan  1 00:00:00 synthetic\n')
        before = source.read_bytes()
        for kind, args in (('strings', [source.name]), ('logs', [source.name]),
                           ('timeline', ['--auth', source.name])):
            with self.subTest(kind=kind):
                result = subprocess.run(['/bin/bash', str(self.framework / '08_Forensics' / LEAVES[kind]), *args],
                                        cwd=source.parent, env=self.env, input='', text=True,
                                        capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.read_bytes(), before)

    def test_resolved_order_preserves_original_nanosecond_precision(self):
        tree = self.source.parent / 'precise tree'
        tree.mkdir()
        for name, stamp in [('a', 946684800123456789), ('b', 946684800123456788)]:
            leaf = tree / name
            leaf.write_text('synthetic')
            os.utime(leaf, ns=(stamp, stamp))
        self.assertEqual(self.invoke('timeline', '--tree', tree).returncode, 0)
        self.assertEqual([e['body'] for e in self.events(self.read())], ['b', 'a'])


if __name__ == '__main__':
    unittest.main()
