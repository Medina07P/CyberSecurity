"""Task2 contracts, written before implementation. NOT RUN before static gate.

No fixtures, old suites, cleanup hooks or host syscalls for BPF installation.
"""
import ast
from contextlib import ExitStack
import errno
from pathlib import Path
import struct
import unittest
from unittest import mock

from automation_sandbox_prepare import IsolationBlocked, PreparedRun, RuntimeFile
import automation_sandbox_policy as policy
import automation_sandbox_launch as launcher
import automation_sandbox_inside as inside
from automation_sandbox_inside import inside_main


def evaluate_bpf(program, number, arch):
    """Interpret exactly our cBPF subset as data; decode ERRNO decisions."""
    instructions = list(struct.iter_unpack('<HBBI', program))
    accumulator, pc = 0, 0
    for _ in range(len(instructions) + 1):
        code, yes, no, value = instructions[pc]
        pc += 1
        if code == 0x20:
            accumulator = {0: number, 4: arch}[value]
        elif code == 0x15:
            pc += yes if accumulator == value else no
        elif code == 0x45:
            pc += yes if accumulator & value else no
        elif code == 0x06:
            return value & 0xffff if value & 0xffff0000 == 0x00050000 else value
        else:
            raise AssertionError('Unexpected BPF opcode')
    raise AssertionError('BPF did not return')


def prepared():
    root = Path('/tmp/opencode/automation-isolated-' + 'a' * 32)
    entries = tuple(RuntimeFile(root / 'runtime' / name.lstrip('/'), name, 'elf')
                    for name in ('/usr/bin/python3', '/bin/bash',
                                 '/lib64/ld-linux-x86-64.so.2'))
    return PreparedRun(root, root / 'source', root / 'runtime', root / 'work',
                       root / 'evidence', entries)


class SandboxPolicyTests(unittest.TestCase):
    def test_host_identity_canary_rejects_alias_races_and_wrong_composition(self):
        host = {'dev': 11, 'ino': 22, 'mode': 0o100400, 'size': 52,
                'uid': 1000, 'gid': 1000, 'nlink': 1, 'mtime_ns': 5, 'ctime_ns': 6}
        record = {'uid': 1234, 'euid': 1234, 'uid_map': [[1234, 0, 1]],
                  'uid_map_scope': 'immediate-parent-user-namespace',
                  'identity_canary': {'host': host, 'inside': dict(host, uid=1234, gid=1234)}}
        with mock.patch.object(launcher, '_canary_metadata', return_value=host), \
                mock.patch.object(launcher.os, 'getuid', return_value=1000), \
                mock.patch.object(launcher.os, 'fstat') as pinned, \
                mock.patch.object(launcher, '_named_canary_metadata', return_value=host) as named:
            launcher._validate_identity_canary(Path('/synthetic'), 42, host, record)
        pinned.assert_called_once_with(42)
        named.assert_called_once_with(Path('/synthetic'))
        for changed in (dict(host, ino=23), dict(host, uid=0), dict(host, ctime_ns=7)):
            for pinned_value, named_value in ((host, changed), (changed, host)):
                with mock.patch.object(launcher, '_canary_metadata', return_value=pinned_value), \
                        mock.patch.object(launcher, '_named_canary_metadata', return_value=named_value), \
                        mock.patch.object(launcher.os, 'fstat'):
                    with self.assertRaises(IsolationBlocked):
                        launcher._validate_identity_canary(Path('/synthetic'), 42, host, record)
        for bad in (dict(record, uid_map_scope='host'),
                    dict(record, identity_canary={'host': host, 'inside': dict(host, uid=0)}),
                    dict(record, uid_map=[[1234, 0, 65536]])):
            with mock.patch.object(launcher, '_canary_metadata', return_value=host), \
                    mock.patch.object(launcher.os, 'getuid', return_value=1000), \
                    mock.patch.object(launcher.os, 'fstat'), \
                    mock.patch.object(launcher, '_named_canary_metadata', return_value=host):
                with self.assertRaises(IsolationBlocked):
                    launcher._validate_identity_canary(Path('/synthetic'), 42, host, bad)

    def test_host_rejects_repaired_descendant_and_incomplete_cancel_evidence(self):
        baseline = {'soft': 256, 'hard': 256, 'uid': 1000, 'euid': 1000,
                    'uid_map': [[1000, 1000, 1]], 'user_namespace': 'user:[private]',
                    'uid_map_scope': 'immediate-parent-user-namespace', 'identity_canary': {},
                    'capabilities': dict.fromkeys(('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'), 0),
                    'observed_uid_tasks': 3, 'counter_scope': 'private-proc-visible-real-uid-threads'}
        good = dict(baseline, inherited_soft_hard=[256, 256])
        launcher._validate_descendant_nproc(good, baseline)
        for bad in (dict(good, inherited_soft_hard=[4096, 8192]),
                    {k: v for k, v in good.items() if k != 'inherited_soft_hard'},
                    dict(good, uid=0)):
            with self.assertRaises(IsolationBlocked):
                launcher._validate_descendant_nproc(bad, baseline)
        observed = dict(good, entry=good)
        probes = {'descendants': [{'role': role, 'nproc': observed} for role in
                                 ('python-child', 'bash-grandchild', 'bash-child')],
                  'cancel': {'worker_nproc': observed, 'fork_nproc': good,
                             'descendant_reaped': True, 'direct_child_reaped': True}}
        launcher._validate_probe_nproc(probes, baseline)
        repaired_entry = dict(observed, entry=dict(good, inherited_soft_hard=[4096, 8192]))
        with self.assertRaises(IsolationBlocked):
            launcher._validate_probe_nproc(dict(probes, descendants=[
                dict(row, nproc=repaired_entry) for row in probes['descendants']]), baseline)
        for bad_cancel in ({'descendant_reaped': True, 'direct_child_reaped': True},
                           dict(probes['cancel'], fork_nproc=dict(good, inherited_soft_hard=[4096, 8192]))):
            with self.assertRaises(IsolationBlocked):
                launcher._validate_probe_nproc(dict(probes, cancel=bad_cancel), baseline)

    def test_bootstrap_inherits_nproc_without_setting_or_raising(self):
        self.assertNotIn(launcher.resource.RLIMIT_NPROC,
                         [kind for kind, _ in launcher.LIMITS])
        text = Path(launcher.__file__).read_text()
        self.assertIn('resource.getrlimit(resource.RLIMIT_NPROC) != inherited_nproc', text)
        with mock.patch.object(launcher.resource, 'getrlimit', return_value=(4096, 8192)), \
                mock.patch.object(launcher, '_host_uid_tasks', return_value=330), \
                mock.patch.object(launcher.os, 'readlink', return_value='user:[host]'), \
                mock.patch.object(launcher.os, 'getuid', return_value=1000), \
                mock.patch.object(launcher.os, 'geteuid', return_value=1000):
            result = launcher._bootstrap_nproc()
        self.assertEqual((result['soft'], result['hard']), (4096, 8192))
        self.assertEqual(result['observed_uid_tasks'], 330)
        self.assertEqual(result['workload_soft_hard'], [256, 256])

    def test_host_consumption_counts_uid_threads_not_processes(self):
        statuses = [mock.mock_open(read_data='Uid:\t1000 1000 1000 1000\nThreads:\t300\n').return_value,
                    mock.mock_open(read_data='Uid:\t1000 1000 1000 1000\nThreads:\t30\n').return_value]
        with mock.patch.object(launcher.os, 'listdir', return_value=['101', '102']), \
                mock.patch('builtins.open', side_effect=statuses):
            self.assertEqual(launcher._host_uid_tasks(1000), 330)
        with mock.patch.object(launcher.os, 'listdir', return_value=['101']), \
                mock.patch('builtins.open', side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError):
                launcher._host_uid_tasks(1000)

    def test_isolated_script_bootstrap_precedes_all_local_imports(self):
        # Inspect the actual -I entry script as data; never start a host Python.
        tree = ast.parse(Path(launcher.__file__).read_text())
        bootstrap = next(n for n in tree.body if isinstance(n, ast.Expr)
                         and isinstance(n.value, ast.Call)
                         and ast.unparse(n.value.func) == 'sys.path.insert')
        self.assertEqual(ast.unparse(bootstrap),
                         'sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent))')
        local = [n for n in tree.body if isinstance(n, ast.ImportFrom)
                 and n.module.startswith('automation_sandbox_')]
        self.assertEqual({n.module for n in local},
                         {'automation_sandbox_prepare', 'automation_sandbox_policy'})
        self.assertTrue(all(bootstrap.lineno < n.lineno for n in local))
        text = Path(launcher.__file__).read_text()
        self.assertNotIn('site.addsitedir', text)
        self.assertNotIn('PYTHONPATH', text)

    def test_no_host_mounts(self):
        run = prepared()
        argv = policy.bubblewrap_argv(run, 9)
        for flag in ('--unshare-all', '--new-session', '--die-with-parent', '--clearenv'):
            self.assertIn(flag, argv)
        for flag in ('--share-net', '--unshare-user-try', '--dev-bind'):
            self.assertNotIn(flag, argv)
        mounts = [(argv[i + 1], argv[i + 2]) for i, value in enumerate(argv)
                  if value in ('--ro-bind', '--bind')]
        self.assertEqual(set(mounts), {
            (str(run.runtime_root / 'usr'), '/usr'),
            (str(run.runtime_root / 'bin'), '/bin'),
            (str(run.runtime_root / 'lib64'), '/lib64'),
            (str(run.source_root), '/source'),
            (str(run.work), '/work'), (str(run.evidence), '/evidence')})
        self.assertEqual(argv[-4:], ('/usr/bin/python3', '-I', '-B', policy.INSIDE))

    def test_bpf_blocks_network_and_x32(self):
        program = policy.seccomp_program()
        self.assertEqual(len(program) % 8, 0)
        for number in (41, 53, 425, 426, 427, 0x40000000, 0x40000029):
            self.assertEqual(evaluate_bpf(program, number, 0xc000003e), errno.EPERM)
        for number in (0, 1, 59, 257):
            self.assertEqual(evaluate_bpf(program, number, 0xc000003e), 0x7fff0000)
        self.assertEqual(evaluate_bpf(program, 1, 0x40000003), 0x80000000)

    def test_missing_prerequisite_stops_before_payload(self):
        with mock.patch.object(launcher, '_open_bwrap',
                               side_effect=IsolationBlocked('missing')) as prerequisite, \
                mock.patch.object(launcher, 'REPO', Path('/unit-test-checkout')), \
                mock.patch.object(launcher, '_validate_limits'), \
                mock.patch.object(launcher, 'prepare') as stage, \
                mock.patch.object(launcher, '_fork_child') as payload, \
                mock.patch.object(launcher.signal, 'getitimer', return_value=(0, 0)), \
                mock.patch.object(launcher.signal, 'getsignal', return_value=launcher.signal.SIG_DFL), \
                mock.patch.object(launcher.signal, 'setitimer'), \
                mock.patch.object(launcher.signal, 'sigtimedwait'), \
                mock.patch.object(launcher.signal, 'pthread_sigmask', return_value=set()), \
                mock.patch.object(launcher.signal, 'signal', return_value=launcher.signal.SIG_DFL), \
                mock.patch.object(launcher.sys, 'argv', ['launcher']):
            self.assertEqual(launcher.launch(), 2)
        prerequisite.assert_called_once_with()
        stage.assert_not_called()
        payload.assert_not_called()

    def test_environment_and_fd_closure(self):
        self.assertEqual(policy.ENVIRONMENT, {
            'PATH': '/usr/bin:/bin', 'HOME': '/work/home',
            'TMPDIR': '/work/tmp', 'LANG': 'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1'})
        tree = ast.parse(Path(launcher.__file__).read_text())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == 'execve']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0]), 'os.execve(bwrap_fd, argv, {})')
        text = Path(launcher.__file__).read_text()
        self.assertIn("os.listdir('/proc/self/fd')", text)
        self.assertIn('number not in (0, 1, 2, bwrap_fd, seccomp_fd)', text)
        self.assertIn('os.set_inheritable(bwrap_fd, False)', text)
        self.assertIn('os.set_inheritable(seccomp_fd, True)', text)
        self.assertIn("os.open('/dev/null'", text)

    def test_deadline_and_cancel_interrupt_prepare_validation_and_startup(self):
        # Deterministic signal callbacks only: no real timer/fork/fs/process.
        for phase in ('prepare', '_validate_staging', 'before_fork', 'startup'):
            for number in (launcher.signal.SIGALRM, launcher.signal.SIGINT,
                           launcher.signal.SIGTERM):
                with self.subTest(phase=phase, number=number), ExitStack() as stack:
                    handlers = {}
                    def install(signum, callback):
                        handlers[signum] = callback
                        return launcher.signal.SIG_DFL
                    timer = stack.enter_context(mock.patch.object(
                        launcher.signal, 'setitimer'))
                    stack.enter_context(mock.patch.object(launcher.signal, 'getitimer',
                                                         return_value=(0, 0)))
                    stack.enter_context(mock.patch.object(launcher.signal, 'getsignal',
                                                         return_value=launcher.signal.SIG_DFL))
                    stack.enter_context(mock.patch.object(launcher.signal, 'pthread_sigmask',
                                                         return_value=set()))
                    stack.enter_context(mock.patch.object(launcher.signal, 'sigtimedwait'))
                    stack.enter_context(mock.patch.object(launcher.signal, 'signal',
                                                         side_effect=install))
                    stack.enter_context(mock.patch.object(launcher, 'REPO', Path('/unit')))
                    stack.enter_context(mock.patch.object(launcher.sys, 'argv', ['launcher']))
                    stack.enter_context(mock.patch.object(launcher, '_validate_limits'))
                    stack.enter_context(mock.patch.object(launcher, '_open_bwrap',
                                                         return_value=(10, {})))
                    stack.enter_context(mock.patch.object(launcher.os, 'close'))
                    stack.enter_context(mock.patch.object(Path, 'mkdir'))
                    stack.enter_context(mock.patch.object(launcher, '_seccomp_memfd',
                                                         return_value=11))
                    stack.enter_context(mock.patch.object(launcher, '_new_log', return_value=12))
                    stack.enter_context(mock.patch.object(launcher, '_new_json'))
                    stack.enter_context(mock.patch.object(launcher, '_probe_inputs'))
                    stack.enter_context(mock.patch.object(launcher, '_create_identity_canary',
                                                         return_value=(14, 15, {})))
                    stage = stack.enter_context(mock.patch.object(launcher, 'prepare',
                                                                 return_value=prepared()))
                    validate = stack.enter_context(mock.patch.object(launcher, '_validate_staging'))
                    def interrupted(*args):
                        self.assertIn(number, handlers)
                        self.assertTrue(timer.called)  # armed before work begins
                        self.assertGreater(timer.call_args.args[1], 0)
                        handlers[number](number, None)
                        self.fail('interruptible host work must not continue')
                    def started(child, *args):
                        child.pid = 123  # only a double, never a live host PID
                    spawn = stack.enter_context(mock.patch.object(launcher, '_fork_child',
                                                                 side_effect=started))
                    pin = stack.enter_context(mock.patch.object(launcher.os, 'pidfd_open',
                                                               side_effect=interrupted))
                    expected = ((1 if phase == 'startup' else 2)
                                if number == launcher.signal.SIGALRM else 128 + number)
                    supervise = stack.enter_context(mock.patch.object(launcher, '_supervise',
                                                                      return_value=(expected, 'STOP')))
                    stack.enter_context(mock.patch.object(launcher._Child, 'poll', return_value=0))
                    if phase == 'prepare':
                        stage.side_effect = interrupted
                    elif phase == '_validate_staging':
                        validate.side_effect = interrupted
                    elif phase == 'before_fork':
                        spawn.side_effect = interrupted
                    self.assertEqual(launcher.launch(), expected)
                    if phase in ('prepare', '_validate_staging'):
                        spawn.assert_not_called()
                        pin.assert_not_called()
                    elif phase == 'before_fork':
                        pin.assert_not_called()
                        supervise.assert_not_called()
                    else:
                        spawn.assert_called_once()
                        supervise.assert_called_once()

    def test_startup_returns_child_without_waiting_for_preexec(self):
        child = launcher._Child()
        with mock.patch.object(launcher.os, 'fork', return_value=123), \
                mock.patch.object(launcher.signal, 'pthread_sigmask', return_value=set()), \
                mock.patch.object(launcher.os, 'execve') as execute:
            launcher._fork_child(child, ('/usr/bin/bwrap',), 10, 11, 12, 13)
        self.assertEqual(child.pid, 123)
        execute.assert_not_called()

    def test_startup_before_pidfd_uses_only_owned_unreaped_child(self):
        child = mock.Mock()
        child.wait.side_effect = [launcher.subprocess.TimeoutExpired('startup', 0.1), -15]
        with mock.patch.object(launcher.time, 'monotonic', side_effect=[0, 1]), \
                mock.patch.object(launcher.signal, 'pidfd_send_signal') as send:
            self.assertEqual(launcher._supervise(child, None, [15]), (143, 'SIGNAL'))
        child.send_signal.assert_called_once_with(15)
        send.assert_not_called()

    def test_rejects_unstaged_runtime_and_reused_layout(self):
        run = prepared()
        bad = PreparedRun(run.root, run.source_root, run.runtime_root, run.work,
                          run.evidence, (RuntimeFile(Path('/usr/bin/bash'),
                                                    '/bin/bash', 'elf'),))
        with self.assertRaises(IsolationBlocked):
            policy.bubblewrap_argv(bad, 9)
        with self.assertRaises(IsolationBlocked):
            policy.bubblewrap_argv(run, 1)

    def test_selectors_are_closed_and_inside_cannot_launch(self):
        for selector in ('--probes', '--suite', '--races', '--cross-consent', '--cross-web'):
            self.assertEqual(launcher._selector([selector]), selector)
        self.assertEqual(launcher._selector([]), '--suite')
        for args in (['bash'], ['--suite', 'id'], ['--unsafe'], ['--suite', '--races'],
                     ['--cross-local'], ['--cross-unknown'], ['--cross-consent', 'id'],
                     ['--cross-web', 'id'], ['--cross-web', '--cross-consent']):
            with self.assertRaises(IsolationBlocked):
                launcher._selector(args)
        with mock.patch.object(inside, '_context', side_effect=ValueError('not inside')), \
                mock.patch.object(inside, 'write_json'):
            self.assertEqual(inside_main(['--suite']), 2)

    def test_memfd_seals_and_limits_are_mandatory_in_source(self):
        text = Path(launcher.__file__).read_text()
        for required in ('F_SEAL_WRITE', 'F_SEAL_GROW', 'F_SEAL_SHRINK',
                         'F_SEAL_SEAL', 'F_GET_SEALS', 'RLIMIT_AS', 'RLIMIT_CPU',
                         'RLIMIT_NOFILE', 'RLIMIT_FSIZE', 'RLIMIT_NPROC',
                         'pidfd_send_signal', 'O_EXCL', 'O_NOFOLLOW'):
            self.assertIn(required, text)

    def test_insufficient_existing_limit_blocks_without_increasing(self):
        with mock.patch.object(launcher.resource, 'getrlimit', return_value=(1, 1)):
            with self.assertRaises(IsolationBlocked):
                launcher._validate_limits()

    def test_timeout_and_signal_only_target_pinned_child(self):
        child = mock.Mock()
        child.wait.side_effect = [launcher.subprocess.TimeoutExpired('bwrap', 0.1), -9]
        with mock.patch.object(launcher.time, 'monotonic', side_effect=[0, 901]), \
                mock.patch.object(launcher.signal, 'pidfd_send_signal') as send:
            self.assertEqual(launcher._supervise(child, 42, []), (1, 'TIMEOUT'))
        send.assert_called_once_with(42, launcher.signal.SIGTERM)
        child.wait.side_effect = [launcher.subprocess.TimeoutExpired('bwrap', 0.1), -15]
        with mock.patch.object(launcher.time, 'monotonic', side_effect=[0, 1]), \
                mock.patch.object(launcher.signal, 'pidfd_send_signal') as send:
            self.assertEqual(launcher._supervise(child, 42, [15]), (143, 'SIGNAL'))
        send.assert_called_once_with(42, 15)


if __name__ == '__main__':
    unittest.main()
