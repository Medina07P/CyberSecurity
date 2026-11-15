"""Trusted probe-first entrypoint; Task4 selection changes NOT RUN.

Namespace observations corroborate the launch, not a host authorization token.
The independently reviewed host launcher is the only permitted entrypoint.
"""
from collections.abc import Sequence
import errno
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import socket
import subprocess
import sys
import time

SELF = '/source/CyberSecurity-Framework/tests/automation_sandbox_inside.py'
TESTS = '/source/CyberSecurity-Framework/tests'
NAMESPACES = ('mnt', 'pid', 'net', 'user', 'ipc', 'uts', 'cgroup')
_VALIDATED = False
_SELECTION = None
_NPROC_ENTRY = None


class NprocBlocked(ValueError):
    """Resource identity/accounting not established: never authorize workload."""


def _compose_identity(uid, euid, host_uid, mapping, host, local, current_ns, host_ns):
    """Map is parent-scoped, VFS translated ownership composes host identity."""
    keys = {'dev', 'ino', 'mode', 'size', 'uid', 'gid', 'nlink', 'mtime_ns', 'ctime_ns'}
    if (not isinstance(host, dict) or not isinstance(local, dict) or
            set(host) != keys or set(local) != keys or
            any(type(value) is not int for value in (*host.values(), *local.values())) or
            type(host_uid) is not int or host_uid <= 0 or uid <= 0 or uid != euid or
            not isinstance(mapping, list) or len(mapping) != 1 or
            not isinstance(mapping[0], list) or len(mapping[0]) != 3 or
            any(type(value) is not int for value in mapping[0]) or
            mapping[0][0] != uid or mapping[0][1] < 0 or mapping[0][2] != 1 or
            current_ns == host_ns or host['uid'] != host_uid or
            host['mode'] != (stat.S_IFREG | 0o400) or host['nlink'] != 1 or host['size'] <= 0 or
            local['uid'] != uid or
            any(local[key] != host[key] for key in
                ('dev', 'ino', 'mode', 'size', 'nlink', 'mtime_ns', 'ctime_ns'))):
        raise NprocBlocked('Synthetic canary VFS identity composition not established')
    return {'uid_map_scope': 'immediate-parent-user-namespace',
            'canary': {'host': host, 'inside': local}}


def _identity_canary():
    # Opening the newly created owner-read-only400 file is required as well as
    # stat equality; an unmapped owner's overflow UID must not masquerade as our
    # UID merely because translated numeric stat values coincide. No contents
    # are read, and the same gate separately requires all capabilities zero.
    path = '/work/identity-canary'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        def metadata(info):
            return {key: getattr(info, 'st_' + key) for key in
                    ('dev', 'ino', 'mode', 'size', 'uid', 'gid', 'nlink', 'mtime_ns', 'ctime_ns')}
        before = metadata(os.fstat(fd))
        if before != metadata(os.stat(path, follow_symlinks=False)):
            raise NprocBlocked('Identity canary named alias differs from pinned file')
        if before != metadata(os.fstat(fd)):
            raise NprocBlocked('Identity canary changed during observation')
        return before
    finally:
        os.close(fd)


def _nproc_observation():
    try:
        return _read_nproc_observation()
    except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
        raise NprocBlocked('NPROC identity/task metadata unavailable: ' + str(exc)) from exc


def _read_nproc_observation():
    """Effective limit/identity and visible local task metadata, not pids.max.

    No argv/environ/data reads. Require one nonroot UID mapping in a distinct
    user namespace and cap-free credentials; otherwise the scope is unproven.
    Visible Threads is a corroborating snapshot, not an exported kernel ucount
    or guarantee of256 free slots (ancestor/global limits still apply).
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    uid, euid = os.getuid(), os.geteuid()
    if (soft, hard) != (256, 256) or uid == 0 or uid != euid:
        raise NprocBlocked('Workload NPROC/identity not enforceable')
    context = read_json('/work/probe-context.json')
    host_uid = context.get('host_uid')
    mapping = [[int(part) for part in line.split()]
               for line in Path('/proc/self/uid_map').read_text().splitlines()]
    user_namespace = os.readlink('/proc/self/ns/user')
    if (type(host_uid) is not int or host_uid <= 0 or
            len(mapping) != 1 or len(mapping[0]) != 3 or
            mapping[0][0] != uid or mapping[0][1] < 0 or mapping[0][2] != 1 or
            user_namespace == context['host_namespaces']['user']):
        # Structural/namespace failure, before the additional VFS composition
        # proof. JSON escaping keeps own/synthetic diagnostics on one line.
        raise NprocBlocked('NPROC accounting identity/user namespace not demonstrable; '
                           'identity_metadata=' + json.dumps({
                               'uid': uid, 'euid': euid, 'host_uid': host_uid,
                               'uid_map': mapping, 'user_namespace': user_namespace,
                               'expected_user_namespace': context['host_namespaces']['user'],
                           }, sort_keys=True, ensure_ascii=True))
    proof = _compose_identity(uid, euid, host_uid, mapping,
                              context['identity_canary'], _identity_canary(),
                              user_namespace, context['host_namespaces']['user'])
    fields = {}
    with open('/proc/self/status', encoding='ascii') as status:
        for line in status:
            key, _, value = line.partition(':')
            if key in ('Uid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
                fields[key] = value.split()
    if (set(fields) != {'Uid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'} or
            any(len(value) != 1 for key, value in fields.items() if key != 'Uid')):
        raise NprocBlocked('Credential metadata unavailable')
    capabilities = {key: int(value[0], 16) for key, value in fields.items() if key != 'Uid'}
    if [int(part) for part in fields['Uid']] != [uid] * 4 or any(capabilities.values()):
        raise NprocBlocked('Workload identity privileged or capabilities present')
    total = 0
    for name in os.listdir('/proc'):
        if not name.isdecimal():
            continue
        try:
            metadata = {}
            with open('/proc/' + name + '/status', encoding='ascii') as status:
                for line in status:
                    key, _, value = line.partition(':')
                    if key in ('Uid', 'Threads'):
                        metadata[key] = [int(part) for part in value.split()]
        except FileNotFoundError:
            continue
        if (set(metadata) != {'Uid', 'Threads'} or len(metadata['Uid']) != 4 or
                len(metadata['Threads']) != 1 or metadata['Threads'][0] < 1):
            raise NprocBlocked('Local task counter unavailable')
        if metadata['Uid'][0] == uid:
            total += metadata['Threads'][0]
    if not 1 <= total < 256:
        raise NprocBlocked('Local UID task consumption unavailable or exhausted')
    return {'soft': soft, 'hard': hard, 'uid': uid, 'euid': euid,
            'uid_map': mapping, 'user_namespace': user_namespace,
            'uid_map_scope': proof['uid_map_scope'], 'identity_canary': proof['canary'],
            'capabilities': capabilities, 'observed_uid_tasks': total,
            'counter_scope': 'private-proc-visible-real-uid-threads'}


def _workload_nproc_gate():
    # Trusted stdlib only precedes this gate. Never raise an inherited ceiling.
    inherited = resource.getrlimit(resource.RLIMIT_NPROC)
    if any(value != resource.RLIM_INFINITY and value < 256 for value in inherited):
        raise NprocBlocked('Inherited ceiling insufficient for workload256')
    resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
    if resource.getrlimit(resource.RLIMIT_NPROC) != (256, 256):
        raise NprocBlocked('Workload NPROC readback differs from hard=soft256')
    result = _nproc_observation()
    result['inherited_soft_hard'] = list(inherited)
    return result


def _inherited_nproc_gate():
    """Descendants observe inheritance; NEVER repair it before evidence."""
    inherited = resource.getrlimit(resource.RLIMIT_NPROC)
    if inherited != (256, 256):
        # Preserve the rejected first readback even when stderr is captured or
        # DEVNULL (cancel worker). No repair or probe follows this receipt.
        write_json('/work/nproc-inheritance-blocked-' + str(os.getpid()) + '.json', {
            'inherited_soft_hard': list(inherited), 'pid': os.getpid(),
            'uid': os.getuid(), 'euid': os.geteuid(), 'state': 'BLOCKED',
        })
        raise NprocBlocked('Descendant inherited NPROC is not hard=soft256: ' + repr(inherited))
    result = _nproc_observation()
    result['inherited_soft_hard'] = list(inherited)
    return result


def _entry_nproc_gate(argv):
    if list(argv) in (['--probe-child'], ['--probe-grandchild'],
                     ['--probe-bash'], ['--probe-cancel']):
        return _inherited_nproc_gate()
    if list(argv) in (['--probes'], ['--suite'], ['--races'], ['--cross-consent'], ['--cross-web'], ['--cross-local']):
        return _workload_nproc_gate()
    raise NprocBlocked('Unknown entry selector')


def _descendant_nproc():
    entry = _NPROC_ENTRY if _NPROC_ENTRY is not None else _inherited_nproc_gate()
    if entry.get('inherited_soft_hard') != [256, 256]:
        raise NprocBlocked('Descendant original entry inheritance not established')
    result = _inherited_nproc_gate()
    result['entry'] = entry
    return result


def _valid_descendant_nproc(record, baseline):
    return (record.get('inherited_soft_hard') == [256, 256] and
            record.get('soft') == record.get('hard') == 256 and
            record.get('uid') == record.get('euid') == baseline['uid'] and
            record.get('uid_map') == baseline['uid_map'] and
            record.get('uid_map_scope') == baseline['uid_map_scope'] and
            record.get('identity_canary') == baseline['identity_canary'] and
            record.get('user_namespace') == baseline['user_namespace'] and
            record.get('capabilities') == baseline['capabilities'] and
            record.get('counter_scope') == baseline['counter_scope'] and
            type(record.get('observed_uid_tasks')) is int and
            1 <= record['observed_uid_tasks'] < 256)


def read_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        data = os.read(fd, 1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('Oversize receipt')
        return json.loads(data)
    finally:
        os.close(fd)


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview((json.dumps(value, sort_keys=True) + '\n').encode())
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError('Short receipt write')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def namespaces():
    return {name: os.readlink('/proc/self/ns/' + name) for name in NAMESPACES}


def _context():
    if str(Path(__file__)) != SELF or not sys.flags.isolated:
        raise ValueError('Only fixed isolated entrypoint permitted')
    data = read_json('/work/probe-context.json')
    if (set(data) != {'version', 'run_id', 'outside_canary', 'external_stub',
                     'external_marker', 'host_namespaces', 'host_uid', 'identity_canary'} or data['version'] != 1 or
            re.fullmatch(r'automation-isolated-[0-9a-f]{32}', data['run_id']) is None):
        raise ValueError('Invalid fresh probe context')
    base = '/tmp/opencode/' + data['run_id'] + '/'
    for key, leaf in (('outside_canary', 'outside-canary'),
                      ('external_stub', 'external-double'),
                      ('external_marker', 'external-marker')):
        if data[key] != base + leaf:
            raise ValueError('Probe paths must be synthetic siblings of mounts')
    if set(data['host_namespaces']) != set(NAMESPACES):
        raise ValueError('Incomplete host namespace observations')
    current = namespaces()
    if any(current[n] == data['host_namespaces'][n] for n in NAMESPACES):
        raise ValueError('Namespace not distinct from launcher')
    return data


def _fd_observation():
    """Observe without closing inherited fds or reading any descriptor contents.

    Fixed CPython listdir(path) opens one directory fd while enumerating. With
    exactly stdio live it must be fd3, and must be EBADF after listdir returns.
    Record EVERY enumerated number, live fd and EBADF; do not silently discard
    unexpected disappearing descriptors or exempt a live fd3. No other own fd
    is open here. This also detects arbitrarily high inherited fd numbers.
    """
    observed = sorted(int(name) for name in os.listdir('/proc/self/fd'))
    live, closed = [], []
    for number in observed:
        try:
            os.fstat(number)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
            closed.append(number)
        else:
            live.append(number)
    return {'observed': observed, 'live': live, 'closed_transient': closed,
            'valid': observed == [0, 1, 2, 3] and live == [0, 1, 2] and closed == [3]}


def _observe(role):
    nproc = _descendant_nproc()
    context = _context()
    inside = Path('/work/inside-canary').read_text() == context['run_id']
    try:
        # Only the freshly created synthetic sibling; never config/evidence.
        Path(context['outside_canary']).read_bytes()
    except OSError as exc:
        outside, outside_errno = False, exc.errno
    else:
        outside, outside_errno = True, None
    if outside or outside_errno != errno.ENOENT:
        raise ValueError('Synthetic outside canary accessible or ambiguous; stop')
    if Path(context['external_stub']).exists():
        raise ValueError('External synthetic double visible; stop without execution')
    errors = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            descriptor = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            errors.append(exc.errno)
            if exc.errno != errno.EPERM:
                raise ValueError('Socket creation did not return EPERM') from exc
        else:
            descriptor.close()
            raise ValueError('Socket unexpectedly created; closed without traffic')
    fd_observation = _fd_observation()
    return {'role': role, 'nproc': nproc, 'inside_canary_read': inside,
            'outside_canary_read': outside, 'outside_errno': outside_errno,
            'socket_errno': errors, 'fds': fd_observation['live'],
            'fd_observation': fd_observation, 'namespaces': namespaces(),
            'external_stub_visible': Path(context['external_stub']).exists(),
            'backend_visible': any(Path(p).exists() for p in
                                   ('/usr/bin/nmap', '/bin/nmap', '/usr/bin/curl',
                                    '/usr/bin/pwsh', '/usr/bin/sudo', '/usr/bin/git'))}


def _python(mode):
    return ['/usr/bin/python3', '-I', '-B', SELF, mode]


def _bash(mode):
    # Fixed positional arguments only; no external stub ever executed, even if
    # unexpectedly visible. Bash is a synthetic descendant, not host fallback.
    return ['/bin/bash', '--noprofile', '--norc', '-c', 'exec "$@"',
            'synthetic-probe', *_python(mode)]


def _capture(argv, timeout):
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, close_fds=True,
                             start_new_session=True)
    try:
        out, err = child.communicate(timeout=timeout)
        if child.returncode == 2:
            raise NprocBlocked('Synthetic descendant resource/boundary gate blocked')
        if child.returncode != 0 or len(out) > 65536 or len(err) > 65536:
            raise ValueError('Synthetic descendant failed')
        return json.loads(out)
    finally:
        if child.poll() is None:
            # Only the process group created above, inside the private PID ns.
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()


def _cancel_worker():
    worker_nproc = _descendant_nproc()
    _context()
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    pid = os.fork()
    if pid == 0:
        fork_nproc = _inherited_nproc_gate()
        write_json('/work/cancel-fork-nproc.json', fork_nproc)
        write_json('/work/cancel-fork-ready.json', {'ready': True})
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
        while True:
            signal.pause()
    # Child remains unreaped/owned until waitpid: no PID reuse or host target.
    deadline = time.monotonic() + 3
    while not Path('/work/cancel-fork-ready.json').exists():
        if time.monotonic() >= deadline:
            raise NprocBlocked('Cancel fork inherited NPROC receipt unavailable')
        time.sleep(0.005)
    fork_nproc = read_json('/work/cancel-fork-nproc.json')
    if not _valid_descendant_nproc(fork_nproc, worker_nproc):
        raise NprocBlocked('Cancel fork NPROC inheritance not established')
    write_json('/work/cancel-ready.json', {'pid': os.getpid()})
    signal.sigwait({signal.SIGTERM})
    os.kill(pid, signal.SIGTERM)
    waited, status = os.waitpid(pid, 0)
    write_json('/work/cancel-reaped.json',
               {'descendant_reaped': waited == pid and os.WIFSIGNALED(status),
                'worker_nproc': worker_nproc, 'fork_nproc': fork_nproc})


def _cancel(deadline):
    child = subprocess.Popen(_python('--probe-cancel'), close_fds=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        while not Path('/work/cancel-ready.json').exists():
            if child.poll() == 2:
                raise NprocBlocked('Cancel worker inherited NPROC gate blocked')
            if child.poll() is not None or time.monotonic() >= deadline:
                raise ValueError('Cancel descendant not ready')
            time.sleep(0.005)
        fd = os.pidfd_open(child.pid)
        try:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)
        child.wait(timeout=max(0.001, deadline - time.monotonic()))
        result = read_json('/work/cancel-reaped.json')
        result['direct_child_reaped'] = child.returncode == 0
        return result
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()


def run_probes(run_id: str) -> dict[str, object]:
    """Corroborate the inherited boundary; no host probes or legacy imports."""
    # Observe the actual entry controller BEFORE any Popen/close_fds. Child
    # sanitization must never stand in for this check or hide its findings.
    entry_fds = _fd_observation()
    context = _context()
    if run_id != context['run_id']:
        raise ValueError('Run identity mismatch')
    current = namespaces()
    nproc = _nproc_observation()
    checks = [{'id': 'entry-fds', 'result': 'PASS' if entry_fds['valid'] else 'FAIL',
               'reason': 'exact entry stdio plus closed listdir fd3 transient'}]
    checks.append({'id': 'workload-nproc', 'result': 'PASS',
                   'reason': 'verified hard=soft256, nonroot single UID map, cap-free task snapshot'})
    if not entry_fds['valid']:
        # Persisted by inside_main even on failure; never sanitize or spawn in
        # order to make the failed entry observation look clean.
        return {'version': 1, 'run_id': run_id, 'state': 'FAIL', 'checks': checks,
                'context': context, 'namespaces': current, 'entry_fds': entry_fds,
                'descendants': [], 'cancel': None, 'nproc': nproc}
    deadline = time.monotonic() + 9.5
    descendants = _capture(_python('--probe-child'), max(0.001, deadline - time.monotonic()))
    descendants.append(_capture(_bash('--probe-bash'), max(0.001, deadline - time.monotonic())))
    for result in descendants:
        ok = (result['inside_canary_read'] is True and
              result['outside_canary_read'] is False and result['outside_errno'] == errno.ENOENT and
              result['socket_errno'] == [errno.EPERM, errno.EPERM] and
              result['fds'] == [0, 1, 2] and result['fd_observation']['valid'] is True and
              result['namespaces'] == current and
              _valid_descendant_nproc(result['nproc'], nproc) and
              _valid_descendant_nproc(result['nproc']['entry'], nproc) and
              not result['external_stub_visible'] and not result['backend_visible'])
        checks.append({'id': result['role'], 'result': 'PASS' if ok else 'FAIL',
                       'reason': 'synthetic inherited boundary observations'})
    cancel = _cancel(deadline)
    checks.append({'id': 'cancel-owned-descendants',
                   'result': 'PASS' if (
                       cancel['descendant_reaped'] is True and cancel['direct_child_reaped'] is True and
                       _valid_descendant_nproc(cancel['worker_nproc'], nproc) and
                       _valid_descendant_nproc(cancel['worker_nproc']['entry'], nproc) and
                       _valid_descendant_nproc(cancel['fork_nproc'], nproc)) else 'FAIL',
                   'reason': 'pidfd direct child signalled, synthetic descendant reaped'})
    return {'version': 1, 'run_id': run_id,
            'state': 'PASS' if all(c['result'] == 'PASS' for c in checks) else 'FAIL',
            'checks': checks, 'context': context, 'namespaces': current, 'entry_fds': entry_fds,
            'descendants': descendants, 'cancel': cancel, 'nproc': nproc}


def inside_main(argv: Sequence[str]) -> int:
    global _VALIDATED, _SELECTION
    _VALIDATED = False
    _SELECTION = None
    if list(argv) not in (['--probes'], ['--suite'], ['--races'], ['--cross-consent'], ['--cross-web'], ['--cross-local']):
        return 2
    state, code, reason = 'BLOCKED', 2, 'Probe prerequisites unavailable'
    previous = None
    armed = False
    tests_started = False
    try:
        nproc = _NPROC_ENTRY if _NPROC_ENTRY is not None else _workload_nproc_gate()
        _nproc_observation()  # verify effective state, not just saved entry data
        write_json('/evidence/workload-nproc.json', dict(nproc, version=1))
        context = _context()
        def expired(number, frame):
            raise TimeoutError('Fixed probe/selection budget exhausted')
        previous = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 10)
        armed = True
        result = run_probes(context['run_id'])
        write_json('/evidence/probes.json', result)
        if result['state'] != 'PASS':
            state, code, reason = 'FAIL', 1, 'Boundary probe failed'
        elif argv[0] == '--probes':
            _VALIDATED = True
            state, code, reason = 'PASS', 0, 'Synthetic probes passed; no legacy tests started'
        else:
            _VALIDATED = True
            _SELECTION = argv[0]
            # Stop the probe budget; selection has its own fixed budget. This
            # is direct discovery, never run_automation/launcher/nested bwrap.
            signal.setitimer(signal.ITIMER_REAL, 240 if argv[0] == '--races' else 600)
            from automation_suite_selection import run_selection
            tests_started = True
            state, code, reason = run_selection(argv[0], write_json)
    except NprocBlocked as exc:
        state, code, reason = 'BLOCKED', 2, str(exc)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        state, code, reason = ('FAIL', 1, str(exc)) if armed else ('BLOCKED', 2, str(exc))
    finally:
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
        if previous is not None:
            signal.signal(signal.SIGALRM, previous)
    write_json('/evidence/inside-result.json', {
        'version': 1, 'state': state, 'returncode': code,
        'reason': reason, 'tests_started': tests_started})
    return code


def validated_diagnostic_context():
    """Local diagnostic state, never authority to launch on host."""
    return (_VALIDATED and str(Path(__file__)) == SELF and
            all(namespaces()[n] != _context()['host_namespaces'][n] for n in NAMESPACES))


def validated_selection() -> str | None:
    """Memory set only after probes; no test argv/environment interpretation."""
    return _SELECTION if validated_diagnostic_context() else None


if __name__ == '__main__':
    os.umask(0o077)
    try:
        # Debian -I does not auto-add this staged PyYAML parent. Add ONLY these
        # fixed staged paths; never site.addsitedir (would process .pth files).
        if str(Path(__file__)) != SELF or not sys.flags.isolated:
            raise ValueError('Blocked outside fixed sandbox entrypoint')
        _NPROC_ENTRY = _entry_nproc_gate(sys.argv[1:])
        sys.path.extend(['/usr/lib/python3.13/site-packages', TESTS])
        if sys.argv[1:] == ['--probe-child']:
            observations = [_observe('python-child')]
            observations.append(_capture(_bash('--probe-grandchild'), 3))
            print(json.dumps(observations))
            raise SystemExit(0)
        if sys.argv[1:] in (['--probe-grandchild'], ['--probe-bash']):
            print(json.dumps(_observe('bash-grandchild' if sys.argv[1] ==
                                      '--probe-grandchild' else 'bash-child')))
            raise SystemExit(0)
        if sys.argv[1:] == ['--probe-cancel']:
            _cancel_worker()
            raise SystemExit(0)
        raise SystemExit(inside_main(sys.argv[1:]))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print('BLOCKED: ' + str(exc), file=sys.stderr)
        raise SystemExit(2)
