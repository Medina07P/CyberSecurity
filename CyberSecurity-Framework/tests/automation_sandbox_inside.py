"""Trusted Task3 entrypoint; NOT RUN. No legacy discovery before Task4.

Namespace observations corroborate the launch, not a host authorization token.
The independently reviewed host launcher is the only permitted entrypoint.
"""
from collections.abc import Sequence
import errno
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

SELF = '/source/CyberSecurity-Framework/tests/automation_sandbox_inside.py'
TESTS = '/source/CyberSecurity-Framework/tests'
NAMESPACES = ('mnt', 'pid', 'net', 'user', 'ipc', 'uts', 'cgroup')
_VALIDATED = False


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
                     'external_marker', 'host_namespaces'} or data['version'] != 1 or
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
    return {'role': role, 'inside_canary_read': inside,
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
        if child.returncode != 0 or len(out) > 65536 or len(err) > 65536:
            raise ValueError('Synthetic descendant failed')
        return json.loads(out)
    finally:
        if child.poll() is None:
            # Only the process group created above, inside the private PID ns.
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()


def _cancel_worker():
    _context()
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    pid = os.fork()
    if pid == 0:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
        while True:
            signal.pause()
    # Child remains unreaped/owned until waitpid: no PID reuse or host target.
    write_json('/work/cancel-ready.json', {'pid': os.getpid()})
    signal.sigwait({signal.SIGTERM})
    os.kill(pid, signal.SIGTERM)
    waited, status = os.waitpid(pid, 0)
    write_json('/work/cancel-reaped.json',
               {'descendant_reaped': waited == pid and os.WIFSIGNALED(status)})


def _cancel(deadline):
    child = subprocess.Popen(_python('--probe-cancel'), close_fds=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        while not Path('/work/cancel-ready.json').exists():
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
    checks = [{'id': 'entry-fds', 'result': 'PASS' if entry_fds['valid'] else 'FAIL',
               'reason': 'exact entry stdio plus closed listdir fd3 transient'}]
    if not entry_fds['valid']:
        # Persisted by inside_main even on failure; never sanitize or spawn in
        # order to make the failed entry observation look clean.
        return {'version': 1, 'run_id': run_id, 'state': 'FAIL', 'checks': checks,
                'context': context, 'namespaces': current, 'entry_fds': entry_fds,
                'descendants': [], 'cancel': None}
    deadline = time.monotonic() + 9.5
    descendants = _capture(_python('--probe-child'), max(0.001, deadline - time.monotonic()))
    descendants.append(_capture(_bash('--probe-bash'), max(0.001, deadline - time.monotonic())))
    for result in descendants:
        ok = (result['inside_canary_read'] is True and
              result['outside_canary_read'] is False and result['outside_errno'] == errno.ENOENT and
              result['socket_errno'] == [errno.EPERM, errno.EPERM] and
              result['fds'] == [0, 1, 2] and result['fd_observation']['valid'] is True and
              result['namespaces'] == current and
              not result['external_stub_visible'] and not result['backend_visible'])
        checks.append({'id': result['role'], 'result': 'PASS' if ok else 'FAIL',
                       'reason': 'synthetic inherited boundary observations'})
    cancel = _cancel(deadline)
    checks.append({'id': 'cancel-owned-descendants',
                   'result': 'PASS' if all(cancel.values()) else 'FAIL',
                   'reason': 'pidfd direct child signalled, synthetic descendant reaped'})
    return {'version': 1, 'run_id': run_id,
            'state': 'PASS' if all(c['result'] == 'PASS' for c in checks) else 'FAIL',
            'checks': checks, 'context': context, 'namespaces': current, 'entry_fds': entry_fds,
            'descendants': descendants, 'cancel': cancel}


def inside_main(argv: Sequence[str]) -> int:
    global _VALIDATED
    _VALIDATED = False
    if list(argv) not in (['--probes'], ['--suite'], ['--races']):
        return 2
    state, code, reason = 'BLOCKED', 2, 'Probe prerequisites unavailable'
    previous = None
    armed = False
    try:
        context = _context()
        def expired(number, frame):
            raise TimeoutError('Global probe budget exhausted')
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
            reason = 'Task4 preservation integration pending; suite/races blocked'
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        state, code, reason = ('FAIL', 1, str(exc)) if armed else ('BLOCKED', 2, str(exc))
    finally:
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
        if previous is not None:
            signal.signal(signal.SIGALRM, previous)
    write_json('/evidence/inside-result.json', {
        'version': 1, 'state': state, 'returncode': code,
        'reason': reason, 'tests_started': False})
    return code


def validated_diagnostic_context():
    """Local diagnostic state, never authority to launch on host."""
    return (_VALIDATED and str(Path(__file__)) == SELF and
            all(namespaces()[n] != _context()['host_namespaces'][n] for n in NAMESPACES))


if __name__ == '__main__':
    os.umask(0o077)
    try:
        # Debian -I does not auto-add this staged PyYAML parent. Add ONLY these
        # fixed staged paths; never site.addsitedir (would process .pth files).
        if str(Path(__file__)) != SELF or not sys.flags.isolated:
            raise ValueError('Blocked outside fixed sandbox entrypoint')
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
