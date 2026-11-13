"""Single-child, fail-closed Task2 launcher. NOT RUN; static review required.

Only stdlib and trusted infrastructure imports on host. No framework/test imports,
runtime discovery by execution, fallback, deletion, finalizers or free command.
"""
import fcntl
import errno
import gzip
import hashlib
import io
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import threading
import time

from automation_sandbox_prepare import (
    IsolationBlocked, REPO, _identity, _new_json, _open_directory, _open_regular,
    load_json, prepare, read_regular, source_names,
)
from automation_sandbox_policy import bubblewrap_argv, seccomp_program


BWRAP = Path('/usr/bin/bwrap')
BWRAP_DOCUMENT = Path('/usr/share/doc/bubblewrap/changelog.Debian.gz')
REVIEWED_PACKAGE = b'bubblewrap (0.11.2-2) unstable; urgency=medium'
HOST_TIMEOUT = 900
SIGNAL_GRACE = 5
LIMITS = ((resource.RLIMIT_AS, 2 * 1024**3), (resource.RLIMIT_CPU, 600),
          (resource.RLIMIT_NOFILE, 256), (resource.RLIMIT_FSIZE, 64 * 1024**2),
          (resource.RLIMIT_NPROC, 256))


class _HostStop(BaseException):
    """Unwind interruptible host work, including Task1's bounded copy loops."""


class _Child:
    """Our one unreaped child; no synchronous preexec/exec handshake."""
    def __init__(self):
        self.pid = None
        self.returncode = None

    def poll(self):
        if self.pid is None:
            return 2
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK,
                                         {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
        try:
            if self.returncode is None:
                waited, status = os.waitpid(self.pid, os.WNOHANG)
                if waited:
                    self.returncode = os.waitstatus_to_exitcode(status)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        return self.returncode

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired('/usr/bin/bwrap', timeout)
            time.sleep(0.01)
        return self.poll()

    def kill(self):
        # This PID is only used while it is our unreaped child. It cannot be
        # reused; all ordinary supervision prefers its pidfd.
        self.send_signal(signal.SIGKILL)

    def send_signal(self, number):
        if self.pid is not None and self.returncode is None:
            try:
                os.kill(self.pid, number)
            except ProcessLookupError:
                pass


def _fork_child(child, argv, bwrap_fd, seccomp_fd, stdout, stderr):
    # Publish the PID into an already-owned object BEFORE unmasking signals.
    # Thus cancellation cannot lose a child between fork and caller assignment.
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK,
                                     {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
    try:
        child.pid = os.fork()
        if child.pid == 0:
            try:
                for number in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
                    signal.signal(number, signal.SIG_DFL)
                signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
                os.umask(0o077)
                null = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
                os.dup2(null, 0)
                os.dup2(stdout, 1)
                os.dup2(stderr, 2)
                for name in os.listdir('/proc/self/fd'):
                    number = int(name)
                    if number not in (0, 1, 2, bwrap_fd, seccomp_fd):
                        try:
                            os.close(number)
                        except OSError as exc:
                            if exc.errno != errno.EBADF:
                                raise
                os.set_inheritable(bwrap_fd, False)
                os.set_inheritable(seccomp_fd, True)
                for kind, limit in LIMITS:
                    resource.setrlimit(kind, (limit, limit))
                # fexecve pins the approved ELF; the fd closes on exec. No host
                # environment, argv command selection, or Python fallback.
                os.execve(bwrap_fd, argv, {})
            except BaseException:
                os._exit(2)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def _selector(argv):
    if not argv:
        return '--suite'
    if len(argv) == 1 and argv[0] in ('--probes', '--suite', '--races'):
        return argv[0]
    raise IsolationBlocked('Only --probes, --suite or --races is accepted')


def _open_bwrap():
    """Pin fixed executable inode. Read installed version documentation as data.

    Child fexecve uses this descriptor, not a second pathname lookup. Package changes
    require explicit review of this fixed documentary version; never --version.
    """
    fd, parent, name = _open_regular(BWRAP)
    try:
        before = os.fstat(fd)
        if (before.st_uid != 0 or before.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)
                or not before.st_mode & 0o111 or not 3 <= fd < 256):
            raise IsolationBlocked('bwrap must be root-owned, non-setid and non-writable')
        try:
            capabilities = os.getxattr(fd, 'security.capability')
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise IsolationBlocked('Cannot validate bwrap file capabilities') from exc
        else:
            if capabilities:
                raise IsolationBlocked('bwrap file capabilities are forbidden')
        doc_fd, doc_parent, _ = _open_regular(BWRAP_DOCUMENT)
        try:
            info = os.fstat(doc_fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise IsolationBlocked('Untrusted bwrap documentation')
            with gzip.GzipFile(fileobj=io.BytesIO(read_regular(BWRAP_DOCUMENT))) as document:
                if document.readline(256).rstrip(b'\n') != REVIEWED_PACKAGE:
                    raise IsolationBlocked('Unreviewed bwrap package documentation')
        finally:
            os.close(doc_fd)
            os.close(doc_parent)
        if (_identity(before) != _identity(os.fstat(fd)) or
                _identity(before) != _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))):
            raise IsolationBlocked('bwrap inode changed')
        return fd, {'path': str(BWRAP), 'identity': list(_identity(before)),
                    'document': str(BWRAP_DOCUMENT),
                    'reviewed_package': REVIEWED_PACKAGE.decode(),
                    'availability_proven': False}
    except BaseException:
        os.close(fd)
        raise
    finally:
        os.close(parent)


def _validate_limits():
    for kind, limit in LIMITS:
        soft, hard = resource.getrlimit(kind)
        if any(value != resource.RLIM_INFINITY and value < limit for value in (soft, hard)):
            raise IsolationBlocked('Existing resource limit insufficient; not increased')


def _validate_staging(run):
    """No injected file/symlink or changed copy can enter directory ro-binds."""
    receipt = load_json(run.root / 'prepared.json',
                        {'version', 'state', 'runtime_executed'})
    if receipt['state'] != 'PREPARED' or receipt['runtime_executed'] is not False:
        raise IsolationBlocked('Not a fresh prepared run')
    data = load_json(run.root / 'manifest.json', {'version', 'files'})
    if not isinstance(data['files'], list) or len(data['files']) > 16384:
        raise IsolationBlocked('Invalid effective file inventory')
    expected = {run.source_root / name for name in source_names()}
    expected.update(entry.source for entry in run.manifest)
    actual = set()
    for base in (run.root, run.source_root, run.runtime_root, run.work, run.evidence):
        fd = _open_directory(base)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise IsolationBlocked('Staging directories must be private 700')
        finally:
            os.close(fd)
    def visit(directory, depth=0):
        if depth > 64:
            raise IsolationBlocked('Staging depth exceeded')
        fd = _open_directory(directory)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise IsolationBlocked('Non-private staging descendant')
            for name in os.listdir(fd):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                path = directory / name
                if stat.S_ISDIR(info.st_mode):
                    visit(path, depth + 1)
                elif stat.S_ISREG(info.st_mode) and path in expected:
                    actual.add(path)
                else:
                    raise IsolationBlocked('Unexpected staging entry')
        finally:
            os.close(fd)
    visit(run.source_root)
    visit(run.runtime_root)
    if actual != expected:
        raise IsolationBlocked('Staged inventory differs from exact allowlist')
    records = set()
    for record in data['files']:
        if not isinstance(record, dict):
            raise IsolationBlocked('Invalid file record')
        destination = record.get('destination')
        if not isinstance(destination, str):
            raise IsolationBlocked('Invalid destination')
        base = run.source_root if record.get('category') == 'source' else run.runtime_root
        path = base / destination.lstrip('/')
        if path not in expected or path in records:
            raise IsolationBlocked('Unexpected or duplicate manifest entry')
        info = path.lstat()
        if (info.st_uid != os.getuid() or info.st_nlink != 1 or
                list(_identity(info)) != record.get('staged_identity') or
                stat.S_IMODE(info.st_mode) != record.get('mode') or
                hashlib.sha256(read_regular(path)).hexdigest() != record.get('sha256')):
            raise IsolationBlocked('Staged bytes or identity changed')
        records.add(path)
    if records != expected:
        raise IsolationBlocked('Incomplete effective manifest')
    # Work/evidence must be empty before the first launch; never reuse a run.
    for directory in (run.work, run.evidence):
        fd = _open_directory(directory)
        try:
            if os.listdir(fd):
                raise IsolationBlocked('Work/evidence already used')
        finally:
            os.close(fd)


def _seccomp_memfd():
    fd = os.memfd_create('automation-seccomp', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(seccomp_program())
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise IsolationBlocked('Short BPF write')
            view = view[count:]
        seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                 fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals or fd >= 256:
            raise IsolationBlocked('BPF seals/descriptor unavailable')
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _new_log(path):
    parent = _open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        os.fchmod(fd, 0o600)
        return fd
    finally:
        os.close(parent)


def _supervise(child, pidfd, pending, deadline=None):
    if deadline is None:
        deadline = time.monotonic() + HOST_TIMEOUT
    forwarded = None
    timed_out = False
    killed = False
    while True:
        try:
            result = child.wait(timeout=0.1)
            if pending:
                return 128 + pending[0], 'SIGNAL'
            if timed_out:
                return 1, 'TIMEOUT'
            return result, 'EXIT'
        except subprocess.TimeoutExpired:
            now = time.monotonic()
            if forwarded is None and (pending or now >= deadline):
                timed_out = not pending
                forwarded = now
                # pidfd pins only our direct child. No killpg/name/PID discovery.
                try:
                    number = pending[0] if pending else signal.SIGTERM
                    if pidfd is None:
                        child.send_signal(number)
                    else:
                        signal.pidfd_send_signal(pidfd, number)
                except ProcessLookupError:
                    pass
            elif forwarded is not None and not killed and now >= forwarded + SIGNAL_GRACE:
                try:
                    if pidfd is None:
                        child.kill()
                    else:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                killed = True


def launch() -> int:
    host_deadline = time.monotonic() + HOST_TIMEOUT
    run = None
    descriptors = []
    previous = {}
    pending = []
    child = None
    pidfd = None
    timer_owned = False
    interrupted_mask = None
    try:
        selector = _selector(sys.argv[1:])
        if (sys.platform != 'linux' or os.uname().machine != 'x86_64' or
                os.getuid() != os.geteuid() or os.getgid() != os.getegid() or
                threading.active_count() != 1 or REPO == Path('/source')):
            raise IsolationBlocked('Unsupported host or nested launcher')
        for name in ('pidfd_open', 'memfd_create'):
            if not hasattr(os, name):
                raise IsolationBlocked('Missing kernel/Python interface: ' + name)
        if not hasattr(signal, 'pidfd_send_signal'):
            raise IsolationBlocked('Missing pinned-child signalling')
        _validate_limits()
        if signal.pthread_sigmask(signal.SIG_BLOCK, set()) & {
                signal.SIGINT, signal.SIGTERM, signal.SIGALRM}:
            raise IsolationBlocked('Managed host signals must not be masked')
        if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
            raise IsolationBlocked('Existing host alarm must not be replaced')
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise IsolationBlocked('Child ownership requires default SIGCHLD disposition')
        def remember(number, frame):
            if not pending:
                pending.append(number)
        def interrupt(number, frame):
            nonlocal interrupted_mask
            # A second cancellation must not interrupt the unwind/reap of the
            # first. Restore the original mask only after child/fd release.
            interrupted_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
            if number != signal.SIGALRM:
                remember(number, frame)
            raise _HostStop()
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
            previous[number] = signal.signal(number, interrupt)
        # Python signal exceptions interrupt progressing Python loops and
        # interruptible syscalls (PEP475 does not retry when the handler raises).
        # No cooperation/change to Task1's API and no auxiliary host process.
        timer_owned = True
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, host_deadline - time.monotonic()))
        bwrap_fd, bwrap_record = _open_bwrap()
        descriptors.append(bwrap_fd)
        run = prepare(REPO)
        _validate_staging(run)
        for name in ('home', 'tmp'):
            (run.work / name).mkdir(mode=0o700)
        seccomp_fd = _seccomp_memfd()
        descriptors.append(seccomp_fd)
        argv = bubblewrap_argv(run, seccomp_fd) + (selector,)
        _new_json(run.evidence / 'launch.json', {
            'version': 1, 'state': 'STARTING', 'argv': list(argv),
            'bwrap': bwrap_record, 'host_timeout': HOST_TIMEOUT,
            'suite_timeout': 600, 'races_timeout': 240, 'probe_timeout': 10,
            'runtime_executed': False,
        })
        stdout = _new_log(run.evidence / 'stdout.log')
        descriptors.append(stdout)
        stderr = _new_log(run.evidence / 'stderr.log')
        descriptors.append(stderr)
        if pending:
            return 128 + pending[0]
        if time.monotonic() >= host_deadline:
            raise IsolationBlocked('Host budget exhausted before payload')
        child = _Child()
        _fork_child(child, argv, bwrap_fd, seccomp_fd, stdout, stderr)
        try:
            pidfd = os.pidfd_open(child.pid, 0)
        except OSError:
            # Our child remains unreaped, so this specific PID cannot be
            # reused. No other process is targeted if pidfd acquisition fails.
            child.kill()
            child.wait()
            raise IsolationBlocked('Could not pin launched child')
        descriptors.append(pidfd)
        result, outcome = _supervise(child, pidfd, pending, deadline=host_deadline)
        _new_json(run.evidence / 'host-wait.json', {
            'version': 1, 'outcome': outcome, 'returncode': result,
        })
        if outcome in ('SIGNAL', 'TIMEOUT'):
            return result
        # A bwrap setup failure has no trusted inside receipt: BLOCKED, never a
        # host fallback. Task3 will supply genuine probe FAIL/PASS receipts.
        receipt = load_json(run.evidence / 'inside-result.json',
                            {'version', 'state', 'returncode', 'reason', 'tests_started'})
        states = {'PASS': 0, 'FAIL': 1, 'BLOCKED': 2}
        if (not isinstance(receipt['state'], str) or receipt['state'] not in states or
                type(receipt['tests_started']) is not bool or
                not isinstance(receipt['reason'], str) or
                type(receipt['returncode']) is not int or
                receipt['returncode'] != states[receipt['state']] or
                result != receipt['returncode']):
            raise IsolationBlocked('Invalid or inconsistent inside receipt')
        return result
    except _HostStop:
        # Stop raising during termination/reap. Supervision now forwards the
        # recorded signal or expired deadline, escalates after5s, and polls our
        # own child. Only uninterruptible kernel tasks can delay SIGKILL/reap.
        signal.setitimer(signal.ITIMER_REAL, 0)
        for number in (signal.SIGINT, signal.SIGTERM):
            signal.signal(number, remember)
        if child is not None and child.pid is not None:
            _supervise(child, pidfd, pending, deadline=host_deadline)
        spawned = child is not None and child.pid is not None
        code = 128 + pending[0] if pending else (1 if spawned else 2)
        # No additional diagnostic I/O after cancellation/deadline: retain all
        # existing (possibly incomplete) artifacts and report only via exit rc.
        return code
    except (IsolationBlocked, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        try:
            print('BLOCKED: ' + str(exc) + '; retained run: ' + str(run.root if run else None),
                  file=sys.stderr)
            if run is not None:
                try:
                    _new_json(run.evidence / 'launch-blocked.json',
                              {'version': 1, 'state': 'BLOCKED', 'reason': str(exc)})
                except (OSError, IsolationBlocked):
                    pass
        except _HostStop:
            pass  # diagnostic I/O is subject to the same still-active timer
        return 128 + pending[0] if pending else 2
    finally:
        final_mask = signal.pthread_sigmask(signal.SIG_BLOCK,
                                           {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
        if timer_owned:
            signal.setitimer(signal.ITIMER_REAL, 0)
            # The owned one-shot alarm may have become pending just before the
            # final mask. Do not deliver it to the restored previous handler.
            signal.sigtimedwait({signal.SIGALRM}, 0)
            # Do not let another cancellation abandon our child during reap.
            for number in (signal.SIGINT, signal.SIGTERM):
                signal.signal(number, remember)
        # Descriptor release is not artifact cleanup: no unlink/rmdir/finalizers.
        if child is not None and child.poll() is None:
            if pidfd is not None:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()  # own, still-unreaped direct child only
            child.wait()
        for fd in reversed(descriptors):
            os.close(fd)
        for number, handler in previous.items():
            signal.signal(number, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK,
                               interrupted_mask if interrupted_mask is not None else final_mask)


if __name__ == '__main__':
    raise SystemExit(launch())
