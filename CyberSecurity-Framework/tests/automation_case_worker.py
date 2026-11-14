"""Test-only per-case fork worker / Landlock ABI>=3. STATIC implementation NOT RUN.

Native x86_64 Linux syscalls from asm/unistd_64.h:444 create,445 add,446 restrict.
Rights/layout from linux/landlock.h ABI3. No alternate host launch or mounts.
"""
import ctypes
import errno
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
from tempfile import mkdtemp

SYSCALLS = (444, 445, 446)
HANDLED = sum(1 << bit for bit in (1, *range(4, 15)))
MAX_RESULT = 65536


class WorkerBlocked(RuntimeError):
    pass


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32)]


def _syscall(number, *args):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(ctypes.c_long(number), *args)
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(result)


def _prctl(option, value):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(option, value, 0, 0, 0) != 0:
        raise WorkerBlocked('Required prctl unavailable: ' + str(ctypes.get_errno()))


def landlock(root_fd):
    try:
        if sys.platform != 'linux' or os.uname().machine != 'x86_64':
            raise WorkerBlocked('Native x86_64 Landlock required')
        abi = _syscall(444, 0, 0, 1)  # LANDLOCK_CREATE_RULESET_VERSION
        if abi < 3:
            raise WorkerBlocked('Landlock ABI>=3 (TRUNCATE) required')
        handled = ctypes.c_uint64(HANDLED)  # ABI1 ruleset layout,8bytes.
        ruleset = _syscall(444, ctypes.byref(handled), ctypes.c_size_t(8), 0)
        try:
            rule = PathRule(HANDLED, root_fd)
            _syscall(445, ruleset, 1, ctypes.byref(rule), 0)
            _prctl(38, 1)  # PR_SET_NO_NEW_PRIVS, never reversible.
            _syscall(446, ruleset, 0)
        finally:
            os.close(ruleset)
        return abi
    except OSError as exc:
        raise WorkerBlocked('Landlock unavailable; no case run: ' + str(exc)) from exc


def identity(root, fd):
    info = os.fstat(fd)
    named = os.stat(root, follow_symlinks=False)
    fields = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode)
    if (fields(info) != fields(named) or not stat.S_ISDIR(info.st_mode) or
            stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()):
        raise WorkerBlocked('Unpinned/nonprivate case root')
    return fields(info)


def verify_outside_write_denied(path):
    # A parent-created current-case log, not real config/evidence. Only attempt
    # OPEN: no O_TRUNC/O_CREAT/write. If enforcement unexpectedly fails, close
    # that descriptor immediately and BLOCK before executing any test.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    except PermissionError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return
        raise
    else:
        os.close(fd)
        raise WorkerBlocked('Landlock did not deny reopening outside scratch for write')


def _close_except(keep):
    # Enumeration transient has disappeared; do not retain any parent evidence,
    # source, root or writeable regular-file fd accidentally inherited by fork.
    for item in os.listdir('/proc/self/fd'):
        fd = int(item)
        if fd not in keep:
            try:
                os.close(fd)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise


def _owned_children():
    # Kernel lists DIRECT children, not pids found by name/process group. The
    # trusted controller is a subreaper in the PRIVATE outer PID namespace.
    text = Path('/proc/self/task/' + str(os.getpid()) + '/children').read_text()
    return [int(value) for value in text.split()]


def reap_owned():
    """Kill/reap direct owned/adopted children, including detached descendants.

    No deadline on kernel reap: an uninterruptible task is reported by outer
    supervision, never left running to fake a passing test.
    """
    while True:
        children = _owned_children()
        if not children:
            return
        for pid in children:
            # Only this unreaped direct child; PID cannot be reused until wait.
            fd = os.pidfd_open(pid)
            try:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # already exited/zombie, still our unreaped child
                os.waitpid(pid, 0)
            finally:
                os.close(fd)


def _send(fd, value):
    raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    if len(raw) > MAX_RESULT:
        raw = (json.dumps({'state': 'FAIL', 'id': value.get('id'),
                           'successful': False, 'errors': 1,
                           'reason': 'Worker result exceeded bound'}) + '\n').encode()
    while raw:
        count = os.write(fd, raw)
        if count <= 0:
            raise WorkerBlocked('Worker result short write')
        raw = raw[count:]


def _child(case, root, root_fd, pinned, result_fd, stdout_fd, stderr_fd, permitted, outside_log):
    result = {'state': 'BLOCKED', 'id': case.id(), 'reason': 'Worker setup incomplete'}
    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
            signal.signal(number, signal.SIG_DFL)
        os.setsid()
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
        null = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(null, 0)
        os.set_inheritable(result_fd, False)
        _close_except({0, 1, 2, root_fd, result_fd})
        identity(root, root_fd)
        _prctl(36, 1)  # PR_SET_CHILD_SUBREAPER
        from automation_sandbox_inside import _inherited_nproc_gate
        inherited = _inherited_nproc_gate()  # read only, never repair inheritance
        abi = landlock(root_fd)
        verify_outside_write_denied(outside_log)
        identity(root, root_fd)
        os.close(root_fd)
        from automation_case_scope import configure_worker
        configure_worker(root, pinned, case.id(), permitted, abi)
        from automation_suite_selection import _run_inline
        # Fork inherits Python buffers referencing parent logs: use fresh stdio
        # wrappers for only the explicit per-case log descriptors duplicated above.
        sys.stdout = io.TextIOWrapper(io.FileIO(1, 'w', closefd=False), write_through=True)
        sys.stderr = io.TextIOWrapper(io.FileIO(2, 'w', closefd=False), write_through=True)
        result = dict(_run_inline([case]), state='DONE', id=case.id(), abi=abi,
                      scratch=str(root), identity=list(pinned), disposable_permission=permitted,
                      nproc=inherited)
    except BaseException as exc:
        result = {'state': 'BLOCKED' if isinstance(exc, WorkerBlocked) else 'FAIL',
                  'id': case.id(), 'reason': type(exc).__name__ + ': ' + str(exc)}
    finally:
        try:
            reap_owned()
        except BaseException as exc:
            result = {'state': 'FAIL', 'id': case.id(), 'reason': 'Owned reap failed: ' + str(exc)}
        try:
            _send(result_fd, result)
        finally:
            os._exit(0)  # Never run inherited atexit hooks/finalizers.


def run_case(case, permitted, index):
    """Only validated controller calls this; permission from exact ID inventory."""
    import __main__ as controller
    from automation_case_scope import in_worker
    if (getattr(controller, '__file__', None) !=
            '/source/CyberSecurity-Framework/tests/automation_sandbox_inside.py' or
            not getattr(controller, 'validated_diagnostic_context', lambda: False)() or in_worker()):
        raise WorkerBlocked('Only validated inside controller may fork case')
    from automation_suite_selection import preservation_inventory
    ids = preservation_inventory()['authorization']['case_ids']
    if permitted != (case.id() in ids) or type(permitted) is not bool:
        raise WorkerBlocked('Case permission does not match closed inventory')
    _prctl(36, 1)
    root = Path(mkdtemp(prefix='case-', dir='/work/fixtures'))
    (root / 'fixtures').mkdir(mode=0o700)
    fd = read_fd = write_fd = None
    logs = []
    pid = None
    oldmask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
    try:
        fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        pinned = identity(root, fd)
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        from automation_sandbox_inside import write_json
        write_json('/evidence/case-' + str(index).zfill(5) + '.registry.json', {
            'version': 1, 'case_id': case.id(), 'root': str(root), 'identity': list(pinned),
            'disposable_permission': permitted, 'state': 'REGISTERED-NOT-RUN'})
        for suffix in ('stdout', 'stderr'):
            logs.append(os.open('/evidence/case-' + str(index).zfill(5) + '.' + suffix + '.log',
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
        pid = os.fork()
        if pid == 0:
            signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
            _child(case, root, fd, pinned, write_fd, *logs, permitted,
                   '/evidence/case-' + str(index).zfill(5) + '.stdout.log')
            os._exit(2)
        os.close(write_fd)
        write_fd = None
        os.set_blocking(read_fd, False)
        deadline = time.monotonic() + 60
        signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
        raw = bytearray()
        status = None
        while True:
            try:
                data = os.read(read_fd, MAX_RESULT + 1 - len(raw))
            except BlockingIOError:
                data = None
            if data:
                raw.extend(data)
            if len(raw) > MAX_RESULT:
                raise WorkerBlocked('Worker receipt too large')
            if status is None:
                waited, value = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    status = value
            if status is not None and data == b'':
                break
            if time.monotonic() >= deadline:
                raise WorkerBlocked('Per-case timeout; owned children must be reaped')
            time.sleep(0.005)
        if status != 0:
            raise WorkerBlocked('Worker terminated without normal result')
        value = json.loads(raw)
        if value.get('id') != case.id() or value.get('state') not in ('DONE', 'BLOCKED', 'FAIL'):
            raise WorkerBlocked('Worker receipt identity/state mismatch')
        if value['state'] == 'DONE' and (value.get('abi', 0) < 3 or
                value.get('scratch') != str(root) or value.get('identity') != list(pinned) or
                value.get('disposable_permission') is not permitted):
            raise WorkerBlocked('Worker Landlock/root receipt mismatch')
        identity(root, fd)
        write_json('/evidence/case-' + str(index).zfill(5) + '.result.json', value)
        return value
    finally:
        # Block repeated cancellation during owned child/adopted descendant reap.
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
        try:
            if pid != 0:
                reap_owned()
            for number in (fd, read_fd, write_fd, *logs):
                if number is not None:
                    os.close(number)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
