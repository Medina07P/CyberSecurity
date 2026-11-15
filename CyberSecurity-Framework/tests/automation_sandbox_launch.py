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

# -I deliberately omits the script directory. Add only the directory derived
# from this trusted entry script, before sibling imports; no host site paths,
# environment search path, working-directory lookup or dependency installation.
sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent))

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
          (resource.RLIMIT_NOFILE, 256), (resource.RLIMIT_FSIZE, 64 * 1024**2))


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
    inherited_nproc = resource.getrlimit(resource.RLIMIT_NPROC)
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
                # Trusted namespace bootstrap inherits the host ceiling. Never
                # set/raise it here; earliest inside gate imposes hard=soft256.
                if resource.getrlimit(resource.RLIMIT_NPROC) != inherited_nproc:
                    raise IsolationBlocked('Bootstrap NPROC inheritance changed')
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
    if len(argv) == 1 and argv[0] in ('--probes', '--suite', '--races', '--cross-consent', '--cross-web', '--cross-local'):
        return argv[0]
    raise IsolationBlocked('Only --probes, --suite, --races, --cross-consent, --cross-web or --cross-local is accepted')


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


def _host_uid_tasks(uid):
    """Procfs metadata only: sum Threads for real UID, not process count.

    Snapshot, NOT kernel ucounts/pids.max or a reserved allowance. Vanished PIDs
    can be skipped; denied/ambiguous metadata blocks rather than guessing.
    """
    total = 0
    for name in os.listdir('/proc'):
        if not name.isdecimal():
            continue
        try:
            fields = {}
            with open('/proc/' + name + '/status', encoding='ascii') as status:
                for line in status:
                    key, _, value = line.partition(':')
                    if key in ('Uid', 'Threads'):
                        fields[key] = [int(part) for part in value.split()]
        except FileNotFoundError:
            continue
        if (set(fields) != {'Uid', 'Threads'} or len(fields['Uid']) != 4 or
                len(fields['Threads']) != 1 or fields['Threads'][0] < 1):
            raise IsolationBlocked('UID task metadata incomplete')
        if fields['Uid'][0] == uid:
            total += fields['Threads'][0]
    if total < 1:
        raise IsolationBlocked('UID task accounting not observable')
    return total


def _bootstrap_nproc():
    uid = os.getuid()
    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    if uid == 0 or os.geteuid() != uid:
        raise IsolationBlocked('NPROC requires nonroot real/effective identity')
    if any(value != resource.RLIM_INFINITY and value < 256 for value in (soft, hard)):
        raise IsolationBlocked('Inherited NPROC cannot admit workload hard256')
    consumed = _host_uid_tasks(uid)
    if soft != resource.RLIM_INFINITY and consumed >= soft:
        raise IsolationBlocked('Inherited host NPROC already exhausted')
    return {'uid': uid, 'soft': soft, 'hard': hard,
            'observed_uid_tasks': consumed, 'counter_scope': 'host-proc-visible-real-uid-threads',
            'user_namespace': os.readlink('/proc/self/ns/user'),
            'workload_soft_hard': [256, 256], 'bootstrap_policy': 'inherit-without-raising'}


def _validate_descendant_nproc(record, baseline):
    """Host checks inherited AND effective evidence, never accepts repair."""
    if (not isinstance(record, dict) or
            record.get('inherited_soft_hard') != [256, 256] or
            any(type(record.get(key)) is not int for key in
                ('soft', 'hard', 'uid', 'euid', 'observed_uid_tasks')) or
            record.get('soft') != 256 or record.get('hard') != 256 or
            record.get('uid') != record.get('euid') or record.get('uid') != baseline['uid'] or
            record.get('uid_map') != baseline['uid_map'] or
            record.get('uid_map_scope') != baseline['uid_map_scope'] or
            record.get('identity_canary') != baseline['identity_canary'] or
            record.get('user_namespace') != baseline['user_namespace'] or
            record.get('capabilities') != baseline['capabilities'] or
            record.get('counter_scope') != baseline['counter_scope'] or
            not 1 <= record['observed_uid_tasks'] < 256):
        raise IsolationBlocked('Descendant inherited NPROC/identity evidence not established')


def _validate_probe_nproc(probes, baseline):
    try:
        descendants = probes['descendants']
        if (not isinstance(descendants, list) or len(descendants) != 3 or
                {row['role'] for row in descendants} !=
                {'python-child', 'bash-grandchild', 'bash-child'}):
            raise IsolationBlocked('Incomplete NPROC descendant observations')
        for row in descendants:
            _validate_descendant_nproc(row['nproc'], baseline)
            _validate_descendant_nproc(row['nproc']['entry'], baseline)
        cancel = probes['cancel']
        if cancel['descendant_reaped'] is not True or cancel['direct_child_reaped'] is not True:
            raise IsolationBlocked('Cancel descendant not reaped')
        _validate_descendant_nproc(cancel['worker_nproc'], baseline)
        _validate_descendant_nproc(cancel['worker_nproc']['entry'], baseline)
        _validate_descendant_nproc(cancel['fork_nproc'], baseline)
    except (KeyError, TypeError) as exc:
        raise IsolationBlocked('Incomplete descendant/cancel NPROC evidence') from exc


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


def _canary_metadata(info):
    return {key: getattr(info, 'st_' + key) for key in
            ('dev', 'ino', 'mode', 'size', 'uid', 'gid', 'nlink', 'mtime_ns', 'ctime_ns')}


def _create_identity_canary(run):
    path = run.work / 'identity-canary'
    output = _new_log(path)
    try:
        data = run.root.name.encode('ascii')
        if os.write(output, data) != len(data):
            raise IsolationBlocked('Short synthetic identity canary write')
        os.fchmod(output, 0o400)
        os.fsync(output)
        identity = _canary_metadata(os.fstat(output))
    finally:
        os.close(output)
    fd, parent, _ = _open_regular(path)
    try:
        if _canary_metadata(os.fstat(fd)) != identity:
            raise IsolationBlocked('Identity canary changed during pinning')
        return fd, parent, identity
    except BaseException:
        os.close(fd)
        os.close(parent)
        raise


def _named_canary_metadata(path):
    directory = _open_directory(path.parent)  # no-follow every host component
    try:
        return _canary_metadata(os.stat(path.name, dir_fd=directory, follow_symlinks=False))
    finally:
        os.close(directory)


def _validate_identity_canary(path, fd, expected, record):
    """Pinned original AND named host file unchanged; VFS composes identity."""
    try:
        inside = record['identity_canary']['inside']
        mapping = record['uid_map']
        if (_canary_metadata(os.fstat(fd)) != expected or
                _named_canary_metadata(path) != expected or
                expected['uid'] != os.getuid() or expected['uid'] <= 0 or
                expected['mode'] != (stat.S_IFREG | 0o400) or expected['nlink'] != 1 or
                expected['size'] <= 0 or set(inside) != set(expected) or
                any(type(value) is not int for value in inside.values()) or
                record['identity_canary']['host'] != expected or
                record['uid_map_scope'] != 'immediate-parent-user-namespace' or
                not isinstance(mapping, list) or len(mapping) != 1 or
                not isinstance(mapping[0], list) or len(mapping[0]) != 3 or
                any(type(v) is not int for v in mapping[0]) or
                mapping[0][0] != record['uid'] or mapping[0][1] < 0 or mapping[0][2] != 1 or
                record['uid'] <= 0 or record['uid'] != record['euid'] or
                inside['uid'] != record['uid'] or
                any(inside[key] != expected[key] for key in
                    ('dev', 'ino', 'mode', 'size', 'nlink', 'mtime_ns', 'ctime_ns'))):
            raise IsolationBlocked('Synthetic canary identity composition not established')
    except (KeyError, TypeError, IndexError) as exc:
        raise IsolationBlocked('Incomplete synthetic identity proof') from exc


def _probe_inputs(run, identity_canary):
    """Exclusive synthetic inputs; siblings outside mounts, no host data reads."""
    for path, content, mode in (
            (run.root / 'outside-canary', run.root.name.encode(), 0o600),
            (run.work / 'inside-canary', run.root.name.encode(), 0o600),
            (run.root / 'external-double',
             ('#!/bin/bash\nprintf synthetic > ' +
              str(run.root / 'external-marker') + '\n').encode(), 0o500)):
        fd = _new_log(path)
        try:
            view = memoryview(content)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise IsolationBlocked('Short synthetic input write')
                view = view[count:]
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
    _new_json(run.work / 'probe-context.json', {
        'version': 1, 'run_id': run.root.name,
        'outside_canary': str(run.root / 'outside-canary'),
        'external_stub': str(run.root / 'external-double'),
        'external_marker': str(run.root / 'external-marker'),
        'host_namespaces': {name: os.readlink('/proc/self/ns/' + name)
                            for name in ('mnt', 'pid', 'net', 'user', 'ipc',
                                         'uts', 'cgroup')},
        'host_uid': os.getuid(),
        'identity_canary': identity_canary,
    })


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
        for name in ('home', 'tmp', 'fixtures'):
            (run.work / name).mkdir(mode=0o700)
        # Synthetic siblings are outside all mounts; the marker double is never
        # executed, even if unexpectedly visible. All failed artifacts retained.
        canary_path = run.work / 'identity-canary'
        canary_fd, canary_parent, canary_identity = _create_identity_canary(run)
        descriptors.extend((canary_fd, canary_parent))
        _probe_inputs(run, canary_identity)
        seccomp_fd = _seccomp_memfd()
        descriptors.append(seccomp_fd)
        argv = bubblewrap_argv(run, seccomp_fd) + (selector,)
        bootstrap_nproc = _bootstrap_nproc()
        _new_json(run.evidence / 'launch.json', {
            'version': 1, 'state': 'STARTING', 'argv': list(argv),
            'bwrap': bwrap_record, 'host_timeout': HOST_TIMEOUT,
            'suite_timeout': 600, 'races_timeout': 240, 'probe_timeout': 10,
            'cross_consent_timeout': 600,
            'runtime_executed': False,
            'bootstrap_nproc': bootstrap_nproc,
            'identity_canary': canary_identity,
        })
        stdout = _new_log(run.evidence / 'stdout.log')
        descriptors.append(stdout)
        stderr = _new_log(run.evidence / 'stderr.log')
        descriptors.append(stderr)
        if pending:
            return 128 + pending[0]
        if time.monotonic() >= host_deadline:
            raise IsolationBlocked('Host budget exhausted before payload')
        if resource.getrlimit(resource.RLIMIT_NPROC) != (bootstrap_nproc['soft'], bootstrap_nproc['hard']):
            raise IsolationBlocked('Host NPROC changed before bootstrap')
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
        if (run.root / 'external-marker').exists():
            raise IsolationBlocked('External synthetic marker unexpectedly exists')
        if receipt['state'] == 'PASS' or (receipt['state'] == 'BLOCKED' and result == 2):
            workload = load_json(run.evidence / 'workload-nproc.json', {
                'version', 'soft', 'hard', 'uid', 'euid', 'uid_map', 'user_namespace',
                'capabilities', 'observed_uid_tasks', 'counter_scope', 'inherited_soft_hard',
                'uid_map_scope', 'identity_canary'})
            _validate_identity_canary(canary_path, canary_fd, canary_identity, workload)
            if (any(type(workload[key]) is not int for key in
                    ('soft', 'hard', 'uid', 'euid', 'observed_uid_tasks')) or
                    not isinstance(workload['capabilities'], dict) or
                    workload['counter_scope'] != 'private-proc-visible-real-uid-threads' or
                    not isinstance(workload['user_namespace'], str) or
                    workload['soft'] != 256 or workload['hard'] != 256 or
                    workload['uid'] != workload['euid'] or workload['uid'] <= 0 or
                    workload['user_namespace'] == bootstrap_nproc['user_namespace'] or
                    workload['inherited_soft_hard'] != [bootstrap_nproc['soft'], bootstrap_nproc['hard']] or
                    set(workload['capabilities']) != {'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'} or
                    any(workload['capabilities'].values()) or
                    not 1 <= workload['observed_uid_tasks'] < 256):
                raise IsolationBlocked('Workload NPROC receipt not established')
            probes = load_json(run.evidence / 'probes.json', {
                'version', 'run_id', 'state', 'checks', 'context', 'namespaces',
                'descendants', 'cancel', 'entry_fds', 'nproc'})
            if (probes['run_id'] != run.root.name or probes['state'] != 'PASS' or
                    probes['entry_fds'] != {'valid': True, 'observed': [0, 1, 2, 3],
                                           'live': [0, 1, 2], 'closed_transient': [3]} or
                    not isinstance(probes['checks'], list) or
                    {row.get('id') for row in probes['checks'] if isinstance(row, dict)} !=
                    {'entry-fds', 'workload-nproc', 'python-child', 'bash-grandchild', 'bash-child',
                     'cancel-owned-descendants'} or
                    len(probes['checks']) != 6 or
                    any(not isinstance(row, dict) or set(row) != {'id', 'result', 'reason'} or
                        row['result'] != 'PASS' for row in probes['checks'])):
                raise IsolationBlocked('Fresh probe result missing or inconsistent')
            _validate_probe_nproc(probes, workload)
            _validate_identity_canary(canary_path, canary_fd, canary_identity, workload)
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
