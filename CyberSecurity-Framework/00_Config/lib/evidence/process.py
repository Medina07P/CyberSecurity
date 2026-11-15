"""Linux owned-session supervision; streams never enter controller memory.

Run from the main thread, one invocation at a time. A temporary Linux subreaper
lets us reap orphaned members of our group, never unrelated children. Explicit
setsid/setpgid escapes by hostile backends are outside this containment boundary.
"""
import ctypes
from dataclasses import dataclass
import math
import os
from pathlib import Path
import signal
import subprocess
import time

from .model import EvidenceError
from .storage import _directory, private_directory


@dataclass
class ProcessResult:
    """stopped_by is the last signal sent, including normal interval SIGINT.

    A zero leader rc alone is never sufficient for publication: consumers must
    reject forced TERM/KILL and residual-group cleanup. Only an explicitly
    requested traffic interval may interpret its normal SIGINT as planned.
    """
    returncode: int
    timed_out: bool
    stopped_by: str | None


class CaptureInterrupted(EvidenceError):
    def __init__(self, signum: int):
        self.signum = signum
        super().__init__(f'ADQUISICIÓN INTERRUMPIDA: {signum}')


def _stream(path):
    path = Path(path).absolute()
    private_directory(path.parent)
    with _directory(path.parent) as parent:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'wb', buffering=0)


def run_child(argv: list[str], stdout: Path, stderr: Path, *, timeout: float,
              interval_stop: bool = False) -> ProcessResult:
    if (not isinstance(argv, list) or not argv or
            any(not isinstance(arg, str) or '\x00' in arg for arg in argv) or
            not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
            not math.isfinite(timeout) or timeout <= 0):
        raise EvidenceError('ARGUMENTOS/DEADLINE INVÁLIDOS')
    interrupted = None
    handlers = {}
    child = None
    libc = ctypes.CDLL(None, use_errno=True)
    prior = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(prior), 0, 0, 0) != 0:
        raise EvidenceError('NO SE PUEDE CONSULTAR SUBREAPER LINUX')

    def receive(signum, frame):
        nonlocal interrupted
        if interrupted is None:
            interrupted = signum

    def alive():
        child.poll()  # Popen alone reaps its leader and preserves returncode.
        while child.returncode is not None:
            try:
                pid, _ = os.waitpid(-child.pid, os.WNOHANG)
                if not pid:
                    break
            except ChildProcessError:
                break
        try:
            os.killpg(child.pid, 0)
            return True
        except ProcessLookupError:
            return False

    def send(signum):
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass

    def stop(first):
        last = None
        sequence = [(signal.SIGINT, 2), (signal.SIGTERM, 2)] if first == signal.SIGINT else [(signal.SIGTERM, 2)]
        sequence.append((signal.SIGKILL, None))
        for signum, grace in sequence:
            if not alive():
                break
            send(signum)
            last = signal.Signals(signum).name
            deadline = time.monotonic() + grace if grace is not None else None
            while alive():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                time.sleep(.01)
        child.wait()
        return last

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            handlers[signum] = signal.signal(signum, receive)
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise EvidenceError('NO SE PUEDE ACTIVAR SUBREAPER LINUX')
        with _stream(stdout) as out, _stream(stderr) as err:
            child = subprocess.Popen(argv, stdout=out, stderr=err, start_new_session=True)
            deadline = time.monotonic() + timeout
            stopped_by, timed_out = None, False
            while True:
                if interrupted is not None:
                    stop(signal.SIGTERM)
                    raise CaptureInterrupted(interrupted)
                if child.poll() is not None:
                    if alive():
                        stopped_by = stop(signal.SIGTERM)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    stopped_by = stop(signal.SIGINT if interval_stop else signal.SIGTERM)
                    break
                time.sleep(.01)
            if interrupted is not None:
                raise CaptureInterrupted(interrupted)
            return ProcessResult(child.returncode, timed_out, stopped_by)
    except OSError as exc:
        raise EvidenceError(f'PROCESO FALLIDO: {exc}') from exc
    finally:
        try:
            if child is not None and alive():
                stop(signal.SIGTERM)
        finally:
            libc.prctl(36, prior.value, 0, 0, 0)
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
