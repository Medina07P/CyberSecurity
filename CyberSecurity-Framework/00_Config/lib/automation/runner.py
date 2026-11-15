"""Sequential Linux executor; backend compilation/preflight belongs to Task4."""
from dataclasses import asdict
from datetime import datetime, timezone
import os
from pathlib import Path
import signal
import subprocess
import time
from typing import Callable

from .model import Command, Permissions, Plan, RunResult, RuntimeContext, Step, StepResult
from .storage import RunStore

_SIGNALS = {signal.SIGINT, signal.SIGTERM}
_POLL = 0.05
_GRACE = 2.0


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _plain(value):
    if hasattr(value, 'items'):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _exited(process):
    # WNOWAIT is essential: Popen.poll()/wait() would release the PGID anchor.
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def _live_group(pgid):
    """Linux group census, ignoring zombies (not executable survivors)."""
    for name in os.listdir('/proc'):
        if not name.isdecimal():
            continue
        try:
            text = Path('/proc', name, 'stat').read_text()
            fields = text[text.rfind(')') + 2:].split()
            if int(fields[2]) == pgid and fields[0] not in ('Z', 'X'):
                return True
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return False


def _finish_group(process):
    """Never reap the session leader until every group signal has been sent."""
    if process.returncode is not None:
        raise ChildProcessError('Identidad del líder ya liberada')
    # Verify direct-child ownership before any signal, including when another
    # waiter or an inherited SIGCHLD disposition has already reaped it.
    _exited(process)
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    end = time.monotonic() + _GRACE
    try:
        while _live_group(process.pid) and time.monotonic() < end:
            time.sleep(_POLL)
    finally:
        # The unreaped direct child pins this PID/PGID even if it already exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            # KILL is asynchronous. Keep the leader's identity pinned until
            # members no longer execute, not merely until KILL was delivered.
            while _live_group(process.pid):
                time.sleep(_POLL)
        finally:
            process.wait()


def run_plan(plan: Plan, ctx: RuntimeContext, permissions: Permissions,
             compile_step: Callable[[Step, Path], tuple[Command, ...]]) -> RunResult:
    """Compile one step at a time. Permissions are not persisted or inferred here.

    Call from the main thread. Compiler closure owns preflight and permission
    checks; only its fixed Commands are executable, never plan/YAML strings.
    """
    cancelled = 0

    def mark(signum, frame):
        nonlocal cancelled
        if not cancelled:
            cancelled = signum

    previous = {}
    store = None
    process = None
    results = []
    rc = 0
    reason = ''
    reason_code = 'completed'
    stage = 'setup_failed'
    current = None
    executing = False
    raw = None
    started = _timestamp()
    deadline = time.monotonic() + plan.timeout

    def save(finished=False):
        recorded = {item.id: item for item in results}
        snapshot = [recorded.get(step.id, StepResult(
            step.id, 'ejecutando' if executing and current == step else 'pendiente',
            None, '')) for step in plan.steps]
        store.write_state({
            'schema_version': 1, 'run_id': store.path.name,
            'plan': {'name': plan.name, 'timeout': plan.timeout, 'steps': [
                {'id': step.id, 'action': step.action, 'inputs': _plain(step.inputs),
                 'depends_on': list(step.depends_on)} for step in plan.steps]},
            'started_at': started, 'updated_at': _timestamp(),
            'finished_at': _timestamp() if finished else None,
            'rc': rc if finished else None, 'reason': reason,
            'steps': [asdict(item) for item in snapshot],
        })

    try:
        for sig in _SIGNALS:
            previous[sig] = signal.signal(sig, mark)
        if not plan.steps:
            return RunResult(2, None, (), 'setup_failed')
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise RuntimeError('SIGCHLD debe conservar la identidad del hijo (SIG_DFL)')
        stage = 'storage_failed'
        store = RunStore.create(ctx.repo)
        save()
        for step in plan.steps:
            current = step
            raw = None
            if cancelled:
                rc, reason = 128 + cancelled, 'Cancelado por señal'
                reason_code = 'cancelled'
                break
            if time.monotonic() >= deadline:
                rc, reason = 1, 'Timeout global'
                reason_code = 'timeout'
                break
            stage = 'setup_failed'
            commands = compile_step(step, store.path)
            if not commands:
                raise ValueError('Compilador no produjo comandos')
            stage = 'storage_failed'
            with store.open_log(step.id, 'stdout') as stdout, store.open_log(step.id, 'stderr') as stderr:
                for command in commands:
                    store.check()
                    if cancelled:
                        rc, reason = 128 + cancelled, 'Cancelado por señal'
                        reason_code = 'cancelled'
                        break
                    end = min(deadline, time.monotonic() + command.timeout)
                    if time.monotonic() >= end:
                        rc, reason = 1, 'Timeout global/comando'
                        reason_code = 'timeout'
                        break
                    # Handlers ONLY set the flag: no exception, wait or cleanup
                    # can interrupt check/spawn/publication. A signal inside
                    # Popen is acted on immediately after its return. Blocking
                    # here would leak a blocked TERM/INT mask to the backend.
                    stage = 'backend_failed'
                    process = subprocess.Popen(
                        command.argv, cwd=command.cwd, env=dict(command.env),
                        stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                        shell=False, start_new_session=True)
                    executing = True
                    try:
                        stage = 'storage_failed'
                        save()
                        while True:
                            if cancelled:
                                rc, reason = 128 + cancelled, 'Cancelado por señal'
                                reason_code = 'cancelled'
                                break
                            if time.monotonic() >= end:
                                rc, reason = 1, 'Timeout global/comando'
                                reason_code = 'timeout'
                                break
                            if _exited(process):
                                break
                            store.check()
                            time.sleep(_POLL)
                    finally:
                        _finish_group(process)
                        raw = process.returncode
                        process = None
                        executing = False
                    if cancelled:
                        rc, reason = 128 + cancelled, 'Cancelado por señal'
                        reason_code = 'cancelled'
                    if rc:
                        break
                    if raw != 0:
                        rc, reason = 1, 'Backend devolvió rc no cero'
                        reason_code = 'backend_failed'
                        break
                os.fsync(stdout.fileno())
                os.fsync(stderr.fileno())
            state = 'cancelado' if cancelled else ('fallido' if rc else 'completado')
            results.append(StepResult(step.id, state, raw, reason))
            current = None
            save()
            if rc:
                break
    except Exception as exc:
        rc, reason = (128 + cancelled if cancelled else 1), f'{type(exc).__name__}: {exc}'
        reason_code = 'cancelled' if cancelled else stage
    finally:
        try:
            if process is not None:
                _finish_group(process)
            if cancelled:
                rc, reason = 128 + cancelled, 'Cancelado por señal'
                reason_code = 'cancelled'
            if current is not None and all(item.id != current.id for item in results):
                results.append(StepResult(current.id, 'cancelado' if cancelled else 'fallido', raw, reason))
            done = {item.id for item in results}
            results.extend(StepResult(step.id, 'omitido', None, reason or 'Paso anterior fallido')
                           for step in plan.steps if step.id not in done)
            if store is not None:
                try:
                    save(finished=True)
                    if cancelled and rc != 128 + cancelled:
                        rc, reason = 128 + cancelled, 'Cancelado por señal'
                        save(finished=True)
                except Exception as exc:
                    rc = 128 + cancelled if cancelled else 1
                    reason_code = 'cancelled' if cancelled else 'storage_failed'
                    reason = f'Error de almacenamiento: {exc}'
                    attempted = [i for i, item in enumerate(results) if item.state != 'omitido']
                    if attempted:
                        index = attempted[-1]
                        last = results[index]
                        results[index] = StepResult(last.id, 'cancelado' if cancelled else 'fallido', last.rc, reason)
        finally:
            if store is not None:
                try:
                    store.close()
                except OSError:
                    rc = 128 + cancelled if cancelled else 1
                    reason_code = 'cancelled' if cancelled else 'storage_failed'
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    if cancelled:
        rc = 128 + cancelled
        reason_code = 'cancelled'
    return RunResult(rc, store.path if store else None, tuple(results), reason_code)
