"""The fixed local cleanup plan and truthful per-operation results.

Consent is checked by cleanup_cli before calling this internal execution API.
No target/session, environment permission, sudo or destination override is read.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import subprocess
import uuid

from . import files


@dataclass(frozen=True)
class CleanupOperation:
    kind: str
    path: Path | None


@dataclass(frozen=True)
class OperationResult:
    operation: CleanupOperation
    success: bool
    error: str | None = None


@dataclass(frozen=True)
class CleanupResult:
    rc: int
    operations: tuple[OperationResult, ...]
    report_dir: Path


def plan_cleanup(home: Path) -> tuple[CleanupOperation, ...]:
    """Describe original capabilities only, without inspecting any destination."""
    return tuple(CleanupOperation('truncate', Path('/var/log') / name)
                 for name in ('auth.log', 'syslog', 'btmp', 'wtmp')) + (
        CleanupOperation('history', Path(home) / '.bash_history'),
        CleanupOperation('child-history', None), CleanupOperation('snapshot', None))


class CleanupOps:
    """Existing operations with current credentials; permission failure is final.

    In particular, never validate here and then sudo/truncate the pathname:
    that would reopen an attacker-swappable name with additional authority.
    """
    def perform(self, operation: CleanupOperation, child: Path) -> bytes | None:
        if operation.kind == 'truncate' and operation.path not in (
                Path('/var/log/auth.log'), Path('/var/log/syslog'),
                Path('/var/log/btmp'), Path('/var/log/wtmp')):
            raise ValueError('Log fuera del plan LOCAL fijo')
        if operation.kind == 'history' and operation.path != Path.home() / '.bash_history':
            raise ValueError('Historial fuera del plan LOCAL fijo')
        if operation.kind in ('child-history', 'snapshot') and operation.path is not None:
            raise ValueError('Operación sin destino de archivo')
        if operation.kind in ('truncate', 'history'):
            files.truncate_regular(operation.path)
        elif operation.kind == 'child-history':
            # -p also ignores BASH_ENV, exported functions and inherited options.
            subprocess.run(['/bin/bash', '--noprofile', '--norc', '-p', '-c',
                            'history -c'], check=True, stdin=subprocess.DEVNULL)
        elif operation.kind == 'snapshot':
            # Same last -a capability, bounded to ten entries/ten output lines.
            # stderr remains visible; stdout is never printed by this core.
            result = subprocess.run(['last', '-a', '-n', '10'], check=True,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
            return b''.join(result.stdout.splitlines(keepends=True)[:10])
        else:
            raise ValueError('Operación de cleanup desconocida')
        return None


def apply_cleanup(plan, report_root: Path, ops: CleanupOps | None = None) -> CleanupResult:
    """Allocate a fresh report child, execute all rows, retain partial failures.

    report_root is the BASE scans/cleanup, not a preallocated report. The open
    child descriptor is retained throughout, so snapshot publication does not
    reopen a substituted directory. No rollback/deletion of partial artifacts.
    """
    ops = CleanupOps() if ops is None else ops
    report_root = Path(report_root)
    rows = []
    with files.directory(report_root, create=True) as base:
        info = os.fstat(base)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError('Base de informes no propia o escribible por terceros')
        name = uuid.uuid4().hex
        os.mkdir(name, mode=0o700, dir_fd=base)  # exclusive; no reuse on collision
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                           os.O_CLOEXEC, dir_fd=base)
        try:
            os.fchmod(child_fd, 0o700)
            child = report_root / name
            for operation in plan:
                try:
                    payload = ops.perform(operation, child)
                    if operation.kind == 'snapshot':
                        files.publish_private(child_fd, 'last_access.txt', payload)
                    elif payload is not None:
                        raise ValueError('Salida inesperada de operación')
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    rows.append(OperationResult(operation, False, str(exc)))
                else:
                    rows.append(OperationResult(operation, True))
        finally:
            os.close(child_fd)
    return CleanupResult(0 if all(row.success for row in rows) else 1, tuple(rows), child)
