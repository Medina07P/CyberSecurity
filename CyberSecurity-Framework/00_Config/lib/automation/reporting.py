"""Explicit integration with engine 11; no parsers or implicit configuration."""
import os
from pathlib import Path
import stat
import sys
from uuid import uuid4

from .model import Command, Plan, PlanError, PreflightError, RuntimeContext, Step
from .planner import validate_plan


ENGINE_SOURCES = ('11_Reports/report_engine.py',
                  '00_Config/lib/postexploitation_evidence.py') + tuple(
    '11_Reports/lib/' + name + '.py' for name in (
        '__init__', 'attribution', 'catalog', 'engine', 'model', 'render', 'sources',
        'parsers/__init__', 'parsers/exploitation', 'parsers/ffuf', 'parsers/headers',
        'parsers/host_sources', 'parsers/http_inject', 'parsers/nikto', 'parsers/nmap',
        'parsers/nuclei', 'parsers/postexploitation', 'parsers/rate_limit',
        'parsers/sqli_findings', 'parsers/sqlmap'))
REPORT_FILES = ('findings.json', 'informe_tecnico.md', 'informe_tecnico.html',
                'informe_cliente.md', 'informe_cliente.html')


def report_preflight(step: Step, ctx: RuntimeContext) -> None:
    """Execution-only metadata checks; never import engine or read evidence."""
    from .adapters import _directory, _path, _regular
    step = validate_plan(Plan('report', (Step(step.id, step.action, step.inputs, ()),), 300)).steps[0]
    if step.action != 'report':
        raise PlanError('Se requiere un paso report')
    for relative in ENGINE_SOURCES:
        try:
            with _regular(ctx.framework / relative):
                pass
        except FileNotFoundError:
            raise PreflightError('Fuente requerida del motor de informes ausente: ' + relative) from None
    # No-follow traversal also rejects FIFOs/devices, even in ignored subtrees.
    def walk(path):
        with _directory(path) as fd:
            for name in os.listdir(fd):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    walk(path / name)
                elif not stat.S_ISREG(info.st_mode):
                    raise PreflightError('report_input contiene enlaces o archivos especiales')
    try:
        walk(_path(ctx, step.inputs['report_input']))
    except (OSError, RecursionError):
        raise PreflightError('Árbol report_input no legible o demasiado profundo') from None


def report_command(step: Step, run_dir: Path, ctx: RuntimeContext) -> Command:
    """Compile exactly three arguments; gates belong to adapters/preflight."""
    from .adapters import _directory, _path, _private_root, _private_write, child_env
    report_preflight(step, ctx)
    env = dict(child_env(ctx, run_dir))
    # The validated step ID is a basename and unique within the plan. Never
    # adopt an existing namespace, even when recompiling the same step.
    private = run_dir / ('report-' + step.id)
    with _directory(run_dir) as fd:
        _private_root(fd)
        os.mkdir(private.name, 0o700, dir_fd=fd)
    profile = _private_write(private, 'report-profile', b'')
    with _directory(private) as fd:
        _private_root(fd)
        os.mkdir('reports', 0o700, dir_fd=fd)
    env['REPORT_PROFILE'] = profile
    print('Aviso: report_input puede contener históricos; el informe no acredita '
          'que 09 haya ejecutado esas fases.', file=sys.stderr)
    return Command((str(ctx.python), '-I', '-B', str(ctx.framework / '11_Reports/report_engine.py'),
                    '--objetivo', step.inputs['target'],
                    '--scans', str(_path(ctx, step.inputs['report_input'])),
                    '--salida', str(private / 'reports'), '--tipo', 'ambos',
                    '--cliente', 'No indicado', '--auditor', 'No indicado'),
                   ctx.framework, env, 300)


def check_report_destination(destination: Path) -> tuple[int, int]:
    """Shim-only external destination: existing parent, NEW directory required."""
    from .adapters import _directory
    with _directory(destination.parent) as fd:
        try:
            os.stat(destination.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            info = os.fstat(fd)
            return info.st_dev, info.st_ino
    raise PlanError('Seleccione un directorio de salida nuevo; no se sobrescriben informes')


def _rename_noreplace(source_fd, source_name, destination_fd, destination_name):
    """Linux atomic publication; never fall back to replacing rename()."""
    import ctypes
    import errno
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        raise PreflightError('Publicación segura requiere renameat2 sin reemplazo')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source_name), destination_fd, os.fsencode(destination_name), 1):
        code = ctypes.get_errno()
        if code == errno.EXDEV:
            raise PreflightError('Publicación segura requiere destino en el mismo sistema de archivos del run')
        raise OSError(code, os.strerror(code))


def publish_reports(source: Path, destination: Path, parent_identity: tuple[int, int]) -> None:
    """Pin a private stage BEFORE exposing it; publish atomically, no replacement."""
    from .adapters import _directory, _regular, _private_root, _DIR
    with _directory(destination.parent) as parent:
        info = os.fstat(parent)
        if (info.st_dev, info.st_ino) != parent_identity:
            raise PreflightError('Ancestro de salida sustituido desde preflight')
        with _directory(source) as private:
            _private_root(private)
            stage = '.report-publication-' + uuid4().hex
            os.mkdir(stage, 0o700, dir_fd=private)
            fd = os.open(stage, _DIR, dir_fd=private)
            published = False
            try:
                _private_root(fd)
                pinned = os.fstat(fd)
                for name in REPORT_FILES:
                    with _regular(source / name) as incoming:
                        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                      0o600, dir_fd=fd)
                        with os.fdopen(out, 'wb') as stream:
                            while data := incoming.read(65536):
                                stream.write(data)
                _rename_noreplace(private, stage, parent, destination.name)
                published = True
                current = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                    raise PreflightError('Destino de informes sustituido')
            finally:
                try:
                    if not published:
                        # Only our fixed artifacts in the pinned private stage;
                        # never clean up or open a competing external directory.
                        for name in REPORT_FILES:
                            try:
                                os.unlink(name, dir_fd=fd)
                            except FileNotFoundError:
                                pass
                        os.rmdir(stage, dir_fd=private)
                finally:
                    os.close(fd)
