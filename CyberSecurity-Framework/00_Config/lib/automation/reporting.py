"""Explicit engine 11 commands and publication receipts; no evidence parsers."""
from contextlib import ExitStack
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import re
import stat
import sys
from uuid import uuid4

from .model import Command, Plan, PlanError, PreflightError, RuntimeContext, Step
from .planner import validate_plan


ENGINE_SOURCES = ('11_Reports/report_engine.py',
                  '00_Config/lib/postexploitation_evidence.py') + tuple(
    '11_Reports/lib/' + name + '.py' for name in (
        '__init__', 'attribution', 'catalog', 'coverage', 'engine',
        'exploitation_metadata', 'history', 'model', 'publication', 'render',
        'sources', 'validation',
        'parsers/__init__', 'parsers/exploitation', 'parsers/ffuf', 'parsers/headers',
        'parsers/host_sources', 'parsers/http_inject', 'parsers/nikto', 'parsers/nmap',
        'parsers/nuclei', 'parsers/postexploitation', 'parsers/prior_modules',
        'parsers/rate_limit', 'parsers/scanner_ports',
        'parsers/sqli_findings', 'parsers/sqlmap')) + tuple(
    '00_Config/lib/evidence/' + name + '.py'
    for name in ('__init__', 'inventory', 'model', 'storage'))
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
    """Compile explicit engine inputs and JSON receipt; gates belong to preflight."""
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
                    '--cliente', 'No indicado', '--auditor', 'No indicado', '--json'),
                   ctx.framework, env, 300)


def _receipt_object(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError('Clave duplicada en recibo')
        data[key] = value
    return data


def _receipt_constant(value):
    raise ValueError('Constante JSON no válida: ' + value)


def _receipt_read(stack, path):
    """Keep the no-follow file identity pinned through the whole validation."""
    from .adapters import _regular
    stream = stack.enter_context(_regular(path))
    info = os.fstat(stream.fileno())
    if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1):
        raise PreflightError('Recibo de informes no privado')
    raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Recibo de informes demasiado grande')
    data = json.loads(raw.decode('utf-8'), object_pairs_hook=_receipt_object,
                      parse_constant=_receipt_constant)
    if not isinstance(data, dict):
        raise ValueError('Se requiere un único objeto de recibo')
    return data


def _receipt_files(actual, expected):
    return (isinstance(actual, list) and all(isinstance(p, str) for p in actual)
            and sorted(actual) == sorted(expected))


def _receipt_utc(value):
    if not isinstance(value, str):
        raise ValueError('Fecha de recibo inválida')
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
        raise ValueError('Fecha UTC requerida en recibo')
    return stamp


def report_generation(run_dir: Path, step_id: str, target: str, rc: int) -> Path:
    """Resolve only this step's stdout receipt and its final private generation.

    Stdout paths are compared as strings, never used as authority for open().
    No engine import, directory discovery, latest selection or flat fallback.
    """
    from .adapters import _directory, _private_root, _regular
    from .validation import validate
    if (not isinstance(step_id, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,47}', step_id)
            or type(rc) is not int or rc not in (0, 3)):
        raise PreflightError('Paso o rc de informes inválido')
    try:
        if validate('target', target) != target:
            raise ValueError('Objetivo no canónico')
        run_dir = Path(run_dir)
        private = run_dir / ('report-' + step_id)
        with ExitStack() as stack:
            # Pin/check every private directory until all file checks complete.
            for path in (run_dir, run_dir / 'logs', private, private / 'reports',
                         private / 'reports/runs'):
                _private_root(stack.enter_context(_directory(path)))
            summary = _receipt_read(stack, run_dir / 'logs' / (step_id + '.stdout.log'))
            if (set(summary) != {'objetivo', 'hallazgos', 'criticos', 'no_evaluable',
                                'salida', 'archivos', 'run_id'}
                    or summary['objetivo'] != target
                    or any(type(summary[key]) is not int or summary[key] < 0
                           for key in ('hallazgos', 'criticos', 'no_evaluable'))):
                raise ValueError('Resumen de informes inválido')
            run_id = summary['run_id']
            if (not isinstance(run_id, str)
                    or not re.fullmatch(r'run-[0-9]{8}T[0-9]{12}Z-[0-9a-f]{32}', run_id)):
                raise ValueError('Identidad de generación inválida')
            generation = private / 'reports/runs' / run_id
            names = (*REPORT_FILES, 'run.json')
            if (summary['salida'] != str(generation)
                    or not _receipt_files(summary['archivos'], [str(generation / n) for n in names])):
                raise ValueError('Rutas del resumen ajenas a este paso')
            _private_root(stack.enter_context(_directory(generation)))
            receipt = _receipt_read(stack, generation / 'run.json')
            if (set(receipt) != {'schema_version', 'module', 'run_id', 'started_at',
                                'finished_at', 'objetivo', 'modo', 'tipo', 'entrada',
                                'estado', 'rc', 'archivos'}
                    or type(receipt['schema_version']) is not int or receipt['schema_version'] != 1
                    or receipt['module'] != '11' or receipt['run_id'] != run_id
                    or receipt['objetivo'] != target or receipt['modo'] != 'objetivo'
                    or receipt['tipo'] != 'ambos' or receipt['entrada'] != 'scans'
                    or type(receipt['rc']) is not int or receipt['rc'] != rc
                    or receipt['estado'] != ('COMPLETADO' if rc == 0 else 'NO_EVALUABLE')
                    or not _receipt_files(receipt['archivos'], REPORT_FILES)):
                raise ValueError('Recibo final incongruente con este paso')
            if _receipt_utc(receipt['finished_at']) < _receipt_utc(receipt['started_at']):
                raise ValueError('Fechas del recibo fuera de orden')
            for name in REPORT_FILES:
                stream = stack.enter_context(_regular(generation / name))
                info = os.fstat(stream.fileno())
                if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_nlink != 1):
                    raise PreflightError('Archivo de informes no privado')
        return generation
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise PreflightError('Generación de informes ausente o inválida: ' + str(exc)) from None


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
