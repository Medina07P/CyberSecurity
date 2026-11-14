"""Generaciones exclusivas de informes; recibo de publicación, no de auditoría."""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from uuid import uuid4

from .coverage import regular
from .exploitation_metadata import read_object
from .publication import preflight, write_private
from .validation import target

FIELDS = {'schema_version', 'module', 'run_id', 'started_at', 'finished_at', 'objetivo',
          'modo', 'tipo', 'entrada', 'estado', 'rc', 'archivos'}


@dataclass(frozen=True)
class ReportRun:
    path: Path
    run_id: str
    metadata: dict


def now() -> datetime:
    return datetime.now(timezone.utc)


def expected(tipo: str) -> list[str]:
    if tipo not in ('tecnico', 'cliente', 'ambos'):
        raise ValueError('tipo de informe inválido')
    types = ('tecnico', 'cliente') if tipo == 'ambos' else (tipo,)
    return ['findings.json'] + [f'informe_{t}.{ext}' for t in types for ext in ('md', 'html')]


def _utc(value):
    if not isinstance(value, str):
        raise ValueError('fecha inválida')
    date = datetime.fromisoformat(value)
    if date.tzinfo is None or date.utcoffset().total_seconds() != 0:
        raise ValueError('fecha UTC requerida')
    return date


def _validate(data, path):
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ValueError('recibo inválido')
    if type(data['schema_version']) is not int or data['schema_version'] != 1 or data['module'] != '11':
        raise ValueError('versión/módulo inválido')
    if (not isinstance(data['run_id'], str) or data['run_id'] != path.name
            or not re.fullmatch(r'run-\d{8}T\d{12}Z-[0-9a-f]{32}', data['run_id'])):
        raise ValueError('identidad inválida')
    start = _utc(data['started_at'])
    if not isinstance(data['modo'], str) or data['modo'] not in ('objetivo', 'todos', 'incluir_sin_objetivo'):
        raise ValueError('modo inválido')
    if not isinstance(data['entrada'], str) or data['entrada'] not in ('scans', 'json'):
        raise ValueError('entrada inválida')
    if not isinstance(data['objetivo'], str):
        raise ValueError('objetivo inválido')
    if data['objetivo']:
        target(data['objetivo'])
    elif data['modo'] != 'todos':
        raise ValueError('objetivo requerido')
    names = expected(data['tipo'])
    if data['estado'] == 'ESCRIBIENDO':
        if data['finished_at'] is not None or data['rc'] is not None or data['archivos'] != []:
            raise ValueError('estado inicial inválido')
    else:
        if type(data['rc']) is not int or (data['estado'], data['rc']) not in (('COMPLETADO', 0), ('NO_EVALUABLE', 3)):
            raise ValueError('estado final inválido')
        if _utc(data['finished_at']) < start:
            raise ValueError('orden temporal inválido')
        if (not isinstance(data['archivos'], list) or not all(isinstance(p, str) for p in data['archivos'])
                or sorted(data['archivos']) != sorted(names)):
            raise ValueError('lista de archivos inválida')


def _mkdir(path):
    preflight(path, [])
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
        preflight(directory, [])


def reserve(base: Path, objetivo: str | None, modo: str, tipo: str, entrada: str) -> ReportRun:
    stamp = now()
    run_id = f'run-{stamp.strftime("%Y%m%dT%H%M%S%fZ")}-{uuid4().hex}'
    path = Path(base).absolute() / 'runs' / run_id
    data = {'schema_version': 1, 'module': '11', 'run_id': run_id,
            'started_at': stamp.isoformat(), 'finished_at': None, 'objetivo': objetivo or '',
            'modo': modo, 'tipo': tipo, 'entrada': entrada, 'estado': 'ESCRIBIENDO',
            'rc': None, 'archivos': []}
    _validate(data, path)
    _mkdir(path.parent)
    path.mkdir(mode=0o700)  # Exclusivo: una colisión no es un permiso para reutilizar.
    write_private(path / 'run.json', json.dumps(data, indent=2, ensure_ascii=False))
    return ReportRun(path, run_id, data)


def finish(run: ReportRun, files: list[Path], rc: int) -> Path:
    preflight(run.path, ['run.json'])
    current = read_object(run.path / 'run.json')
    _validate(current, run.path)
    if current != run.metadata or current['estado'] != 'ESCRIBIENDO' or run.run_id != run.path.name:
        raise ValueError('el run no está pendiente de publicación')
    if type(rc) is not int or rc not in (0, 3):
        raise ValueError('rc de publicación inválido')
    names = expected(current['tipo'])
    paths = [Path(p).absolute() for p in files]
    if (any(p.parent != run.path or p.name not in names for p in paths)
            or sorted(p.name for p in paths) != sorted(names)):
        raise ValueError('archivos no corresponden a este run/tipo')
    for path in paths:
        regular(path)
    data = dict(current, estado='COMPLETADO' if rc == 0 else 'NO_EVALUABLE', rc=rc,
                finished_at=now().isoformat(), archivos=names)
    _validate(data, run.path)
    receipt = run.path / 'run.json'
    write_private(receipt, json.dumps(data, indent=2, ensure_ascii=False))
    return receipt


def published(run_dir: Path) -> bool:
    try:
        path = Path(run_dir).absolute()
        data = read_object(path / 'run.json')
        _validate(data, path)
        if data['estado'] == 'ESCRIBIENDO':
            return False
        for name in data['archivos']:
            regular(path / name)
        return True
    except (OSError, ValueError, TypeError, KeyError):
        return False


def has_published(base: Path) -> bool:
    try:
        base = Path(base).absolute()
        preflight(base, [])
        if not base.is_dir():
            return False
        for target_dir in sorted(base.iterdir()):
            runs = target_dir / 'runs'
            if target_dir.is_symlink() or runs.is_symlink() or not runs.is_dir():
                continue
            if any(published(p) for p in sorted(runs.iterdir()) if p.name.startswith('run-')):
                return True
    except OSError:
        return False
    return False
