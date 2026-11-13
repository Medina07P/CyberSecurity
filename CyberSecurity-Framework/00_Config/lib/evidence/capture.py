"""Private acquisition ledger only. Backends and public CLI live in later tasks.

work/ is diagnostic, unpublished material, never evidence. Neither ledger IDs
nor successful action statuses certify integrity of referenced evidence.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .model import EvidenceError
from .storage import _directory, private_directory


ACTIONS = ('web', 'traffic', 'scan', 'system')
STATES = {'pending', 'running', 'success', 'no-traffic', 'failed', 'interrupted', 'not-run'}
TERMINAL = STATES - {'pending', 'running'}
ID = re.compile(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}')
FIELDS = {'action', 'status', 'started_at', 'finished_at', 'rc', 'reason', 'evidence_ids', 'stdout', 'stderr'}


def _now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', value):
        raise EvidenceError('FECHA LEDGER INVÁLIDA')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _validate(data, identity):
    if not isinstance(data, dict) or set(data) != {'schema_version', 'id', 'started_at', 'finished_at', 'status', 'actions'}:
        raise EvidenceError('CAMPOS LEDGER INVÁLIDOS')
    if type(data['schema_version']) is not int or data['schema_version'] != 1 or data['id'] != identity or not ID.fullmatch(identity):
        raise EvidenceError('IDENTIDAD/VERSIÓN LEDGER INVÁLIDA')
    started = _date(data['started_at'])
    status, finished = data['status'], data['finished_at']
    if not isinstance(status, str) or status not in STATES or status in {'pending', 'no-traffic', 'not-run'}:
        raise EvidenceError('ESTADO GLOBAL INVÁLIDO')
    if (status == 'running') != (finished is None):
        raise EvidenceError('CIERRE LEDGER INVÁLIDO')
    if finished is not None and _date(finished) < started:
        raise EvidenceError('ORDEN TEMPORAL INVÁLIDO')
    if not isinstance(data['actions'], list) or not data['actions']:
        raise EvidenceError('ACCIONES INVÁLIDAS')
    seen, previous = [], None
    for item in data['actions']:
        if not isinstance(item, dict) or set(item) != FIELDS:
            raise EvidenceError('CAMPOS ACCIÓN INVÁLIDOS')
        action, state = item['action'], item['status']
        if not isinstance(action, str) or action not in ACTIONS or action in seen:
            raise EvidenceError('ACCIÓN INVÁLIDA/DUPLICADA')
        seen.append(action)
        if not isinstance(state, str) or state not in STATES:
            raise EvidenceError('ESTADO ACCIÓN INVÁLIDO')
        if item['stdout'] != f'{action}.stdout' or item['stderr'] != f'{action}.stderr':
            raise EvidenceError('NOMBRES DE STREAM INVÁLIDOS')
        if item['rc'] is not None and type(item['rc']) is not int:
            raise EvidenceError('RC INVÁLIDO')
        if item['reason'] is not None and not isinstance(item['reason'], str):
            raise EvidenceError('CAUSA INVÁLIDA')
        ids = item['evidence_ids']
        if not isinstance(ids, list) or any(not isinstance(i, str) or not ID.fullmatch(i) for i in ids) or len(ids) != len(set(ids)):
            raise EvidenceError('IDS DE EVIDENCIA INVÁLIDOS')
        if state != 'success' and ids:
            raise EvidenceError('ACCIÓN NO EXITOSA CON EVIDENCIA')
        if state == 'running' and (item['rc'] is not None or item['reason'] is not None):
            raise EvidenceError('ACCIÓN EN CURSO CON RESULTADO')
        begin, end = item['started_at'], item['finished_at']
        if state in {'pending', 'not-run'}:
            if begin is not None or item['rc'] is not None:
                raise EvidenceError('ACCIÓN NO EJECUTADA CON INICIO/RC')
            if state == 'pending' and item['reason'] is not None:
                raise EvidenceError('ACCIÓN PENDIENTE CON CAUSA')
        elif begin is None or _date(begin) < started:
            raise EvidenceError('INICIO DE ACCIÓN INVÁLIDO')
        if (state in TERMINAL) != (end is not None):
            raise EvidenceError('FIN DE ACCIÓN INVÁLIDO')
        if end is not None and _date(end) < (_date(begin) if begin else started):
            raise EvidenceError('ORDEN DE ACCIÓN INVÁLIDO')
        if finished is not None and (state not in TERMINAL or _date(end) > _date(finished)):
            raise EvidenceError('CIERRE CON ACCIONES INCOMPLETAS')
        if state == 'success' and item['rc'] != 0:
            raise EvidenceError('ÉXITO SIN RC CERO')
        if previous is not None and state not in {'pending', 'not-run'}:
            if previous['status'] not in TERMINAL or _date(begin) < _date(previous['finished_at']):
                raise EvidenceError('ORDEN DE EJECUCIÓN INVÁLIDO')
        previous = item
    if seen != [action for action in ACTIONS if action in seen]:
        raise EvidenceError('ORDEN DE ACCIONES INVÁLIDO')
    if status == 'success' and any(item['status'] not in {'success', 'no-traffic'} for item in data['actions']):
        raise EvidenceError('ÉXITO GLOBAL INCONSISTENTE')


def read_run(path: Path):
    # Reuse the strict, stable reader lazily to avoid an inventory import cycle.
    from .inventory import _read, _object, _constant
    try:
        path = Path(path)
        data = json.loads(_read(path / 'run.json').decode('utf-8'), object_pairs_hook=_object, parse_constant=_constant)
        _validate(data, path.name)
        allowed = {'run.json', 'work'} | {item[key] for item in data['actions'] for key in ('stdout', 'stderr')}
        with _directory(path) as fd:
            if 'work' not in os.listdir(fd):
                raise EvidenceError('DIRECTORIO DIAGNÓSTICO AUSENTE')
            for name in os.listdir(fd):
                mode = os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode
                if name not in allowed or (not stat.S_ISDIR(mode) if name == 'work' else not stat.S_ISREG(mode)):
                    raise EvidenceError('CONTENIDO LEDGER INVÁLIDO')
        return data
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise EvidenceError(f'LEDGER INVÁLIDO: {exc}') from exc


class RunLedger:
    def __init__(self, root: Path, actions: list[str]):
        if not isinstance(actions, list) or not actions or any(not isinstance(a, str) or a not in ACTIONS for a in actions) or len(set(actions)) != len(actions):
            raise EvidenceError('ACCIONES INVÁLIDAS/DUPLICADAS')
        self.id = uuid.uuid4().hex
        parent = private_directory(Path(root) / 'logs/runs')
        self.path = parent / self.id
        try:
            with _directory(parent) as fd:
                os.mkdir(self.id, 0o700, dir_fd=fd)
                os.chmod(self.id, 0o700, dir_fd=fd, follow_symlinks=False)
            private_directory(self.path / 'work')
            self._data = {'schema_version': 1, 'id': self.id, 'started_at': _now(),
                          'finished_at': None, 'status': 'running', 'actions': [
                              {'action': a, 'status': 'pending', 'started_at': None, 'finished_at': None,
                               'rc': None, 'reason': None, 'evidence_ids': [],
                               'stdout': f'{a}.stdout', 'stderr': f'{a}.stderr'} for a in ACTIONS if a in actions]}
            self._save()
        except OSError as exc:
            raise EvidenceError(f'CREACIÓN LEDGER FALLIDA: {exc}') from exc

    def _save(self):
        _validate(self._data, self.id)
        name = '.run-' + uuid.uuid4().hex
        try:
            with _directory(self.path) as parent:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                        json.dump(self._data, stream, ensure_ascii=True, allow_nan=False)
                        stream.write('\n')
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(name, 'run.json', src_dir_fd=parent, dst_dir_fd=parent)
                    os.fsync(parent)
                finally:
                    try:
                        os.unlink(name, dir_fd=parent)
                    except FileNotFoundError:
                        pass
        except OSError as exc:
            raise EvidenceError(f'ESCRITURA LEDGER FALLIDA: {exc}') from exc

    def _action(self, action):
        if self._data['status'] != 'running':
            raise EvidenceError('LEDGER CERRADO')
        for item in self._data['actions']:
            if item['action'] == action:
                return item
        raise EvidenceError('ACCIÓN NO SELECCIONADA')

    def start(self, action: str) -> None:
        item = self._action(action)
        preceding = self._data['actions'][:self._data['actions'].index(item)]
        if item['status'] != 'pending' or any(a['status'] not in TERMINAL for a in preceding):
            raise EvidenceError('TRANSICIÓN/ORDEN DE INICIO INVÁLIDO')
        item.update(status='running', started_at=_now())
        self._save()

    def finish(self, action: str, status: str, rc: int | None, reason: str | None,
               evidence_ids: list[str]) -> None:
        item = self._action(action)
        if item['status'] != 'running' or status not in TERMINAL - {'not-run'}:
            raise EvidenceError('TRANSICIÓN DE FIN INVÁLIDA')
        candidate = dict(item, status=status, rc=rc, reason=reason,
                         evidence_ids=list(evidence_ids), finished_at=_now())
        trial = dict(self._data, actions=[candidate if a is item else a for a in self._data['actions']])
        _validate(trial, self.id)
        item.update(candidate)
        self._save()

    def close(self, status: str) -> None:
        if self._data['status'] != 'running' or status not in {'success', 'failed', 'interrupted'}:
            raise EvidenceError('CIERRE INVÁLIDO')
        now = _now()
        actions = []
        for item in self._data['actions']:
            candidate = dict(item)
            if item['status'] == 'pending':
                candidate.update(status='not-run', finished_at=now)
            elif item['status'] == 'running':
                candidate.update(status='interrupted' if status == 'interrupted' else 'failed', finished_at=now,
                                 reason='Cierre antes de terminar la acción')
            actions.append(candidate)
        trial = dict(self._data, status=status, finished_at=now, actions=actions)
        _validate(trial, self.id)
        self._data = trial
        self._save()
