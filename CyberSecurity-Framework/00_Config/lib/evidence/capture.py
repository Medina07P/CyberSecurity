"""Explicit bounded acquisition and private diagnostics (no public CLI here).

work/ is diagnostic, unpublished material, never evidence. Neither ledger IDs
nor successful action statuses certify integrity of referenced evidence.
"""
from datetime import datetime, timezone
from dataclasses import dataclass
from contextlib import contextmanager
import getpass
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import stat
import struct
import uuid
from urllib.parse import urlsplit

from .model import EvidenceError, UsageError
from .storage import _directory, private_directory
from .storage import add
from .process import CaptureInterrupted, run_child, _stream


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


@dataclass
class CapturePlan:
    web: str | None = None
    traffic: str | None = None
    interface: str | None = None
    scan: str | None = None
    scan_profile: str | None = None
    system: bool = False
    duration: int = 10
    packet_limit: int = 100
    authorize_network: bool = False


def _host(host):
    if not isinstance(host, str) or not host or '%' in host:
        raise UsageError('HOST INVÁLIDO')
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    # Nmap parses numeric dotted octet ranges before attempting DNS. These
    # otherwise valid DNS labels must not turn one requested host into many.
    if '-' in host and re.fullmatch(r'(?:[0-9]+(?:-[0-9]+)?\.){3}[0-9]+(?:-[0-9]+)?', host):
        raise UsageError('RANGO IPv4 AMBIGUO: SE REQUIERE UN HOST ÚNICO')
    if (len(host) > 253 or not host.isascii() or
            any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                for label in host.split('.'))):
        raise UsageError('HOST INVÁLIDO')


def _url(url):
    if (not isinstance(url, str) or not url or '\\' in url or '#' in url or
            any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url)):
        raise UsageError('URL INVÁLIDA')
    try:
        parts = urlsplit(url)
        if (parts.scheme not in ('http', 'https') or not parts.netloc or
                parts.username is not None or parts.password is not None or
                parts.netloc.endswith(':') or (parts.port is not None and not 1 <= parts.port <= 65535)):
            raise ValueError('esquema/autoridad/puerto')
        _host(parts.hostname)
    except (ValueError, TypeError) as exc:
        raise UsageError('URL INVÁLIDA') from exc


def validate_plan(plan: CapturePlan) -> None:
    if (not isinstance(plan, CapturePlan) or type(plan.system) is not bool or
            type(plan.authorize_network) is not bool):
        raise UsageError('PLAN INVÁLIDO')
    if not any((plan.web is not None, plan.traffic is not None, plan.scan is not None, plan.system)):
        raise UsageError('SE REQUIERE UNA ACCIÓN EXPLÍCITA')
    if any(x is not None for x in (plan.web, plan.traffic, plan.scan)) and not plan.authorize_network:
        raise UsageError('SE REQUIERE AUTORIZACIÓN DE RED')
    if (type(plan.duration) is not int or not 1 <= plan.duration <= 300 or
            type(plan.packet_limit) is not int or not 1 <= plan.packet_limit <= 10000):
        raise UsageError('LÍMITES DE TRÁFICO INVÁLIDOS')
    if plan.traffic is None:
        if plan.interface is not None or plan.duration != 10 or plan.packet_limit != 100:
            raise UsageError('OPCIONES DE TRÁFICO SIN ACCIÓN')
    else:
        _host(plan.traffic)
        if (not isinstance(plan.interface, str) or not plan.interface or len(plan.interface) > 15 or
                plan.interface.startswith('-') or
                any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in '/:' for c in plan.interface)):
            raise UsageError('INTERFAZ INVÁLIDA')
    if plan.scan is None:
        if plan.scan_profile is not None:
            raise UsageError('PERFIL SIN ESCANEO')
    else:
        _host(plan.scan)
        if plan.scan_profile not in ('basic', 'full'):
            raise UsageError('PERFIL OBLIGATORIO: basic/full')
    if plan.web is not None:
        _url(plan.web)


def capture(root: Path, plan: CapturePlan) -> int:
    validate_plan(plan)
    actions = [a for a in ACTIONS if (getattr(plan, a) if a == 'system' else getattr(plan, a) is not None)]
    ledger = RunLedger(root, actions)
    handlers = {}
    failed = False

    def interrupted(signum, frame):
        raise CaptureInterrupted(signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            handlers[signum] = signal.signal(signum, interrupted)
        for action in actions:
            ledger.start(action)
            try:
                status, record = _acquire(root, plan, ledger, action)
                ledger.finish(action, status, 0, None, [record.id] if record else [])
            except CaptureInterrupted:
                raise
            except (EvidenceError, OSError) as exc:
                failed = True
                ledger.finish(action, 'failed', exc.rc if isinstance(exc, _ProcessFailure) else 1, str(exc), [])
        ledger.close('failed' if failed else 'success')
        return 1 if failed else 0
    except CaptureInterrupted as exc:
        ledger.close('interrupted')
        return 128 + exc.signum
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


@contextmanager
def _artifact(path):
    """Read only regular artifacts, without following any path component link."""
    try:
        path = Path(path).absolute()
        with _directory(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise EvidenceError('ARTEFACTO NO REGULAR')
            yield stream
    except OSError as exc:
        raise EvidenceError(f'ARTEFACTO NO LEGIBLE: {exc}') from exc


def validate_png(path: Path) -> None:
    with _artifact(path) as stream:
        data = stream.read(9)
        if len(data) != 9 or data[:8] != b'\x89PNG\r\n\x1a\n':
            raise EvidenceError('PNG INVÁLIDO O VACÍO')


def pcap_packet_count(path: Path) -> int:
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
               b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
    with _artifact(path) as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in formats:
            raise EvidenceError('CABECERA PCAP INVÁLIDA')
        endian, resolution = formats[header[:4]]
        major, minor, zone, accuracy, snaplen, network = struct.unpack(endian + 'HHiIII', header[4:])
        if (major, minor) != (2, 4) or snaplen == 0:
            raise EvidenceError('VERSIÓN/SNAPLEN PCAP INVÁLIDO')
        count = 0
        while True:
            packet = stream.read(16)
            if not packet:
                return count
            if len(packet) != 16:
                raise EvidenceError('CABECERA DE PAQUETE TRUNCADA')
            seconds, fraction, included, original = struct.unpack(endian + 'IIII', packet)
            if fraction >= resolution or included > snaplen or included > original:
                raise EvidenceError('LONGITUD/FECHA DE PAQUETE INVÁLIDA')
            remaining = included
            while remaining:
                chunk = stream.read(min(remaining, 65536))
                if not chunk:
                    raise EvidenceError('PAQUETE TRUNCADO')
                remaining -= len(chunk)
            count += 1


def validate_nmap(path: Path, host: str) -> None:
    _host(host)
    footer = re.compile(rb'# Nmap done at [^\x00-\x1f\x7f]+ -- 1 IP address \([01] hosts? up\) scanned in [0-9]+(?:\.[0-9]+)? seconds')
    with _artifact(path) as stream:
        last = b''
        while True:
            line = stream.readline(1048577)
            if not line:
                break
            if len(line) > 1048576:
                raise EvidenceError('LÍNEA NMAP EXCESIVA')
            if line.strip():
                last = line.rstrip(b'\r\n')
        if not footer.fullmatch(last):
            raise EvidenceError('NMAP SIN FINALIZACIÓN NORMAL')


class _ProcessFailure(EvidenceError):
    def __init__(self, result):
        self.rc = result.returncode
        super().__init__(f'PROCESO INCOMPLETO: rc={result.returncode}, deadline={result.timed_out}, señal={result.stopped_by}')


def _acquire(root, plan, ledger, action):
    work = ledger.path / 'work'
    stdout, stderr = ledger.path / f'{action}.stdout', ledger.path / f'{action}.stderr'
    path = work / {'web': 'web.png', 'traffic': 'traffic.pcap', 'scan': 'scan.nmap', 'system': 'operator.json'}[action]
    # Reserve private mode before a cooperating tool opens/truncates its output.
    with _stream(path):
        pass
    target = getattr(plan, action) if action != 'system' else None
    if action == 'system':
        with _stream(stdout), _stream(stderr):
            uname = platform.uname()
            # Do not iterate/_asdict(): its lazy processor field launches uname -p.
            data = {'scope': 'OPERADOR', 'utc': _now(), 'user': getpass.getuser(),
                    'hostname': socket.gethostname(), 'uname': {
                        key: getattr(uname, key) for key in ('system', 'node', 'release', 'version', 'machine')}}
            with path.open('w', encoding='utf-8') as stream:
                json.dump(data, stream, ensure_ascii=True, allow_nan=False)
                stream.write('\n')
        kind = 'log'
    else:
        if action == 'web':
            argv, timeout = ['cutycapt', f'--url={plan.web}', f'--out={path}'], 60
            kind = 'screenshot'
        elif action == 'traffic':
            argv = ['tcpdump', '-U', '-n', '-c', str(plan.packet_limit), '-i', plan.interface,
                    '-w', str(path), 'host', plan.traffic]
            timeout, kind = plan.duration, 'pcap'
        else:
            try:
                ipv6 = ipaddress.ip_address(plan.scan).version == 6
            except ValueError:
                ipv6 = False
            profile = ['--top-ports', '100'] if plan.scan_profile == 'basic' else ['-sV', '-p-']
            argv = ['nmap'] + (['-6'] if ipv6 else []) + ['-n', '-sT'] + profile + ['-oN', str(path), plan.scan]
            timeout, kind = (120 if plan.scan_profile == 'basic' else 1800), 'log'
        result = run_child(argv, stdout, stderr, timeout=timeout, interval_stop=action == 'traffic')
        normal = result.returncode == 0 and not result.timed_out and result.stopped_by is None
        interval = (action == 'traffic' and result.timed_out and result.stopped_by == 'SIGINT' and
                    result.returncode in (0, -signal.SIGINT))
        if not (normal or interval):
            raise _ProcessFailure(result)
        if action == 'web':
            validate_png(path)
        elif action == 'scan':
            validate_nmap(path, plan.scan)
        elif pcap_packet_count(path) == 0:
            return 'no-traffic', None
    record = add(root, kind, path, target=target, origin='capture', run_id=ledger.id, method=action)
    return 'success', record
