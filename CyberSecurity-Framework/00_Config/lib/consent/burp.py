"""Burp GUI, passive observation, explicit GET and pinned stop are separate operations.

Administrative receipts are local same-user metadata, not a hostile-user security
boundary or proof that a TCP listener belongs to Burp. Never adopt legacy PIDs.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import time
from urllib.parse import urlsplit
import uuid

from consent.files import directory


INSTANCE = re.compile(r'burp-[0-9a-f]{32}\Z')
IDENTITY_FIELDS = ('pid', 'start_ticks', 'uid', 'boot_id')


@dataclass(frozen=True)
class BurpInstance:
    instance_id: str
    directory: Path
    port: int
    pid: int
    managed: bool


@dataclass(frozen=True)
class BurpObservation:
    instance_id: str | None
    port: int | None
    listening: bool | None
    owner: str = 'NO_DETERMINADO'
    capture: str = 'NO_VERIFICADA'


class BurpOps:
    """Production OS boundary. Injection is Python-only, never CLI/environment."""

    def listening_ports(self):
        if not shutil.which('ss'):
            return None
        try:
            result = subprocess.run(['ss', '-ltn'], capture_output=True, text=True,
                                    timeout=5, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode:
            return None
        ports = set()
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[0] == 'LISTEN':
                match = re.search(r':([0-9]+)$', fields[3])
                if match:
                    ports.add(int(match[1]))
        return ports

    def launch(self, config: Path, log_fd: int):
        # Community ignores project-file; its history remains in memory.
        process = subprocess.Popen(['burpsuite', '--config-file=' + str(config)],
                                   stdin=subprocess.DEVNULL, stdout=log_fd,
                                   stderr=log_fd, close_fds=True)
        self._process = process  # keep the direct child's handle; never adopt descendants
        return process.pid

    def identity(self, pid):
        text = Path(f'/proc/{pid}/stat').read_text()
        # comm may contain spaces/parentheses; starttime is field22.
        fields = text[text.rfind(')') + 2:].split()
        uid_line = next(line for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                        if line.startswith('Uid:'))
        uids = [int(value) for value in uid_line.split()[1:]]
        if len(uids) != 4 or any(value != os.getuid() for value in uids):
            raise ValueError('Identidad de usuario no propia')
        return {'pid': pid, 'start_ticks': int(fields[19]), 'uid': uids[0],
                'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}

    def pidfd_open(self, pid):
        return os.pidfd_open(pid, 0)

    def pidfd_send_signal(self, fd, number):
        signal.pidfd_send_signal(fd, number)

    def wait(self, fd, timeout):
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        return bool(poller.poll(timeout * 1000))

    def close(self, fd):
        os.close(fd)

    def request(self, url, port):
        # No redirects, insecure TLS, retries, session lookup or hidden extra GET.
        # Prevent operator ~/.curlrc/XDG curlrc from silently adding requests or
        # redirect/retry options. No directory is created or operator file read.
        environment = dict(os.environ, CURL_HOME='/dev/null',
                           XDG_CONFIG_HOME='/dev/null', HOME='/dev/null')
        result = subprocess.run(
            ['curl', '--request', 'GET', '--max-time', '5', '--noproxy', '',
             '--proxy', f'http://127.0.0.1:{port}', '--output', '/dev/null',
             '--write-out', '%{http_code}', '--', url],
            capture_output=True, text=True, check=False, timeout=7, env=environment)
        # Raw stderr can contain URL/query secrets. Publish only a classified result.
        return result.returncode, result.stdout.strip()

    def await_listener(self, port):
        deadline = time.monotonic() + 60
        while True:
            ports = self.listening_ports()
            if ports is None or port in ports:
                return
            if time.monotonic() >= deadline:
                return
            time.sleep(2)

    def assist_gui(self):
        """Optional, specifically consented legacy Start Burp GUI assistance."""
        import sys
        if not (sys.stdin.isatty() and sys.stderr.isatty() and
                shutil.which('xdotool') and shutil.which('xwininfo')):
            return
        print("¿Pulsar Start Burp en la GUI? Escriba INICIAR GUI (no autoriza GET):",
              file=sys.stderr)
        if sys.stdin.readline().rstrip('\n') != 'INICIAR GUI':
            return
        windows = subprocess.run(['xdotool', 'search', '--name', 'Burp Suite Community'],
                                 capture_output=True, text=True, timeout=5)
        ids = windows.stdout.splitlines()
        if windows.returncode or len(ids) != 1 or not ids[0].isdigit():
            return  # ambiguous windows: manual assistance instead of first match
        window = ids[0]
        geometry = subprocess.run(['xwininfo', '-id', window], capture_output=True,
                                  text=True, timeout=5)
        if geometry.returncode:
            return
        values = []
        for label in ('Absolute upper-left X', 'Absolute upper-left Y', 'Width', 'Height'):
            match = re.search(r'^\s*' + label + r':\s*(-?\d+)\s*$',
                              geometry.stdout, re.MULTILINE)
            if not match:
                return
            values.append(int(match[1]))
        x, y, width, height = values
        for args in (['windowraise', window], ['windowactivate', '--sync', window],
                     ['mousemove', str(x + width - 62), str(y + height - 33), 'click', '1']):
            result = subprocess.run(['xdotool', *args], capture_output=True, timeout=5)
            if result.returncode:
                return


def validate_port(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Puerto requerido entre 1 y 65535')
    return port


def validate_url(url):
    if not isinstance(url, str) or any(c.isspace() or ord(c) <= 32 or
                                        127 <= ord(c) <= 159 for c in url):
        raise ValueError('URL HTTP(S) completa sin controles requerida')
    try:
        parsed = urlsplit(url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                '\\' in parsed.netloc or parsed.fragment or
                any(c in parsed.path + parsed.query for c in '{}[]') or
                any(c in parsed.netloc for c in '{}') or
                (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise ValueError
    except ValueError:
        raise ValueError('URL HTTP(S) completa sin credenciales requerida') from None
    return url


def _valid_identity(value):
    return (isinstance(value, dict) and
            type(value.get('pid')) is int and value['pid'] > 0 and
            type(value.get('start_ticks')) is int and value['start_ticks'] > 0 and
            type(value.get('uid')) is int and value['uid'] >= 0 and
            isinstance(value.get('boot_id'), str) and bool(value['boot_id']) and
            len(value['boot_id']) <= 128)


def _private_directory(fd):
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Directorio de instancia no privado/propio')


def _receipt(root, instance_id):
    if instance_id is None:
        with directory(root / 'instances') as parent:
            candidates = [name for name in os.listdir(parent) if INSTANCE.fullmatch(name)]
        if len(candidates) != 1:
            raise ValueError('Se requiere una única instancia nueva inequívoca')
        instance_id = candidates[0]
    if not isinstance(instance_id, str) or not INSTANCE.fullmatch(instance_id):
        raise ValueError('ID de instancia inválido')
    with directory(root / 'instances' / instance_id) as state:
        _private_directory(state)
        fd = os.open('instance.json', os.O_PATH | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=state)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or
                    info.st_size > 16384):
                raise ValueError('Recibo no regular/privado/propio')
            # Only reopen the already pinned regular inode, not its pathname.
            reader = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_CLOEXEC)
            with os.fdopen(reader, 'rb') as stream:
                value = json.loads(stream.read(16385))
        finally:
            os.close(fd)
    if (not _valid_identity(value) or type(value.get('version')) is not int or
            value['version'] != 1 or value.get('instance_id') != instance_id):
        raise ValueError('Recibo incongruente')
    return value


def _publish(fd, name, payload):
    # Fixed names at callers, always new; never replace a prior receipt/log/config.
    child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                    os.O_CLOEXEC, 0o600, dir_fd=fd)
    with os.fdopen(child, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _session_scope(framework):
    """Retain optional GUI scope from fixed session metadata, never network consent.

    This is used only when opening, never help/status/verification/stop. No shell,
    session setter, target registration, source config mutation or environment alias.
    """
    try:
        with directory(framework / '00_Config') as config:
            fd = os.open('.session', os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=config)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 2048:
                    return None
                reader = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_CLOEXEC)
                with os.fdopen(reader, 'r', encoding='utf-8') as stream:
                    target = stream.readline(2049).rstrip('\r\n')
            finally:
                os.close(fd)
        # Session scope remains an exact host regex, not executable config syntax.
        if target and re.fullmatch(r'[A-Za-z0-9_.:-]+', target):
            return {'scope': {'advanced_mode': True, 'include': [
                {'enabled': True, 'protocol': 'any', 'host': '^' + re.escape(target) + '$'}]}}
    except (OSError, ValueError):
        pass
    return None


def start_burp(framework: Path, port: int | None, ops: BurpOps) -> BurpInstance:
    if port is not None:
        validate_port(port)
    ports = ops.listening_ports()
    if ports is None:
        raise ValueError('Puertos: NO_DETERMINADO; se requiere ss, sin fallback de sockets')
    if port is None:
        port = next((value for value in range(8080, 8100) if value not in ports), None)
        if port is None:
            raise ValueError('Sin puerto disponible entre 8080 y 8099')
    elif port in ports:
        raise ValueError(f'Puerto ocupado: {port}\nPropietario: NO_DETERMINADO\nCaptura: NO_VERIFICADA')
    if not shutil.which('burpsuite'):
        raise ValueError("No se encontró burpsuite; no se instala automáticamente")
    instance_id = 'burp-' + uuid.uuid4().hex
    root = framework.parent / 'scans/burp/instances'
    state_path = root / instance_id
    with directory(root, create=True) as parent:
        os.mkdir(instance_id, mode=0o700, dir_fd=parent)  # exclusive namespace
        with directory(state_path) as state:
            os.fchmod(state, 0o700)
            config = {'proxy': {'request_listeners': [
                {'listener_port': port, 'listen_mode': 'loopback_only', 'running': True}]}}
            scope = _session_scope(framework)
            if scope is not None:
                config['target'] = scope
            _publish(state, 'config.json', (json.dumps(config) + '\n').encode())
            log = os.open('launcher.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                          os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=state)
            try:
                os.fchmod(log, 0o600)
                pid = ops.launch(state_path / 'config.json', log)
            finally:
                os.close(log)
            managed = False
            try:
                identity = ops.identity(pid)
                if not _valid_identity(identity) or identity['pid'] != pid:
                    raise ValueError('Identidad inicial no acreditada')
                receipt = {**identity, 'version': 1, 'instance_id': instance_id, 'port': port}
                _publish(state, 'instance.json', (json.dumps(receipt) + '\n').encode())
                managed = True
            except (OSError, ValueError, IndexError, StopIteration):
                # GUI dispatch remains useful even if its wrapper exited/daemonized.
                # No receipt means no authority to stop any descendant by PID/name.
                pass
    return BurpInstance(instance_id, state_path, port, pid, managed)


def observe_burp(root: Path, instance_id: str | None, ops: BurpOps) -> BurpObservation:
    port = None
    try:
        receipt = _receipt(root, instance_id)
        instance_id = receipt['instance_id']
        port = validate_port(receipt.get('port'))
    except (OSError, ValueError, TypeError):
        pass
    ports = ops.listening_ports()
    return BurpObservation(instance_id, port,
                           None if port is None or ports is None else port in ports)


def verify_proxy(url: str, port: int, authorized: bool, ops: BurpOps) -> int:
    validate_url(url)
    validate_port(port)
    if authorized is not True:
        return 2
    rc, code = ops.request(url, port)
    if rc or not re.fullmatch(r'[1-5][0-9]{2}', code):
        print('GET sin respuesta HTTP determinada; captura NO_VERIFICADA.')
        return 1
    print(f'Respuesta HTTP observada: {code}; no certifica origen ni captura.')
    return 0


def stop_burp(root: Path, instance_id: str | None, ops: BurpOps) -> int:
    fd = None
    try:
        receipt = _receipt(root, instance_id)
        expected = {key: receipt[key] for key in IDENTITY_FIELDS}
        if ops.identity(receipt['pid']) != expected:
            return 1
        fd = ops.pidfd_open(receipt['pid'])
        if ops.identity(receipt['pid']) != expected:
            return 1
        ops.pidfd_send_signal(fd, signal.SIGTERM)
        if not ops.wait(fd, 5):
            ops.pidfd_send_signal(fd, signal.SIGKILL)
        return 0
    except (OSError, ValueError, TypeError, AttributeError, IndexError, StopIteration):
        return 1  # unavailable pidfd/identity: no numeric PID or process-group fallback
    finally:
        if fd is not None:
            ops.close(fd)
