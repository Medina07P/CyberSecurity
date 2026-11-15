"""Stable operations; importing this module never starts a backend."""
import ipaddress
import os
from dataclasses import dataclass
import uuid
from pathlib import Path
import re
import resource
import shutil
import subprocess
import stat
import sys
import unicodedata


def _text(value: str) -> bool:
    return bool(value) and not any(unicodedata.category(c).startswith('C') for c in value)


def validate_host(host: str) -> None:
    if not _text(host) or any(c.isspace() for c in host) or host.startswith('-'):
        raise ValueError('Host no válido.')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if (re.fullmatch(r'[0-9.]+', host) or len(host) > 253 or
                not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                        for label in host.rstrip('.').split('.'))):
            raise ValueError('Host no válido.') from None
    else:
        if address.version != 4:
            raise ValueError('Esta interfaz requiere IPv4 o dominio.')


def validate_smb(host: str, prefix: str | None) -> str:
    validate_host(host)
    prefix = 'smb_enum' if prefix is None else prefix
    if not re.fullmatch(r'[A-Za-z0-9_-]+', prefix):
        raise ValueError('Prefijo no válido.')
    return prefix


def validate_psexec(host: str, domain: str, user: str, password: str, command: str) -> None:
    validate_host(host)
    # Impacket target grammar: domain/user:password@host. Reject ambiguity rather
    # than encoding/rewriting operator input or silently selecting another identity.
    for value in (domain, user):
        if not _text(value) or any(c in value for c in '/\\:@'):
            raise ValueError('Credenciales vacías, con controles o delimitadores ambiguos.')
    # With explicit domain/user already present, : and / inside the password
    # are literal Impacket password data; @ would split the host boundary.
    if not _text(password) or '@' in password:
        raise ValueError('Contraseña vacía, con controles o delimitador @ ambiguo.')
    if domain.startswith('-') or any(c.isspace() for c in domain + user):
        raise ValueError('Dominio/usuario no válido para el formato del backend.')
    if not _text(command):
        raise ValueError('Comando vacío o con controles.')


_SMB_DRIVER = '''
source "$1/enumeration_services.bash" || exit 1
ENUM_STRICT_RC=1
enum_service smb "$2"
rc=$?
[[ -n "${ENUM_WORK:-}" ]] || exit 1
enum_common_shares "$3"
shares_rc=$?
(( rc == 0 && shares_rc == 0 && ENUM_FAILED == 0 ))
'''


def run_smb(host: str, prefix: str | None) -> int:
    prefix = validate_smb(host, prefix)
    lib = Path(__file__).absolute().parent.parent
    try:
        return subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c',
                               _SMB_DRIVER, 'stable-smb', str(lib), host, prefix],
                              check=False).returncode
    except OSError:
        print('No se pudo iniciar la enumeración SMB.', file=sys.stderr)
        return 1


def run_psexec(host: str, domain: str, user: str, password: str, command: str) -> int:
    validate_psexec(host, domain, user, password, command)
    backend = shutil.which('psexec.py') or shutil.which('impacket-psexec')
    if backend is None:
        print('PSExec no instalado.', file=sys.stderr)
        return 1
    try:
        # One argv item is not enough: Impacket also parses backend options.
        # Terminate options so even --help/-k/-target-ip are remote command DATA.
        result = subprocess.run([backend, f'{domain}/{user}:{password}@{host}', '--', command],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError:
        print('No se pudo iniciar PSExec.', file=sys.stderr)
        return 1
    # No product log. Suppress literal password echoes in backend diagnostics;
    # this is NOT universal redaction (encoded/transformed secrets or OS argv).
    secret = password.encode('utf-8')
    for stream, body in ((sys.stdout, result.stdout), (sys.stderr, result.stderr)):
        stream.buffer.write(body.replace(secret, b'[oculto]'))
        stream.flush()
    return result.returncode


LINPEAS_URL = 'https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh'
LINPEAS_MAX_SECONDS = 60
LINPEAS_MAX_BYTES = 16 * 1024 * 1024


@dataclass
class LinpeasOps:
    run_id: str = ''
    run_dir: object = None
    source_path: object = None
    download_path: object = None
    stdout_path: object = None
    stderr_path: object = None
    backend: str = 'sudo'


def _linpeas_scans_root(root):
    root = Path(root)
    if root.name == 'scans':
        return root
    if root.name == 'CyberSecurity-Framework' or (root / '00_Config').is_dir():
        return root.parent / 'scans'
    return root / 'scans'


def _valid_local_binary(path):
    try:
        candidate = Path(path)
    except (TypeError, ValueError):
        return False
    if not candidate.is_absolute():
        return False
    if '..' in candidate.parts:
        return False
    try:
        if candidate.is_symlink():
            return False
        if not candidate.is_file():
            return False
    except OSError:
        return False
    # Reject any symlink component without resolving the final target.
    current = Path('/')
    for part in candidate.parts[1:]:
        if part in ('', '.', '..'):
            return False
        current = current / part
        try:
            if current.is_symlink():
                return False
        except OSError:
            return False
    return True


def _download_limits():
    # Child-only cap applies even when a server omits Content-Length or wget
    # lacks curl's max-filesize option. Never raise an inherited tighter cap.
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    cap = min(v for v in (soft, hard, LINPEAS_MAX_BYTES) if v != resource.RLIM_INFINITY)
    resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))


def _new_linpeas_run(root):
    parent = (_linpeas_scans_root(root) / 'linpeas').absolute()
    if '..' in parent.parts:
        raise ValueError('Ruta de salida no válida.')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for index, component in enumerate(parent.parts[1:], start=1):
            # Only the output hierarchy may be created, never missing ancestors.
            if index >= len(parent.parts) - 2:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        run_id = uuid.uuid4().hex
        os.mkdir(run_id, 0o700, dir_fd=fd)  # No adoption on UUID collision.
        child = os.open(run_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                        os.O_CLOEXEC, dir_fd=fd)
        return parent / run_id, child
    finally:
        os.close(fd)


def _private_run_file(directory_fd, name):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, 'wb')
    except BaseException:
        os.close(fd)
        raise


def run_linpeas(binary=None, download=False, allow_sudo=False, root=None, ops=None):
    """Run Linpeas only from an explicitly selected local or downloaded source.

    Returns an integer status. No source is adopted from cwd and no permission
    is granted by generation or preview.
    """
    if allow_sudo is not True:
        return 2
    if download and binary is not None:
        return 2
    if not download and binary is None:
        return 2

    if ops is None:
        ops = LinpeasOps()
    if root is None:
        root = Path.cwd()

    try:
        run_dir, run_fd = _new_linpeas_run(root)
    except OSError:
        return 1
    try:
        return _run_linpeas_selected(binary, download, ops, run_dir, run_fd)
    finally:
        os.close(run_fd)


def _run_linpeas_selected(binary, download, ops, run_dir, run_fd):
    ops.run_id = run_dir.name
    ops.run_dir = run_dir
    ops.download_path = None
    ops.source_path = None
    ops.stdout_path = None
    ops.stderr_path = None

    selected = None
    if download:
        downloader = shutil.which('curl')
        is_curl = downloader is not None
        if downloader is None:
            downloader = shutil.which('wget')
        if downloader is None:
            return 1
        destination = run_dir / 'downloaded-linpeas.sh'
        if is_curl:
            command = [downloader, '--fail', '--silent', '--show-error', '--location',
                       '--max-time', str(LINPEAS_MAX_SECONDS),
                       '--max-filesize', str(LINPEAS_MAX_BYTES),
                       '-o', str(destination), LINPEAS_URL]
        else:
            command = [downloader, '--timeout=' + str(LINPEAS_MAX_SECONDS),
                       '--tries=1',
                       '-O', str(destination), LINPEAS_URL]
        stdout_path = run_dir / 'download.stdout.log'
        stderr_path = run_dir / 'download.stderr.log'
        try:
            with _private_run_file(run_fd, stdout_path.name) as stdout, \
                    _private_run_file(run_fd, stderr_path.name) as stderr:
                result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False,
                                        timeout=LINPEAS_MAX_SECONDS, umask=0o077,
                                        preexec_fn=_download_limits)
        except (OSError, subprocess.TimeoutExpired):
            # subprocess.run kills and waits for the direct downloader on timeout.
            # Preserve its partial; no sudo fallback and no second downloader.
            return 1
        ops.download_path = destination
        ops.stdout_path = stdout_path
        ops.stderr_path = stderr_path
        if result.returncode != 0:
            return result.returncode
        try:
            metadata = os.stat(destination.name, dir_fd=run_fd, follow_symlinks=False)
            if (not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= LINPEAS_MAX_BYTES):
                return 1
            downloaded_fd = os.open(destination.name, os.O_RDONLY | os.O_NOFOLLOW |
                                    os.O_CLOEXEC, dir_fd=run_fd)
            try:
                opened = os.fstat(downloaded_fd)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    return 1
                os.fchmod(downloaded_fd, 0o600)
            finally:
                os.close(downloaded_fd)
        except OSError:
            return 1
        selected = destination
    else:
        source = Path(binary)
        if not _valid_local_binary(source):
            return 2
        destination = run_dir / 'selected-linpeas.sh'
        try:
            fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=run_fd)
        except OSError:
            return 1
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    with os.fdopen(source_fd, 'rb') as source_stream:
                        if not stat.S_ISREG(os.fstat(source_stream.fileno()).st_mode):
                            return 2
                        shutil.copyfileobj(source_stream, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                except BaseException:
                    os.close(source_fd)
                    raise
        except OSError:
            return 1
        selected = destination
        ops.source_path = destination

    if selected is None:
        return 1

    if ops.source_path is None and download:
        ops.source_path = selected

    stdout_path = run_dir / 'linpeas.stdout.log'
    stderr_path = run_dir / 'linpeas.stderr.log'
    try:
        # Refuse a moved/replaced hierarchy before handing path argv to sudo.
        # This is not a guarantee against a hostile concurrent rename after check.
        pinned = os.fstat(run_fd)
        current = os.stat(run_dir, follow_symlinks=False)
        if (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino):
            return 1
        with _private_run_file(run_fd, stdout_path.name) as stdout, \
                _private_run_file(run_fd, stderr_path.name) as stderr:
            result = subprocess.run(['sudo', '/bin/bash', str(selected)],
                                    stdout=stdout, stderr=stderr, check=False)
    except OSError:
        return 1
    ops.stdout_path = stdout_path
    ops.stderr_path = stderr_path
    return result.returncode
