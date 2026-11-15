"""Stable operations; importing this module never starts a backend."""
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
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
        result = subprocess.run([backend, f'{domain}/{user}:{password}@{host}', command],
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
