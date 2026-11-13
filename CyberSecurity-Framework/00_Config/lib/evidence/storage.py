"""Private, exclusive, stable streaming imports. No legacy data is rewritten.

Directory walks use descriptors and O_NOFOLLOW, including every ancestor.
The destination ID directory is an exclusive reservation; evidence.json is
published last. An incomplete reservation never represents a valid record.
This is not protection against privileged writers or restored timestamps.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import unicodedata
import uuid

from .model import EvidenceError, Record, UsageError


PUBLIC_ROOTS = {
    'screenshot': 'screenshots/web', 'pcap': 'pcaps/traffic',
    'credential': 'credentials/found', 'finding': 'findings/vulnerabilities',
    'proof': 'proofs/access',
}
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def safe_text(value: str) -> str:
    """Escape control/format characters, retaining ordinary Unicode text."""
    result = []
    for char in str(value):
        code = ord(char)
        if char in '\n\r\t':
            result.append({'\n': r'\n', '\r': r'\r', '\t': r'\t'}[char])
        elif unicodedata.category(char).startswith('C') or char in '\u2028\u2029':
            result.append(f'\\x{code:02x}' if code <= 255 else
                          f'\\u{code:04x}' if code <= 65535 else f'\\U{code:08x}')
        else:
            result.append(char)
    return ''.join(result)


@contextmanager
def _directory(path: Path, *, create: bool = False):
    """Open a real directory chain; never repair existing directory modes."""
    path = Path(path).absolute()
    fd = os.open(path.anchor, DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            created = False
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                    created = True
                    # mkdir applies umask. Restore only directories we created,
                    # before opening them (umask 0777 otherwise denies traversal).
                    os.chmod(component, 0o700, dir_fd=fd, follow_symlinks=False)
                except FileExistsError:
                    pass
            next_fd = os.open(component, DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            if created:
                os.fchmod(fd, 0o700)
        yield fd
    finally:
        os.close(fd)


def private_directory(path: Path) -> Path:
    path = Path(path).absolute()
    try:
        with _directory(path, create=True):
            pass
        return path
    except OSError as exc:
        raise EvidenceError(f'DIRECTORIO INVÁLIDO: {path}: {exc}') from exc


def _identity(info):
    return info.st_dev, info.st_ino


def _version(info):
    return (_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _unlink_owned(directory_fd, name, identity):
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _identity(info) == identity:
            os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        pass


@contextmanager
def _reservation(parent_fd, name):
    # mkdir is the no-replace reservation; collision is a hard failure.
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    identity = _identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    try:
        os.chmod(name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
        yield identity
    except BaseException:
        try:
            if _identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == identity:
                os.rmdir(name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise


def copy_regular(source: Path, destination: Path) -> tuple[int, str]:
    """Copy via descriptors; reject unstable/nonregular sources and existing dests.

    The parent destination must already exist. On failure only our own newly
    created destination is removed, never a preexisting file or a replacement.
    """
    source, destination = Path(source).absolute(), Path(destination).absolute()
    try:
        with _directory(source.parent) as src_parent, _directory(destination.parent) as dst_parent:
            src_fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=src_parent)
            try:
                before = os.fstat(src_fd)
                if not stat.S_ISREG(before.st_mode):
                    raise EvidenceError(f'ORIGEN NO REGULAR: {source}')
                dst_fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dst_parent)
                owned = _identity(os.fstat(dst_fd))
                try:
                    os.fchmod(dst_fd, 0o600)
                    total, digest = 0, hashlib.sha256()
                    while True:
                        chunk = os.read(src_fd, 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        total += len(chunk)
                        remaining = memoryview(chunk)
                        while remaining:
                            written = os.write(dst_fd, remaining)
                            if written <= 0:
                                raise EvidenceError('COPIA FALLIDA: escritura incompleta')
                            remaining = remaining[written:]
                    os.fsync(dst_fd)
                    after = os.fstat(src_fd)
                    # Rewalk ancestors: the original path must still name this file.
                    with _directory(source.parent) as current_parent:
                        current = os.stat(source.name, dir_fd=current_parent, follow_symlinks=False)
                    if (_version(before) != _version(after) or _version(before) != _version(current)
                            or not stat.S_ISREG(current.st_mode) or total != before.st_size):
                        raise EvidenceError(f'ORIGEN MODIFICADO: {source}')
                    return total, digest.hexdigest()
                except BaseException:
                    _unlink_owned(dst_parent, destination.name, owned)
                    raise
                finally:
                    os.close(dst_fd)
            finally:
                os.close(src_fd)
    except OSError as exc:
        raise EvidenceError(f'COPIA FALLIDA: {source}: {exc}') from exc


def add(root: Path, kind: str, source: Path, description: str = '', target: str | None = None,
        *, origin: str = 'import', run_id: str | None = None, method: str | None = None) -> Record:
    if origin not in ('import', 'capture'):
        raise UsageError('Origen no válido')
    if origin == 'import' and (run_id is not None or method is not None):
        raise UsageError('Una importación no admite método ni ejecución')
    if origin == 'capture' and (not run_id or not method):
        raise UsageError('Una captura requiere método y ejecución')
    roots = dict(PUBLIC_ROOTS)
    if origin == 'capture' and kind == 'log' and method in ('scan', 'system'):
        roots['log'] = 'logs/results' if method == 'scan' else 'logs/audit'
    if kind not in roots:
        raise UsageError(f'Tipo no válido: {kind}')
    source = Path(source).absolute()
    parent = private_directory(Path(root) / roots[kind])
    record_id = uuid.uuid4().hex
    record_dir = parent / record_id
    try:
        with _directory(parent) as parent_fd:
            with _reservation(parent_fd, record_id) as reservation, _directory(record_dir) as record_fd:
                owned = {}
                try:
                    os.fchmod(record_fd, 0o700)
                    size, digest = copy_regular(source, record_dir / 'artifact')
                    owned['artifact'] = _identity(os.stat('artifact', dir_fd=record_fd, follow_symlinks=False))
                    metadata = {
                        'schema_version': 1, 'id': record_id, 'type': kind,
                        'original_name': source.name, 'stored_name': 'artifact',
                        'size': size, 'sha256': digest,
                        'created_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                        'description': description, 'origin': origin, 'target': target,
                        'run_id': run_id, 'method': method,
                    }
                    fd = os.open('.metadata.tmp', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=record_fd)
                    owned['.metadata.tmp'] = _identity(os.fstat(fd))
                    with os.fdopen(fd, 'w', encoding='utf-8') as output:
                        os.fchmod(output.fileno(), 0o600)
                        json.dump(metadata, output, ensure_ascii=True, allow_nan=False, sort_keys=True)
                        output.write('\n')
                        output.flush()
                        os.fsync(output.fileno())
                    if _identity(os.stat(record_id, dir_fd=parent_fd, follow_symlinks=False)) != reservation:
                        raise EvidenceError('RESERVA MODIFICADA')
                    os.link('.metadata.tmp', 'evidence.json', src_dir_fd=record_fd,
                            dst_dir_fd=record_fd, follow_symlinks=False)
                    owned['evidence.json'] = owned['.metadata.tmp']
                    os.unlink('.metadata.tmp', dir_fd=record_fd)
                    os.fsync(record_fd)
                except BaseException:
                    for name, identity in owned.items():
                        _unlink_owned(record_fd, name, identity)
                    raise
        return Record(record_id, kind, 'sha256-v1', record_dir / 'artifact',
                      record_dir / 'evidence.json', target)
    except OSError as exc:
        raise EvidenceError(f'IMPORTACIÓN FALLIDA: {exc}') from exc
