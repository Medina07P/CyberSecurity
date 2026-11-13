"""Verified private snapshots, never a tar of live evidence or an overwrite.

This is an integrity snapshot, not encryption or proof of historical authenticity.
As with storage, privileged writers and edits after the final check are outside
the guarantee; there is no filesystem-wide transactional read lock.
"""
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import uuid

from . import inventory
from .model import EvidenceError, UsageError
from .storage import (copy_regular, private_directory, _directory, _identity,
                      _reservation, _unlink_owned, _version)


def _path(value):
    if (not isinstance(value, str) or not value or '\\' in value or '\x00' in value or
            value.startswith('/') or any(p in ('', '.', '..') for p in value.split('/')) or
            PurePosixPath(value).as_posix() != value):
        raise EvidenceError('RUTA DE PAQUETE INVÁLIDA')
    return value


def _manifest(data):
    if (not isinstance(data, dict) or
            set(data) != {'schema_version', 'id', 'created_at', 'records', 'members'} or
            type(data['schema_version']) is not int or data['schema_version'] != 1 or
            not isinstance(data['id'], str) or not re.fullmatch(r'[0-9a-f]{32}', data['id']) or
            not isinstance(data['created_at'], str) or not data['created_at'].endswith('Z')):
        raise EvidenceError('MANIFIESTO INVÁLIDO')
    datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
    if not isinstance(data['members'], list) or not isinstance(data['records'], list) or not data['records']:
        raise EvidenceError('MANIFIESTO VACÍO/INVÁLIDO')
    members = {}
    for entry in data['members']:
        if not isinstance(entry, dict) or set(entry) != {'path', 'size', 'sha256'}:
            raise EvidenceError('MIEMBRO DE MANIFIESTO INVÁLIDO')
        name = _path(entry['path'])
        if (name == 'manifest.json' or name in members or type(entry['size']) is not int or
                entry['size'] < 0 or not isinstance(entry['sha256'], str) or
                not re.fullmatch(r'[0-9a-f]{64}', entry['sha256'])):
            raise EvidenceError('MIEMBRO DUPLICADO/INVÁLIDO')
        members[name] = entry
    referenced, ids = set(), set()
    for record in data['records']:
        if (not isinstance(record, dict) or
                set(record) != {'id', 'format', 'type', 'payload', 'metadata'} or
                not isinstance(record['id'], str) or not record['id'] or record['id'] in ids or
                record['format'] not in ('sha256-v1', 'legacy-md5') or
                record['type'] not in inventory.CATEGORIES.values()):
            raise EvidenceError('REGISTRO DE MANIFIESTO INVÁLIDO')
        ids.add(record['id'])
        for key in ('payload', 'metadata'):
            name = _path(record[key])
            if name not in members or name in referenced:
                raise EvidenceError('REFERENCIA DE MANIFIESTO INVÁLIDA')
            referenced.add(name)
    if referenced != set(members):
        raise EvidenceError('MIEMBROS SIN REGISTRO')
    return members


def check_archive(path: Path) -> None:
    """Read a tar streaming, never extract; require exactly the declared bytes."""
    path = Path(path).absolute()
    try:
        with _directory(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if _version(before) != _version(inventory._regular_stat(path)):
                raise EvidenceError('PAQUETE MODIFICADO')
            # tarfile's built-in streaming gzip reader does not validate CRC or
            # a missing trailer. GzipFile does, provided we drain it to EOF.
            with gzip.GzipFile(fileobj=source, mode='rb') as decoded, \
                    tarfile.open(fileobj=decoded, mode='r|') as archive:
                first = archive.next()
                if first is None or first.name != 'manifest.json' or not first.isfile():
                    raise EvidenceError('FALTA MANIFIESTO REGULAR')
                with archive.extractfile(first) as content:
                    data = json.load(content, object_pairs_hook=inventory._object,
                                     parse_constant=inventory._constant)
                expected = _manifest(data)
                seen = {'manifest.json'}
                for member in archive:
                    # Streaming TarFile iteration includes its cached first entry.
                    if member is first:
                        continue
                    name = _path(member.name)
                    if not member.isfile() or name in seen or name not in expected:
                        raise EvidenceError('MIEMBRO AJENO, DUPLICADO O NO REGULAR')
                    seen.add(name)
                    entry = expected[name]
                    if member.size != entry['size']:
                        raise EvidenceError('TAMAÑO DE MIEMBRO NO COINCIDE')
                    digest, size = hashlib.sha256(), 0
                    with archive.extractfile(member) as content:
                        while True:
                            chunk = content.read(1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            digest.update(chunk)
                    if size != entry['size'] or digest.hexdigest() != entry['sha256']:
                        raise EvidenceError('HASH DE MIEMBRO NO COINCIDE')
                if seen != set(expected) | {'manifest.json'}:
                    raise EvidenceError('FALTAN MIEMBROS')
                while decoded.read(1024 * 1024):
                    pass
            if (_version(before) != _version(os.fstat(source.fileno())) or
                    _version(before) != _version(inventory._regular_stat(path))):
                raise EvidenceError('PAQUETE MODIFICADO DURANTE LECTURA')
    except (OSError, tarfile.TarError, EOFError, ValueError, TypeError, UnicodeError) as exc:
        raise EvidenceError(f'PAQUETE INVÁLIDO: {exc}') from exc


def _write(path, content):
    with _directory(path.parent) as parent:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def create(root: Path, name: str | None = None) -> Path:
    root = Path(root).absolute()
    if name is not None and (not isinstance(name, str) or
                             re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', name) is None):
        raise UsageError('Nombre de paquete inválido (1–80 letras ASCII, números, _ o -)')
    now = datetime.now(timezone.utc)
    name = now.strftime('%Y%m%d_evidence') if name is None else name
    try:
        initial = inventory.verify(root)
        if not initial.ok:
            details = '; '.join(f'[{issue.code}] {issue.path}: {issue.message}'
                                for issue in initial.issues) or 'SIN EVIDENCIAS'
            raise EvidenceError(f'EXPORTACIÓN BLOQUEADA: {details}')
        versions = {path: _version(inventory._regular_stat(path))
                    for entry in initial.entries for path in (entry.record.payload, entry.record.metadata)}
        output = private_directory(root.parent / '11_Reports/evidence')
        package_id = uuid.uuid4().hex
        final_name = f'{name}_{package_id}.tar.gz'
        stage_name = '.export-' + uuid.uuid4().hex
        stage = output / stage_name
        with _directory(output) as out_fd:
            with _reservation(out_fd, stage_name) as identity, _directory(stage) as stage_fd:
                published = None
                try:
                    os.fchmod(stage_fd, 0o700)
                    members, records = [], []
                    for entry in initial.entries:
                        record = entry.record
                        paths = {}
                        for key, source, size, digest in (
                                ('payload', record.payload, entry.size, entry.sha256),
                                ('metadata', record.metadata, entry.metadata_size, entry.metadata_sha256)):
                            relative = _path(source.relative_to(root).as_posix())
                            destination = stage / relative
                            private_directory(destination.parent)
                            if copy_regular(source, destination) != (size, digest):
                                raise EvidenceError('FUENTE MODIFICADA DESDE VERIFICACIÓN')
                            paths[key] = relative
                            members.append({'path': relative, 'size': size, 'sha256': digest})
                        records.append({'id': record.id, 'format': record.format,
                                        'type': record.kind, **paths})
                    manifest = {'schema_version': 1, 'id': package_id,
                                'created_at': now.isoformat().replace('+00:00', 'Z'),
                                'records': records, 'members': members}
                    _manifest(manifest)
                    _write(stage / 'manifest.json',
                           (json.dumps(manifest, ensure_ascii=True, allow_nan=False, sort_keys=True) + '\n').encode())
                    fd = os.open('archive.tmp', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=stage_fd)
                    with os.fdopen(fd, 'wb') as stream:
                        os.fchmod(stream.fileno(), 0o600)
                        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                            for relative in ['manifest.json'] + [m['path'] for m in members]:
                                source = stage / relative
                                with _directory(source.parent) as parent:
                                    member_fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW,
                                                        dir_fd=parent)
                                with os.fdopen(member_fd, 'rb') as content:
                                    info = tarfile.TarInfo(relative)
                                    info.size = os.fstat(content.fileno()).st_size
                                    info.mode = 0o600
                                    archive.addfile(info, content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    check_archive(stage / 'archive.tmp')
                    current = inventory.verify(root)
                    if current != initial or any(_version(inventory._regular_stat(p)) != v
                                                 for p, v in versions.items()):
                        raise EvidenceError('INVENTARIO/FUENTES MODIFICADOS ANTES DE PUBLICAR')
                    with _directory(output) as current_fd:
                        if (_identity(os.fstat(current_fd)) != _identity(os.fstat(out_fd)) or
                                _identity(os.stat(stage_name, dir_fd=out_fd, follow_symlinks=False)) != identity):
                            raise EvidenceError('DESTINO MODIFICADO')
                    published = _identity(os.stat('archive.tmp', dir_fd=stage_fd, follow_symlinks=False))
                    try:
                        os.link('archive.tmp', final_name, src_dir_fd=stage_fd,
                                dst_dir_fd=out_fd, follow_symlinks=False)
                    except BaseException:
                        published = None  # A collision never belongs to this operation.
                        raise
                    os.fsync(out_fd)
                except BaseException:
                    if published is not None:
                        _unlink_owned(out_fd, final_name, published)
                    raise
                finally:
                    try:
                        if _identity(os.stat(stage_name, dir_fd=out_fd, follow_symlinks=False)) == identity:
                            shutil.rmtree(stage_name, dir_fd=out_fd)
                    except BaseException:
                        if published is not None:
                            _unlink_owned(out_fd, final_name, published)
                        raise
        return output / final_name
    except (OSError, tarfile.TarError, ValueError, TypeError) as exc:
        raise EvidenceError(f'EXPORTACIÓN FALLIDA: {exc}') from exc
