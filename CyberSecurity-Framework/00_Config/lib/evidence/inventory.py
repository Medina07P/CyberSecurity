"""Read-only, fail-closed inventory of new records and historical MD5 pairs.

Listing opens metadata only. All content reads use regular-file descriptors,
no-follow ancestor walks and before/after identity/version checks. Internal
SHA-256 snapshots of legacy bytes do not upgrade their historical trust.
"""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .model import EvidenceError, Inventory, Issue, Record, Verification, VerifiedRecord
from .storage import PUBLIC_ROOTS, DIRECTORY_FLAGS, _directory, _version


CATEGORIES = {'screenshots': 'screenshot', 'pcaps': 'pcap',
              'credentials': 'credential', 'findings': 'finding',
              'proofs': 'proof', 'logs': 'log'}
FIELDS = {'schema_version', 'id', 'type', 'original_name', 'stored_name', 'size',
          'sha256', 'created_at', 'description', 'origin', 'target', 'run_id', 'method'}
LEGACY_FIELDS = {'TYPE', 'DATE', 'FILE', 'DESCRIPTION', 'HASH', 'USER'}


def _confined(path, root):
    path, root = Path(path).absolute(), Path(root).absolute()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise EvidenceError('RUTA AJENA AL INVENTARIO') from exc
    if '..' in relative.parts or not relative.parts or relative.parts[0] not in CATEGORIES:
        raise EvidenceError('RUTA AJENA AL INVENTARIO')
    return path, relative


def _regular_stat(path):
    with _directory(path.parent) as parent:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise EvidenceError('ARCHIVO NO REGULAR')
    return info


def _read(path, *, content=False):
    """Return exact metadata bytes, or streaming (size, SHA-256, MD5)."""
    with _directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceError('ARCHIVO NO REGULAR')
            chunks, size = [], 0
            sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if content:
                    sha.update(chunk)
                    md5.update(chunk)
                else:
                    chunks.append(chunk)
            if (_version(before) != _version(os.fstat(fd)) or
                    _version(before) != _version(_regular_stat(path)) or size != before.st_size):
                raise EvidenceError('ARCHIVO MODIFICADO DURANTE LECTURA')
            return (size, sha.hexdigest(), md5.hexdigest()) if content else b''.join(chunks)
        finally:
            os.close(fd)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError('CLAVE JSON DUPLICADA')
        result[key] = value
    return result


def _constant(value):
    raise EvidenceError('CONSTANTE JSON NO FINITA')


def _basename(value):
    return (isinstance(value, str) and value not in ('', '.', '..', '.gitkeep') and
            '/' not in value and '\\' not in value and '\x00' not in value)


def _decode(metadata, root, raw):
    metadata, relative = _confined(metadata, root)
    kind = CATEGORIES[relative.parts[0]]
    text = raw.decode('utf-8')
    if metadata.name == 'evidence.json':
        data = json.loads(text, object_pairs_hook=_object, parse_constant=_constant)
        if not isinstance(data, dict) or set(data) != FIELDS:
            raise EvidenceError('CAMPOS DE ESQUEMA INVÁLIDOS')
        if type(data['schema_version']) is not int or data['schema_version'] != 1:
            raise EvidenceError('VERSIÓN NO ADMITIDA')
        if (not isinstance(data['id'], str) or
                re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', data['id']) is None or
                data['id'] != metadata.parent.name or data['type'] != kind):
            raise EvidenceError('IDENTIDAD/TIPO INVÁLIDOS')
        expected = PUBLIC_ROOTS.get(kind)
        if kind == 'log':
            expected = {'scan': 'logs/results', 'system': 'logs/audit'}.get(data['method'])
        if expected is None or relative.parent.parent != Path(expected):
            raise EvidenceError('UBICACIÓN INVÁLIDA')
        if data['stored_name'] != 'artifact':
            raise EvidenceError('NOMBRE ALMACENADO INVÁLIDO')
        if type(data['size']) is not int or data['size'] < 0:
            raise EvidenceError('TAMAÑO INVÁLIDO')
        if not isinstance(data['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', data['sha256']):
            raise EvidenceError('SHA-256 INVÁLIDO')
        if any(not isinstance(data[key], str) for key in
               ('original_name', 'created_at', 'description', 'origin')):
            raise EvidenceError('CAMPOS TEXTUALES INVÁLIDOS')
        if not data['original_name'] or (data['target'] is not None and not isinstance(data['target'], str)):
            raise EvidenceError('NOMBRE/ETIQUETA INVÁLIDOS')
        if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', data['created_at']):
            raise EvidenceError('FECHA UTC INVÁLIDA')
        datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        if data['origin'] == 'import':
            if kind == 'log' or data['run_id'] is not None or data['method'] is not None:
                raise EvidenceError('CONTEXTO DE IMPORTACIÓN INVÁLIDO')
        elif data['origin'] == 'capture':
            if any(not isinstance(data[key], str) or not data[key] for key in ('run_id', 'method')):
                raise EvidenceError('CONTEXTO DE CAPTURA INVÁLIDO')
        else:
            raise EvidenceError('ORIGEN INVÁLIDO')
        record = Record(data['id'], kind, 'sha256-v1', metadata.parent / 'artifact',
                        metadata, data['target'])
    elif metadata.name.endswith('.meta'):
        data = {}
        for line in text.splitlines():
            key, separator, value = line.partition(':')
            if not separator or key not in LEGACY_FIELDS or key in data:
                raise EvidenceError('CAMPO LEGACY INVÁLIDO/DUPLICADO')
            # Exactly the one space written by the old format, not strip().
            data[key] = value[1:] if value.startswith(' ') else value
        if set(data) != LEGACY_FIELDS or data['TYPE'] != kind:
            raise EvidenceError('CAMPOS/TIPO LEGACY INVÁLIDOS')
        if not _basename(data['FILE']) or not re.fullmatch(r'[0-9a-fA-F]{32}', data['HASH']):
            raise EvidenceError('RUTA/HASH LEGACY INVÁLIDOS')
        record = Record(str(relative), kind, 'legacy-md5', metadata.parent / data['FILE'],
                        metadata, None)
    else:
        raise EvidenceError('METADATOS NO RECONOCIDOS')
    _regular_stat(record.payload)
    return record, data


def read_record(metadata: Path, root: Path) -> Record:
    """Validate metadata and payload stat, without reading payload bytes."""
    try:
        metadata, _ = _confined(metadata, root)
        return _decode(metadata, root, _read(metadata))[0]
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise EvidenceError(f'METADATOS INVÁLIDOS: {exc}') from exc


def scan(root: Path) -> Inventory:
    root = Path(root).absolute()
    records, issues, files, directories = [], [], set(), set()

    def issue(path, code, message):
        issues.append(Issue(path, code, str(message)))

    def walk(fd, path):
        try:
            with os.scandir(fd) as entries:
                names = sorted(entry.name for entry in entries)
            for name in names:
                child = path / name
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        directories.add(child)
                        child_fd = os.open(name, DIRECTORY_FLAGS, dir_fd=fd)
                        try:
                            walk(child_fd, child)
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(info.st_mode):
                        if name != '.gitkeep':
                            files.add(child)
                    else:
                        issue(child, 'INVALID', 'ENLACE O ARCHIVO NO REGULAR')
                except OSError as exc:
                    issue(child, 'UNREADABLE', exc)
        except OSError as exc:
            issue(path, 'UNREADABLE', exc)

    try:
        with _directory(root) as root_fd:
            for category in CATEGORIES:
                path = root / category
                try:
                    fd = os.open(category, DIRECTORY_FLAGS, dir_fd=root_fd)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    issue(path, 'UNREADABLE', exc)
                    continue
                try:
                    walk(fd, path)
                finally:
                    os.close(fd)
    except OSError as exc:
        issue(root, 'UNREADABLE', exc)

    parsed, failures, payloads = {}, {}, set()
    # Resolve outer sidecars first: foo.meta.meta is metadata for foo.meta,
    # not a reason to parse foo.meta's payload bytes as metadata. Chains that
    # also admit the inner pairing are ambiguous, never silently selected.
    for path in sorted(files, key=lambda path: (-path.name.count('.meta'), path)):
        # Even a malformed outer sidecar does not authorize opening its
        # apparent payload during listing. Report the invalid/uncovered pair.
        if path in payloads or path.with_name(path.name + '.meta') in files:
            if ((path.name.endswith('.meta') and path.with_name(path.name[:-5]) in files) or
                    (path.name == 'evidence.json' and path.parent / 'artifact' in files)):
                issue(path, 'AMBIGUOUS', 'ARCHIVO ES CONTENIDO Y POSIBLES METADATOS')
            continue
        if path.name == 'evidence.json' or path.name.endswith('.meta'):
            try:
                parsed[path] = read_record(path, root)
                payloads.add(parsed[path].payload)
            except EvidenceError as exc:
                failures[path] = exc
    covered, references = set(), {}
    for path, record in parsed.items():
        if path in payloads:
            issue(path, 'AMBIGUOUS', 'ARCHIVO ES CONTENIDO Y METADATOS')
        references.setdefault(record.payload, []).append(path)
        if record.format == 'legacy-md5' and path.name != record.payload.name + '.meta':
            issue(path, 'INVALID', 'SIDECAR NO COINCIDE CON FILE')
        records.append(record)
        covered.update((path, record.payload))
    for payload, metadata_paths in references.items():
        if len(metadata_paths) > 1:
            issue(payload, 'DUPLICATE', 'REFERENCIAS DE CONTENIDO REPETIDAS')
    for path, failure in failures.items():
        if path not in payloads:
            issue(path, 'INVALID', failure)
            covered.add(path)
    for path in sorted(files - covered):
        issue(path, 'MISSING_METADATA', 'CONTENIDO SIN METADATOS')
    for path in sorted(directories):
        if path == root / 'logs/runs':
            issue(path, 'INVALID', 'LEDGER SIN ESQUEMA ADMITIDO EN ESTA VERSIÓN')
        if re.fullmatch(r'[0-9a-f]{32}', path.name) and path / 'evidence.json' not in parsed:
            issue(path, 'INVALID', 'REGISTRO INCOMPLETO O INVÁLIDO')
    return Inventory(records, issues)


def verify(root: Path) -> Verification:
    inventory = scan(root)
    entries, issues = [], list(inventory.issues)
    for record in inventory.records:
        try:
            raw = _read(record.metadata)
            current, data = _decode(record.metadata, root, raw)
            if current != record:
                raise EvidenceError('IDENTIDAD MODIFICADA DESDE INVENTARIO')
            size, sha, md5 = _read(record.payload, content=True)
            if record.format == 'sha256-v1':
                if size != data['size'] or sha != data['sha256']:
                    raise EvidenceError('TAMAÑO O SHA-256 MODIFICADO')
            elif md5 != data['HASH'].lower():
                raise EvidenceError('MD5 MODIFICADO')
            if _read(record.metadata) != raw:
                raise EvidenceError('METADATOS MODIFICADOS DURANTE VERIFICACIÓN')
            entries.append(VerifiedRecord(record, size, sha, len(raw), hashlib.sha256(raw).hexdigest()))
        except (EvidenceError, OSError, ValueError, TypeError, UnicodeError) as exc:
            issues.append(Issue(record.metadata, 'INVALID', str(exc)))
    return Verification(entries, issues)
