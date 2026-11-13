#!/usr/bin/env python3
"""Private module-08 file evidence store, not an executor or custody guarantee.

Additional roots require exclusive creation and a signed private registration;
manifest paths alone never authorize reads. Writers are single-owner/sequential.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import selectors
import signal as process_signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid


STATES = ('COMPLETADO', 'PARCIAL', 'FALLIDO', 'OMITIDO', 'NO_EVALUABLE', 'CANCELADO')
OPERATIONS = ('strings', 'logs', 'timeline', 'pcap', 'volatility', 'disk',
              'carving', 'memory', 'workflow', 'dependencies')
MODES = ('offline', 'local', 'physical')
IDENTIFIER = re.compile(r'[a-zA-Z][a-zA-Z0-9_.-]{0,63}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
RUN_ID = re.compile(r'run-[0-9a-f]{32}\Z')
INPUT_ID = re.compile(r'in-[0-9a-f]{32}\Z')


class PreconditionError(ValueError):
    """Invalid use before a copy or metadata write has begun."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, 'Uso forense inválido; consulte --help.\n')


def _require(condition):
    if not condition:
        raise PreconditionError('Metadata o precondición forense inválida')


def _identifier(value):
    _require(isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None)


def _integer(value, low, high):
    _require(type(value) is int and low <= value <= high)


def _hash(value):
    _require(isinstance(value, str) and HEX.fullmatch(value) is not None)


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names.split()))


def _choice(value, choices):
    _require(isinstance(value, str) and value in choices)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _time(value):
    _require(isinstance(value, str))
    result = datetime.fromisoformat(value)
    _require(result.tzinfo is not None and result.utcoffset() is not None)
    return result.astimezone(timezone.utc)


def _path(value):
    """Reject symlinks in every existing component, before canonicalization."""
    result = Path(os.path.abspath(value))
    _require(not any(ord(c) < 32 or ord(c) == 127 for c in str(result)))
    for part in (*reversed(result.parents), result):
        _require(not part.is_symlink())
    return result


def _private(path, directory=False):
    path = _path(path)
    info = path.lstat()
    _require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)))
    _require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
    return path


def _mkdir(path):
    path = _path(path)
    if not path.exists():
        if not path.parent.exists():
            _mkdir(path.parent)
        path.mkdir(mode=0o700)
    _require(path.is_dir())


def _overlaps(a, b):
    return a == b or a in b.parents or b in a.parents


def _open_read(path):
    path = _path(path)
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o444))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _require(stat.S_ISREG(os.fstat(fd).st_mode))
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def _digest_file(path):
    digest = hashlib.sha256()
    size = 0
    with _open_read(path) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _snapshot(path, kind):
    path = _path(path)
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if kind == 'file':
        digest, size = _digest_file(path)
        return {'sha256': digest, 'size': size, 'mode': mode}
    _require(kind == 'tree' and stat.S_ISDIR(info.st_mode) and bool(mode & 0o444)
             and bool(mode & 0o111))
    entries = []
    times = []

    def visit(current):
        current = _path(current)
        entry_info = current.lstat()
        relative = current.relative_to(path).as_posix()
        times.append({'path': relative, 'mtime_ns': entry_info.st_mtime_ns})
        entry = {'path': relative, 'mode': stat.S_IMODE(entry_info.st_mode)}
        if stat.S_ISDIR(entry_info.st_mode):
            _require(bool(entry_info.st_mode & 0o444) and bool(entry_info.st_mode & 0o111))
            entry.update(kind='tree', size=0, sha256=None)
            entries.append(entry)
            for child in sorted(current.iterdir()):
                visit(child)
        else:
            digest, size = _digest_file(current)  # rejects links/devices/pipes
            entry.update(kind='file', size=size, sha256=digest)
            entries.append(entry)

    visit(path)
    return {'sha256': hashlib.sha256(_encoded(entries)).hexdigest(),
            'size': sum(entry['size'] for entry in entries), 'mode': mode,
            'inventory': entries,
            'temporal': {'clock': 'unix_ns', 'entries': times,
                         'sha256': hashlib.sha256(_encoded(times)).hexdigest()}}


def _matches_snapshot(observed, recorded):
    # Historical v1 trees did not observe timestamps. Only that optional field
    # is normalized; content, size, inventory and modes remain authoritative.
    if 'inventory' in recorded and 'temporal' not in recorded:
        observed = {k: v for k, v in observed.items() if k != 'temporal'}
    return observed == recorded


def _copy_file(source, destination):
    # O_EXCL: collisions and symlinks never truncate an existing object.
    with _open_read(source) as src:
        fd = os.open(_path(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as dst:
            while chunk := src.read(1024 * 1024):
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())


def _copy(source, destination, kind, snapshot):
    if kind == 'file':
        _copy_file(source, destination)
    else:
        destination.mkdir(mode=0o700)
        for entry in snapshot['inventory']:
            if entry['path'] == '.':
                continue
            target = destination / entry['path']
            if entry['kind'] == 'tree':
                target.mkdir(mode=0o700)
            else:
                _copy_file(source / entry['path'], target)


def _atomic(path, data):
    path = _path(path)
    if path.exists():
        _private(path)
    temporary = path.parent / ('.metadata-' + uuid.uuid4().hex)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(_encoded(data) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _load(path):
    _private(path)
    with _open_read(path) as stream:
        return json.load(stream, object_pairs_hook=_pairs)


def _identity(inputs):
    identities = sorted((item['kind'], item['sha256']) for item in inputs)
    return hashlib.sha256(_encoded(identities)).hexdigest() if inputs else None


def _run_identity(data):
    if data.get('observed_devices'):
        # Observation timestamp and random receipt id are not source identity.
        identities = [{k: item[k] for k in ('dev', 'ino', 'rdev', 'size')}
                      for item in data['observed_devices']]
        return hashlib.sha256(_encoded(['physical_observation', identities])).hexdigest()
    return _identity(data['inputs'])


def _root_records(run):
    """Authenticate registrations, not user-controlled artifact_roots strings.

    Private per-run key is a local integrity anchor, not protection from a
    malicious writer running as the same uid. Supports cross-filesystem roots.
    """
    registry = run / 'roots.json'
    if not registry.exists():
        _require(not (run / '.roots-key').exists())
        return {}
    key_path = _private(run / '.roots-key')
    _require(key_path.stat().st_uid == os.geteuid())
    with _open_read(key_path) as stream:
        key = stream.read(33)
    _require(len(key) == 32)
    envelope = _load(registry)
    _keys(envelope, 'records signature')
    records = envelope['records']
    _require(type(records) is dict and set(records) <= {'recovered', 'captures'})
    _require(hmac.compare_digest(envelope['signature'], hmac.new(
        key, _encoded([str(run), records]), hashlib.sha256).hexdigest()))
    for name, record in records.items():
        _keys(record, 'path dev ino uid')
        path = _private(record['path'], True)
        _require(path.name == run.name and not _overlaps(run, path))
        info = path.lstat()
        _require(all(type(record[k]) is int and record[k] == v for k, v in
                     (('dev', info.st_dev), ('ino', info.st_ino), ('uid', info.st_uid))))
        _require(info.st_uid == os.geteuid())
        marker = _load(path / '.forensics-owner.json')
        _require(marker == {'run': str(run), 'root': name})
    return records


def _artifact_roots(run, data):
    roots = {'analysis': str(run / 'analysis')}
    roots.update({name: item['path'] for name, item in _root_records(run).items()})
    _require(data['artifact_roots'] == roots)
    return {name: Path(path) for name, path in roots.items()}


def register_artifact_root(run_dir, name, parent):
    """Create PARENT/RUN_ID exclusively; return its authenticated private path."""
    run = _path(run_dir)
    data = read_run(run)
    _choice(name, ('recovered', 'captures'))
    _require(data['finished'] is None and not data['dependents_blocked'] and not data['steps'])
    _require(name not in data['artifact_roots'])
    parent = _path(parent)
    _require(not _overlaps(parent, run))
    sources = _load(run / 'sources.json')
    for value in sources.values():
        _require(not _overlaps(parent, _path(value)))
    _mkdir(parent)  # existing parent's mode/content is not changed
    target = parent / run.name
    target.mkdir(mode=0o700)
    _require(target.lstat().st_uid == os.geteuid())
    _atomic(target / '.forensics-owner.json', {'run': str(run), 'root': name})
    records = _root_records(run)
    info = target.lstat()
    records[name] = dict(path=str(target), dev=info.st_dev, ino=info.st_ino, uid=info.st_uid)
    key_path = run / '.roots-key'
    if not key_path.exists():
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(os.urandom(32))
            stream.flush()
            os.fsync(stream.fileno())
    with _open_read(_private(key_path)) as stream:
        key = stream.read()
    signature = hmac.new(key, _encoded([str(run), records]), hashlib.sha256).hexdigest()
    _atomic(run / 'roots.json', dict(records=records, signature=signature))
    data['artifact_roots'][name] = str(target)
    _atomic(run / 'run.json', data)
    return target


def _device_identity(source):
    info = _path(source).lstat()  # deliberately no open/hash/ioctl on device
    _require(stat.S_ISBLK(info.st_mode))
    return dict(dev=info.st_dev, ino=info.st_ino, rdev=info.st_rdev,
                mode=stat.S_IMODE(info.st_mode))


def probe_source(source, kind):
    """Preflight before run creation; no content digest or device payload read."""
    source = _path(source)
    _choice(kind, ('file', 'device'))
    if kind == 'device':
        _device_identity(source)
    else:
        with _open_read(source):
            pass
    return {'source': str(source)}


def _device_observation(source):
    observed = _device_identity(source)
    observed['size'] = None
    # Metadata only; never read a payload byte and never request write access.
    # Size failure is explicit unknown, not zero and not an acquisition failure.
    try:
        fd = os.open(_path(source), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            actual = os.fstat(fd)
            _require(stat.S_ISBLK(actual.st_mode) and all(
                getattr(actual, 'st_' + k) == observed[k] for k in ('dev', 'ino', 'rdev')))
            observed['size'] = struct.unpack('=Q', fcntl.ioctl(fd, 0x80081272, bytes(8)))[0]
        finally:
            os.close(fd)
    except (OSError, ValueError, struct.error):
        pass
    return observed


def observe_device(run_dir, source):
    run = _path(run_dir)
    data = read_run(run)
    _require(data['mode'] == 'physical' and not data['inputs'] and not data['steps'] and
             not data.get('observed_devices') and data['finished'] is None and
             not data['dependents_blocked'])
    source = _path(source)
    for root in _artifact_roots(run, data).values():
        _require(not _overlaps(root, source))
    observed = _device_observation(source)
    observed.update(input_id='in-' + uuid.uuid4().hex, observed=_now())
    sources = _load(run / 'sources.json')
    sources[observed['input_id']] = str(source)
    _atomic(run / 'sources.json', sources)
    data['observed_devices'] = [observed]
    data['identity'] = _run_identity(data)
    _atomic(run / 'run.json', data)
    return observed


def _aggregate(data):
    if data['dependents_blocked']:
        return 'FALLIDO'
    requested = [s for s in data['steps'] if s['coverage']['requested']]
    if any(s['state'] == 'FALLIDO' for s in requested):
        return 'FALLIDO'
    if any(s['state'] == 'CANCELADO' for s in requested):
        return 'CANCELADO'
    if requested and all(s['state'] == 'COMPLETADO' and s['coverage']['complete']
                         and s['rc'] == 0 and s['signal'] is None for s in requested):
        return 'COMPLETADO'
    return 'PARCIAL'


def _status(data):
    data['state'] = _aggregate(data) if data['finished'] or data['dependents_blocked'] else 'PARCIAL'
    data['complete'] = data['state'] == 'COMPLETADO'
    data['rc'] = 0 if data['complete'] else 1


def start_run(root: Path, operation: str, mode: str, inputs: list[dict]) -> Path:
    _choice(operation, OPERATIONS)
    _choice(mode, MODES)
    _require(type(inputs) is list)
    root = _path(root)
    for item in inputs:
        _keys(item, 'source kind')
        _choice(item['kind'], ('file', 'tree'))
        source = _path(item['source'])
        _require(not _overlaps(root, source))
        _snapshot(source, item['kind'])
    _mkdir(root)
    run = root / ('run-' + uuid.uuid4().hex)
    run.mkdir(mode=0o700)  # collision fails; no retry/truncation
    for name in ('work', 'analysis', 'steps'):
        (run / name).mkdir(mode=0o700)
    data = dict(version=1, module='08', run_id=run.name, operation=operation,
                mode=mode, identity=None, inputs=[], started=_now(), finished=None,
                state='PARCIAL', complete=False, rc=1, steps=[],
                artifact_roots={'analysis': str(run / 'analysis')}, dependents_blocked=False)
    _atomic(run / 'sources.json', {})
    _atomic(run / 'run.json', data)
    print('Aviso: resultados sensibles; raíces externas requieren protección y exclusión git propias.',
          file=sys.stderr)
    for item in inputs:
        stage_input(run, Path(item['source']), item['kind'])
    return run


def _same_content(original, work, kind):
    if original['size'] != work['size']:
        return False
    if kind == 'file':
        return original['sha256'] == work['sha256']
    # Tree digests include permissions; compare every inventory field except
    # mode, since staging deliberately makes the copy private (700/600).
    def contents(snapshot):
        return [{k: v for k, v in entry.items() if k != 'mode'}
                for entry in snapshot['inventory']]
    return contents(original) == contents(work)


def stage_input(run_dir: Path, source: Path, kind: str = 'file') -> dict:
    run = _path(run_dir)
    data = read_run(run)
    _require(data['finished'] is None and not data['dependents_blocked'] and not data['steps'])
    _require(not data.get('observed_devices'))
    _choice(kind, ('file', 'tree'))
    source = _path(source)
    _require(not _overlaps(run.parent, source))
    for name, root in _artifact_roots(run, data).items():
        if name != 'analysis':
            _require(not _overlaps(root.parent, source))
    try:
        snapshot = _snapshot(source, kind)
    except (OSError, ValueError):
        raise PreconditionError('Entrada no regular, ilegible o inválida') from None
    input_id = 'in-' + uuid.uuid4().hex
    destination = run / 'work' / input_id
    try:
        _copy(source, destination, kind, snapshot)
        _require(_snapshot(source, kind) == snapshot)
        work = _snapshot(destination, kind)
        _require(_same_content(snapshot, work, kind))
        item = dict(input_id=input_id, kind=kind, work_path=str(destination),
                    sha256=snapshot['sha256'], size=snapshot['size'], mode=snapshot['mode'],
                    original=snapshot, work=work)
        sources = _load(run / 'sources.json')
        sources[input_id] = str(source)
        _atomic(run / 'sources.json', sources)
        data['inputs'].append(item)
        data['identity'] = _identity(data['inputs'])
        _atomic(run / 'run.json', data)
        return item
    except (OSError, ValueError):
        data['dependents_blocked'] = True
        _status(data)
        _atomic(run / 'run.json', data)
        raise ValueError('No se pudo preparar una copia íntegra privada') from None


def _validate_snapshot(value, kind):
    temporal = kind == 'tree' and type(value) is dict and 'temporal' in value
    _keys(value, 'sha256 size mode' + (' inventory' if kind == 'tree' else '') +
          (' temporal' if temporal else ''))
    _hash(value['sha256'])
    _integer(value['size'], 0, 2**63 - 1)
    _integer(value['mode'], 0, 0o7777)
    if kind == 'tree':
        _require(type(value['inventory']) is list and bool(value['inventory']))
        seen = set()
        total = 0
        for entry in value['inventory']:
            _keys(entry, 'path mode kind size sha256')
            relative = entry['path']
            _require(isinstance(relative, str) and relative not in seen and
                     not Path(relative).is_absolute() and '..' not in Path(relative).parts and
                     Path(relative).as_posix() == relative and
                     not any(ord(c) < 32 or ord(c) == 127 for c in relative))
            seen.add(relative)
            _choice(entry['kind'], ('file', 'tree'))
            _integer(entry['mode'], 0, 0o7777)
            _integer(entry['size'], 0, 2**63 - 1)
            if entry['kind'] == 'file':
                _hash(entry['sha256'])
            else:
                _require(entry['sha256'] is None and entry['size'] == 0)
            total += entry['size']
        _require(value['inventory'][0]['path'] == '.' and total == value['size'])
        _require(hashlib.sha256(_encoded(value['inventory'])).hexdigest() == value['sha256'])
        if temporal:
            times = value['temporal']
            _keys(times, 'clock entries sha256')
            _require(times['clock'] == 'unix_ns' and type(times['entries']) is list)
            _require(len(times['entries']) == len(value['inventory']))
            for time, entry in zip(times['entries'], value['inventory']):
                _keys(time, 'path mtime_ns')
                _require(time['path'] == entry['path'])
                _integer(time['mtime_ns'], -2**63, 2**63 - 1)
            _hash(times['sha256'])
            _require(hashlib.sha256(_encoded(times['entries'])).hexdigest() == times['sha256'])


def _validate_step(step, run, verify, roots=None):
    roots = roots or {'analysis': run / 'analysis'}
    _keys(step, 'name tool rc signal state coverage artifacts')
    _identifier(step['name'])
    _identifier(step['tool'])
    _integer(step['rc'], 0, 255)
    if step['signal'] is not None:
        _integer(step['signal'], 1, 127)
        _require(step['state'] in ('CANCELADO', 'FALLIDO') and step['rc'] != 0)
    _choice(step['state'], STATES)
    coverage = step['coverage']
    _keys(coverage, 'code complete requested')
    _identifier(coverage['code'])
    _require(type(coverage['complete']) is bool and type(coverage['requested']) is bool)
    if step['state'] == 'COMPLETADO':
        _require(step['rc'] == 0 and step['signal'] is None and coverage['complete'])
    else:
        _require(not coverage['complete'])
    _require(type(step['artifacts']) is list)
    if coverage['code'] in (CAPTURE_PENDING, CAPTURE_READY):
        _require(step['state'] == 'PARCIAL' and step['signal'] is None and
                 not coverage['complete'] and coverage['requested'])
        if coverage['code'] == CAPTURE_PENDING:
            _require(step['rc'] == 0 and not step['artifacts'])
        else:
            _require([a.get('path') for a in step['artifacts'] if type(a) is dict] ==
                     [step['name'] + '.stdout', step['name'] + '.stderr'])
    seen = set()
    for artifact in step['artifacts']:
        _keys(artifact, 'root path sha256 size')
        _require(artifact['root'] in roots)
        if coverage['code'] in (CAPTURE_PENDING, CAPTURE_READY, 'runtime_cancelled'):
            _require(artifact['root'] == 'analysis')
        relative = artifact['path']
        _require(isinstance(relative, str) and relative not in seen and bool(relative) and
                 not Path(relative).is_absolute() and '..' not in Path(relative).parts and
                  Path(relative).as_posix() == relative and
                  not any(ord(c) < 32 or ord(c) == 127 for c in relative))
        _require((artifact['root'], relative) not in seen)
        seen.add((artifact['root'], relative))
        _hash(artifact['sha256'])
        _integer(artifact['size'], 0, 2**63 - 1)
        if verify:
            root = roots[artifact['root']]
            path = _private(root / relative)
            for parent in path.parents:
                if parent == root.parent:
                    break
                _private(parent, True)
            _require(_digest_file(path) == (artifact['sha256'], artifact['size']))


def read_run(path: Path, *, verify_artifacts: bool = True) -> dict:
    """Read own metadata/artifacts only; never reopen original evidence."""
    try:
        run = _path(path)
        if run.name == 'run.json':
            run = run.parent
        _private(run, True)
        _require(RUN_ID.fullmatch(run.name) is not None)
        data = _load(run / 'run.json')
        _keys(data, 'version module run_id operation mode identity inputs started finished state complete rc steps artifact_roots dependents_blocked' +
              (' observed_devices' if 'observed_devices' in data else ''))
        _require(type(data['version']) is int and data['version'] == 1 and data['module'] == '08')
        _require(data['run_id'] == run.name)
        _choice(data['operation'], OPERATIONS)
        _choice(data['mode'], MODES)
        _choice(data['state'], STATES)
        _require(type(data['complete']) is bool and type(data['dependents_blocked']) is bool)
        _integer(data['rc'], 0, 1)
        started = _time(data['started'])
        if data['finished'] is not None:
            _require(_time(data['finished']) >= started)
        roots = _artifact_roots(run, data)
        for name in ('work', 'analysis', 'steps'):
            _private(run / name, True)
        _require(type(data['inputs']) is list)
        ids = set()
        for item in data['inputs']:
            _keys(item, 'input_id kind work_path sha256 size mode original work')
            iid = item['input_id']
            _require(isinstance(iid, str) and INPUT_ID.fullmatch(iid) is not None and iid not in ids)
            ids.add(iid)
            _choice(item['kind'], ('file', 'tree'))
            _require(item['work_path'] == str(run / 'work' / iid))
            for snapshot in ('original', 'work'):
                _validate_snapshot(item[snapshot], item['kind'])
            _require(_same_content(item['original'], item['work'], item['kind']))
            _require(all(item[k] == item['original'][k] and type(item[k]) is type(item['original'][k])
                         for k in ('sha256', 'size', 'mode')))
            if verify_artifacts:
                work_path = _private(Path(item['work_path']), item['kind'] == 'tree')
                _require(_matches_snapshot(_snapshot(work_path, item['kind']), item['work']))
                if item['kind'] == 'tree':
                    for entry in item['work']['inventory']:
                        _private(work_path / entry['path'], entry['kind'] == 'tree')
        if 'observed_devices' in data:
            _require(data['mode'] == 'physical' and not data['inputs'] and
                     type(data['observed_devices']) is list and len(data['observed_devices']) == 1)
            observed = data['observed_devices'][0]
            _keys(observed, 'dev ino rdev mode size input_id observed')
            _require(INPUT_ID.fullmatch(observed['input_id']) is not None)
            for name in ('dev', 'ino', 'rdev'):
                _integer(observed[name], 0, 2**64 - 1)
            _integer(observed['mode'], 0, 0o7777)
            if observed['size'] is not None:
                _integer(observed['size'], 0, 2**63 - 1)
            _time(observed['observed'])
        _require(data['identity'] == _run_identity(data))
        _require(type(data['steps']) is list)
        names = set()
        sidecars = set()
        for index, step in enumerate(data['steps']):
            _validate_step(step, run, verify_artifacts, roots)
            _require(step['name'] not in names)
            names.add(step['name'])
            filename = f'{index:04d}-{step["name"]}.json'
            sidecars.add(filename)
            sidecar = _load(run / 'steps' / filename)
            _validate_step(sidecar, run, verify_artifacts, roots)
            _require(_encoded(sidecar) == _encoded(step))
        _require({p.name for p in (run / 'steps').iterdir()} == sidecars)
        expected = dict(data)
        _status(expected)
        _require(all(data[k] == expected[k] for k in ('state', 'complete', 'rc')))
        return data
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError('Ejecución forense inválida o ilegible') from None


def check_integrity(run_dir: Path) -> bool:
    run = _path(run_dir)
    data = read_run(run, verify_artifacts=False)
    okay = not data['dependents_blocked']
    try:
        sources = _load(run / 'sources.json')
        observations = data.get('observed_devices', [])
        _require(type(sources) is dict and set(sources) ==
                 {i['input_id'] for i in data['inputs'] + observations})
        for item in observations:
            observed = _device_identity(sources[item['input_id']])
            okay = all(observed[k] == item[k] for k in observed) and okay
        for item in data['inputs']:
            source = _path(sources[item['input_id']])
            _require(not _overlaps(run.parent, source))
            okay = (_matches_snapshot(_snapshot(source, item['kind']), item['original']) and
                    _matches_snapshot(_snapshot(Path(item['work_path']), item['kind']), item['work'])) and okay
    except (OSError, ValueError, TypeError):
        okay = False
    if not okay:
        data['dependents_blocked'] = True
        _status(data)
        _atomic(run / 'run.json', data)
    return okay


def _make_step(run, roots, name, rc, state, coverage, artifacts, tool, signal):
    _require(type(artifacts) is list)
    references = []
    for value in artifacts:
        path = _private(_path(value))
        matches = [(name, root) for name, root in roots.items() if root in path.parents]
        _require(len(matches) == 1)
        name_root, root = matches[0]
        digest, size = _digest_file(path)
        references.append(dict(root=name_root, path=path.relative_to(root).as_posix(),
                               sha256=digest, size=size))
    step = dict(name=name, tool=tool, rc=rc, signal=signal, state=state,
                coverage=coverage, artifacts=references)
    _validate_step(step, run, True, roots)
    return step


def record_step(run_dir, name, rc, state, coverage, artifacts, *, tool='internal', signal=None):
    run = _path(run_dir)
    data = read_run(run)
    _require(data['finished'] is None and not data['dependents_blocked'])
    step = _make_step(run, _artifact_roots(run, data), name, rc, state, coverage, artifacts, tool, signal)
    _require(name not in [s['name'] for s in data['steps']])
    sidecar = run / 'steps' / f'{len(data["steps"]):04d}-{name}.json'
    _require(not sidecar.exists())
    _atomic(sidecar, step)
    data['steps'].append(step)
    _atomic(run / 'run.json', data)
    return step


def _cleanup_owner(run):
    run = _private(run, True)
    _require(RUN_ID.fullmatch(run.name) is not None)
    info = run.stat()
    _require(info.st_uid == os.geteuid())
    return dict(run=str(run), dev=info.st_dev, ino=info.st_ino, uid=info.st_uid)


def init_cleanup(run_dir):
    """Opt-in independent resource journal, created BEFORE resource allocation.

    This journal is NOT a valid analysis run and cannot repair/certify one.
    It remains writable through the explicit cleanup API if run.json is corrupt.
    """
    run = _path(run_dir)
    data = read_run(run)
    _require(data['finished'] is None and not data['steps'])
    _require(not (run / 'cleanup.json').exists())
    receipt = dict(version=1, owner=_cleanup_owner(run), finished=None, steps=[])
    _atomic(run / 'cleanup.json', receipt)
    return receipt


def read_cleanup(run_dir):
    """Validate resource receipts only, without reading run.json/work/originals."""
    run = _path(run_dir)
    receipt = _load(run / 'cleanup.json')
    _keys(receipt, 'version owner finished steps')
    _require(type(receipt['version']) is int and receipt['version'] == 1)
    _require(_encoded(receipt['owner']) == _encoded(_cleanup_owner(run)))
    if receipt['finished'] is not None:
        _time(receipt['finished'])
    _require(type(receipt['steps']) is list)
    names = set()
    _private(run / 'analysis', True)
    for step in receipt['steps']:
        _validate_step(step, run, True)
        _require(step['name'] in ('cleanup_umount', 'cleanup_detach', 'disk_resources') and
                 step['name'] not in names)
        names.add(step['name'])
        _require(step['coverage']['code'] in ('cleanup_command', 'resource_ownership'))
    return receipt


def record_cleanup_step(run_dir, name, rc, state, coverage, artifacts, *, tool='internal', signal=None):
    run = _path(run_dir)
    receipt = read_cleanup(run)
    _require(receipt['finished'] is None)
    step = _make_step(run, {'analysis': run / 'analysis'}, name, rc, state, coverage, artifacts, tool, signal)
    _require(name in ('cleanup_umount', 'cleanup_detach', 'disk_resources') and
             name not in [s['name'] for s in receipt['steps']] and
             coverage['code'] in ('cleanup_command', 'resource_ownership'))
    receipt['steps'].append(step)
    _atomic(run / 'cleanup.json', receipt)
    return step


def finish_cleanup(run_dir):
    run = _path(run_dir)
    receipt = read_cleanup(run)
    if receipt['finished'] is None:
        receipt['finished'] = _now()
        _atomic(run / 'cleanup.json', receipt)
    return receipt


def finish_run(run_dir) -> dict:
    run = _path(run_dir)
    data = read_run(run, verify_artifacts=False)
    if data['finished'] is not None:
        return read_run(run)
    check_integrity(run)
    data = read_run(run, verify_artifacts=False)
    # Every artifact is checked even when its producer failed.
    try:
        read_run(run)
    except ValueError:
        data['dependents_blocked'] = True
    data['finished'] = _now()
    _status(data)
    _atomic(run / 'run.json', data)
    return data


# Runtime receipts deliberately reuse v1 steps: pending/captured are incomplete
# PARCIAL steps with reserved coverage codes, never provisional successes.
CAPTURE_PENDING = 'runtime_pending'
CAPTURE_READY = 'runtime_captured'


def block_run(run_dir):
    run = _path(run_dir)
    data = read_run(run, verify_artifacts=False)
    _require(data['finished'] is None)
    data['dependents_blocked'] = True
    _status(data)
    _atomic(run / 'run.json', data)
    return data


def _capture_paths(run, name):
    _identifier(name)
    return [run / 'analysis' / (name + suffix) for suffix in ('.stdout', '.stderr')]


def prepare_capture(run_dir, name, tool):
    run = _path(run_dir)
    data = read_run(run)
    _identifier(name)
    _identifier(tool)
    _require(data['finished'] is None and not data['dependents_blocked'])
    _require(name not in [step['name'] for step in data['steps']])
    paths = _capture_paths(run, name)
    for path in paths:
        fd = os.open(_path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    record_step(run, name, 0, 'PARCIAL',
                dict(code=CAPTURE_PENDING, complete=False, requested=True), [], tool=tool)
    return dict(stdout=str(paths[0]), stderr=str(paths[1]))


def _pending_capture(run_dir, name, code):
    run = _path(run_dir)
    data = read_run(run)
    _require(data['finished'] is None and not data['dependents_blocked'])
    matches = [(i, s) for i, s in enumerate(data['steps']) if s['name'] == name]
    _require(len(matches) == 1)
    index, step = matches[0]
    _require(step['state'] == 'PARCIAL' and step['coverage'] ==
             dict(code=code, complete=False, requested=True) and step['signal'] is None)
    return run, data, index, dict(step)


def _publish_capture(run, data, index, step):
    _validate_step(step, run, True, _artifact_roots(run, data))
    _atomic(run / 'steps' / f'{index:04d}-{step["name"]}.json', step)
    data['steps'][index] = step
    _atomic(run / 'run.json', data)
    return step


def capture_result(run_dir, name, rc, *, signal=None, cancelled=False):
    """Seal streams once after the writer is reaped; rc belongs to this name."""
    run, data, index, step = _pending_capture(run_dir, name, CAPTURE_PENDING)
    _integer(rc, 0, 255)
    _require(type(cancelled) is bool)
    _require(step['rc'] == 0 and not step['artifacts'])
    references = []
    for path in _capture_paths(run, name):
        _private(path)
        digest, size = _digest_file(path)
        references.append(dict(root='analysis', path=path.name, sha256=digest, size=size))
    interrupted = cancelled or signal is not None
    step.update(rc=rc, signal=signal, artifacts=references,
                state='CANCELADO' if interrupted else 'PARCIAL',
                coverage=dict(code='runtime_cancelled' if interrupted else CAPTURE_READY,
                              complete=False, requested=True))
    return _publish_capture(run, data, index, step)


def complete_capture(run_dir, name, state, coverage_code):
    run, data, index, step = _pending_capture(run_dir, name, CAPTURE_READY)
    _identifier(coverage_code)
    _require(coverage_code not in (CAPTURE_PENDING, CAPTURE_READY))
    # Contrasts name, sealed stream references and their hashes before publishing.
    expected = [p.name for p in _capture_paths(run, name)]
    _require([a['path'] for a in step['artifacts']] == expected)
    step.update(state=state, coverage=dict(code=coverage_code,
                complete=state == 'COMPLETADO', requested=True))
    return _publish_capture(run, data, index, step)


class _OwnedProcessGroup:
    """Dedicated unreaped child reserves the PGID until every group signal ends.

    Only the dedicated supervisor owns/reaps this fork child. In particular it
    is NOT a Popen object subject to subprocess's asynchronous cleanup list.
    """
    def __init__(self):
        _require(process_signal.getsignal(process_signal.SIGCHLD) == process_signal.SIG_DFL)
        read_fd, self.hold_fd = os.pipe()
        self.pid = os.fork()
        if self.pid == 0:
            try:
                os.close(self.hold_fd)
                os.setpgid(0, 0)
                process_signal.signal(process_signal.SIGTERM, process_signal.SIG_IGN)
                process_signal.signal(process_signal.SIGINT, process_signal.SIG_IGN)
                for fd in (0, 1, 2):
                    if fd != read_fd:
                        os.close(fd)
                os.read(read_fd, 1)  # supervisor death closes the sole writer
            finally:
                os._exit(0)
        os.close(read_fd)
        os.setpgid(self.pid, self.pid)

    def stop(self):
        if self.pid is not None:
            try:
                os.killpg(self.pid, process_signal.SIGKILL)
            except ProcessLookupError:
                # Even a dead anchor is NOT reaped yet; its PID cannot be reused.
                pass

    def close(self):
        if self.pid is not None:
            self.stop()
            while True:
                try:
                    os.waitpid(self.pid, 0)
                    break
                except InterruptedError:
                    continue
            # No group signal is allowed beyond this ownership-release point.
            self.pid = None
            os.close(self.hold_fd)


_EXEC_GATE = '''import os, signal, sys
gate = int(sys.argv[1])
permission = os.read(gate, 1)
os.close(gate)
if permission != b'G':
    os._exit(125)
# Match Popen(restore_signals=True) again: starting this Python gate reset
# these dispositions to SIG_IGN after Popen's initial child restoration.
for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ'):
    if hasattr(signal, name):
        signal.signal(getattr(signal, name), signal.SIG_DFL)
if sys.argv[2] == '--leaf':
    # The pidfd must refer to the leaf shell itself, not an intermediary shell
    # whose optimization/fork policy might defer parent-only cancellation.
    os.execvp('bash', ['bash', *sys.argv[3:]])
os.execvp('bash', ['bash', '-c', 'set -o pipefail; "$@"', 'forensics', *sys.argv[2:]])
'''


def _supervise_capture(run_dir, name, tool, arguments):
    """Internal Linux supervisor; stdin/stdout are private protocol pipes.

    READY -> GO|CANCEL N -> RESULT json -> RELEASE. GO is launch authorization;
    cancellation queued before authorization wins. GO permits an innocuous
    worker only; the tool's exec is gated on that worker's concrete pidfd and
    selector registration. Exec retains the PID to which the handle refers.
    """
    run, _, _, _ = _pending_capture(run_dir, name, CAPTURE_PENDING)
    _identifier(tool)
    _require(sys.version_info >= (3, 11) and hasattr(os, 'pidfd_open'))
    streams = [_private(p) for p in _capture_paths(run, name)]
    return _supervise_owned(streams, tool, arguments)


def _supervise_preflight(kind, tool, arguments):
    """Dedicated pre-run CLI only. No manifests, arbitrary commands or deadlines
    on acquisition/analysis. Subreaper is confined to this supervisor process.
    """
    _require((kind == 'compatibility' and tool in ('avml', 'lime') and arguments == ['--help']) or
             (kind == 'privilege' and tool == 'sudo' and arguments == ['-n', 'true']))
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    _require(libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0)
    _require(libc.prctl(36, 1, 0, 0, 0) == 0)
    try:
        with tempfile.TemporaryDirectory(prefix='forensics-preflight-', dir=Path.home()) as directory:
            streams = [Path(directory) / name for name in ('stdout', 'stderr')]
            for stream in streams:
                fd = os.open(stream, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            return _supervise_owned(streams, tool, arguments, preflight_kind=kind)
    finally:
        # This CLI owns no unrelated children. The common engine has stopped
        # the anchored group, waited its worker and released the anchor first.
        # Reap adopted grandchildren too; never signal after anchor release.
        while True:
            try:
                os.waitpid(-1, 0)
            except InterruptedError:
                continue
            except ChildProcessError:
                break
        libc.prctl(36, previous.value, 0, 0, 0)


def _supervise_leaf(log, leaf, input_fd, arguments, interactive=False):
    """Workflow leaf: concrete pidfd cancellation, wait for its own cleanup.

    No operational deadline, no kill of a recyclable identifier. The common
    anchor still contains descendants after the leaf has returned.
    """
    leaf = _path(leaf)
    module = Path(__file__).resolve().parents[2] / '08_Forensics'
    _require(leaf in [module / name for name in (
        'memory/memory_dump.sh', 'memory/strings_analysis.sh', 'logs/log_analyzer.sh',
        'pcaps/pcap_analyzer.sh', 'disk/disk_forensics.sh', 'timeline/timeline_creator.sh')])
    _require(leaf.is_file())
    return _supervise_owned([_private(log), _private(log)], 'bash', [str(leaf), *arguments],
                            workflow_input=input_fd, interactive=interactive)


def _supervise_owned(streams, tool, arguments, *, preflight_kind=None,
                     workflow_input=None, interactive=False):
    """One engine for capture and whitelisted preflight; same gate/ownership.
    Only compatibility preflight has a fixed ten-second monotonic deadline.
    """
    _require(sys.version_info >= (3, 11) and hasattr(os, 'pidfd_open'))
    group = backend = None
    pid_fd = None
    gate_write = None
    tool_authorized = False
    cancelled = 0
    authorized = False
    deadline = None
    timed_out = False
    cancellation_sent = False
    buffered = b''
    wake_read, wake_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    previous_wakeup = process_signal.set_wakeup_fd(wake_write)
    previous_handlers = {}

    def cancellation(signum, frame):
        nonlocal cancelled
        cancelled = cancelled or signum

    for sig in (process_signal.SIGINT, process_signal.SIGTERM):
        previous_handlers[sig] = process_signal.signal(sig, cancellation)

    def control():
        nonlocal buffered, authorized, cancelled, deadline
        chunk = os.read(0, 256)
        _require(bool(chunk))
        buffered += chunk
        _require(len(buffered) <= 1024)
        while b'\n' in buffered:
            line, buffered = buffered.split(b'\n', 1)
            if line == b'GO':
                _require(not authorized)
                authorized = True
                if preflight_kind == 'compatibility':
                    deadline = time.monotonic() + 10
            else:
                _require(line in (b'CANCEL 2', b'CANCEL 15'))
                cancelled = cancelled or int(line.split()[1])

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(0, selectors.EVENT_READ, 'control')
            selector.register(wake_read, selectors.EVENT_READ, 'signal')
            print('READY', flush=True)
            while True:
                remaining = max(0, deadline - time.monotonic()) if deadline is not None else None
                for key, _ in selector.select(remaining):
                    if key.data == 'control':
                        control()
                    elif key.data == 'signal':
                        os.read(wake_read, 4096)
                if cancelled:
                    if workflow_input is None or backend is None:
                        break
                    if not cancellation_sent:
                        # A graceful leaf owns cleanup; do not kill its group
                        # while it is releasing authenticated resources.
                        try:
                            process_signal.pidfd_send_signal(pid_fd, cancelled)
                        except ProcessLookupError:
                            pass
                        cancellation_sent = True
                if deadline is not None and time.monotonic() >= deadline:
                    timed_out = True
                    break
                if authorized and backend is None:
                    group = _OwnedProcessGroup()
                    # Drain cancellation already queued while establishing the
                    # anchor, before committing to the backend fork.
                    for key, _ in selector.select(0):
                        if key.data == 'control':
                            control()
                        elif key.data == 'signal':
                            os.read(wake_read, 4096)
                    if cancelled:
                        break
                    gate_read, gate_write = os.pipe()
                    try:
                        with streams[0].open('ab' if workflow_input is not None else 'wb') as out, \
                             streams[1].open('ab' if workflow_input is not None else 'wb') as err:
                            gate_arguments = ['--leaf', *arguments] if workflow_input is not None else [tool, *arguments]
                            backend = subprocess.Popen(
                                [sys.executable, '-B', '-c', _EXEC_GATE, str(gate_read), *gate_arguments],
                                stdin=subprocess.DEVNULL if workflow_input is None else workflow_input,
                                stdout=out, stderr=None if interactive else err,
                                pass_fds=(gate_read,), process_group=group.pid)
                    finally:
                        os.close(gate_read)
                    pid_fd = os.pidfd_open(backend.pid)
                    selector.register(pid_fd, selectors.EVENT_READ, 'backend')
                    # A self-probe or hasattr cannot represent this child's
                    # permissions. Until the real handle is usable, this PID
                    # runs only the inert gate, never Bash or the requested tool.
                    for key, _ in selector.select(0):
                        if key.data == 'control':
                            control()
                        elif key.data == 'signal':
                            os.read(wake_read, 4096)
                    if cancelled:
                        break
                    if deadline is not None and time.monotonic() >= deadline:
                        timed_out = True
                        break
                    os.write(gate_write, b'G')
                    tool_authorized = True
                    os.close(gate_write)
                    gate_write = None
                if backend is not None and backend.poll() is not None:
                    selector.unregister(pid_fd)
                    os.close(pid_fd)
                    pid_fd = None
                    break
            if (cancelled or timed_out) and group is not None and workflow_input is None:
                group.stop()  # anchor is still live or an unreaped zombie
            actual_rc = backend.wait() if backend is not None else 0
            terminating_signal = -actual_rc if actual_rc < 0 else None
            result = dict(rc=128 - actual_rc if actual_rc < 0 else actual_rc,
                          terminating_signal=terminating_signal,
                          cancellation_wrapper_signal=cancelled or None,
                          started=tool_authorized, worker_created=backend is not None)
            if group is not None:
                group.close()
            if preflight_kind is not None:
                # Never emit backend bodies on the console. RESULT travels only
                # over the owner's private control pipe, before temp cleanup.
                bodies = []
                limited = False
                for stream in streams:
                    with stream.open('rb') as source:
                        body = source.read(1048577)
                    limited = limited or len(body) > 1048576
                    bodies.append(body[:1048576].decode('utf-8', errors='replace'))
                result.update(timed_out=timed_out, output=''.join(bodies), output_limited=limited)
            print('RESULT ' + json.dumps(result, sort_keys=True), flush=True)
            # A late cancellation can no longer signal a group: ownership has
            # ended. Keep the pipe alive until the owner releases the channel.
            while True:
                line = sys.stdin.buffer.readline(64)
                if line == b'RELEASE\n':
                    break
                _require(line in (b'CANCEL 2\n', b'CANCEL 15\n', b'GO\n'))
            return result
    finally:
        if group is not None:
            group.close()
        if backend is not None:
            backend.wait()
        if pid_fd is not None:
            os.close(pid_fd)
        if gate_write is not None:
            os.close(gate_write)
        process_signal.set_wakeup_fd(previous_wakeup)
        for sig, handler in previous_handlers.items():
            process_signal.signal(sig, handler)
        os.close(wake_read)
        os.close(wake_write)


def reconcile_current(rows):
    """Conservative attribution, shared by selector and multi-root viewer.

    An offline attempt without a usable input has no trustworthy source identity.
    It blocks current attribution, NOT joins the identities of other evidence.
    Legacy/unfinished attempts are deliberately subject to the same rule.
    """
    rows.sort(key=lambda row: (_time(row['started']) if row['started'] else
              datetime.min.replace(tzinfo=timezone.utc), row['run_id']), reverse=True)
    blocked = any(row['invalid'] or (row['mode'] == 'offline' and row['identity'] is None and
                  row['operation'] not in ('dependencies', 'workflow')) for row in rows)
    seen = set()
    for row in rows:
        if row['invalid']:
            continue
        group = (row['operation'], row['mode'], row['identity'])
        row['current'] = not blocked and group not in seen
        seen.add(group)
    return rows


def select_runs(root, filters) -> list[dict]:
    """Newest-first summaries. Any unreadable run blocks current attribution.

    No external destinations are discovered from manifests. Select one external
    run/run.json explicitly, or explicitly select its parent root.
    """
    _require(type(filters) is dict and set(filters) <= {'run_id', 'operation', 'identity'})
    for key, value in filters.items():
        _require(isinstance(value, str))
        if key == 'operation':
            _choice(value, OPERATIONS)
        elif key == 'identity':
            _hash(value)
        else:
            _require(RUN_ID.fullmatch(value) is not None)
    root = _path(root)
    if root.name == 'run.json' or RUN_ID.fullmatch(root.name):
        candidates = [root.parent if root.name == 'run.json' else root]
    else:
        _require(root.is_dir())
        candidates = sorted(p for p in root.iterdir() if RUN_ID.fullmatch(p.name))
    rows = []
    invalid = False
    for candidate in candidates:
        try:
            data = read_run(candidate)
            if any(data[k] != v for k, v in filters.items() if k != 'identity'):
                continue
            row = {k: data[k] for k in ('run_id', 'operation', 'mode', 'identity', 'started',
                                       'finished', 'state', 'complete', 'rc')}
            row['steps'] = data['steps']
            row['inputs'] = [{k: i[k] for k in ('kind', 'sha256', 'size', 'mode')} for i in data['inputs']]
            if data.get('observed_devices'):
                row['identity_kind'] = 'device_observation'
                row['observed_devices'] = data['observed_devices']
            row.update(invalid=False, current=False)
            rows.append(row)
        except ValueError:
            invalid = True
            rows.append(dict(run_id=candidate.name, invalid=True, current=False,
                             state='NO_EVALUABLE', rc=1, started=None,
                             diagnostic='Manifiesto inválido; vigencia bloqueada conservadoramente'))
    reconcile_current(rows)
    if 'identity' in filters:
        rows = [row for row in rows if row['invalid'] or row['identity'] == filters['identity']]
    return rows


def show_results(root, filters):
    rows = select_runs(root, filters)
    print(json.dumps(rows, ensure_ascii=True, sort_keys=True))
    return rows


def main(argv=None):
    parser = SafeParser(description='Almacén privado forense 08 (sin ejecutores)')
    subs = parser.add_subparsers(dest='command', required=True)
    init = subs.add_parser('init')
    init.add_argument('--root', required=True, type=Path)
    init.add_argument('--operation', required=True, choices=OPERATIONS)
    init.add_argument('--mode', default='offline', choices=MODES)
    stage = subs.add_parser('stage')
    stage.add_argument('--run', required=True, type=Path)
    stage.add_argument('--source', required=True, type=Path)
    stage.add_argument('--kind', default='file', choices=('file', 'tree'))
    register = subs.add_parser('register-root')
    register.add_argument('--run', required=True, type=Path)
    register.add_argument('--name', required=True, choices=('recovered', 'captures'))
    register.add_argument('--parent', required=True, type=Path)
    observe = subs.add_parser('observe-device')
    observe.add_argument('--run', required=True, type=Path)
    observe.add_argument('--source', required=True, type=Path)
    probe = subs.add_parser('probe-source')
    probe.add_argument('--source', required=True, type=Path)
    probe.add_argument('--kind', required=True, choices=('file', 'device'))
    step = subs.add_parser('step', aliases=['cleanup-step'])
    step.add_argument('--run', required=True, type=Path)
    step.add_argument('--name', required=True)
    step.add_argument('--tool', default='internal')
    step.add_argument('--rc', required=True, type=int)
    step.add_argument('--signal', type=int)
    step.add_argument('--state', required=True, choices=STATES)
    step.add_argument('--coverage-code', required=True)
    step.add_argument('--complete', action='store_true')
    step.add_argument('--not-requested', action='store_true')
    step.add_argument('--artifact', action='append', default=[], type=Path)
    for name in ('finish', 'validate', 'integrity', 'init-cleanup', 'validate-cleanup', 'finish-cleanup'):
        subs.add_parser(name).add_argument('--run', required=True, type=Path)
    subs.add_parser('block').add_argument('--run', required=True, type=Path)
    prepare = subs.add_parser('prepare-capture')
    prepare.add_argument('--run', required=True, type=Path)
    prepare.add_argument('--name', required=True)
    prepare.add_argument('--tool', required=True)
    capture = subs.add_parser('capture-result')
    capture.add_argument('--run', required=True, type=Path)
    capture.add_argument('--name', required=True)
    capture.add_argument('--rc', required=True, type=int)
    capture.add_argument('--signal', type=int)
    capture.add_argument('--cancelled', action='store_true')
    complete = subs.add_parser('complete-capture')
    complete.add_argument('--run', required=True, type=Path)
    complete.add_argument('--name', required=True)
    complete.add_argument('--state', required=True, choices=STATES)
    complete.add_argument('--coverage-code', required=True)
    supervise = subs.add_parser('supervise')
    supervise.add_argument('--run', required=True, type=Path)
    supervise.add_argument('--name', required=True)
    supervise.add_argument('--tool', required=True)
    supervise.add_argument('arguments', nargs=argparse.REMAINDER)
    preflight = subs.add_parser('supervise-preflight')
    preflight.add_argument('--kind', required=True, choices=('compatibility', 'privilege'))
    preflight.add_argument('--tool', required=True)
    preflight.add_argument('arguments', nargs=argparse.REMAINDER)
    leaf = subs.add_parser('supervise-leaf')
    leaf.add_argument('--log', required=True, type=Path)
    leaf.add_argument('--leaf', required=True, type=Path)
    leaf.add_argument('--stdin-fd', required=True, type=int)
    leaf.add_argument('--interactive', action='store_true')
    leaf.add_argument('arguments', nargs=argparse.REMAINDER)
    listing = subs.add_parser('list')
    listing.add_argument('--root', required=True, type=Path)
    for flag in ('run-id', 'operation', 'identity'):
        listing.add_argument('--' + flag)
    args = parser.parse_args(argv)
    command = args.command
    try:
        rc = 0
        if command == 'init':
            run = start_run(args.root, args.operation, args.mode, [])
            result = {'run_dir': str(run), 'run_id': run.name}
        elif command == 'stage':
            result = stage_input(args.run, args.source, args.kind)
        elif command == 'register-root':
            result = {'path': str(register_artifact_root(args.run, args.name, args.parent))}
        elif command == 'observe-device':
            result = observe_device(args.run, args.source)
        elif command == 'probe-source':
            result = probe_source(args.source, args.kind)
        elif command in ('init-cleanup', 'validate-cleanup', 'finish-cleanup'):
            result = {'init-cleanup': init_cleanup, 'validate-cleanup': read_cleanup,
                      'finish-cleanup': finish_cleanup}[command](args.run)
        elif command == 'cleanup-step':
            result = record_cleanup_step(args.run, args.name, args.rc, args.state,
                                 dict(code=args.coverage_code, complete=args.complete,
                                      requested=not args.not_requested), args.artifact,
                                 tool=args.tool, signal=args.signal)
            rc = 0 if result['state'] == 'COMPLETADO' else 1
        elif command == 'step':
            result = record_step(args.run, args.name, args.rc, args.state,
                                 dict(code=args.coverage_code, complete=args.complete,
                                      requested=not args.not_requested), args.artifact,
                                 tool=args.tool, signal=args.signal)
            rc = 0 if (result['state'] == 'COMPLETADO' or
                       (result['state'] == 'OMITIDO' and args.not_requested)) else 1
        elif command == 'finish':
            result = finish_run(args.run)
            rc = result['rc']
        elif command == 'block':
            result = block_run(args.run)
        elif command == 'prepare-capture':
            result = prepare_capture(args.run, args.name, args.tool)
        elif command == 'capture-result':
            result = capture_result(args.run, args.name, args.rc, signal=args.signal,
                                    cancelled=args.cancelled)
        elif command == 'complete-capture':
            result = complete_capture(args.run, args.name, args.state, args.coverage_code)
        elif command == 'supervise':
            arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
            _supervise_capture(args.run, args.name, args.tool, arguments)
            return 0
        elif command == 'supervise-preflight':
            arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
            _supervise_preflight(args.kind, args.tool, arguments)
            return 0
        elif command == 'supervise-leaf':
            arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
            _supervise_leaf(args.log, args.leaf, args.stdin_fd, arguments, args.interactive)
            return 0
        elif command == 'validate':
            result = read_run(args.run)
        elif command == 'integrity':
            okay = check_integrity(args.run)
            result, rc = {'integrity': okay}, 0 if okay else 1
        else:
            result = select_runs(args.root, {k: getattr(args, k) for k in
                                 ('run_id', 'operation', 'identity') if getattr(args, k) is not None})
            rc = 1 if any(row['invalid'] for row in result) else 0
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return rc
    except (OSError, ValueError, TypeError) as error:
        print('Error forense: precondición, integridad o persistencia inválida; sin datos sensibles.',
              file=sys.stderr)
        return 2 if isinstance(error, PreconditionError) or command in ('validate', 'list') else 1


if __name__ == '__main__':
    sys.exit(main())
