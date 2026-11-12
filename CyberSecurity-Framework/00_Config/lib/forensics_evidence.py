#!/usr/bin/env python3
"""Private module-08 file evidence store, not an executor or custody guarantee.

Only analysis/ is an artifact root in v1. Roots are derived from the selected
run, never followed from JSON. Future acquisition roots need an explicit API,
not a caller-supplied manifest path. Writers are single-owner/sequential.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
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

    def visit(current):
        current = _path(current)
        entry_info = current.lstat()
        relative = current.relative_to(path).as_posix()
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
            'inventory': entries}


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
    _choice(kind, ('file', 'tree'))
    source = _path(source)
    _require(not _overlaps(run.parent, source))
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
    _keys(value, 'sha256 size mode' + (' inventory' if kind == 'tree' else ''))
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


def _validate_step(step, run, verify):
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
        _require(artifact['root'] == 'analysis')
        relative = artifact['path']
        _require(isinstance(relative, str) and relative not in seen and bool(relative) and
                 not Path(relative).is_absolute() and '..' not in Path(relative).parts and
                 Path(relative).as_posix() == relative)
        seen.add(relative)
        _hash(artifact['sha256'])
        _integer(artifact['size'], 0, 2**63 - 1)
        if verify:
            path = _private(run / 'analysis' / relative)
            for parent in path.parents:
                if parent == run:
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
        _keys(data, 'version module run_id operation mode identity inputs started finished state complete rc steps artifact_roots dependents_blocked')
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
        _require(data['artifact_roots'] == {'analysis': str(run / 'analysis')})
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
                _require(_snapshot(work_path, item['kind']) == item['work'])
                if item['kind'] == 'tree':
                    for entry in item['work']['inventory']:
                        _private(work_path / entry['path'], entry['kind'] == 'tree')
        _require(data['identity'] == _identity(data['inputs']))
        _require(type(data['steps']) is list)
        names = set()
        sidecars = set()
        for index, step in enumerate(data['steps']):
            _validate_step(step, run, verify_artifacts)
            _require(step['name'] not in names)
            names.add(step['name'])
            filename = f'{index:04d}-{step["name"]}.json'
            sidecars.add(filename)
            sidecar = _load(run / 'steps' / filename)
            _validate_step(sidecar, run, verify_artifacts)
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
        _require(type(sources) is dict and set(sources) == {i['input_id'] for i in data['inputs']})
        for item in data['inputs']:
            source = _path(sources[item['input_id']])
            _require(not _overlaps(run.parent, source))
            okay = (_snapshot(source, item['kind']) == item['original'] and
                    _snapshot(Path(item['work_path']), item['kind']) == item['work']) and okay
    except (OSError, ValueError, TypeError):
        okay = False
    if not okay:
        data['dependents_blocked'] = True
        _status(data)
        _atomic(run / 'run.json', data)
    return okay


def record_step(run_dir, name, rc, state, coverage, artifacts, *, tool='internal', signal=None):
    run = _path(run_dir)
    data = read_run(run)
    _require(data['finished'] is None and not data['dependents_blocked'])
    _require(type(artifacts) is list)
    references = []
    for value in artifacts:
        path = _private(_path(value))
        _require(run / 'analysis' in path.parents)
        digest, size = _digest_file(path)
        references.append(dict(root='analysis', path=path.relative_to(run / 'analysis').as_posix(),
                               sha256=digest, size=size))
    step = dict(name=name, tool=tool, rc=rc, signal=signal, state=state,
                coverage=coverage, artifacts=references)
    _validate_step(step, run, True)
    _require(name not in [s['name'] for s in data['steps']])
    sidecar = run / 'steps' / f'{len(data["steps"]):04d}-{name}.json'
    _require(not sidecar.exists())
    _atomic(sidecar, step)
    data['steps'].append(step)
    _atomic(run / 'run.json', data)
    return step


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
    _validate_step(step, run, True)
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
            if any(data[k] != v for k, v in filters.items()):
                continue
            row = {k: data[k] for k in ('run_id', 'operation', 'mode', 'identity', 'started',
                                       'finished', 'state', 'complete', 'rc')}
            row['steps'] = data['steps']
            row['inputs'] = [{k: i[k] for k in ('kind', 'sha256', 'size', 'mode')} for i in data['inputs']]
            row.update(invalid=False, current=False)
            rows.append(row)
        except ValueError:
            invalid = True
            rows.append(dict(run_id=candidate.name, invalid=True, current=False,
                             state='NO_EVALUABLE', rc=1, started=None,
                             diagnostic='Manifiesto inválido; vigencia bloqueada conservadoramente'))
    rows.sort(key=lambda row: (_time(row['started']) if row['started'] else datetime.min.replace(tzinfo=timezone.utc),
                               row['run_id']), reverse=True)
    seen = set()
    for row in rows:
        if row['invalid']:
            continue
        group = (row['operation'], row['mode'], row['identity'])
        row['current'] = not invalid and group not in seen
        seen.add(group)
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
    step = subs.add_parser('step')
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
    for name in ('finish', 'validate', 'integrity'):
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
