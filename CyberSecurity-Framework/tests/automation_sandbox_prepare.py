"""Host preparation as data only. No execution, fallback, deletion or finalizer.

NOT RUN: collective independent static gate for Tasks1–3 is still required.
The only checkout accepted by prepare is derived from this file. JSON inputs
are the two fixed adjacent manifests, never CLI/YAML/environment supplied.
"""
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import uuid


class IsolationBlocked(RuntimeError):
    """Fail closed, preserving any incomplete staging tree."""


@dataclass(frozen=True)
class RuntimeFile:
    source: Path
    destination: str
    category: str


@dataclass(frozen=True)
class PreparedRun:
    root: Path
    source_root: Path
    runtime_root: Path
    work: Path
    evidence: Path
    manifest: tuple[RuntimeFile, ...]


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RUN_PARENT = Path('/tmp/opencode')
MAX_JSON = 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
LIBDIR = Path('/usr/lib/x86_64-linux-gnu')
STDLIB = Path('/usr/lib/python3.13')
YAML = Path('/usr/lib/python3/dist-packages/yaml')
PYTHON_ALIAS = '_sysconfigdata__x86_64-linux-gnu.py'
PYTHON_CANONICAL = '_sysconfigdata__linux_x86_64-linux-gnu.py'
UTILITIES = ('basename', 'cat', 'chmod', 'cp', 'date', 'dirname', 'env',
             'find', 'grep', 'head', 'mkdir', 'mktemp', 'mv', 'od', 'printf',
             'readlink', 'sed', 'sort', 'stat', 'tail', 'timeout', 'tr', 'wc')
CROSS_RUNTIME = (
    ('/usr/bin/mawk', '/usr/bin/awk'), ('/usr/bin/cut', '/usr/bin/cut'),
    ('/usr/bin/seq', '/usr/bin/seq'), ('/usr/bin/sleep', '/usr/bin/sleep'),
    ('/usr/bin/tee', '/usr/bin/tee'), ('/usr/bin/rm', '/usr/bin/rm'))


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _parts(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or '\x00' in str(path):
        raise IsolationBlocked('Expected absolute normalized path')
    return path.parts[1:]


def _open_regular(path):
    """Walk every component using pinned no-follow directory descriptors."""
    parts = _parts(path)
    if not parts:
        raise IsolationBlocked('Expected regular file')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise IsolationBlocked('Not a regular file: ' + str(path))
        except BaseException:
            os.close(fd)
            raise
        return fd, directory, parts[-1]
    except BaseException:
        os.close(directory)
        raise


def read_regular(path, limit=MAX_FILE):
    """Bounded stable read, including descriptor and named-entry revalidation."""
    try:
        fd, parent, name = _open_regular(path)
        try:
            before = _identity(os.fstat(fd))
            if before[3] > limit:
                raise IsolationBlocked('File exceeds bound: ' + str(path))
            chunks, size = [], 0
            while True:
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > limit:
                    raise IsolationBlocked('File grew beyond bound')
            if (before != _identity(os.fstat(fd)) or
                    before != _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) or
                    size != before[3]):
                raise IsolationBlocked('Source changed during read')
            return b''.join(chunks)
        finally:
            os.close(fd)
            os.close(parent)
    except OSError as exc:
        raise IsolationBlocked('Read blocked: ' + str(path)) from exc


def copy_regular(source, destination, mode=0o600):
    """No overwrite. Failed/partial copies are deliberately retained."""
    try:
        fd, parent, name = _open_regular(source)
        output = None
        target_parent = None
        try:
            before = _identity(os.fstat(fd))
            if before[3] > MAX_FILE:
                raise IsolationBlocked('Source exceeds 32MiB')
            # The destination parent must already be a private directory;
            # reuse the same no-follow walker with a directory-only final step.
            target_parent = _open_directory(Path(destination).parent)
            output = os.open(Path(destination).name, os.O_WRONLY | os.O_CREAT |
                             os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=target_parent)
            total = 0
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE:
                    raise IsolationBlocked('Source grew beyond bound')
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        raise IsolationBlocked('Short write')
                    view = view[written:]
            if (before != _identity(os.fstat(fd)) or total != before[3] or
                    before != _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))):
                raise IsolationBlocked('Source changed during copy')
            os.fchmod(output, mode)
            os.fsync(output)
            copied = os.fstat(output)
            return {'sha256': digest.hexdigest(), 'source_identity': list(before),
                    'staged_identity': list(_identity(copied)), 'mode': mode,
                    'size': total}
        finally:
            if output is not None:
                os.close(output)
            if target_parent is not None:
                os.close(target_parent)
            os.close(fd)
            os.close(parent)
    except OSError as exc:
        reason = 'ENOSPC (retained)' if exc.errno == errno.ENOSPC else 'Copy blocked'
        raise IsolationBlocked(reason + ': ' + str(destination)) from exc


def _open_directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in _parts(path):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _mkdirs(path):
    """Create private descendants; existing directories must not be symlinks."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in _parts(path):
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
    finally:
        os.close(fd)


def _closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IsolationBlocked('Duplicate JSON key')
        result[key] = value
    return result


def load_json(path, keys, *, version=1):
    try:
        result = json.loads(read_regular(path, MAX_JSON), object_pairs_hook=_closed_pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IsolationBlocked('Invalid JSON') from exc
    if not isinstance(result, dict) or set(result) != set(keys):
        raise IsolationBlocked('Closed JSON schema mismatch')
    if type(result.get('version')) is not int or result['version'] != version:
        raise IsolationBlocked('Unsupported manifest version')
    return result


def source_names():
    data = load_json(HERE / 'automation_sandbox_sources.json', {'version', 'files'})
    names = data['files']
    if not isinstance(names, list) or not names or len(names) > 4096:
        raise IsolationBlocked('Invalid source inventory')
    seen = set()
    for name in names:
        if not isinstance(name, str):
            raise IsolationBlocked('Invalid source name')
        path = PurePosixPath(name)
        if ('\x00' in name or str(path) != name or path.is_absolute() or '..' in path.parts or
                any(p.startswith('.') for p in path.parts) or name in seen):
            raise IsolationBlocked('Unsafe/duplicate source name')
        allowed = (name.startswith('CyberSecurity-Framework/') and
                   (path.suffix in ('.sh', '.bash', '.py', '.ps1') or
                    name in _SOURCE_DATA)) or name in _SOURCE_DOCS
        if not allowed or any(p in _FORBIDDEN_PARTS for p in path.parts):
            raise IsolationBlocked('Non-source input denied: ' + name)
        seen.add(name)
    return tuple(names)


_SOURCE_DATA = frozenset({
    'CyberSecurity-Framework/tests/cross_module_cases.json',
    'CyberSecurity-Framework/00_Config/lib/dangerous.txt',
    'CyberSecurity-Framework/09_Automation/workflows/quick_scan.yaml',
    'CyberSecurity-Framework/09_Automation/workflows/full_audit.yaml',
    'CyberSecurity-Framework/09_Automation/docker/Dockerfile',
    'CyberSecurity-Framework/09_Automation/docker/docker-compose.yml',
    'CyberSecurity-Framework/09_Automation/docker/Dockerfile.dockerignore',
    'CyberSecurity-Framework/tests/automation_preservation_cases.json',
    'CyberSecurity-Framework/tests/automation_operational_baseline.json',
    'CyberSecurity-Framework/tests/automation_sandbox_manifest.json',
    'CyberSecurity-Framework/tests/automation_sandbox_sources.json',
})
_SOURCE_DOCS = frozenset({
    'docs/MENU-OPCIONES.md', 'docs/AUTOMATION-2026-11-13.md',
    'docs/AUTOMATION-TEST-ISOLATION-2026-11-13.md',
    'CyberSecurity-Framework/09_Automation/docker/README.md',
    'CyberSecurity-Framework/09_Automation/README.md',
    'CyberSecurity-Framework/09_Automation/USE.md',
})
# Some tracked source leaves live under loot/ and cleanup/: names, not broad
# directory exclusions, distinguish them from generated data.
_FORBIDDEN_PARTS = frozenset({'credentials', 'scans', '__pycache__',
                              'home', 'site-packages', 'dist-packages'})


def _ordinary_runtime_identity(source):
    """New fixed runtime must be root-owned regular executable, never a link."""
    fd, parent, name = _open_regular(source)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022) or
                not info.st_mode & 0o111 or
                _identity(info) != _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))):
            raise IsolationBlocked('Untrusted fixed ordinary runtime: ' + str(source))
    finally:
        os.close(fd)
        os.close(parent)


def _runtime_entries():
    data = load_json(HERE / 'automation_sandbox_manifest.json',
                     {'version', 'executables', 'stdlib', 'yaml', 'extensions', 'python_aliases'})
    if data['python_aliases'] != [{
            'destination': str(STDLIB / PYTHON_ALIAS),
            'source': str(STDLIB / PYTHON_CANONICAL), 'link': PYTHON_CANONICAL}]:
        raise IsolationBlocked('Python alias differs from fixed allowlist')
    _python_alias_identity()
    expected = [('/usr/bin/python3.13', '/usr/bin/python3'),
                ('/usr/bin/python3.13', '/usr/bin/python3.13'),
                ('/usr/bin/bash', '/bin/bash'), ('/usr/bin/bash', '/usr/bin/bash'),
                ('/usr/bin/bash', '/bin/sh')]
    expected += [('/usr/bin/' + name, '/usr/bin/' + name) for name in UTILITIES]
    expected += list(CROSS_RUNTIME)
    rows = data['executables']
    if (not isinstance(rows, list) or any(not isinstance(r, dict) or
            set(r) != {'source', 'destination'} for r in rows) or
            rows != [{'source': s, 'destination': d} for s, d in expected] or
            data['stdlib'] != str(STDLIB) or data['yaml'] != str(YAML)):
        raise IsolationBlocked('Runtime policy differs from fixed allowlist')
    entries = []
    for source, destination in expected:
        if (source, destination) in CROSS_RUNTIME:
            _ordinary_runtime_identity(Path(source))
            entries.append(RuntimeFile(Path(source), destination, 'elf'))
            continue  # exact ordinary source; never canonicalize a new alias
        # Only fixed runtime aliases are canonicalized. No repo source follows
        # links. Canonical targets must remain in the approved binary directory.
        try:
            canonical = Path(source).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise IsolationBlocked('Missing/invalid fixed executable') from exc
        if canonical.parent != Path('/usr/bin'):
            raise IsolationBlocked('Executable alias escapes /usr/bin')
        entries.append(RuntimeFile(canonical, destination, 'elf'))
    for base, destination, category in (
            (STDLIB, STDLIB, 'python'),
            (YAML, STDLIB / 'site-packages/yaml', 'yaml')):
        entries.extend(_python_files(base, destination, category))
    extensions = data['extensions']
    if not isinstance(extensions, list) or not extensions or len(extensions) > 256:
        raise IsolationBlocked('Invalid extension inventory')
    for name in extensions:
        if (not isinstance(name, str) or Path(name).name != name or
                not name.endswith('.so') or name.startswith('.')):
            raise IsolationBlocked('Invalid extension name')
        path = STDLIB / 'lib-dynload' / name
        entries.append(RuntimeFile(path, str(path), 'elf'))
    return tuple(entries)


def _python_alias_identity():
    """Validate exactly one literal link; never resolve arbitrary Python links."""
    directory = _open_directory(STDLIB)
    canonical_fd = canonical_parent = None
    try:
        before = os.stat(PYTHON_ALIAS, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISLNK(before.st_mode) or
                os.readlink(PYTHON_ALIAS, dir_fd=directory) != PYTHON_CANONICAL):
            raise IsolationBlocked('Fixed Python alias metadata mismatch')
        canonical_fd, canonical_parent, name = _open_regular(STDLIB / PYTHON_CANONICAL)
        identity = _identity(os.fstat(canonical_fd))
        if (identity != _identity(os.stat(name, dir_fd=canonical_parent, follow_symlinks=False)) or
                identity != _identity(os.fstat(canonical_fd)) or
                _identity(before) != _identity(os.stat(PYTHON_ALIAS, dir_fd=directory,
                                                     follow_symlinks=False)) or
                os.readlink(PYTHON_ALIAS, dir_fd=directory) != PYTHON_CANONICAL):
            raise IsolationBlocked('Fixed Python alias identity changed')
        return (_identity(before), identity)
    except OSError as exc:
        raise IsolationBlocked('Fixed Python alias unavailable or nonregular: ' +
                               str(STDLIB / PYTHON_ALIAS)) from exc
    finally:
        if canonical_fd is not None:
            os.close(canonical_fd)
        if canonical_parent is not None:
            os.close(canonical_parent)
        os.close(directory)


def _python_files(base, destination, category):
    # Enumerate names as data through no-follow fds, never import packages.
    result = []
    def visit(directory, relative, depth):
        if depth > 64:
            raise IsolationBlocked('Python directory depth exceeded')
        fd = _open_directory(directory)
        try:
            for name in sorted(os.listdir(fd)):
                if name in ('site-packages', 'dist-packages', '__pycache__', 'lib-dynload',
                            'sitecustomize.py', 'usercustomize.py'):
                    continue
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if directory == STDLIB and name == PYTHON_ALIAS and category == 'python':
                    _python_alias_identity()
                    result.append(RuntimeFile(STDLIB / PYTHON_CANONICAL,
                                              str(destination / relative / name), category))
                    continue
                if stat.S_ISLNK(info.st_mode):
                    if name.endswith('.py'):
                        raise IsolationBlocked('Python source symlink denied: ' + str(directory / name))
                    continue  # Never traverse aliases or copy non-Python files.
                rel = relative / name
                if stat.S_ISDIR(info.st_mode):
                    visit(directory / name, rel, depth + 1)
                elif (stat.S_ISREG(info.st_mode) and name.endswith('.py') and
                      name not in ('sitecustomize.py', 'usercustomize.py')):
                    result.append(RuntimeFile(directory / name, str(destination / rel), category))
                    if len(result) > 4096:
                        raise IsolationBlocked('Python inventory bound exceeded')
        finally:
            os.close(fd)
    visit(base, Path(), 0)
    if not result:
        raise IsolationBlocked('Empty Python tree')
    return result


def _new_json(path, value):
    payload = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if len(payload) > MAX_JSON:
        raise IsolationBlocked('Output JSON exceeds 1MiB; retained staging must not launch')
    parent = _open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            view = memoryview(payload)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise IsolationBlocked('Short manifest write')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def prepare(repo: Path) -> PreparedRun:
    """Stage exact sources and closed runtime; never execute staged content."""
    from automation_sandbox_elf import _read_staged_elf, resolve_runtime
    root = None
    try:
        if Path(repo).absolute() != REPO:
            raise IsolationBlocked('Only the checkout derived from __file__ is accepted')
        names = source_names()
        entries = resolve_runtime(_runtime_entries())
        alias_identity = _python_alias_identity()
        # Do not mkdir the approved parent: it must already exist, no-follow.
        parent = _open_directory(RUN_PARENT)
        try:
            name = 'automation-isolated-' + uuid.uuid4().hex
            os.mkdir(name, 0o700, dir_fd=parent)  # EEXIST blocks; no retry/reuse.
        finally:
            os.close(parent)
        root = RUN_PARENT / name
        for child in ('source', 'runtime', 'work', 'evidence'):
            (root / child).mkdir(mode=0o700)
        free = os.statvfs(root)
        _new_json(root / 'state.json', {
            'version': 1, 'state': 'PREPARING', 'root': str(root),
            'available_bytes': free.f_bavail * free.f_frsize,
            'available_inodes': free.f_favail,
            'runtime_executed': False,
        })
        _new_json(root / 'initial-manifest.json', {
            'version': 1, 'sources': list(names),
            'runtime': [{'source': str(entry.source),
                         'destination': entry.destination, 'category': entry.category}
                        for entry in entries],
        })
        records = []
        for relative in names:
            target = root / 'source' / relative
            _mkdirs(target.parent)
            mode = 0o500 if target.suffix in ('.sh', '.py', '.ps1') else 0o600
            record = copy_regular(REPO / relative, target, mode)
            records.append(dict(record, source=relative, destination=relative,
                                category='source'))
        runtime_snapshots = {}
        for entry in entries:
            target = root / 'runtime' / entry.destination.lstrip('/')
            _mkdirs(target.parent)
            is_python_alias = entry.destination == str(STDLIB / PYTHON_ALIAS)
            if is_python_alias and _python_alias_identity() != alias_identity:
                raise IsolationBlocked('Fixed Python alias changed before copy')
            record = copy_regular(entry.source, target, 0o500 if entry.category == 'elf' else 0o600)
            if is_python_alias and (tuple(record['source_identity']) != alias_identity[1] or
                                    _python_alias_identity() != alias_identity):
                raise IsolationBlocked('Fixed Python alias changed during copy')
            snapshot = (record['sha256'], record['source_identity'])
            if entry.source in runtime_snapshots and runtime_snapshots[entry.source] != snapshot:
                raise IsolationBlocked('Canonical runtime alias changed between copies')
            runtime_snapshots[entry.source] = snapshot
            records.append(dict(record, source=str(entry.source),
                                destination=entry.destination, category=entry.category))
        # Re-parse the actual copied bytes. Resolution/copy races must never
        # yield a staged ELF whose loader/dependency is absent from the closure.
        destinations = {entry.destination for entry in entries}
        for entry in entries:
            if entry.category != 'elf':
                continue
            target = root / 'runtime' / entry.destination.lstrip('/')
            info = _read_staged_elf(target, entry.destination)
            required = {str(LIBDIR / name) for name in info.needed}
            if info.interpreter:
                required.add(info.interpreter)
            if not required <= destinations:
                raise IsolationBlocked('Staged ELF closure changed during preparation')
        _new_json(root / 'manifest.json', {'version': 1, 'files': records})
        _new_json(root / 'prepared.json', {'version': 1, 'state': 'PREPARED',
                                          'runtime_executed': False})
        # Host origins exist only in the diagnostic JSON, not in any path a
        # launcher might interpret as a runtime mount/execution reference.
        staged = tuple(RuntimeFile(root / 'runtime' / entry.destination.lstrip('/'),
                                   entry.destination, entry.category) for entry in entries)
        return PreparedRun(root, root / 'source', root / 'runtime',
                           root / 'work', root / 'evidence', staged)
    except (OSError, ValueError, IsolationBlocked) as exc:
        reason = ''.join(c if c.isprintable() else ' ' for c in str(exc)[:512])
        # No removal or overwrite even for failures. Initial state remains;
        # a separate failure receipt is best effort if space is exhausted.
        if root is not None:
            try:
                _new_json(root / 'blocked.json', {'version': 1, 'state': 'BLOCKED',
                                                 'reason': reason})
            except (OSError, IsolationBlocked):
                pass
        raise IsolationBlocked('Preparation blocked: ' + reason +
                               '; artifacts retained: ' + str(root)) from exc
