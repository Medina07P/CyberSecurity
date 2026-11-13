"""Synthetic evidence fixtures. Never copy module data or local configuration."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


SOURCES = (
    '10_Evidence/evidence_manager.sh',
    '00_Config/lib/evidence/__init__.py',
    '00_Config/lib/evidence/model.py',
    '00_Config/lib/evidence/storage.py',
    '00_Config/lib/evidence/inventory.py',
    '00_Config/lib/evidence/package.py',
    '00_Config/lib/evidence/cli.py',
    'tests/evidence_fixture.py',
    'tests/test_evidence_storage.py',
    'tests/test_evidence_inventory.py',
    'tests/test_evidence_package.py',
    'tests/run_evidence.sh',
)


@contextmanager
def sandbox():
    with tempfile.TemporaryDirectory(prefix='evidence-', dir='/tmp/opencode') as name:
        root = Path(name)
        root.chmod(0o700)
        yield root


def copy_sources(root):
    source = Path(__file__).absolute().parents[1]
    framework = root / 'CyberSecurity-Framework'
    for relative in SOURCES:
        original = source / relative
        # Missing product sources are allowed during RED, links never are.
        for ancestor in (original, *original.parents):
            if ancestor.is_symlink():
                raise ValueError(f'symlink source: {ancestor}')
        if not original.exists():
            continue
        if not stat.S_ISREG(original.lstat().st_mode):
            raise ValueError(f'nonregular source: {original}')
        dest = framework / relative
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(original, dest)
        dest.chmod(0o600)
    config = framework / '00_Config'
    config.mkdir(parents=True, exist_ok=True)
    (config / 'scope.yaml').write_text('targets: {ips: [], domains: []}\n')
    (config / 'targets.txt').write_text('# synthetic only\n')
    (config / '.session').write_text('')
    return framework


def closed_env(root, stubs=None):
    bindir = root / 'bin'
    bindir.mkdir(exist_ok=True, mode=0o700)
    for name, executable in [('python3', sys.executable), ('bash', '/bin/bash')]:
        path = bindir / name
        if not path.exists():
            path.symlink_to(executable)
    for name, body in (stubs or {}).items():
        if Path(name).name != name or name in ('python3', 'bash'):
            raise ValueError('invalid stub name')
        path = bindir / name
        path.write_text('#!/bin/bash\n' + body)
        path.chmod(0o700)
    home = root / 'home'
    home.mkdir(exist_ok=True, mode=0o700)
    config = root / 'CyberSecurity-Framework/00_Config'
    return {
        'PATH': str(bindir), 'HOME': str(home), 'LC_ALL': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1',
        'SESSION_FILE': str(config / '.session'),
        'SESSION_SCOPE_FILE': str(config / 'scope.yaml'),
        'SESSION_TARGETS_FILE': str(config / 'targets.txt'),
    }


def snapshot(root):
    """lstat-only traversal; links are recorded, never opened or descended."""
    result = {}
    if not root.exists():
        return result
    def visit(path):
        info = path.lstat()
        entry = [stat.S_IMODE(info.st_mode), stat.S_IFMT(info.st_mode)]
        if stat.S_ISREG(info.st_mode):
            entry += [info.st_size, hashlib.sha256(path.read_bytes()).hexdigest()]
        elif stat.S_ISLNK(info.st_mode):
            entry.append(os.readlink(path))
        result[str(path.relative_to(root))] = tuple(entry)
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child)
    visit(root)
    return result
