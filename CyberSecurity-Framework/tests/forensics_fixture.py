"""Synthetic-only fixtures; consumers may supply every backend as a closed PATH stub."""
import contextlib
from pathlib import Path
import tempfile


LIBRARY = Path(__file__).resolve().parents[1] / '00_Config/lib/forensics_evidence.py'


def load_evidence():
    # Compile directly: importing this helper normally must not cache production code.
    import types
    module = types.ModuleType('forensics_evidence')
    module.__file__ = str(LIBRARY)
    exec(compile(LIBRARY.read_bytes(), str(LIBRARY), 'exec'), module.__dict__)
    return module


@contextlib.contextmanager
def sandbox():
    with tempfile.TemporaryDirectory(prefix='forensics-', dir='/tmp/opencode') as tmp:
        root = Path(tmp)
        for name in ('home', 'bin', 'sources', 'outputs'):
            (root / name).mkdir(mode=0o700)
        yield root


def closed_environment(root, stubs=None):
    """No host PATH fallback. Caller supplies stubs, including dangerous binaries.

    Stub bodies must have an absolute interpreter shebang (e.g. /bin/sh).
    Missing tools stay missing; this fixture never executes any tool itself.
    """
    for name, body in (stubs or {}).items():
        if not name or Path(name).name != name:
            raise ValueError('invalid stub name')
        target = root / 'bin' / name
        with target.open('x') as stream:
            stream.write(body)
        target.chmod(0o700)
    return {'PATH': str(root / 'bin'), 'HOME': str(root / 'home'),
            'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}


def inventory(root):
    import hashlib
    return {str(p.relative_to(root)): (p.stat().st_mode,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
            for p in root.rglob('*')}
