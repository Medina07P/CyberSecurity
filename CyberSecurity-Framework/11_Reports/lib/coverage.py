"""Cobertura de fuentes, distinta de confianza y de integridad de artefactos."""
import os
from pathlib import Path
import stat


def regular(path):
    """Rechazar dependencias enlazadas/especiales antes de abrirlas."""
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)) or not stat.S_ISREG(path.stat().st_mode):
        raise OSError('archivo de evidencia no regular o enlace rechazado')
    return path


def entry(module, path, root, host, state, reason):
    return {'modulo': module, 'fuente': os.path.relpath(Path(path).absolute(), Path(root).absolute()),
            'objetivo': host or '', 'estado': state, 'motivo': reason}


def walk(root):
    """Solo nombres y lstat; enlaces y archivos especiales nunca se abren."""
    root = Path(root)
    if any(p.is_symlink() for p in (root, *root.parents)):
        yield root, 'enlace no permitido'
        return
    if not root.is_dir():
        return
    def failed(error):
        failures.append((Path(error.filename), 'directorio no legible'))
    failures = []
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        dirs.sort()
        for name in list(dirs):
            path = Path(directory) / name
            if path.is_symlink():
                dirs.remove(name)
                yield path, 'enlace no permitido'
        for name in sorted(files):
            path = Path(directory) / name
            if path.name == '.gitkeep':
                continue
            yield path, ('enlace no permitido' if path.is_symlink() else
                         '' if path.is_file() else 'archivo no regular')
    yield from failures
