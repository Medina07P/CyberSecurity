"""Publicación privada por archivo; no sigue enlaces ni trunca destinos ajenos."""
import os
from pathlib import Path
import stat
import tempfile


def preflight(out_dir: Path, names: list[str]) -> None:
    out_dir = Path(out_dir).absolute()
    for ancestor in (out_dir, *out_dir.parents):
        if ancestor.is_symlink():
            raise OSError('enlace no permitido en salida')
        if ancestor.exists() and not ancestor.is_dir():
            raise OSError('la salida requiere directorios regulares')
    for name in names:
        path = out_dir / name
        if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.lstat().st_mode)):
            raise OSError('destino no regular o enlace rechazado')


def write_private(path: Path, text: str) -> None:
    path = Path(path).absolute()
    preflight(path.parent, [path.name])
    # Crear cada padre que falte con 700, sin cambiar permisos existentes.
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix='.report-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        preflight(path.parent, [path.name])
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
