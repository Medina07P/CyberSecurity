"""Exclusive optional launchers, never source materialization or execution.

The generated body depends on Bash/Python3 and an explicit runtime framework
root. Only a closed kind chooses code; no operator path/arguments enter it.
Failed new writes remain as partials. Existing objects are never replaced.
"""
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import shlex
import stat


_LEAVES = {
    'smb': '04_Enumeration/smb/enum_smb.sh',
    'psexec': '06_PostExploitation/lateral_movement/ps_exec.sh',
    'linpeas': '06_PostExploitation/privilege_escalation/linpeas.sh',
}

# Fixed Python body quoted as ONE Bash -c argument, not a heredoc: preserve the
# caller's stdin for the public leaf's own prompts. @LEAF@ is a closed constant,
# never a value from root/destination/operator arguments. No eval/shell=True.
_LAUNCHER_CODE = '''import os
from pathlib import Path
import stat
import sys

def absolute(value):
    path = Path(value)
    if ".." in path.parts:
        raise ValueError("Raiz con traversal no permitida")
    return path if path.is_absolute() else Path.cwd() / path

def directory(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

def main():
    args = sys.argv[1:]
    if len(args) < 3 or args[0] != "--framework-root" or not args[1]:
        raise ValueError("Uso: --framework-root DIR <argumentos y modo explicito de hoja>")
    root = absolute(args[1])
    args = args[2:]
    if "--framework-root" in args:
        raise ValueError("Raiz duplicada no permitida")
    if not any(mode in args for mode in ("--execute", "--generate", "--preview", "--help")):
        raise ValueError("Selecciona un modo explicito de la hoja; no se concede ejecucion")
    leaf = root / "@LEAF@"
    parent = directory(leaf.parent)
    try:
        info = os.stat(leaf.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("La hoja debe ser un archivo regular sin enlaces simbolicos")
        fd = os.open(leaf.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("La identidad de la hoja cambio")
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    # Use the public path, preserving its self-location contract and stdin.
    # Validation refuses existing links; it is not a hostile-writer/kernel
    # certificate against replacement between validation and interpreter open.
    os.execv("/bin/bash", ["/bin/bash", "--noprofile", "--norc", str(leaf), *args])

try:
    main()
except (OSError, ValueError):
    # No argv, credentials, operator paths or raw backend diagnostics on error.
    print("Lanzador rechazado: indica raiz valida sin enlaces y modo explicito de hoja.", file=sys.stderr)
    sys.exit(2)
'''


def _absolute(path: Path) -> Path:
    path = Path(path)
    if '..' in path.parts:
        raise ValueError('Ruta con traversal no permitida')
    return path if path.is_absolute() else Path.cwd() / path


@contextmanager
def _directory(path: Path, forbidden=None):
    """Pin existing directories only, including every ancestor, without links."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if forbidden is not None and (info.st_dev, info.st_ino) == forbidden:
                raise ValueError('El destino debe estar fuera del framework')
        yield fd
    finally:
        os.close(fd)


def emit_launcher(kind: str, destination: Path, framework: Path) -> Path:
    """Create a NEW0700 launcher outside an existing no-link framework root.

    No parent creation, deletion, rename, downloads, privilege or child process.
    Framework is validated only for containment; never embedded in the output.
    Args are supplied only when the generated file is explicitly launched later.
    """
    if kind not in _LEAVES:
        raise ValueError('Tipo de lanzador no permitido')
    original = Path(destination)
    target, root = _absolute(original), _absolute(framework)
    if target == root or root in target.parents:
        raise ValueError('El destino debe estar fuera del framework')
    payload = ('#!/bin/bash\n'
               '# Dependencia: framework existente; --framework-root DIR y modo explicito obligatorios.\n'
               '# No concede permisos: conserva argumentos y los gates de la hoja publica.\n'
               'exec /usr/bin/python3 -I -B -c ' +
               shlex.quote(_LAUNCHER_CODE.replace('@LEAF@', _LEAVES[kind])) + ' "$@"\n').encode('utf-8')
    with _directory(root) as framework_fd:
        info = os.fstat(framework_fd)
        with _directory(target.parent, (info.st_dev, info.st_ino)) as parent:
            fd = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError(errno.EIO, 'Escritura parcial del lanzador; archivo nuevo conservado')
                    view = view[written:]
                os.fchmod(fd, 0o700)
                os.fsync(fd)
                current = os.fstat(fd)
                named = os.stat(target.name, dir_fd=parent, follow_symlinks=False)
                if (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1 or
                        (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino)):
                    raise ValueError('La identidad del destino nuevo cambio; no se reemplaza')
            finally:
                os.close(fd)  # Retain even incomplete output; never unlink/repair.
    return original
