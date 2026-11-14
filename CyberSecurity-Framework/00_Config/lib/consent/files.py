"""Descriptor-based files: never truncate through a link or create a missing log."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat


@contextmanager
def directory(path: Path, *, create: bool = False):
    """Pin every absolute path component without following symlinks.

    Existing ancestors are not chmodded/adopted as private directories. Only
    newly created components receive 0700. No resolve() before opening.
    """
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Se requiere una ruta absoluta sin ..')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for name in path.parts[1:]:
            if create:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def truncate_regular(path: Path) -> None:
    """Open without O_TRUNC, validate the pinned inode, then ftruncate it.

    No privilege escalation, creation, shell redirection or pathname reopen.
    O_PATH pins even special objects without opening their device/FIFO backend.
    Only an already validated regular inode is reopened through its own procfd;
    that is not a fresh lookup of the original pathname. Hardlinked files are
    refused too, rather than mutating another name's contents. Linux/procfd is
    required; its absence fails closed, never falls back to the pathname.
    """
    path = Path(path)
    with directory(path.parent) as parent:
        pinned = os.open(path.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
        try:
            info = os.fstat(pinned)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Destino no regular o con enlaces múltiples')
            fd = os.open('/proc/self/fd/' + str(pinned), os.O_WRONLY | os.O_CLOEXEC)
            try:
                current = os.fstat(fd)
                if ((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or
                        not stat.S_ISREG(current.st_mode) or current.st_nlink != 1):
                    raise ValueError('Identidad del destino cambió')
                os.ftruncate(fd, 0)
            finally:
                os.close(fd)
        finally:
            os.close(pinned)


def publish_private(directory_fd: int, name: str, payload: bytes) -> None:
    """Exclusive publication into the already pinned private report directory."""
    if name != 'last_access.txt' or not isinstance(payload, bytes):
        raise ValueError('Snapshot inválido')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
