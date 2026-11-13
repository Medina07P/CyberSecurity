"""FD-relative private run storage. No configuration or evidence is read."""
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, BinaryIO
from uuid import uuid4

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class RunStore:
    """Own the flock and directory descriptors until close; never unlink the lock."""

    def __init__(self):
        self._fds = []
        self._links = []
        self._lock = None
        self.path = None

    @classmethod
    def create(cls, repo: Path) -> 'RunStore':
        store = cls()
        try:
            # Do not resolve(): a symbolic ancestor is an error, not an alias.
            absolute = Path(os.path.abspath(repo))
            parent = os.open('/', _DIRECTORY)
            store._fds.append(parent)
            for name in absolute.parts[1:]:
                parent = store._directory(parent, name)
            scans = store._directory(parent, 'scans', create=True)
            root = store._directory(scans, 'automation', create=True, private=True)
            lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                           0o600, dir_fd=root)
            store._lock = lock
            store._private_file(lock)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise OSError(errno.EBUSY, 'automation lock ocupado') from exc
            store._root = root
            store._lock_inode = os.fstat(lock)
            run_id = uuid4().hex
            store._run = store._directory(root, run_id, create=True, private=True, exclusive=True)
            store._logs = store._directory(store._run, 'logs', create=True, private=True, exclusive=True)
            store.path = absolute / 'scans' / 'automation' / run_id
            store.check()
            return store
        except BaseException:
            store.close()
            raise

    def _directory(self, parent, name, create=False, private=False, exclusive=False):
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                if exclusive:
                    raise
        fd = os.open(name, _DIRECTORY, dir_fd=parent)
        self._fds.append(fd)
        info = os.fstat(fd)
        if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise OSError(errno.EACCES, 'Directorio automation no privado')
        self._links.append((parent, name, fd))
        return fd

    @staticmethod
    def _private_file(fd):
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise OSError(errno.EACCES, 'Archivo automation no privado o enlazado')

    def check(self):
        """Detect replaced ancestors; all writes still use pinned, no-follow fds."""
        for parent, name, fd in self._links:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            pinned = os.fstat(fd)
            if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise OSError(errno.ESTALE, 'Ancestro automation sustituido')
        current = os.stat('.lock', dir_fd=self._root, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (self._lock_inode.st_dev, self._lock_inode.st_ino):
            raise OSError(errno.ESTALE, 'Lock automation sustituido')

    def write_state(self, data: Mapping[str, object]) -> None:
        self.check()
        try:
            old = os.stat('run.json', dir_fd=self._run, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if (not stat.S_ISREG(old.st_mode) or old.st_nlink != 1
                    or old.st_uid != os.geteuid() or stat.S_IMODE(old.st_mode) != 0o600):
                raise OSError(errno.EACCES, 'Estado automation inseguro')
        temporary = '.state-' + uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self._run)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(data, stream, ensure_ascii=False, allow_nan=False)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            self.check()
            os.replace(temporary, 'run.json', src_dir_fd=self._run, dst_dir_fd=self._run)
            os.fsync(self._run)
        finally:
            try:
                os.unlink(temporary, dir_fd=self._run)
            except FileNotFoundError:
                pass

    def open_log(self, step_id: str, stream: str) -> BinaryIO:
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,47}', step_id) or stream not in ('stdout', 'stderr'):
            raise ValueError('Identificador de log inválido')
        self.check()
        fd = os.open(step_id + '.' + stream + '.log',
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self._logs)
        return os.fdopen(fd, 'wb', buffering=0)

    def close(self):
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None
        while self._fds:
            os.close(self._fds.pop())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
