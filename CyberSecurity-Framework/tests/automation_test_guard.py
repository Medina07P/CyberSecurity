"""Fail-fast discovery guard, not a sandbox for arbitrary test code.

Never inspect/hash protected data to prove it unchanged. Fixtures construct
synthetic configuration; only source/documentation reads are allowed here.
"""
import os
from contextvars import ContextVar
from pathlib import Path
import sys

_OPEN_PATH = ContextVar('automation_guard_open_path', default=None)


def check_event(root, event, args):
    root = Path(root).resolve()

    def in_checkout(value, directory=None):
        if not isinstance(value, (str, bytes, os.PathLike)):
            return None
        path = Path(os.fsdecode(value))
        if not path.is_absolute() and isinstance(directory, int) and directory >= 0:
            path = Path(os.readlink(f'/proc/self/fd/{directory}')) / path
        # Resolve metadata only, so a fixture symlink cannot redirect a read
        # into protected checkout data; no contents are opened for this guard.
        path = path.resolve(strict=False)
        try:
            return path.relative_to(root)
        except ValueError:
            return None

    if event == 'open':
        # Directory FDs are metadata handles, not reads of protected contents.
        if isinstance(args[2], int) and args[2] & os.O_DIRECTORY:
            return
        relative = in_checkout(_OPEN_PATH.get() or args[0])
        if relative is None:
            return
        mode, flags = args[1:3]
        write = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or (
            isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        parts = relative.parts
        forbidden = {'scans', 'credentials', 'captures', 'analysis', 'recovered',
                     'loot', 'final_report', 'executive', 'technical', 'domains',
                     'emails', 'metadata', 'social_media', 'subdomains'}
        config_data = ('00_Config' in parts and 'lib' not in parts and 'scripts' not in parts
                       and relative.name not in ('README.md', '.gitignore'))
        if write or config_data or set(parts) & forbidden or relative.name.startswith('.'):
            raise PermissionError('Automation tests must not open checkout data: ' + str(relative))
    elif event == 'subprocess.Popen':
        executable, argv, cwd, _env = args
        if list(argv) == ['git', 'ls-files', '-z', 'CyberSecurity-Framework']:
            return
        if any(isinstance(arg, str) and arg.startswith(str(root) + os.sep) for arg in argv):
            raise PermissionError('Run copied entries only, never checkout scripts')
        name = Path(os.fsdecode(executable)).name
        synthetic = (os.path.isabs(executable) and
                     str(Path(os.fsdecode(executable)).resolve()).startswith('/tmp/opencode/automation-'))
        if name not in ('bash', 'python', 'python3', Path(sys.executable).name, 'pwsh') and not synthetic:
            raise PermissionError('Real backend forbidden during automation tests: ' + name)
    elif event in ('os.remove', 'os.rmdir', 'os.mkdir', 'os.chmod', 'os.rename'):
        if event == 'os.rename':
            paths = ((args[0], args[2]), (args[1], args[3]))
        else:
            paths = ((args[0], args[2] if event in ('os.mkdir', 'os.chmod') else args[1]),)
        if any(in_checkout(path, directory) is not None for path, directory in paths):
            raise PermissionError('Checkout mutation forbidden during discovery/tests')
    elif event in ('socket.connect', 'socket.bind'):
        raise PermissionError('Network forbidden in automation test controller')


def install(root):
    original_open = os.open

    def open_with_directory(path, flags, mode=0o777, *, dir_fd=None):
        # CPython's open audit event omits dir_fd. Preserve syscall semantics
        # while supplying its actual metadata-only parent to our audit hook.
        effective = path
        if dir_fd is not None and isinstance(path, (str, bytes, os.PathLike)) and not os.path.isabs(path):
            effective = Path(os.readlink(f'/proc/self/fd/{dir_fd}')) / os.fsdecode(path)
        token = _OPEN_PATH.set(effective)
        try:
            return original_open(path, flags, mode, dir_fd=dir_fd)
        finally:
            _OPEN_PATH.reset(token)

    os.open = open_with_directory
    sys.addaudithook(lambda event, args: check_event(root, event, args))
