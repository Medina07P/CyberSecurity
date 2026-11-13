"""Pure Task2 argv/cBPF construction. NOT RUN; no host protection installed."""
import errno
from pathlib import Path, PurePosixPath
import re
import struct

from automation_sandbox_prepare import IsolationBlocked, PreparedRun


INSIDE = '/source/CyberSecurity-Framework/tests/automation_sandbox_inside.py'
ENVIRONMENT = {
    'PATH': '/usr/bin:/bin', 'HOME': '/work/home', 'TMPDIR': '/work/tmp',
    'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
}


def seccomp_program() -> bytes:
    """x86_64 only. No sockets (including UNIX), x32 or io_uring escape."""
    deny = 0x00050000 | errno.EPERM
    instructions = [
        (0x20, 0, 0, 4),               # LD arch
        (0x15, 1, 0, 0xc000003e),      # JEQ AUDIT_ARCH_X86_64
        (0x06, 0, 0, 0x80000000),      # RET KILL_PROCESS, foreign ABI
        (0x20, 0, 0, 0),               # LD syscall number
        (0x45, 0, 1, 0x40000000),      # JSET __X32_SYSCALL_BIT
        (0x06, 0, 0, deny),
    ]
    for number in (41, 53, 425, 426, 427):
        instructions.extend(((0x15, 0, 1, number), (0x06, 0, 0, deny)))
    instructions.append((0x06, 0, 0, 0x7fff0000))  # RET ALLOW
    return b''.join(struct.pack('<HBBI', *row) for row in instructions)


def bubblewrap_argv(run: PreparedRun, seccomp_fd: int) -> tuple[str, ...]:
    """Mount only freshly prepared, individually allowlisted staging trees.

    No CLI paths/commands or environment input. Runtime top-level dirs contain
    only the exact manifest files; the launcher revalidates this before spawn.
    """
    if (not isinstance(run, PreparedRun) or type(seccomp_fd) is not int or
            not 3 <= seccomp_fd < 256 or
            run.root.parent != Path('/tmp/opencode') or
            re.fullmatch(r'automation-isolated-[0-9a-f]{32}', run.root.name) is None):
        raise IsolationBlocked('Invalid prepared run or seccomp descriptor')
    for name, value in (('source', run.source_root), ('runtime', run.runtime_root),
                        ('work', run.work), ('evidence', run.evidence)):
        if value != run.root / name:
            raise IsolationBlocked('Prepared layout must not be redirected')
    tops, destinations = set(), set()
    for entry in run.manifest:
        dest = PurePosixPath(entry.destination)
        if (not dest.is_absolute() or str(dest) != entry.destination or
                '..' in dest.parts or len(dest.parts) < 3 or
                dest.parts[1] not in ('usr', 'bin', 'lib64') or
                entry.category not in ('elf', 'python', 'yaml') or
                entry.source != run.runtime_root / entry.destination.lstrip('/') or
                entry.destination in destinations):
            raise IsolationBlocked('Runtime references must be exact staged files')
        tops.add(dest.parts[1])
        destinations.add(entry.destination)
    if not {'/usr/bin/python3', '/bin/bash',
            '/lib64/ld-linux-x86-64.so.2'} <= destinations:
        raise IsolationBlocked('Incomplete runtime manifest')
    argv = ['/usr/bin/bwrap', '--unshare-all', '--new-session', '--die-with-parent',
            '--cap-drop', 'ALL', '--clearenv']
    for name in sorted(tops):
        argv.extend(('--ro-bind', str(run.runtime_root / name), '/' + name))
    argv.extend(('--ro-bind', str(run.source_root), '/source',
                 '--bind', str(run.work), '/work',
                 '--bind', str(run.evidence), '/evidence',
                 '--proc', '/proc', '--dev', '/dev',
                 '--chdir', '/work', '--seccomp', str(seccomp_fd)))
    for name, value in ENVIRONMENT.items():
        argv.extend(('--setenv', name, value))
    argv.extend(('/usr/bin/python3', '-I', '-B', INSIDE))
    return tuple(argv)
