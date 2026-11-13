"""Task2 placeholder: no imports/discovery of tests or product; always BLOCKED.

Task3 owns the trusted fixed sys.path bootstrap and boundary probes. Task4 owns
preservation adaptation before any legacy suite can be imported or discovered.
Never reenter the host launcher here, even for nested test invocations.
"""
from collections.abc import Sequence
import json
import os
import sys


def inside_main(argv: Sequence[str]) -> int:
    # Even an invalid selector cannot select a command or bypass this gate.
    print('BLOCKED: boundary probes not implemented (Task3); no tests started',
          file=sys.stderr)
    return 2


def _placeholder_receipt():
    """Only fixed sandbox paths; no overwritten receipt, no cleanup."""
    os.umask(0o077)
    fd = os.open('/evidence/inside-result.json', os.O_WRONLY | os.O_CREAT |
                 os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        payload = (json.dumps({'version': 1, 'state': 'BLOCKED', 'returncode': 2,
                               'reason': 'Task3 probes not implemented',
                               'tests_started': False}) + '\n').encode()
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError('Short receipt write')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


if __name__ == '__main__':
    result = inside_main(sys.argv[1:])
    try:
        _placeholder_receipt()
    except OSError as exc:
        print('BLOCKED: cannot persist placeholder receipt: ' + str(exc), file=sys.stderr)
    raise SystemExit(result)
