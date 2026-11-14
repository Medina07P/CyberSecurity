"""Internal fork-local fixture API. No environment/CLI grants; NOT RUN."""
import os
from pathlib import Path

_SCOPE = None


def in_worker():
    return _SCOPE is not None


def configure_worker(root, pinned, case_id, permitted, abi):
    """Called only after the trusted worker has successfully restricted itself."""
    global _SCOPE
    if (_SCOPE is not None or type(abi) is not int or abi < 3 or
            type(permitted) is not bool or
            root.parent != Path('/work/fixtures') or not root.name.startswith('case-')):
        raise ValueError('Invalid fork-local case scope')
    from automation_suite_selection import case_disposable_allowed
    if permitted != case_disposable_allowed(case_id):
        raise ValueError('Case grant differs from validated selection inventory')
    import __main__ as controller
    selector = getattr(controller, 'validated_selection', lambda: None)()
    if selector in ('--cross-consent', '--cross-web'):
        from cross_module_selection import group_cases
        if case_id not in group_cases(selector):
            raise ValueError('Case identity outside validated cross selection')
    info = root.stat(follow_symlinks=False)
    if (info.st_dev, info.st_ino, info.st_uid, info.st_mode) != pinned:
        raise ValueError('Case root identity changed')
    _SCOPE = (os.getpid(), root, pinned, case_id, bool(permitted), abi)


def fixture_parent():
    return (_SCOPE[1] / 'fixtures') if _SCOPE is not None else Path('/work/fixtures')


def destructive_path(value, directory=None):
    """Redundant local diagnostic, NEVER a replacement for inherited Landlock."""
    if _SCOPE is None or not _SCOPE[4]:
        return False
    _, root, pinned, _, _, _ = _SCOPE
    info = root.stat(follow_symlinks=False)
    if (info.st_dev, info.st_ino, info.st_uid, info.st_mode) != pinned:
        return False
    if isinstance(value, int):
        path = Path(os.readlink('/proc/self/fd/' + str(value)))
    elif isinstance(value, (str, bytes, os.PathLike)):
        path = Path(os.fsdecode(value))
        if not path.is_absolute() and directory not in (None, -1):
            path = Path(os.readlink('/proc/self/fd/' + str(directory))) / path
    else:
        return False
    # Reject escaping symlinks, renamed roots and the root itself. Existing
    # synthetic ancestors may be swapped by a test; Landlock still pins inodes.
    resolved = path.resolve(strict=False)
    return resolved != root and root in resolved.parents
