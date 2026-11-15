"""Task1 contracts written before implementation. NOT RUN before static gate.

Only synthetic bytes and persistent new directories; no legacy fixture import,
cleanup, finalizer or real executable used as a negative ELF fixture.
"""
import ast
from dataclasses import FrozenInstanceError
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import uuid

from automation_sandbox_prepare import (
    IsolationBlocked, PreparedRun, RuntimeFile, copy_regular, load_json,
    source_names,
)
from automation_sandbox_elf import read_elf, resolve_runtime


def persistent_case():
    root = Path('/work/fixtures') / ('sandbox-prepare-case-' + uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    return root


def elf_bytes(needed=(), interpreter=None, rpath=None):
    """Minimal ELF64 ET_DYN fixture, never executed."""
    strings = b'\0'
    dynamic = []
    for name in needed:
        dynamic.append((1, len(strings)))
        strings += name.encode() + b'\0'
    if rpath is not None:
        dynamic.append((29, len(strings)))
        strings += rpath.encode() + b'\0'
    dynamic += [(5, 0x400200), (10, len(strings)), (0, 0)]
    dyn = b''.join(struct.pack('<qQ', *item) for item in dynamic)
    phnum = 2 + (interpreter is not None)
    header = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    header += struct.pack('<HHIQQQIHHHHHH', 3, 62, 1, 0, 64, 0, 0,
                          64, 56, phnum, 0, 0, 0)
    size = 0x400 + len(dyn)
    headers = struct.pack('<IIQQQQQQ', 1, 4, 0, 0x400000, 0, size, size, 0x1000)
    headers += struct.pack('<IIQQQQQQ', 2, 4, 0x400, 0x400400, 0,
                           len(dyn), len(dyn), 8)
    if interpreter is not None:
        raw = interpreter.encode() + b'\0'
        headers += struct.pack('<IIQQQQQQ', 3, 4, 0x300, 0, 0,
                               len(raw), len(raw), 1)
    data = bytearray(size)
    data[:64] = header
    data[64:64 + len(headers)] = headers
    data[0x200:0x200 + len(strings)] = strings
    if interpreter is not None:
        data[0x300:0x300 + len(raw)] = raw
    data[0x400:] = dyn
    return bytes(data)


class Preparation(unittest.TestCase):
    def test_consent_runtime_is_exact_ordinary_files_without_backend_aliases(self):
        import automation_sandbox_prepare as prepare
        self.assertEqual(prepare.CROSS_RUNTIME, (
            ('/usr/bin/mawk', '/usr/bin/awk'), ('/usr/bin/cut', '/usr/bin/cut'),
            ('/usr/bin/seq', '/usr/bin/seq'), ('/usr/bin/sleep', '/usr/bin/sleep'),
            ('/usr/bin/tee', '/usr/bin/tee'), ('/usr/bin/rm', '/usr/bin/rm'),
            ('/usr/bin/ls', '/usr/bin/ls'), ('/usr/bin/rmdir', '/usr/bin/rmdir')))
        from unittest import mock
        good = mock.Mock(st_uid=0, st_mode=0o100755, st_dev=1, st_ino=2,
                         st_size=100, st_mtime_ns=3, st_ctime_ns=4)
        for name in ('mawk', 'rm', 'ls', 'rmdir'):
            good.st_uid, good.st_mode = 0, 0o100755
            with patch.object(prepare, '_open_regular', return_value=(41, 42, name)), \
                    patch.object(prepare.os, 'close'), \
                    patch.object(prepare.os, 'fstat', return_value=good), \
                    patch.object(prepare.os, 'stat', return_value=good):
                prepare._ordinary_runtime_identity(Path('/usr/bin/' + name))
                for uid, mode in ((1000, 0o100755), (0, 0o100777), (0, 0o104755),
                                  (0, 0o102755), (0, 0o100775), (0, 0o100644), (0, 0o120755)):
                    good.st_uid, good.st_mode = uid, mode
                    with self.subTest(name=name, uid=uid, mode=mode), self.assertRaises(IsolationBlocked):
                        prepare._ordinary_runtime_identity(Path('/usr/bin/' + name))
            good.st_uid, good.st_mode = 0, 0o100755
            changed = mock.Mock(st_uid=0, st_mode=0o100755, st_dev=1, st_ino=999,
                                st_size=100, st_mtime_ns=3, st_ctime_ns=4)
            with patch.object(prepare, '_open_regular', return_value=(41, 42, name)), \
                    patch.object(prepare.os, 'close'), \
                    patch.object(prepare.os, 'fstat', return_value=good), \
                    patch.object(prepare.os, 'stat', return_value=changed), \
                    self.assertRaises(IsolationBlocked):
                prepare._ordinary_runtime_identity(Path('/usr/bin/' + name))
            with patch.object(prepare, '_open_regular', side_effect=IsolationBlocked('nofollow refusal')), \
                    self.assertRaises(IsolationBlocked):
                prepare._ordinary_runtime_identity(Path('/usr/bin/' + name))

    def test_exact_stdlib_alias_materialized_regular(self):
        from automation_sandbox_prepare import _python_files
        root = persistent_case()
        canonical = root / '_sysconfigdata__linux_x86_64-linux-gnu.py'
        alias = root / '_sysconfigdata__x86_64-linux-gnu.py'
        canonical.write_bytes(b'# synthetic sysconfig\n')
        alias.symlink_to(canonical.name)
        with patch('automation_sandbox_prepare.STDLIB', root):
            entries = _python_files(root, root, 'python')
        entry = next(e for e in entries if e.destination == str(alias))
        self.assertEqual(entry.source, canonical)
        target = root / 'materialized'
        copy_regular(entry.source, target)
        self.assertFalse(target.is_symlink())
        self.assertEqual(target.read_bytes(), canonical.read_bytes())

    def test_stdlib_alias_changed_external_or_unknown_rejected(self):
        from automation_sandbox_prepare import _python_files
        for literal in ('other.py', '../external.py',
                        '/usr/lib/python3.13/_sysconfigdata__linux_x86_64-linux-gnu.py'):
            root = persistent_case()
            (root / '_sysconfigdata__linux_x86_64-linux-gnu.py').write_bytes(b'# synthetic')
            (root / '_sysconfigdata__x86_64-linux-gnu.py').symlink_to(literal)
            with patch('automation_sandbox_prepare.STDLIB', root):
                with self.subTest(literal=literal), self.assertRaises(IsolationBlocked):
                    _python_files(root, root, 'python')
        root = persistent_case()
        (root / 'regular.py').write_bytes(b'# synthetic')
        (root / 'unknown.py').symlink_to('regular.py')
        with patch('automation_sandbox_prepare.STDLIB', root):
            with self.assertRaises(IsolationBlocked):
                _python_files(root, root, 'python')

    def test_stdlib_alias_canonical_identity_change_rejected(self):
        from automation_sandbox_prepare import _python_files
        root = persistent_case()
        name = '_sysconfigdata__linux_x86_64-linux-gnu.py'
        (root / name).write_bytes(b'# synthetic')
        (root / '_sysconfigdata__x86_64-linux-gnu.py').symlink_to(name)
        with patch('automation_sandbox_prepare.STDLIB', root):
            with patch('automation_sandbox_prepare._identity',
                       side_effect=lambda info: object()):
                with self.assertRaises(IsolationBlocked):
                    _python_files(root, root, 'python')

    def test_stdlib_alias_regular_replacement_rejected(self):
        from automation_sandbox_prepare import _python_files
        root = persistent_case()
        for name in ('_sysconfigdata__linux_x86_64-linux-gnu.py',
                     '_sysconfigdata__x86_64-linux-gnu.py'):
            (root / name).write_bytes(b'# synthetic')
        with patch('automation_sandbox_prepare.STDLIB', root):
            with self.assertRaises(IsolationBlocked):
                _python_files(root, root, 'python')

    def test_stdlib_alias_canonical_link_rejected(self):
        from automation_sandbox_prepare import _python_files
        root = persistent_case()
        canonical = '_sysconfigdata__linux_x86_64-linux-gnu.py'
        (root / canonical).symlink_to('../external.py')
        (root / '_sysconfigdata__x86_64-linux-gnu.py').symlink_to(canonical)
        with patch('automation_sandbox_prepare.STDLIB', root):
            with self.assertRaises(IsolationBlocked):
                _python_files(root, root, 'python')

    def test_preparation_reason_preserved_and_bounded(self):
        from automation_sandbox_prepare import REPO, prepare
        reason = 'Python source symlink denied: synthetic\n' + 'x' * 2000
        with patch('automation_sandbox_prepare.source_names',
                   side_effect=IsolationBlocked(reason)):
            with self.assertRaises(IsolationBlocked) as raised:
                prepare(REPO)
        self.assertIn('Python source symlink denied: synthetic', str(raised.exception))
        self.assertNotIn('\n', str(raised.exception))
        self.assertLess(len(str(raised.exception)), 700)

    def test_source_symlink_rejected(self):
        root = persistent_case()
        (root / 'real').write_bytes(b'synthetic')
        (root / 'link').symlink_to('real')
        (root / 'dir').symlink_to(root, target_is_directory=True)
        for name in ('link', 'dir/real'):
            with self.subTest(name=name), self.assertRaises(IsolationBlocked):
                copy_regular(root / name, root / ('copy-' + name.replace('/', '-')))

    def test_no_config_or_generated_input(self):
        names = source_names()
        self.assertNotIn('CyberSecurity-Framework/00_Config/scope.yaml', names)
        self.assertNotIn('CyberSecurity-Framework/00_Config/targets.txt', names)
        for name in names:
            self.assertNotIn('.git', Path(name).parts)
            self.assertNotIn('credentials', Path(name).parts)
            self.assertNotIn('scans', Path(name).parts)
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('docs/MENU-OPCIONES.md', names)

    def test_runtime_dependencies_closed(self):
        root = persistent_case()
        program = root / 'program'
        program.write_bytes(elf_bytes(('libsynthetic.so',)))
        dependency = root / 'libsynthetic.so'
        dependency.write_bytes(elf_bytes())
        # No host binary involved; dependency resolver's sole library lookup
        # is replaced by an explicit synthetic path.
        with patch('automation_sandbox_elf._library', return_value=dependency):
            runtime = resolve_runtime((RuntimeFile(program, '/usr/bin/synthetic', 'elf'),))
        self.assertEqual(len({entry.destination for entry in runtime}), len(runtime))
        self.assertIn('/usr/lib/x86_64-linux-gnu/libsynthetic.so',
                      {entry.destination for entry in runtime})
        with patch('automation_sandbox_elf._library', side_effect=IsolationBlocked('missing')):
            with self.assertRaises(IsolationBlocked):
                resolve_runtime((RuntimeFile(program, '/usr/bin/synthetic', 'elf'),))

    def test_dependency_depth_and_count_bounded(self):
        root = persistent_case()
        files = []
        for index in range(4):
            path = root / ('libsynthetic' + str(index) + '.so')
            path.write_bytes(elf_bytes(('libsynthetic' + str(index + 1) + '.so',)
                                      if index < 3 else ()))
            files.append(path)
        initial = (RuntimeFile(files[0], '/usr/bin/synthetic', 'elf'),)
        with patch('automation_sandbox_elf._library', side_effect=lambda name: root / name):
            with patch('automation_sandbox_elf.MAX_DEPTH', 1):
                with self.assertRaises(IsolationBlocked):
                    resolve_runtime(initial)
            with patch('automation_sandbox_elf.MAX_DEPENDENCIES', 2):
                with self.assertRaises(IsolationBlocked):
                    resolve_runtime(initial)

    def test_enospc_retains_partial_copy(self):
        import errno
        root = persistent_case()
        source = root / 'source'
        target = root / 'target'
        source.write_bytes(b'synthetic')
        with patch('automation_sandbox_prepare.os.write', side_effect=OSError(errno.ENOSPC, 'full')):
            with self.assertRaises(IsolationBlocked):
                copy_regular(source, target)
        self.assertTrue(source.is_file())
        self.assertTrue(target.is_file())

    def test_conflicting_destination_rejected(self):
        entry = RuntimeFile(Path('/synthetic'), '/usr/bin/synthetic', 'elf')
        with self.assertRaises(IsolationBlocked):
            resolve_runtime((entry, entry))

    def test_no_cleanup_or_reuse(self):
        root = persistent_case()
        source, target = root / 'source', root / 'target'
        source.write_bytes(b'preserve')
        copy_regular(source, target)
        with self.assertRaises(IsolationBlocked):
            copy_regular(source, target)
        self.assertEqual(target.read_bytes(), b'preserve')
        for name in ('automation_sandbox_prepare.py', 'automation_sandbox_elf.py'):
            tree = ast.parse(Path(__file__).with_name(name).read_text())
            forbidden = {'unlink', 'rmdir', 'rmtree', 'remove', 'TemporaryDirectory',
                         'cleanup', 'register', '__del__'}
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    self.assertNotIn(getattr(node.func, 'attr', getattr(node.func, 'id', '')), forbidden)

    def test_elf_bounds_and_architecture(self):
        root = persistent_case()
        for name, data in (('elf32', b'\x7fELF\x01' + b'\0' * 80),
                           ('truncated', elf_bytes()[:70]),
                           ('needed-slash', elf_bytes(('../evil.so',))),
                           ('rpath', elf_bytes(rpath='/home/private')),
                           ('origin', elf_bytes(rpath='$ORIGIN/../outside')),
                           ('loader', elf_bytes(interpreter='/tmp/loader'))):
            path = root / name
            path.write_bytes(data)
            with self.subTest(name=name), self.assertRaises(IsolationBlocked):
                read_elf(path)
        good = root / 'good'
        good.write_bytes(elf_bytes(('libc.so.6',)))
        self.assertEqual(read_elf(good).needed, ('libc.so.6',))
        huge = root / 'huge'
        with huge.open('xb') as stream:
            stream.truncate(32 * 1024 * 1024 + 1)
        with self.assertRaises(IsolationBlocked):
            read_elf(huge)

    def test_json_closed_and_bounded(self):
        root = persistent_case()
        for name, data in (('extra', b'{"version":1,"other":0}'),
                           ('duplicate', b'{"version":1,"version":1}'),
                           ('huge', b' ' * (1024 * 1024 + 1))):
            path = root / name
            path.write_bytes(data)
            with self.subTest(name=name), self.assertRaises(IsolationBlocked):
                load_json(path, {'version'})

    def test_new_json_no_overwrite_or_oversize(self):
        from automation_sandbox_prepare import _new_json
        root = persistent_case()
        path = root / 'state.json'
        _new_json(path, {'version': 1})
        with self.assertRaises((IsolationBlocked, FileExistsError)):
            _new_json(path, {'version': 2})
        with self.assertRaises(IsolationBlocked):
            _new_json(root / 'large.json', {'version': 1, 'data': 'x' * (1024 * 1024)})
        self.assertEqual(path.read_text().count('1'), 1)

    def test_copy_identity_change_blocks(self):
        root = persistent_case()
        source = root / 'source'
        source.write_bytes(b'synthetic')
        with patch('automation_sandbox_prepare._identity',
                   side_effect=[(1, 1, 1, 9, 1, 1), (2, 1, 1, 9, 1, 1)]):
            with self.assertRaises(IsolationBlocked):
                copy_regular(source, root / 'target')

    def test_models_frozen(self):
        entry = RuntimeFile(Path('/synthetic'), '/usr/bin/synthetic', 'elf')
        with self.assertRaises(FrozenInstanceError):
            entry.destination = '/changed'
        run = PreparedRun(*(Path('/synthetic') for _ in range(5)), (entry,))
        with self.assertRaises(FrozenInstanceError):
            run.root = Path('/changed')


if __name__ == '__main__':
    unittest.main()
