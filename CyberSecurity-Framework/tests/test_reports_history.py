"""Runs propios sintéticos: exclusividad, privacidad y marcador final."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / '11_Reports'))
from lib.publication import write_private


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.h = importlib.import_module('lib.history')

    def reserve(self, base=None, tipo='tecnico'):
        return self.h.reserve(base or self.root / 'out', '192.0.2.10', 'objetivo', tipo, 'scans')

    def files(self, run):
        result = []
        for name in ('findings.json', 'informe_tecnico.md', 'informe_tecnico.html'):
            p = run.path / name
            write_private(p, 'synthetic')
            result.append(p)
        return result

    def test_two_reservations_preserve_previous(self):
        first = self.reserve()
        self.h.finish(first, self.files(first), 0)
        before = {p.name: p.read_bytes() for p in first.path.iterdir()}
        second = self.reserve()
        self.assertNotEqual(first.path, second.path)
        self.assertEqual(before, {p.name: p.read_bytes() for p in first.path.iterdir()})
        self.assertEqual(second.path.parent.name, 'runs')

    def test_parallel_reservations_are_exclusive(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            runs = list(pool.map(lambda _: self.reserve(), range(12)))
        self.assertEqual(len({r.path for r in runs}), 12)
        self.assertTrue(all((r.path / 'run.json').is_file() for r in runs))

    def test_uuid_collision_never_reuses_directory(self):
        with patch('lib.history.uuid4', return_value=UUID(int=1)), patch('lib.history.now', return_value=datetime(2026, 11, 13, tzinfo=timezone.utc)):
            first = self.reserve()
            marker = first.path / 'KEEP'
            marker.write_text('original')
            with self.assertRaises(FileExistsError):
                self.reserve()
            self.assertEqual(marker.read_text(), 'original')

    def test_new_history_is_private(self):
        run = self.reserve()
        self.h.finish(run, self.files(run), 0)
        for p in (run.path, run.path.parent, run.path.parent.parent):
            self.assertEqual(p.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all((p.stat().st_mode & 0o777) == 0o600 for p in run.path.iterdir()))

    def test_links_or_special_files_are_rejected(self):
        target = self.root / 'outside'
        target.mkdir()
        link = self.root / 'link'
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            self.reserve(link)
        run = self.reserve()
        files = self.files(run)
        files[0].unlink()
        files[0].symlink_to(target / 'private')
        self.assertFalse(self.h.published(run.path))
        with self.assertRaises(OSError):
            self.h.finish(run, files, 0)
        files[0].unlink()
        os.mkfifo(files[0])
        with self.assertRaises(OSError):
            self.h.finish(run, files, 0)

    def test_finish_accepts_only_expected_local_files(self):
        for case in ('missing', 'other', 'duplicate', 'traversal', 'wrong-type'):
            run = self.reserve()
            files = self.files(run)
            bad = {'missing': files[:-1], 'other': files[:-1] + [self.root / files[-1].name],
                   'duplicate': files + [files[0]], 'traversal': files[:-1] + [run.path / '..' / files[-1].name],
                   'wrong-type': files[:-1] + [run.path / 'informe_cliente.html']}[case]
            with self.subTest(case=case), self.assertRaises((OSError, ValueError)):
                self.h.finish(run, bad, 0)
            self.assertFalse(self.h.published(run.path))

    def test_incomplete_never_counts_as_published(self):
        run = self.reserve(self.root / 'generated/target')
        self.files(run)
        self.assertFalse(self.h.published(run.path))
        self.assertFalse(self.h.has_published(self.root / 'generated'))
        self.h.finish(run, self.files(run), 0)
        self.assertTrue(self.h.has_published(self.root / 'generated'))

    def test_rc3_is_published_but_not_evaluated(self):
        run = self.reserve()
        receipt = self.h.finish(run, self.files(run), 3)
        data = json.loads(receipt.read_text())
        self.assertEqual((data['estado'], data['rc']), ('NO_EVALUABLE', 3))
        self.assertTrue(self.h.published(run.path))

    def test_receipt_write_failure_preserves_incomplete_run(self):
        run = self.reserve()
        files = self.files(run)
        before = (run.path / 'run.json').read_bytes()
        with patch('lib.history.write_private', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.h.finish(run, files, 0)
        self.assertEqual((run.path / 'run.json').read_bytes(), before)
        self.assertFalse(self.h.published(run.path))

    def test_malformed_or_other_module_receipt_is_not_published(self):
        run = self.reserve()
        receipt = self.h.finish(run, self.files(run), 0)
        valid = json.loads(receipt.read_text())
        for change in ({'module': '05'}, {'schema_version': True}, {'rc': True}, {'run_id': 'other'},
                       {'archivos': ['../findings.json']}, {'finished_at': 'no-date'}):
            with self.subTest(change=change):
                receipt.write_text(json.dumps({**valid, **change}))
                self.assertFalse(self.h.published(run.path))
        receipt.write_text('[]')
        self.assertFalse(self.h.published(run.path))


if __name__ == '__main__':
    unittest.main()
