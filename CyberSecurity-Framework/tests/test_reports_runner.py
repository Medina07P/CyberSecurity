"""El runner jamás necesita abrir configuración o evidencia del origen."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reports_fixture import SOURCES, manifest


class RunnerSafetyTests(unittest.TestCase):
    def test_manifest_does_not_read_outside_allowlist(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for relative in SOURCES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('source')
            forbidden = root / '00_Config/scope.yaml'
            forbidden.write_text('SECRET')
            original = Path.read_bytes
            def allowed(path):
                if str(path.relative_to(root)) not in SOURCES:
                    raise AssertionError('read outside allowlist')
                return original(path)
            with patch.object(Path, 'read_bytes', allowed):
                self.assertTrue(manifest(root))

    def test_symlink_source_rejected_without_opening_destination(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'source'
            source.write_text('SECRET')
            (root / 'link').symlink_to(source)
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('must not read')):
                with self.assertRaises(ValueError):
                    manifest(root, ('link',))


if __name__ == '__main__':
    unittest.main()
