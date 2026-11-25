"""Pruebas unitarias de 00_Config/lib/session.bash: alcance, CIDR y temporales."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
SESSION_LIB = FW / "00_Config" / "lib" / "session.bash"


class SessionScopeTests(unittest.TestCase):
    def run_bash(self, script: str, *, scope_file: Path | None = None):
        env = dict(os.environ)
        if scope_file is not None:
            env["SESSION_SCOPE_FILE"] = str(scope_file)
        return subprocess.run(
            ["/bin/bash", "-c", f"source '{SESSION_LIB}'\n{script}"],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_scope_allows_ignores_excluded_and_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.yaml"
            scope.write_text(
                "# NO AUTORIZADO: 10.99.99.1\n"
                "targets:\n"
                "  ips:\n"
                '    - "192.0.2.0/24"\n'
                '    - "198.51.100.15"\n'
                "  domains:\n"
                '    - "example.com"\n'
                '    - "*.example.com"\n'
                "  excluded:\n"
                '    - "192.0.2.1"\n'
                '    - "198.51.100.1"\n'
                '    - "blocked.example.com"\n',
                encoding="utf-8",
            )
            for host, expected_rc in (
                ("192.0.2.10", 0),
                ("198.51.100.15", 0),
                ("192.0.2.1", 1),
                ("198.51.100.1", 1),
                ("10.99.99.1", 1),
                ("sub.example.com", 0),
                ("blocked.example.com", 1),
            ):
                with self.subTest(host=host):
                    res = self.run_bash(f"scope_allows '{host}'", scope_file=scope)
                    self.assertEqual(res.returncode, expected_rc, res.stderr)

    def test_ip_to_int_uses_base10_and_validates_octets(self):
        res_octal = self.run_bash("_ip_to_int 010.0.0.1 && _ip_to_int 08.0.0.1")
        self.assertEqual(res_octal.returncode, 0, res_octal.stderr)
        nums = res_octal.stdout.strip().splitlines()
        self.assertEqual(nums, [str((10 << 24) + 1), str((8 << 24) + 1)])

        for bad in ("256.1.1.1", "1.2.3", "999.0.0.1"):
            with self.subTest(bad=bad):
                res_bad = self.run_bash(f"_ip_to_int '{bad}'")
                self.assertNotEqual(res_bad.returncode, 0)

    def test_scope_add_target_uses_private_temp_and_safe_bak(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = root / "scope.yaml"
            victim = root / "victim.txt"
            victim.write_text("intacto", encoding="utf-8")
            scope.write_text(
                "targets:\n"
                "  ips:\n"
                '    - "192.0.2.10"\n'
                "  domains:\n"
                '    - "example.com"\n',
                encoding="utf-8",
            )
            (root / "scope.yaml.bak").symlink_to(victim)
            res = self.run_bash("scope_add_target 203.0.113.5", scope_file=scope)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(victim.read_text(encoding="utf-8"), "intacto")
            self.assertFalse((root / "scope.yaml.bak").is_symlink())
            self.assertEqual(list(root.glob(".scope.auto.*")), [])
            self.assertEqual(self.run_bash("scope_allows 203.0.113.5", scope_file=scope).returncode, 0)


if __name__ == "__main__":
    unittest.main()
