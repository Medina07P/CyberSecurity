"""Pruebas del descubrimiento de fuentes y de la redacción del asistente IA."""
import sys
import tempfile
import time
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

from ai import redact, sources  # noqa: E402


def w(p: Path, text="contenido", mode="w"):
    p.parent.mkdir(parents=True, exist_ok=True)
    if mode == "wb":
        p.write_bytes(text)
    else:
        p.write_text(text)
    return p


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.repo = Path(self._t.name)
        self.fw = self.repo / "CyberSecurity-Framework"
        self.fw.mkdir()

    def docs(self, **kw):
        return {d.path: d for d in sources.discover(self.fw, **kw)}


class DiscoverTests(Base):
    def test_discovers_docs_and_results(self):
        w(self.fw / "03_Scanners" / "README.md", "guia")
        w(self.fw / "12_Knowledge_Base" / "cheatsheets" / "x.md", "kb")
        w(self.repo / "docs" / "nota.md", "doc raiz")
        w(self.repo / "scans" / "nmap" / "nmap_192.0.2.10.txt", "80/tcp open")
        w(self.fw / "11_Reports" / "generated" / "192.0.2.10" / "informe_tecnico.md", "inf")
        w(self.fw / "11_Reports" / "generated" / "192.0.2.10" / "findings.json", "{}")
        d = self.docs()
        self.assertEqual(d["03_Scanners/README.md"].kind, "doc")
        self.assertEqual(d["12_Knowledge_Base/cheatsheets/x.md"].kind, "doc")
        self.assertEqual(d["../docs/nota.md"].kind, "doc")
        self.assertEqual(d["../scans/nmap/nmap_192.0.2.10.txt"].kind, "resultado")
        inf = d["11_Reports/generated/192.0.2.10/informe_tecnico.md"]
        self.assertEqual((inf.kind, inf.target), ("informe", "192.0.2.10"))
        self.assertIn("11_Reports/generated/192.0.2.10/findings.json", d)

    def test_excludes_credentials_loot_and_session(self):
        for rel in ("10_Evidence/credentials/a.txt", "06_PostExploitation/loot/b.txt",
                    "00_Config/credentials/c.md", "00_Config/.session",
                    "00_Config/credentials/api-keys.yaml"):
            w(self.fw / rel, "secreto")
        w(self.fw / "00_Config" / "README.md", "ok")
        d = self.docs()
        self.assertEqual(list(d), ["00_Config/README.md"])

    def test_include_credentials_flag_includes_them(self):
        w(self.fw / "10_Evidence/credentials/a.txt", "x")
        w(self.fw / "06_PostExploitation/loot/b.txt", "x")
        w(self.fw / "00_Config/.session", "TARGET=1.2.3.4")
        d = self.docs(include_credentials=True)
        for rel in ("10_Evidence/credentials/a.txt", "06_PostExploitation/loot/b.txt",
                    "00_Config/.session"):
            self.assertIn(rel, d)

    def test_symlinks_not_followed(self):
        with tempfile.TemporaryDirectory() as ext:
            w(Path(ext) / "ext.md", "externo")
            w(Path(ext) / "dentro" / "z.md", "externo2")
            w(self.fw / "00_Config" / "README.md", "ok")
            (self.fw / "link.md").symlink_to(Path(ext) / "ext.md")
            (self.fw / "linkdir").symlink_to(Path(ext) / "dentro")
            (self.repo / "scans").mkdir()
            (self.repo / "scans" / "nmap").symlink_to(Path(ext) / "dentro")
            d = self.docs()
            self.assertEqual(list(d), ["00_Config/README.md"])

    def test_target_tag_from_filename(self):
        w(self.repo / "scans/nmap/nmap_192.0.2.10.txt", "x")
        w(self.repo / "scans/nikto/nikto_http___h.txt", "x")
        d = self.docs()
        self.assertEqual(d["../scans/nmap/nmap_192.0.2.10.txt"].target, "192.0.2.10")
        self.assertEqual(d["../scans/nikto/nikto_http___h.txt"].target, sources.slug("http://h"))
        self.assertEqual(sources.slug("http://h:8443/x"), "http___h_8443_x")

    def test_large_file_truncated_to_max_bytes(self):
        p = self.fw / "big.md"
        with open(p, "wb") as f:
            f.truncate(5 * 1024 * 1024)
            f.seek(0)
            f.write(b"a" * 1000)
        d = self.docs(max_file_bytes=4096)
        self.assertLessEqual(len(d["big.md"].text), 4096)

    def test_non_utf8_does_not_raise(self):
        w(self.fw / "bin.md", b"hola \xff\xfe fin", mode="wb")
        t = self.docs()["bin.md"].text
        self.assertIn("hola", t)
        self.assertIn("�", t)

    def test_hydra_and_login_outputs_use_deny_list(self):
        w(self.repo / "scans/hydra/hydra_h.txt", "login: a password: hunter2")
        w(self.repo / "scans/web_login_bruteforce/x_h.txt", "x")
        w(self.repo / "scans/nmap/nmap_h.txt", "ok")
        self.assertIn("hydra", sources.BRUTEFORCE_TOOL_DIRS)
        d = self.docs()
        self.assertEqual(list(d), ["../scans/nmap/nmap_h.txt"])

    def test_redaction_applied_in_discover_even_across_cut(self):
        w(self.repo / "scans/nmap/nmap_h.txt", "password=hunter2\n")
        d = self.docs()
        t = d["../scans/nmap/nmap_h.txt"].text
        self.assertNotIn("hunter2", t)
        self.assertIn("[REDACTADO]", t)
        # corte a mitad del valor: el prefijo visible no debe filtrarse
        w(self.fw / "cut.md", "x" * 10 + " password=hunter2secretvalue")
        t = self.docs(max_file_bytes=25)["cut.md"].text
        self.assertNotIn("hunter2", t)


class RedactTests(unittest.TestCase):
    def test_redaction_cases(self):
        md5 = "5f4dcd" + "0" * 26
        sha1 = "a" * 40
        sha256 = "b1" * 32
        cases = [
            "password=hunter2", "passwd=hunter2", "pass: hunter2", "pwd=hunter2",
            '"password": "hunter2"', md5, sha1, sha256,
            "$1$salt$abcdefghijklmnop", "$6$salt$abcdefghijklmnopqrstuv",
            "$2b$12$abcdefghijklmnopqrstuv", "$5$salt$abcdef",
            "Authorization: Bearer eyJhbGciOi.abc.def",
            "api_key=hunter2", "apikey=hunter2", "token=hunter2", "secret=hunter2",
            "ghp_" + "A1b2C3d4" * 5, "http://admin:hunter2@10.0.0.1/x",
        ]
        for c in cases:
            out = redact.redact("antes " + c + " despues")
            self.assertIn("[REDACTADO]", out, c)
            for leak in ("hunter2", md5, sha1, sha256, "eyJhbGciOi", "abcdefghijklmnop"):
                self.assertNotIn(leak, out, c)
            self.assertTrue(out.startswith("antes "), c)

    def test_non_sensitive_text_intact(self):
        t = ("Host 192.0.2.10 puerto 8443/tcp OpenSSH 8.9p1 CVE-2021-44228 "
             "color #ff00aa commit a1b2c3d4e5f6 hex 0123456789abcdef "
             "usuario admin http://example.com:8080/path "
             "hex48 " + "c" * 48 + " passed: 5")
        self.assertEqual(redact.redact(t), t)

    def test_user_kept_password_masked_in_url(self):
        out = redact.redact("ftp://admin:hunter2@h/x")
        self.assertIn("admin", out)
        self.assertIn("@h/x", out)

    def test_no_catastrophic_backtracking(self):
        lines = ["a" * 1_000_000, "password=" + "x" * 1_000_000, "://" * 300_000,
                 "$6$" * 300_000, "0" * 1_000_000, "api_key " * 100_000,
                 "ghp_" * 250_000, "Authorization: " * 70_000]
        for ln in lines:
            t0 = time.monotonic()
            redact.redact(ln)
            self.assertLess(time.monotonic() - t0, 2.0, ln[:20])


if __name__ == "__main__":
    unittest.main()
