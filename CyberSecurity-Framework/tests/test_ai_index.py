"""Pruebas del índice BM25 del asistente IA."""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

from ai import index as aindex  # noqa: E402
from ai.sources import Document  # noqa: E402


def doc(path, text, kind="doc", target=None):
    return Document(path, kind, target, text)


SQL = "# Intro\nTexto general.\n\n## SQL injection\nLa inyeccion SQL permite leer la base de datos.\nUsa sqlmap.\n"
XSS = "# XSS\nCross site scripting en formularios.\n"


class IndexTests(unittest.TestCase):
    def test_markdown_split_by_heading(self):
        idx = aindex.Index.build([doc("kb/sql_injection.md", SQL)])
        starts = [(c.line_start, c.line_end) for c in idx.chunks]
        self.assertEqual(starts, [(1, 3), (4, 6)])

    def test_search_ranks_relevant_chunk_first(self):
        idx = aindex.Index.build([doc("kb/sql_injection.md", SQL), doc("kb/xss.md", XSS)])
        r = idx.search("SQL injection")
        self.assertEqual(r[0].path, "kb/sql_injection.md")
        self.assertEqual(r[0].line_start, 4)

    def test_cite_has_path_and_lines(self):
        c = aindex.Chunk("../docs/a.md", 3, 9, "x", "doc", None)
        self.assertEqual(c.cite(), "../docs/a.md:3-9")

    def test_block_chunks_have_original_lines(self):
        text = "\n".join(f"linea{i} comun" for i in range(1, 101))
        idx = aindex.Index.build([doc("scans/x.txt", text, "resultado", "a")], chunk_lines=40)
        self.assertEqual([(c.line_start, c.line_end) for c in idx.chunks],
                         [(1, 40), (41, 80), (81, 100)])

    def test_target_filter_excludes_other_targets(self):
        docs = [doc("kb/gen.md", "# Gen\nnmap puerto abierto\n"),
                doc("scans/a.txt", "puerto 22 ssh", "resultado", "a"),
                doc("scans/b.txt", "puerto 8443 puerto 8443 puerto 8443 ssh ssh ssh", "resultado", "b")]
        idx = aindex.Index.build(docs)
        self.assertEqual(idx.search("puerto 8443 ssh", target="b")[0].path, "scans/b.txt")
        r = idx.search("puerto 8443 ssh", target="a")
        self.assertNotIn("scans/b.txt", [c.path for c in r])
        self.assertIn("scans/a.txt", [c.path for c in r])
        self.assertIn("kb/gen.md", [c.path for c in idx.search("nmap", target="a")])

    def test_kinds_filter(self):
        idx = aindex.Index.build([doc("kb/x.md", "# X\nssh\n"), doc("scans/x.txt", "ssh", "resultado", "a")])
        self.assertEqual([c.kind for c in idx.search("ssh", kinds={"resultado"}, target="a")], ["resultado"])

    def test_no_match_returns_empty_list(self):
        idx = aindex.Index.build([doc("kb/xss.md", XSS)])
        self.assertEqual(idx.search("zzzqqq"), [])
        self.assertEqual(idx.search(""), [])
        self.assertEqual(aindex.Index.build([]).search("xss"), [])

    def test_tokenizer_accents_ips_cves(self):
        t = aindex.tokenize("Inyección 192.168.0.10 CVE-2021-44228 a")
        self.assertIn("inyeccion", t)
        self.assertIn("192.168.0.10", t)
        self.assertIn("cve-2021-44228", t)
        self.assertIn("192", t)
        self.assertNotIn("a", t)
        idx = aindex.Index.build([doc("s/a.txt", "host 192.168.0.10 vulnerable a CVE-2021-44228", "resultado", "a"),
                                  doc("s/b.txt", "host 192.168.0.11", "resultado", "a")])
        self.assertEqual(idx.search("192.168.0.10", target="a")[0].path, "s/a.txt")
        self.assertEqual(idx.search("cve-2021-44228", target="a")[0].path, "s/a.txt")

    def test_save_load_roundtrip_and_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ai" / "index.json"
            idx = aindex.Index.build([doc("kb/sql_injection.md", SQL)])
            idx.save(p)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(p.parent).st_mode), 0o700)
            self.assertEqual([x for x in os.listdir(p.parent)], ["index.json"])
            back = aindex.Index.load(p)
            self.assertEqual(back.search("sqlmap")[0].cite(), idx.search("sqlmap")[0].cite())

    def test_load_missing_corrupt_wrong_version(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "i.json"
            self.assertIsNone(aindex.Index.load(p))
            p.write_text("{no json")
            self.assertIsNone(aindex.Index.load(p))
            p.write_text('{"version": 999, "chunks": []}')
            self.assertIsNone(aindex.Index.load(p))
            p.write_text('{"version": %d, "chunks": [{"x": 1}]}' % aindex.VERSION)
            self.assertIsNone(aindex.Index.load(p))
            p.write_text("[1]")
            self.assertIsNone(aindex.Index.load(p))

    def test_stale_detects_changed_source(self):
        with tempfile.TemporaryDirectory() as d:
            fw = Path(d) / "fw"
            (fw / "12_Knowledge_Base").mkdir(parents=True)
            f = fw / "12_Knowledge_Base" / "a.md"
            f.write_text("# A\nhola\n")
            from ai import sources
            idx = aindex.Index.build(sources.discover(fw), fingerprint=aindex.fingerprint(fw))
            self.assertFalse(idx.stale(fw))
            f.write_text("# A\nhola mundo cambiado\n")
            self.assertTrue(idx.stale(fw))
            idx2 = aindex.Index.build(sources.discover(fw), fingerprint=aindex.fingerprint(fw))
            self.assertFalse(idx2.stale(fw))
            (fw / "12_Knowledge_Base" / "b.md").write_text("# B\n")
            self.assertTrue(idx2.stale(fw))

    def test_stale_survives_roundtrip_and_no_fingerprint_is_stale(self):
        with tempfile.TemporaryDirectory() as d:
            fw = Path(d) / "fw"
            fw.mkdir()
            (fw / "a.md").write_text("# A\n")
            idx = aindex.Index.build([], fingerprint=aindex.fingerprint(fw))
            idx.save(Path(d) / "o" / "i.json")
            self.assertFalse(aindex.Index.load(Path(d) / "o" / "i.json").stale(fw))
            self.assertTrue(aindex.Index.build([]).stale(fw))

    def test_chunk_cap_for_huge_document(self):
        text = "\n".join("linea %d de relleno" % i for i in range(120000))
        self.assertGreater(len(text), 2_000_000)
        idx = aindex.Index.build([doc("scans/big.txt", text, "resultado", "a")])
        self.assertEqual(len(idx.chunks), aindex.MAX_CHUNKS_PER_DOC)
        self.assertEqual(idx.chunks[0].line_start, 1)
        self.assertEqual(aindex.CHUNK_LINES, 40)

    def test_tie_break_deterministic(self):
        idx = aindex.Index.build([doc("b.txt", "ssh", "resultado", "a"), doc("a.txt", "ssh", "resultado", "a")])
        self.assertEqual([c.path for c in idx.search("ssh", target="a")], ["a.txt", "b.txt"])


if __name__ == "__main__":
    unittest.main()
