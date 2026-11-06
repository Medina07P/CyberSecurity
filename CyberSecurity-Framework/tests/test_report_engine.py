import json, os, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "11_Reports"))

_TMP = Path(tempfile.mkdtemp(prefix="reportes-fixtures-"))

def write_at(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="")
    return p

def write(rel, text):
    return write_at(_TMP, rel, text)

def tmp():
    return tempfile.mkdtemp(prefix="reportes-out-")


from lib.model import Evidence, Finding, merge_findings, sort_findings, finding_to_dict, finding_from_dict

class ModelTests(unittest.TestCase):
    def mk(self, key, sev="alta", conf="confirmado", line=1):
        return Finding(rule="r", key=key, titulo="t", categoria="web", severidad=sev,
                       confianza=conf, activo="h", tecnica="x", descripcion="d",
                       impacto_cliente="i", recomendacion="r", esfuerzo="medio",
                       cve=None, cvss=None, evidencia=[Evidence("a", line, "e")],
                       referencias=[])

    def test_id_is_stable_and_ignores_evidence_order(self):
        a, b = self.mk("k"), self.mk("k", line=2)
        b.evidencia.reverse()
        self.assertEqual(a.id, b.id)
        self.assertEqual(len(a.id), 40)

    def test_merge_keeps_strongest_and_unions_evidence(self):
        out = merge_findings([self.mk("k", "media", "candidato"), self.mk("k", "critica", line=7)])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severidad, "critica")
        self.assertEqual(len(out[0].evidencia), 2)

    def test_sort_puts_critical_first_and_confirmed_before_candidate(self):
        out = sort_findings([self.mk("a", "info"), self.mk("b", "alta", "candidato"),
                             self.mk("c", "alta", "confirmado"), self.mk("d", "critica")])
        self.assertEqual([f.key for f in out], ["d", "c", "b", "a"])

    def test_json_roundtrip(self):
        f = self.mk("k")
        self.assertEqual(finding_from_dict(finding_to_dict(f)), f)


if __name__ == "__main__":
    unittest.main(verbosity=2)
