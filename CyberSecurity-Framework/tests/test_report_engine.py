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


from lib.catalog import KNOWN_RULES, build

class CatalogTests(unittest.TestCase):
    def test_every_rule_has_real_texts(self):
        for rule in KNOWN_RULES:
            f = build(rule, key="k", activo="a", evidencia=[Evidence("f", 1, "e")])
            for campo in (f.titulo, f.descripcion, f.impacto_cliente, f.recomendacion):
                self.assertTrue(campo.strip(), rule)
                self.assertNotIn("[", campo); self.assertNotIn("TODO", campo)

    def test_rule_defaults_set_severity_and_confidence(self):
        f = build("sqlmap.sqli", key="k", activo="a", evidencia=[])
        self.assertEqual((f.severidad, f.confianza), ("critica", "confirmado"))
        self.assertEqual(build("ssh.password_auth", key="k", activo="a", evidencia=[]).confianza, "observacion")

    def test_variables_are_substituted(self):
        f = build("rate_limit.no_throttle", key="k", activo="a", evidencia=[], variables={"endpoint": "/login"})
        self.assertIn("/login", f.descripcion)

    def test_unknown_rule_fails_loudly(self):
        with self.assertRaises(KeyError):
            build("no.existe", key="k", activo="a", evidencia=[])


from lib.attribution import slug, normalize_host, guess_host, belongs_to

class AttributionTests(unittest.TestCase):
    def test_slug_matches_bash_convention(self):
        self.assertEqual(slug("https://127.0.0.1:8080"), "https___127.0.0.1_8080")

    def test_partial_octet_is_not_the_same_target(self):
        self.assertFalse(belongs_to("http://127.0.0.10/x", "127.0.0.1"))
        self.assertTrue(belongs_to("https://127.0.0.1:8443/a?b=1", "127.0.0.1"))

    def test_domains_are_case_insensitive_and_port_agnostic(self):
        self.assertTrue(belongs_to("https://Example.COM:443/", "example.com"))

    def test_guess_host_reads_slugs_but_not_unlabelled_names(self):
        self.assertEqual(guess_host("nuclei_https___127.0.0.1_8080.txt"), "127.0.0.1")
        self.assertEqual(guess_host("security_headers_8080.txt"), None)
        self.assertEqual(guess_host("rate_limit_sgcrc.example.com_443.txt"), "sgcrc.example.com")

    def test_normalize_keeps_ipv4_and_strips_scheme_path_port(self):
        self.assertEqual(normalize_host("https://u:p@10.1.2.3:8443/x"), "10.1.2.3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
