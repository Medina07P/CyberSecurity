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


from lib.engine import collect, filter_findings
from lib.sources import discover

class SourceTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tmp()) / "scans"
        files = {
            "nmap/a.xml": "<x/>", "nuclei/a.jsonl": "{}", "nuclei/a.txt": "[x] [http] [high] u",
            "nikto/a.txt": "+ ok", "web/ffuf_a.json": "{}", "web/http_inject_a.tsv": "nivel\tparam",
            "web/sqlmap_a.txt": "- Veredicto: x", "web/sqli_findings_a.txt": "u|200:1|base:200:2",
            "web/rate_limit_a.txt": "- Veredicto: x", "web/security_headers_a.txt": "",
            "web/headers_a.txt": "HTTP/1.1 200 OK", "web/technologies_a.txt": "x",
            "api/methods.txt": "x", "ssh/auth_methods.txt": "x", "database/anon.txt": "",
            "nmap/errores.log": "e", "web/robots_a.txt": "User-agent: *",
            "web/suelto.txt": "password inject CVE-2024-1234",
        }
        for rel, txt in files.items():
            write_at(self.root, rel, txt)

    def kind(self, rel):
        for s in discover(self.root):
            if str(s.path).endswith(rel):
                return s.kind
        return None

    def test_known_patterns_are_classified(self):
        esperado = {"nmap/a.xml": "nmap", "nuclei/a.jsonl": "nuclei_jsonl",
                    "nuclei/a.txt": "nuclei_txt", "nikto/a.txt": "nikto",
                    "web/ffuf_a.json": "ffuf", "web/http_inject_a.tsv": "http_inject",
                    "web/sqlmap_a.txt": "sqlmap", "web/sqli_findings_a.txt": "sqli_findings",
                    "web/rate_limit_a.txt": "rate_limit", "web/security_headers_a.txt": "security_headers",
                    "web/headers_a.txt": "headers", "web/technologies_a.txt": "technologies",
                    "api/methods.txt": "api", "ssh/auth_methods.txt": "ssh",
                    "database/anon.txt": "db", "nmap/errores.log": "errores"}
        for rel, kind in esperado.items():
            self.assertEqual(self.kind(rel), kind, rel)

    def test_unrelated_and_keyword_files_are_ignored(self):
        self.assertEqual(self.kind("web/robots_a.txt"), "ignored")
        self.assertEqual(self.kind("web/suelto.txt"), "ignored")

    def mk(self, activo):
        return Finding(rule="r", key="k"+activo, titulo="t", categoria="web", severidad="info",
                       confianza="observacion", activo=activo, tecnica="x", descripcion="d",
                       impacto_cliente="i", recomendacion="r", esfuerzo="medio", cve=None, cvss=None,
                       evidencia=[], referencias=[])

    def test_filter_keeps_only_the_target_and_drops_unattributable(self):
        fs = [self.mk("https://127.0.0.1:8080"), self.mk("https://127.0.0.10/"), self.mk("")]
        out = filter_findings(fs, "127.0.0.1", False, False)
        self.assertEqual([f.activo for f in out], ["https://127.0.0.1:8080"])
        self.assertEqual(len(filter_findings(fs, "127.0.0.1", True, False)), 2)
        self.assertEqual(len(filter_findings(fs, "127.0.0.1", False, True)), 3)

    def test_errores_log_is_an_incident_not_a_finding(self):
        c = collect(self.root, ROOT, "127.0.0.1")
        self.assertEqual(c.findings, [])
        self.assertEqual(len(c.incidencias), 1)


from lib.parsers import nmap

XML_127 = """<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080"><state state="open"/>
<service name="http" product="SimpleHTTP" version="0.6"/></port></ports>
<hostscript><script id="vulners" output="CVE-2021-41773: 7.5: https://x"/></hostscript>
</host></nmaprun>"""

class NmapTests(unittest.TestCase):
    def test_open_port_and_cve(self):
        r = nmap.parse(write("nmap/a.xml", XML_127), ROOT)
        self.assertEqual(len([f for f in r.findings if f.rule == "nmap.open_port"]), 1)
        cve = [f for f in r.findings if f.rule == "nmap.cve"][0]
        self.assertEqual((cve.cve, cve.severidad), ("CVE-2021-41773", "alta"))
        self.assertEqual(r.activos[0]["puertos"][0]["puerto"], 8080)

    def test_cve_without_score_is_media_and_says_so(self):
        r = nmap.parse(write("nmap/b.xml", XML_127.replace(": 7.5:", "")), ROOT)
        f = [x for x in r.findings if x.rule == "nmap.cve"][0]
        self.assertEqual(f.severidad, "media")
        self.assertIn("CVSS no consultado", f.descripcion)

    def test_malformed_xml_is_no_evaluable(self):
        r = nmap.parse(write("nmap/bad.xml", "<nmaprun>"), ROOT)
        self.assertFalse(r.evaluado)
        self.assertTrue(r.no_evaluable)


from lib.parsers import nuclei

JSONL = '{"template-id":"CVE-2021-1","info":{"name":"X","severity":"high","classification":{"cve-id":["CVE-2021-1"]}},"matched-at":"https://127.0.0.1:8443/a"}\n'

class NucleiTests(unittest.TestCase):
    def test_jsonl_maps_severity_and_asset(self):
        r = nuclei.parse_jsonl(write("nuclei/a.jsonl", JSONL), ROOT)
        f = r.findings[0]
        self.assertEqual((f.severidad, f.confianza, f.activo), ("alta", "confirmado", "https://127.0.0.1:8443/a"))
        self.assertEqual(f.cve, "CVE-2021-1")

    def test_txt_standard_lines_and_garbage(self):
        txt = "[tech] [http] [info] http://127.0.0.1:8080/\r\nlinea rota\r\n[CVE-2] [http] [medium] http://127.0.0.1:8080/x\r\n"
        r = nuclei.parse_txt(write("nuclei/b.txt", txt), ROOT)
        self.assertEqual(len(r.findings), 2)
        self.assertEqual([f.severidad for f in r.findings], ["info", "media"])
        self.assertEqual(len(r.no_evaluable), 1)

    def test_jsonl_bad_line_is_no_evaluable_and_crlf_ok(self):
        r = nuclei.parse_jsonl(write("nuclei/c.jsonl", JSONL.replace("\n", "\r\n") + "no-json\n"), ROOT)
        self.assertEqual(len(r.findings), 1); self.assertTrue(r.no_evaluable)


from lib.parsers import nikto

class NiktoTests(unittest.TestCase):
    def test_noise_produces_nothing_and_no_noise(self):
        txt = "+ No CGI Directories found (use '-C all' to force check all possible dirs)\n+ Server leaks inodes via ETags\n"
        r = nikto.parse(write("nikto/a.txt", txt), ROOT)
        self.assertEqual(r.findings, []); self.assertEqual(r.no_evaluable, [])

    def test_cve_is_confirmed_and_osvdb_is_observation(self):
        txt = "+ /x: CVE-2020-1234: demo\n+ OSVDB-3092: /admin/: admin found\n"
        r = nikto.parse(write("nikto/b.txt", txt), ROOT)
        self.assertEqual([f.rule for f in r.findings], ["nikto.cve", "nikto.osvdb"])
        self.assertEqual([f.confianza for f in r.findings], ["confirmado", "observacion"])
        self.assertEqual(r.findings[0].evidencia[0].linea, 1)

    def test_security_header_lines_are_left_to_headers_parser(self):
        r = nikto.parse(write("nikto/c.txt", "+ The anti-clickjacking X-Frame-Options header is not present.\n"), ROOT)
        self.assertEqual(r.findings, [])


class CollectTests(unittest.TestCase):
    def test_evidence_paths_are_repo_relative(self):
        tmpdir = Path(tmp())
        scans = tmpdir / "scans"
        xml = scans / "nmap" / "a.xml"
        xml.parent.mkdir(parents=True, exist_ok=True)
        xml.write_text(XML_127, encoding="utf-8")
        c = collect(scans, tmpdir, "127.0.0.1")
        self.assertGreater(len(c.findings), 0)
        for f in c.findings:
            if f.evidencia:
                self.assertTrue(
                    f.evidencia[0].archivo.startswith("scans/nmap/"),
                    f"Evidence path should be repo-relative: {f.evidencia[0].archivo}"
                )


from lib.parsers import ffuf

def ffuf_json(base, results):
    return json.dumps({"commandline": f"ffuf -u http://127.0.0.1:8080/FUZZ -mc 200 {base}",
                       "results": results})

class FfufTests(unittest.TestCase):
    def test_hit_equal_to_baseline_is_discarded(self):
        r = ffuf.parse(write("web/ffuf_a.json", ffuf_json("-fs 96", [{"status":200,"length":96,"url":"u"}])), ROOT)
        self.assertEqual(r.findings, []); self.assertEqual(len(r.descartados), 1)

    def test_hit_with_different_length_is_inventory_observation(self):
        r = ffuf.parse(write("web/ffuf_b.json", ffuf_json("-fs 96", [{"status":200,"length":5000,"url":"http://127.0.0.1:8080/admin"}])), ROOT)
        self.assertEqual((r.findings[0].confianza, r.findings[0].severidad), ("observacion", "info"))

    def test_missing_baseline_is_no_evaluable(self):
        r = ffuf.parse(write("web/ffuf_c.json", ffuf_json("", [{"status":200,"length":1,"url":"u"}])), ROOT)
        self.assertEqual(r.findings, []); self.assertTrue(r.no_evaluable)

    def test_valid_empty_results_is_an_evaluable_zero(self):
        r = ffuf.parse(write("web/ffuf_d.json", ffuf_json("", [])), ROOT)
        self.assertEqual(r.findings, []); self.assertEqual(r.no_evaluable, [])
        self.assertTrue(r.evaluado)


from lib.parsers import http_inject, sqlmap, sqli_findings, rate_limit

class VerdictTests(unittest.TestCase):
    def test_http_inject_three_levels(self):
        tsv = "nivel\tparam\tclase\tpayload\tcodigo\ttamano\tms\tevidencia\n"
        tsv += "CONFIRMADO\tid\tsqli\t' OR 1=1\t200\t99\t12\tx\n"
        tsv += "FUERTE\tq\txss\t<script>\t200\t99\t12\ty\n"
        tsv += "DEBIL\tz\txss\tx\t200\t99\t12\tz\n"
        path = write("web/http_inject_a.tsv", tsv)
        write("web/http_inject_a/contexto.txt", "host=127.0.0.1\n")
        r = http_inject.parse(path, ROOT)
        self.assertEqual([f.confianza for f in r.findings], ["confirmado", "candidato"])
        self.assertEqual(r.findings[0].severidad, "critica")
        self.assertEqual(len(r.descartados), 1)

    def test_sqlmap_verdicts(self):
        ok = "- Objetivo: 127.0.0.1:443 (https)\n- Veredicto: INYECTABLE (id): boolean-based blind\n"
        r = sqlmap.parse(write("web/sqlmap_a.txt", ok), ROOT)
        self.assertEqual((r.findings[0].severidad, r.findings[0].confianza), ("critica", "confirmado"))
        self.assertEqual(sqlmap.parse(write("web/sqlmap_b.txt", ok.replace("INYECTABLE", "NO INYECTABLE")), ROOT).findings, [])
        self.assertTrue(sqlmap.parse(write("web/sqlmap_c.txt", ok.replace("INYECTABLE (id): boolean-based blind", "NO DETERMINADO (código 2)")), ROOT).no_evaluable)

    def test_rate_limit_verdicts(self):
        base = "- Objetivo: 127.0.0.1:443 (https)\n- Petición: POST /login\n- Veredicto: {}\n"
        self.assertEqual(rate_limit.parse(write("web/rate_limit_a.txt", base.format("SIN FRENO")), ROOT).findings[0].severidad, "alta")
        self.assertEqual(rate_limit.parse(write("web/rate_limit_b.txt", base.format("FRENADO")), ROOT).findings, [])
        self.assertTrue(rate_limit.parse(write("web/rate_limit_c.txt", base.format("NO DETERMINADO")), ROOT).no_evaluable)

    def test_sqli_findings_is_candidate_and_merges_with_sqlmap(self):
        line = "https://127.0.0.1:443/?id=1|200:999|base:200:433\n"
        sq = sqli_findings.parse(write("web/sqli_findings_a.txt", line), ROOT)
        self.assertEqual((sq.findings[0].confianza, sq.findings[0].severidad), ("candidato", "media"))
        sql = sqlmap.parse(write("web/sqlmap_d.txt", "- Objetivo: 127.0.0.1:443 (https)\n- Veredicto: INYECTABLE (id): x\n"), ROOT)
        merged = merge_findings(sq.findings + sql.findings)
        self.assertEqual(len(merged), 1); self.assertEqual(merged[0].confianza, "confirmado")


from lib.parsers import headers

class HeadersTests(unittest.TestCase):
    def test_missing_headers_need_a_paired_successful_response(self):
        p = write("web/security_headers_443.txt", "Server: x\n")
        write("web/headers_443.txt", "HTTP/1.1 200 OK\nServer: x\n")
        r = headers.parse_security(p, ROOT)
        self.assertEqual({f.rule for f in r.findings},
                         {"headers.missing.csp", "headers.missing.xfo", "headers.missing.xcto", "headers.missing.hsts"})

    def test_without_guard_nothing_is_claimed(self):
        p = write("web/security_headers_b.txt", "")
        r = headers.parse_security(p, ROOT)
        self.assertEqual(r.findings, []); self.assertTrue(r.no_evaluable)

    def test_http_scheme_skips_hsts_and_present_header_is_not_reported(self):
        p = write("web/security_headers_8080.txt", "Content-Security-Policy: default-src 'self'\n")
        write("web/headers_8080.txt", "HTTP/1.1 200 OK\n")
        rules = {f.rule for f in headers.parse_security(p, ROOT).findings}
        self.assertNotIn("headers.missing.csp", rules); self.assertNotIn("headers.missing.hsts", rules)
        self.assertEqual(rules, {"headers.missing.xfo", "headers.missing.xcto"})


from lib.parsers import host_sources

class HostSourceTests(unittest.TestCase):
    def test_api_mutating_methods_are_low_observations_and_unattributable(self):
        r = host_sources.parse_api(write("api/methods.txt", " ✅ GET (404)\n ✅ PUT (200)\n ✅ DELETE (501)\n"), ROOT)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual((r.findings[0].severidad, r.findings[0].activo), ("baja", ""))

    def test_ssh_password_auth_with_host(self):
        txt = "Nmap scan report for localhost (127.0.0.1)\n| ssh-auth-methods:\n|     publickey\n|_    password\n"
        r = host_sources.parse_ssh(write("ssh/auth_methods.txt", txt), ROOT)
        self.assertEqual((r.findings[0].rule, r.findings[0].activo), ("ssh.password_auth", "127.0.0.1"))

    def test_db_anon_empty_is_no_evaluable(self):
        self.assertTrue(host_sources.parse_db(write("database/anon.txt", ""), ROOT).no_evaluable)
        r = host_sources.parse_db(write("database/anon.txt", "version()\n8.0.36\n"), ROOT)
        self.assertEqual((r.findings[0].rule, r.findings[0].severidad), ("db.anonymous", "alta"))

    def test_technologies_enrich_without_findings(self):
        r = host_sources.parse_technologies(write("web/technologies_8080.txt", "http://127.0.0.1:8080 [200 OK] Server[SimpleHTTP/0.6]\n"), ROOT)
        self.assertEqual(r.findings, []); self.assertTrue(r.activos)


from lib.render import write_reports, to_json, from_json
from lib.engine import Collected

class RenderTests(unittest.TestCase):
    def collected(self):
        f = Finding(rule="sqlmap.sqli", key="k", titulo="SQLi", categoria="web", severidad="critica",
                    confianza="confirmado", activo="https://127.0.0.1", tecnica="sqlmap",
                    descripcion="d", impacto_cliente="i", recomendacion="r", esfuerzo="medio",
                    cve=None, cvss=None, evidencia=[Evidence("scans/web/sqlmap_a.txt", 3, "- Veredicto: INYECTABLE")],
                    referencias=[])
        c = Finding(rule="sqli_findings.differential", key="c", titulo="Dif", categoria="web", severidad="media",
                    confianza="candidato", activo="https://127.0.0.1", tecnica="sqli",
                    descripcion="d", impacto_cliente="i", recomendacion="r", esfuerzo="medio",
                    cve=None, cvss=None, evidencia=[], referencias=[])
        return Collected([f, c], {"127.0.0.1": {"host": "127.0.0.1", "puertos": []}},
                         [{"fuente": "scans/x", "motivo": "vacío"}], [{"fuente": "scans/y", "motivo": "catch-all"}],
                         ["127.0.0.1"], True)

    def test_technical_has_evidence_and_appendix(self):
        out = Path(tmp()); write_reports(self.collected(), {"cliente": "ACME", "auditor": "Ana"}, out, ["tecnico"])
        md = (out / "informe_tecnico.md").read_text()
        self.assertIn("scans/web/sqlmap_a.txt:3", md)
        self.assertIn("Candidatos", md); self.assertIn("No evaluable", md)
        self.assertIn("Incidencias de ejecución", md); self.assertIn("Descartados", md)
        self.assertIn("Activos", md)
        self.assertIn("Técnica", md)
        html = (out / "informe_tecnico.html").read_text()
        self.assertIn("Técnica", html)

    def test_client_has_no_internal_paths_or_payloads(self):
        out = Path(tmp()); write_reports(self.collected(), {"cliente": "ACME", "auditor": "Ana"}, out, ["cliente"])
        text = (out / "informe_cliente.md").read_text() + (out / "informe_cliente.html").read_text()
        for prohibido in ("scans/", "INYECTABLE", "CONFIRMADO", "sqlmap", "payload"):
            self.assertNotIn(prohibido, text)
        self.assertIn("30/60/90", text); self.assertIn("ACME", text)

    def test_html_is_self_contained_and_escaped(self):
        c = self.collected(); c.findings[0].titulo = "<script>x</script>"
        out = Path(tmp()); write_reports(c, {}, out, ["tecnico", "cliente"])
        html_tecnico = (out / "informe_tecnico.html").read_text()
        html_cliente = (out / "informe_cliente.html").read_text()
        self.assertIn("<style", html_tecnico); self.assertNotIn("cdn", html_tecnico.lower())
        self.assertIn("&lt;script&gt;", html_tecnico); self.assertNotIn("<script>x", html_tecnico)
        self.assertIn("<style", html_cliente); self.assertNotIn("cdn", html_cliente.lower())
        self.assertIn("&lt;script&gt;", html_cliente); self.assertNotIn("<script>x", html_cliente)

    def test_roundtrip_json(self):
        c = self.collected(); data = to_json(c, {"cliente": "ACME"})
        c2, meta = from_json(data)
        self.assertEqual(len(c2.findings), 2); self.assertEqual(meta["cliente"], "ACME")

    def test_client_singular_plural_pruebas(self):
        # With 1 candidate, should say "1 prueba requiere"
        from lib.engine import Collected
        f = Finding(rule="r", key="k", titulo="t", categoria="web", severidad="critica",
                    confianza="confirmado", activo="h", tecnica="x", descripcion="d",
                    impacto_cliente="i", recomendacion="r", esfuerzo="medio",
                    cve=None, cvss=None, evidencia=[], referencias=[])
        c = Finding(rule="r2", key="k2", titulo="t2", categoria="web", severidad="media",
                    confianza="candidato", activo="h", tecnica="x", descripcion="d",
                    impacto_cliente="i", recomendacion="r", esfuerzo="medio",
                    cve=None, cvss=None, evidencia=[], referencias=[])
        col = Collected([f, c], {}, [], [], ["h"], True)
        out = Path(tmp()); write_reports(col, {"cliente": "X"}, out, ["cliente"])
        md = (out / "informe_cliente.md").read_text()
        self.assertIn("1 prueba requiere", md)

        # With 2 candidates, should say "2 pruebas requieren"
        c2 = Finding(rule="r3", key="k3", titulo="t3", categoria="web", severidad="baja",
                     confianza="candidato", activo="h", tecnica="x", descripcion="d",
                     impacto_cliente="i", recomendacion="r", esfuerzo="medio",
                     cve=None, cvss=None, evidencia=[], referencias=[])
        col2 = Collected([f, c, c2], {}, [], [], ["h"], True)
        out2 = Path(tmp()); write_reports(col2, {"cliente": "X"}, out2, ["cliente"])
        md2 = (out2 / "informe_cliente.md").read_text()
        self.assertIn("2 pruebas requieren", md2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
