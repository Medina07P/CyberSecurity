# Informes automatizados (técnico y cliente) — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convertir `scans/` en un registro determinista de hallazgos y generar, desde el menú, un informe técnico y otro de cliente sin inventar ni filtrar datos de otro objetivo.

**Architecture:** Motor Python stdlib en `11_Reports/` con un parser por fuente y un catálogo de textos; un `findings.json` canónico alimenta dos renderizadores (Markdown + HTML autocontenido). El gestor gana la acción `R`, un perfil de cliente local y un envoltorio compatible. No hay red, LLM ni palabras clave.

**Tech Stack:** Python 3 (solo stdlib: `dataclasses`, `xml.etree`, `json`, `csv`, `re`, `hashlib`, `html`, `unittest`), Bash 4+, sin dependencias nuevas.

**Spec:** `docs/superpowers/specs/2026-11-05-informes-automatizados-design.md`

## Global Constraints

- Todo el texto de usuario va en **español**; identificadores y reglas en inglés.
- Python **solo stdlib**; nada de `yaml`, `requests`, `jinja2`, `pytest`.
- **Sin red**: el motor solo lee archivos.
- Salidas en `11_Reports/generated/<slug>/`; el slug sustituye `:` y `/` por `_` (misma regla que `scans_slug`).
- `findings.json` con `severidad ∈ critica|alta|media|baja|info` y `confianza ∈ confirmado|candidato|observacion`.
- Códigos de salida del motor: `0` informes escritos, `1` uso/E/S, `3` nada evaluable.
- HTML **autocontenido**: sin CDN, sin `http(s)://` en `<link>`/`<script>`, CSS embebido.
- Evidencia siempre con ruta relativa al repo y `linea` cuando el formato la permita.
- Ningún parser usa búsqueda de palabras clave sobre texto libre para decidir un hallazgo.
- Archivos `.sh`/`.py` en LF; `.sh` con `#!/bin/bash`, `Uso:`/`Ejemplo:` y `exit 1` por uso.
- Las libs del gestor viven en `00_Config/lib/*.bash` (invisibles al menú) y resuelven su ruta con `${BASH_SOURCE[0]:-$0}`.
- No se versiona ningún informe generado: `11_Reports/generated/` y `.report_profile` van al `.gitignore`.
- Los cuatro suites existentes (`run_tests.sh`, `run_e2e.sh`, `run_smoke.sh`, `run_wizard.sh`) y el nuevo `run_reports.sh` deben pasar.

## Review Focus

1. **Mezcla de objetivos**: `scans/` contiene `127.0.0.1` y puede contener `127.0.0.10`; un informe de un cliente no puede llevar datos del otro, ni siquiera por coincidencia parcial. Task 3 (`belongs_to`), Task 4 (`filter_findings`) y Task 13 (e2e con ambos hosts).
2. **Archivo con palabras**: un `.txt` con «password», «inject» o «CVE-…» en texto suelto no puede producir hallazgos. Task 4 (patrón no reconocido → ignorado) y Task 6/7 (nuclei/nikto solo por estructura o CVE real).
3. **Freno y no determinado**: un `429`/`503`/timeout o un `NO DETERMINADO` no puede salir como hallazgo ni como «limpio». Task 9 (rate_limit/sqlmap) y Task 12 (apéndice y recuento).
4. **Edición del registro**: `--desde-json` debe re-renderizar respetando el JSON editado sin volver a escanear. Task 13.
5. **Fuga al cliente**: el informe de cliente no puede citar `scans/`, payloads, candidatos como explotados ni cargar CSS de CDN. Task 12.

---

### Task 1: Modelo, ids estables y fusión de duplicados

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/__init__.py`
- Create: `CyberSecurity-Framework/11_Reports/lib/model.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`
- Create: `CyberSecurity-Framework/tests/run_reports.sh`

**Interfaces:**
- Produces:
  - `SEVERITY_ORDER: dict[str, int]` (`critica=0 … info=4`), `CONFIDENCE_ORDER: dict[str, int]` (`confirmado=0, candidato=1, observacion=2`).
  - `@dataclass(frozen=True) Evidence(archivo: str, linea: int | None, extracto: str)`.
  - `@dataclass Finding(rule, key, titulo, categoria, severidad, confianza, activo, tecnica, descripcion, impacto_cliente, recomendacion, esfuerzo, cve, cvss, evidencia, referencias)`; property `id -> str`.
  - `stable_id(key: str) -> str`, `merge_findings(items: list[Finding]) -> list[Finding]`, `sort_findings(items) -> list[Finding]`, `finding_to_dict`, `finding_from_dict`, `relpath(path: Path, repo_root: Path) -> str`.
  - `@dataclass ParseResult(findings, activos, no_evaluable, descartados, evaluado=True)` con listas y `evaluado: bool`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_report_engine.py` with this bootstrap, then append the tests (keep `unittest.main(verbosity=2)` at the end):

```python
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
```

```python
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
```

Create `tests/run_reports.sh` with `#!/bin/bash`, header `Uso:/Ejemplo:`, `cd` to its own directory and:
`python3 tests/test_report_engine.py` (propagate exit code).

- [ ] **Step 2: Run the tests and see them fail**

Run: `cd CyberSecurity-Framework && ./tests/run_reports.sh`
Expected: `ModuleNotFoundError: No module named 'lib.model'`.

- [ ] **Step 3: Implement `lib/model.py`**

`stable_id` = `hashlib.sha1(key.encode()).hexdigest()`. `merge_findings` groups by `key`, keeps min by `(SEVERITY_ORDER, CONFIDENCE_ORDER)`, unions `evidencia` deduplicating by `(archivo, linea, extracto)`, unions references, keeps non-null `cve` and max `cvss`. `sort_findings` sorts by `(SEVERITY_ORDER[severidad], CONFIDENCE_ORDER[confianza], activo, id)`. `relpath` returns POSIX relative path or `path.name` on `ValueError`.

- [ ] **Step 4: Run the tests and see them pass**

Run: `cd CyberSecurity-Framework && ./tests/run_reports.sh`
Expected: 4 tests, OK.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib CyberSecurity-Framework/tests/test_report_engine.py CyberSecurity-Framework/tests/run_reports.sh
git commit -m "feat(reportes): modelo de hallazgos con ids estables y dedupe"
```

---

### Task 2: Catálogo de textos en español

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/catalog.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Consumes: `Finding`, `Evidence`.
- Produces: `build(rule: str, *, key: str, activo: str, evidencia: list[Evidence], variables: dict[str, str] | None = None, severidad: str | None = None, confianza: str | None = None, cve: str | None = None, cvss: float | None = None) -> Finding` y `KNOWN_RULES: tuple[str, ...]`.
- Reglas: `nmap.open_port`, `nmap.cve`, `nuclei.template`, `nikto.cve`, `nikto.osvdb`, `ffuf.resource`, `http_inject.cmd`, `http_inject.sqli`, `http_inject.ssti`, `http_inject.xss`, `http_inject.redirect`, `sqlmap.sqli`, `sqli_findings.differential`, `rate_limit.no_throttle`, `headers.missing.csp`, `headers.missing.xfo`, `headers.missing.xcto`, `headers.missing.hsts`, `api.method`, `ssh.password_auth`, `db.anonymous`.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failure**

Run: `cd CyberSecurity-Framework && ./tests/run_reports.sh`
Expected: `ModuleNotFoundError: No module named 'lib.catalog'`.

- [ ] **Step 3: Implement `catalog.py`**

Define an internal `_RULES` dict of `rule -> (severidad, confianza, titulo, descripcion, impacto_cliente, recomendacion, esfuerzo, referencias)`. Texts name the tool for the technical report and explain business impact for the client one; include the tool's own caveat where it exists (`rate_limit` says "esto no prueba que el login no tenga freno más adelante"; `http_inject.fuerte` not applicable here). `build` formats `descripcion`/`impacto`/`recomendacion` with `variables` via `str.format`; if a placeholder is missing raise `KeyError` (do not swallow). Caller overrides for severity/confidence are applied last.

- [ ] **Step 4: Run and see them pass**

Run: `cd CyberSecurity-Framework && ./tests/run_reports.sh`
Expected: 8 tests, OK.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/catalog.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): catálogo de textos por regla, en español"
```

---

### Task 3: Atribución de un archivo o activo al objetivo

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/attribution.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Produces: `slug(target: str) -> str`, `normalize_host(raw: str) -> str`, `host_of(raw: str) -> str`, `port_of(raw: str) -> int | None`, `guess_host(text: str) -> str | None`, `belongs_to(activo: str, objetivo: str) -> bool`.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failure.** Expected: `No module named 'lib.attribution'`.

- [ ] **Step 3: Implement**

`normalize_host` strips scheme/userinfo/path/query/fragment/port, lowercases, and trims a trailing dot. IPv6 is out of scope v1: if the host contains more than one `:`, return it unchanged. `guess_host` first tries IPv4 with a boundary-aware regex, then a domain with at least one dot and a valid TLD-ish suffix, ignoring tokens `http`, `https`, `www`. `belongs_to` compares normalized host equality only (never substring).

- [ ] **Step 4: Run and see them pass.** Expected: 13 tests, OK.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/attribution.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): atribución estricta de activos al objetivo"
```

---

### Task 4: Descubrimiento de fuentes, filtrado y `no_evaluable`

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Create: `CyberSecurity-Framework/11_Reports/lib/engine.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Consumes: `ParseResult`, `Finding`, `belongs_to`, `relpath`.
- Produces:
  - `Source(path: Path, kind: str, parser: Callable | None)`; `discover(scans_dir: Path) -> list[Source]`.
  - `filter_findings(findings, objetivo: str | None, incluir_sin_objetivo: bool, todos: bool) -> list[Finding]`.
  - `Collected(findings, activos: dict[str, dict], no_evaluable: list[dict], descartados: list[dict], objetivos: list[str], evaluado: bool, incidencias: list[dict] = [])`.
  - `collect(scans_dir: Path, repo_root: Path, objetivo: str | None, incluir_sin_objetivo=False, todos=False) -> Collected`.
- `kind` ∈ `nmap|nuclei_jsonl|nuclei_txt|nikto|ffuf|http_inject|sqlmap|sqli_findings|rate_limit|security_headers|headers|technologies|api|ssh|db|errores|ignored`.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failure.** Expected: `No module named 'lib.engine'`.

- [ ] **Step 3: Implement**

`discover` walks `scans_dir.rglob("*")` and classifies by directory + basename table from the spec. Return one `Source` per expected file, with `parser=None` until the parser tasks register it (later tasks fill the registry). `filter_findings`: if `todos`, return all; keep findings whose `activo` is non-empty and `belongs_to(activo, objetivo)`; include `activo == ""` only when `incluir_sin_objetivo`. `collect` runs each source's parser when present, merges findings, aggregates assets by host, concatenates `no_evaluable`/`descartados`, computes `objetivos` from assets and finding activos, sets `evaluado = any(r.evaluado)`, and builds `incidencias` from every non-empty `errores.log` (`{"fuente": relpath, "motivo": "<N> bytes de error"}`). Missing parser → skip without claiming anything (the source is not evaluated yet).

- [ ] **Step 4: Run and see them pass.** Expected: OK. The discovery/filter tests do not depend on parsers; keep them green from this task on.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/sources.py CyberSecurity-Framework/11_Reports/lib/engine.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): descubrimiento de fuentes y filtrado por objetivo"
```

---

### Task 5: Parser de nmap (XML)

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/__init__.py`
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/nmap.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Produces: `parse(path: Path, repo_root: Path) -> ParseResult`. Each open port yields one observación `nmap.open_port`; each CVE in a `<script>` yields one `nmap.cve` confirmed. `activos` entries `{"host": str, "puertos": [{"puerto": int, "servicio": str, "producto": str}]}`.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failure.** Expected: `No module named 'lib.parsers'`.

- [ ] **Step 3: Implement**

Parse with `ElementTree`; on `ParseError` return `ParseResult(evaluado=False, no_evaluable=[{"fuente": relpath(path, repo_root), "motivo": str(exc)}])`. CVE severity from `CVE-x: <score>:` if present (>=9 critica, >=7 alta, >=4 media, else baja), else media. Evidence `archivo=relpath`, `linea=None`, `extracto` = script id + first 120 chars of output. Register `nmap` in `sources.PARSERS` for kind `nmap`.

- [ ] **Step 4: Run and see them pass.** Expected: OK.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/parsers CyberSecurity-Framework/11_Reports/lib/sources.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): parser de nmap con puertos y CVE"
```

---

### Task 6: Parsers de nuclei (JSONL preferente, TXT estándar)

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/nuclei.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Produces: `parse_jsonl(path, repo_root) -> ParseResult`, `parse_txt(path, repo_root) -> ParseResult`, `severity(raw: str) -> str` (`critical→critica … unknown→info`).

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failure.**

- [ ] **Step 3: Implement**

Read with `encoding="utf-8", errors="replace"` and `line.rstrip("\r\n")`. Text regex `^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)`. Dedupe key `nuclei|<template-id>|<host>|<path>`. Evidence line number. If the file is empty → `evaluado=False`, `no_evaluable=[{"fuente":…, "motivo":"archivo vacío"}]`. Register both kinds.

- [ ] **Step 4: Run and see them pass.**

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/parsers/nuclei.py CyberSecurity-Framework/11_Reports/lib/sources.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): parser de nuclei en JSONL y texto"
```

---

### Task 7: Parser de nikto con lista de ruido

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/nikto.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Produces: `parse(path, repo_root) -> ParseResult`; `NOISE: tuple[str, ...]` exportada para el test.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failure.**

- [ ] **Step 3: Implement**

`NOISE` covers the spec list plus header names (`x-frame-options`, `x-content-type-options`, `strict-transport-security`, `content-security-policy`) to avoid duplicates. Match `CVE-\d{4}-\d{4,}` first; else `OSVDB-\d+`. Severity media/baja, CVSS `None`. Host from `guess_host` of the file name; if `None`, `activo=""` (unattributable). Evidence line + text. Empty file → `evaluado=False`.

- [ ] **Step 4: Run and see them pass.**

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/parsers/nikto.py CyberSecurity-Framework/11_Reports/lib/sources.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): parser de nikto sin ruido y con CVE/OSVDB"
```

---

### Task 8: Parser de ffuf con línea base obligatoria

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/ffuf.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Produces: `parse(path, repo_root) -> ParseResult`, `baseline_from_commandline(cmd: str) -> int | None`.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failure.**

- [ ] **Step 3: Implement**

`baseline_from_commandline` regex `(?:^|\s)-fs\s+"?(\d+)"?`. Only `2xx/3xx` results can be observations; others go to `descartados` with the status. `activo` = host extracted from `url` or the `-u` URL; key `ffuf|<host>|<url>`. A hit with `length == baseline` → `descartados` "catch-all". Evidence: no line, extracto `url (status, length)`. JSON parse error → `evaluado=False`.

- [ ] **Step 4: Run and see them pass.**

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/parsers/ffuf.py CyberSecurity-Framework/11_Reports/lib/sources.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): parser de ffuf con baseline obligatoria"
```

---

### Task 9: Parsers de veredicto (http_inject, sqlmap, sqli_findings, rate_limit)

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/http_inject.py`
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/sqlmap.py`
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/sqli_findings.py`
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/rate_limit.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Produces: each module exposes `parse(path, repo_root) -> ParseResult`. `http_inject` reads the sibling `<slug>/contexto.txt` when present to get `host`; `rate_limit`/`sqlmap` read `- Objetivo:`; `sqli_findings` takes the host from the URL. All SQLi-shaped findings use key `sqli|<host>|<param>` so they merge.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failures.**

- [ ] **Step 3: Implement**

- `http_inject`: `csv.DictReader(delimiter="\t")`; classify by `nivel` (`CONFIRMADO`→confirmado, `FUERTE`→candidato, `DEBIL`→descartado) and `clase` (severity from the catalog). Dedupe keys: `sqli|host|param` for `sqli`, `cmd|host|param` for `cmd`, `ssti|host|param`, `xss|host|param`, `redirect|host|param`. Host from the sibling `contexto.txt`, else `guess_host`. Evidence line = row index + 2.
- `sqlmap`: only lines starting `- Veredicto:`; `NO INYECTABLE` check **before** `INYECTABLE`; `NO DETERMINADO` → no_evaluable; param from parentheses.
- `sqli_findings`: split on `|`; compare `sig` with `base:` value; always candidate when different (the tool already only writes differentials).
- `rate_limit`: verdict line; `SIN FRENO` → confirmed alta; `FRENADO` → nothing; anything else → no_evaluable. Dedupe key `rate_limit|host|endpoint`. Endpoint from `- Petición:` for the text. Evidence also the TSV first data row when the file exists.
- Empty file in any → `evaluado=False`.

- [ ] **Step 4: Run and see them pass.**

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/parsers/http_inject.py CyberSecurity-Framework/11_Reports/lib/parsers/sqlmap.py CyberSecurity-Framework/11_Reports/lib/parsers/sqli_findings.py CyberSecurity-Framework/11_Reports/lib/parsers/rate_limit.py CyberSecurity-Framework/11_Reports/lib/sources.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): parsers de veredictos web y dedupe de SQLi"
```

---

### Task 10: Cabeceras de seguridad con guarda de respuesta

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/headers.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Produces: `parse_security(path, repo_root) -> ParseResult`, `parse_context(path, repo_root) -> ParseResult`, `REQUIRED: tuple[tuple[str, str], ...]` (header, rule).

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failure.**

- [ ] **Step 3: Implement**

The paired file is `security_headers_<suffix>.txt` → `headers_<suffix>.txt` (same suffix). Guard requires the first line to match `^HTTP/\S+\s+[23]\d\d`. Scheme = `https` if the filename/slug contains `https` or the suffix has `443`/`8443`; otherwise `http` and skip HSTS. Severity: CSP media, XFO media, HSTS media, XCTO baja. `activo` from `guess_host(filename)`; if `None`, `activo=""`. Evidence: the security_headers line that shows the present header, or line 1 with the guard. Empty but guarded → all missing (legitimate). Empty without guard → no_evaluable.

- [ ] **Step 4: Run and see them pass.**

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/parsers/headers.py CyberSecurity-Framework/11_Reports/lib/sources.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): cabeceras ausentes solo con respuesta verificada"
```

---

### Task 11: Fuentes sin objetivo, SSH y base de datos

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/host_sources.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Produces: `parse_api(path, repo_root)`, `parse_ssh(path, repo_root)`, `parse_db(path, repo_root)`, `parse_technologies(path, repo_root) -> ParseResult`. API findings have `activo=""`; SSH takes the host from the `Nmap scan report for … (addr)` line when present.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run and see failure.**

- [ ] **Step 3: Implement**

API regex `([A-Z]+)\s+\((\d{3})\)`; only `PUT|DELETE|PATCH|TRACE|CONNECT` with `2xx` → observación baja. SSH: find `password` before the auth block ends; host regex `Nmap scan report for .*\(([0-9.]+)\)`, else `guess_host`. DB: non-empty first non-blank line is evidence → confirmed alta, `activo=""`; empty → no_evaluable "archivo vacío: no consta que la conexión se intentara". Technologies: extract `Nombre[valor]` pairs, drop `Country|IP|Title`, return as `activos=[{"host":…, "tecnologias":[…]}]`.

- [ ] **Step 4: Run and see them pass.**

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/parsers/host_sources.py CyberSecurity-Framework/11_Reports/lib/sources.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): fuentes de host, SSH y base de datos"
```

---

### Task 12: Renderizadores técnico y cliente

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/render.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Consumes: `Collected`, `Finding`, `meta: dict`.
- Produces: `to_json(collected, meta) -> dict`, `from_json(data) -> tuple[Collected, dict]`, `write_reports(collected, meta, out_dir, tipos) -> list[Path]`.

- [ ] **Step 1: Write the failing tests**

```python
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

    def test_client_has_no_internal_paths_or_payloads(self):
        out = Path(tmp()); write_reports(self.collected(), {"cliente": "ACME", "auditor": "Ana"}, out, ["cliente"])
        text = (out / "informe_cliente.md").read_text() + (out / "informe_cliente.html").read_text()
        for prohibido in ("scans/", "INYECTABLE", "sqlmap", "payload"):
            self.assertNotIn(prohibido, text)
        self.assertIn("30/60/90", text); self.assertIn("ACME", text)

    def test_html_is_self_contained_and_escaped(self):
        c = self.collected(); c.findings[0].titulo = "<script>x</script>"
        out = Path(tmp()); write_reports(c, {}, out, ["tecnico", "cliente"])
        html = (out / "informe_tecnico.html").read_text()
        self.assertIn("<style", html); self.assertNotIn("cdn", html.lower())
        self.assertIn("&lt;script&gt;", html); self.assertNotIn("<script>x", html)

    def test_roundtrip_json(self):
        c = self.collected(); data = to_json(c, {"cliente": "ACME"})
        c2, meta = from_json(data)
        self.assertEqual(len(c2.findings), 2); self.assertEqual(meta["cliente"], "ACME")
```

- [ ] **Step 2: Run and see failure.**

- [ ] **Step 3: Implement**

Markdown with headings from the spec: `## Candidatos`, `## No evaluable`, `## Incidencias de ejecución`, `## Hallazgos`, `## Observaciones`, `## Descartados`. HTML generated from the same data with `html.escape` (never by converting Markdown). Client renderer ignores `evidencia`, `tecnica`, `descripcion`, payloads; uses `impacto_cliente` and `recomendacion`; candidates only as a count. Plan 30/60/90: group confirmed findings by severity into three buckets (critical+high → 30, medium → 60, low+info → 90). Include a "No evaluable" appendix and the execution incidents in the technical report, and a short "límites" paragraph in the client one. `to_json` uses `finding_to_dict`.

- [ ] **Step 4: Run and see them pass.**

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/render.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): informes técnico y cliente en Markdown y HTML"
```

---

### Task 13: CLI, perfil, `--desde-json` y códigos de salida

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/report_engine.py`
- Test: `CyberSecurity-Framework/tests/test_report_engine.py`

**Interfaces:**
- Produces: `build_parser() -> argparse.ArgumentParser`, `read_profile(path: Path) -> dict[str, str]`, `write_profile(path: Path, data: dict[str, str]) -> None`, `run(argv: list[str] | None = None) -> int`, `main() -> None`.
- Env: `REPORT_SCANS_DIR`, `REPORT_OUT_DIR`, `REPORT_PROFILE`.
- Flags exactly as the spec table.

- [ ] **Step 1: Write the failing tests**

```python
from report_engine import run, read_profile, write_profile

class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tmp()); self.scans = self.tmp / "scans"; self.out = self.tmp / "out"
        self.empty = self.tmp / "empty"; self.empty.mkdir()
        self.profile = self.tmp / ".report_profile"
        write_at(self.scans, "nmap/a.xml", XML_127)
        write_at(self.scans, "nmap/b.xml", XML_127.replace("127.0.0.1", "127.0.0.10"))
        write_at(self.scans, "api/methods.txt", " ✅ PUT (200)\n")
        os.environ["REPORT_PROFILE"] = str(self.profile)

    def test_generates_both_reports_and_json(self):
        rc = run(["--scans", str(self.scans), "--objetivo", "127.0.0.1", "--tipo", "ambos",
                  "--salida", str(self.out), "--cliente", "ACME", "--auditor", "Ana"])
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / "findings.json").exists())
        self.assertEqual(json.loads((self.out / "findings.json").read_text())["meta"]["cliente"], "ACME")
        self.assertTrue((self.out / "informe_tecnico.html").exists())
        self.assertTrue((self.out / "informe_cliente.html").exists())

    def test_exit_3_when_nothing_is_evaluable(self):
        self.assertEqual(run(["--scans", str(self.empty), "--objetivo", "127.0.0.1", "--salida", str(self.out)]), 3)

    def test_usage_error_returns_1_and_help_returns_0(self):
        self.assertEqual(run(["--no-existe"]), 1)
        self.assertEqual(run(["--help"]), 0)

    def test_desde_json_respects_an_edit(self):
        run(["--scans", str(self.scans), "--objetivo", "127.0.0.1", "--salida", str(self.out)])
        data = json.loads((self.out / "findings.json").read_text()); data["hallazgos"][0]["titulo"] = "EDITADO"
        (self.out / "findings.json").write_text(json.dumps(data))
        self.assertEqual(run(["--desde-json", str(self.out / "findings.json"), "--salida", str(self.out), "--tipo", "tecnico"]), 0)
        self.assertIn("EDITADO", (self.out / "informe_tecnico.md").read_text())

    def test_profile_is_used_when_flags_are_absent(self):
        write_profile(self.profile, {"cliente": "Perfil SA", "auditor": "Ana"})
        run(["--scans", str(self.scans), "--objetivo", "127.0.0.1", "--salida", str(self.out)])
        self.assertEqual(json.loads((self.out / "findings.json").read_text())["meta"]["cliente"], "Perfil SA")

    def test_json_summary_is_machine_readable(self):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(["--scans", str(self.scans), "--objetivo", "127.0.0.1", "--salida", str(self.out), "--json"])
        resumen = json.loads(buf.getvalue().strip().splitlines()[-1])
        self.assertGreaterEqual(resumen["hallazgos"], 1)

    def test_todos_and_incluir_sin_objetivo(self):
        run(["--scans", str(self.scans), "--todos", "--salida", str(self.out)])
        ids = {h["activo"] for h in json.loads((self.out / "findings.json").read_text())["hallazgos"]}
        self.assertIn("127.0.0.10", " ".join(ids))
        run(["--scans", str(self.scans), "--objetivo", "127.0.0.1", "--incluir-sin-objetivo", "--salida", str(self.out)])
        self.assertTrue(any(h["rule"] == "api.method" for h in json.loads((self.out / "findings.json").read_text())["hallazgos"]))
```

`XML_127` is the same minimal nmap XML as Task 5, defined once at module level.

- [ ] **Step 2: Run and see failure.**

- [ ] **Step 3: Implement**

Header comment with `Uso: python3 report_engine.py --objetivo <objetivo> --tipo <tipo>` and `Ejemplo:`. Resolve defaults: `scans = env REPORT_SCANS_DIR or repo/scans`; `salida = env REPORT_OUT_DIR or repo/11_Reports/generated/<slug>`; profile env or `repo/11_Reports/.report_profile`. Target = `--objetivo`, else first line of `00_Config/.session`, else `None` → warn and `todos=True`. Flags override profile. `--desde-json` loads and skips `collect` (so scan files are never touched), applies `--cliente/--auditor` overrides, writes reports, returns 0. Exit 3 when `not collected.evaluado`; catch `SystemExit` from argparse and return its code mapped to 1 for errors and 0 for `--help`. `--json` prints `{"objetivo":…,"hallazgos":N,"criticos":N,"no_evaluable":N,"salida":…}`. `--abrir` uses `xdg-open` and ignores failure.

- [ ] **Step 4: Run and see them pass.**

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/report_engine.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reportes): CLI del motor con perfil y re-render desde JSON"
```

---

### Task 14: Envoltorio, menú `R`, fase 11 y compatibilidad

**Files:**
- Modify: `CyberSecurity-Framework/11_Reports/report_generator.sh` (reescritura completa)
- Create: `CyberSecurity-Framework/00_Config/lib/report_profile.bash`
- Modify: `CyberSecurity-Framework/cyber_framework.sh` (main menu, `show_help`, new `quick_report`)
- Modify: `CyberSecurity-Framework/00_Config/lib/phase_status.bash:57-66`
- Modify: `CyberSecurity-Framework/11_Reports/run_all_reports.sh`
- Modify: `CyberSecurity-Framework/11_Reports/README.md`
- Modify: `CyberSecurity-Framework/11_Reports/FLUJO.md`
- Modify: `CyberSecurity-Framework/09_Automation/python/report_generator.py`
- Modify: `.gitignore`
- Modify: `CyberSecurity-Framework/tests/run_tests.sh:84-91` (move wrapper to slots)
- Modify: `CyberSecurity-Framework/tests/run_smoke.sh:102-117`
- Test: `CyberSecurity-Framework/tests/run_reports.sh` (extend with shell checks)

**Interfaces:**
- `report_generator.sh`: `Uso: ./report_generator.sh [tipo]`, `Ejemplo: ./report_generator.sh ambos`; accepts `tecnico|cliente|ambos` and aliases `--executive|--technical|--full|--all`; forwards remaining args (`--scans`, `--salida`, `--objetivo`).
- `00_Config/lib/report_profile.bash`: `report_profile_path`, `report_profile_get <clave>`, `report_profile_set <clave> <valor>`; file `11_Reports/.report_profile`.
- `quick_report`: submenu 1/2/3, prompts client/auditor only when missing, passes `--objetivo "$(session_target)"` when set, runs the wrapper, prints paths, offers `xdg-open`.

- [ ] **Step 1: Write the failing shell checks**

Add to `tests/run_reports.sh`:
- `params_mode 11_Reports/report_generator.sh` → `slots`; `params_slot_count` → `1` (source `00_Config/lib/params.bash`).
- `printf 'R\n0\nQ\n' | timeout 20 bash ./cyber_framework.sh` output contains `Informe técnico`.
- `printf '?\n\nQ\n' | ...` output contains `MANUAL-GESTOR.md`.
- `printf 'R\n3\n\n\n\nQ\n' | ...` with `REPORT_SCANS_DIR`, `REPORT_OUT_DIR` and `REPORT_PROFILE` pointing at temp paths → creates `informe_cliente.md` and `informe_tecnico.md` under the fixture output dir.
- `phase_status`: with `PHASE_FW_DIR=<tmp>` containing `11_Reports/generated/x/findings.json`, `phase_state 11_Reports` → `done`.
- legacy shim with fixture dir prints `obsoleto` and writes the two reports.
- `bash -n` on every modified `.sh`; `py_compile` on every modified `.py`.

- [ ] **Step 2: Run and see failures.**

- [ ] **Step 3: Implement**

- Wrapper: `cd` to its own dir, map args, call `python3 report_engine.py --tipo <tipo> "$@"`; `--help` prints usage; `exit 1` on unknown type.
- `quick_report`: save client/auditor in the profile (Enter keeps current), then run wrapper with the chosen type; no confirmation prompt (offline).
- Menu: source `report_profile.bash` next to the other libs; add `R` line between `99` and `T`; case `R|r`; help section.
- `phase_status`: `11_Reports` done if `generated/*/findings.json` or legacy report.
- `run_all_reports.sh`: call `./report_generator.sh --all`; list `generated/`.
- `11_Reports/README.md` and `FLUJO.md`: document `generated/`, the two report types and the `R` action; remove the old `--executive/--technical` quick-start as the primary path (keep them as aliases).
- Legacy shim: deprecation notice; map `--input` → `--scans`, `--output` dirname → `--salida`; call engine, exit with its code.
- `.gitignore`: add `CyberSecurity-Framework/11_Reports/generated/` and `CyberSecurity-Framework/11_Reports/.report_profile`.
- `run_tests.sh`: remove the wrapper from the manual list and add an assertion that it is `slots` with 1 slot.
- `run_smoke.sh`: replace the PLANTILLA block with the `R` submenu assertion (generation is covered by `run_reports.sh`).

- [ ] **Step 4: Run the checks and see them pass.**

Run: `cd CyberSecurity-Framework && ./tests/run_reports.sh && ./tests/run_smoke.sh`
Expected: 0 fallos.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports CyberSecurity-Framework/00_Config/lib/report_profile.bash CyberSecurity-Framework/cyber_framework.sh CyberSecurity-Framework/09_Automation/python/report_generator.py .gitignore CyberSecurity-Framework/tests
git commit -m "feat(gestor): acción R, perfil de cliente e informes reales en fase 11"
```

---

### Task 15: Manual, ayuda y cierre

**Files:**
- Create: `docs/MANUAL-GESTOR.md`
- Modify: `CyberSecurity-Framework/cyber_framework.sh` (`show_help`)
- Modify: `README.md` (link)
- Modify: `docs/superpowers/specs/2026-11-05-informes-automatizados-design.md` (estado: aprobado)
- Modify: `AGENTS.md` (estado actual: motor de informes, suite nueva)
- Test: `CyberSecurity-Framework/tests/run_reports.sh` (doc checks)

**Interfaces:** none.

- [ ] **Step 1: Write the failing doc checks**

In `tests/run_reports.sh`: for each heading `## Arranque`, `## Objetivo de sesión`, `## Informes`, `## Cómo leer los veredictos`, `## Problemas frecuentes` assert `grep -qF` in `../docs/MANUAL-GESTOR.md`; assert `README.md` links to it; assert the `?` output names it.

- [ ] **Step 2: Run and see failures.**

- [ ] **Step 3: Write `docs/MANUAL-GESTOR.md`**

Cover: requisitos e instalación; arranque; objetivo y `.session`; recorrido por fases; marcas; generación de informes (menú `R`, wrapper y motor); perfil de cliente; atribución, `--todos` y `--incluir-sin-objetivo`; estados (`confirmado`/`candidato`/`observacion`) y veredictos (`CONFIRMADO` ≠ `FUERTE`, `NO DETERMINADO` ≠ limpio); apéndice de no evaluable; alcance/seguridad; problemas frecuentes; referencia rápida de comandos. Update `?` and README link.

- [ ] **Step 4: Run everything**

Run:
```bash
cd CyberSecurity-Framework
./tests/run_reports.sh && ./tests/run_tests.sh && ./tests/run_e2e.sh && ./tests/run_smoke.sh && ./tests/run_wizard.sh
```
Expected: all green. If a count assertion changes because of the new scripts (wrapper mode), update the count and note why in the commit message.

- [ ] **Step 5: Commit**

```bash
git add docs/MANUAL-GESTOR.md docs/superpowers/specs/2026-11-05-informes-automatizados-design.md README.md AGENTS.md CyberSecurity-Framework/cyber_framework.sh CyberSecurity-Framework/tests/run_reports.sh
git commit -m "docs(gestor): manual de uso y estado del motor de informes"
```

---

## Self-review (hecho al escribir el plan)

- Cobertura del spec: motor (T1–T11), dos informes (T12), CLI/perfil (T13), menú/fase/compatibilidad (T14), manual (T15), pruebas de trampa y atribución (T3, T4, T12, T13).
- Tipos consistentes: `Finding`/`Evidence`/`ParseResult` definidos en T1 y usados con los mismos nombres en todo el plan; `build(...)` con `key` obligatorio; `collect(...)` con la misma firma en T4 y T13.
- Cada paso decide una acción verificable; no hay cuerpos de implementación salvo los que la firma no determina.
