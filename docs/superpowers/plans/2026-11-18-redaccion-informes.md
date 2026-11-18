# Redacción en `report_engine.py` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ningún `Evidence.extracto` que `report_engine.py` escriba en
`findings.json` o renderice en los informes técnico/cliente puede contener
un secreto en claro que `00_Config/lib/ai/redact.py::redact()` ya sepa
reconocer.

**Architecture:** Un helper puro `redact_findings(findings) -> list[Finding]`
en `11_Reports/lib/model.py`, que importa y reutiliza `ai.redact.redact` sin
reimplementarlo (mismo patrón de `sys.path.insert` que ya usan
`09_Automation/ai/ai_assistant.py` y `09_Automation/python/orchestrator.py`
para llegar a `00_Config/lib/`). Se invoca una sola vez dentro de
`lib/engine.py::collect()`, sobre la lista completa de hallazgos recién
agregados y antes de `merge_findings`/`sort_findings` — así cubre
`findings.json` y ambos informes por construcción, sin tocar los 14
parsers.

**Tech Stack:** Python 3 stdlib únicamente (`re` vía `redact.py`), `unittest`
(suite existente `tests/test_report_engine.py`).

**Spec:** `docs/superpowers/specs/2026-11-18-redaccion-informes-design.md`

## Global Constraints

- `redact()` se reutiliza tal cual; cero cambios en
  `00_Config/lib/ai/redact.py`.
- Solo se toca `Evidence.extracto`. `descripcion`, `impacto_cliente`,
  `recomendacion`, `titulo`, `activo`, `archivo`, `linea` quedan igual
  (plantillas fijas o metadatos de ubicación, no texto crudo de `scans/`).
- No se cambia la firma pública de `collect()`, `Finding` ni `Evidence`.
- La ruta `--desde-json` (`finding_from_dict`) no vuelve a redactar: un
  `findings.json` ya escrito ya pasó por este punto una vez.
- `10_Evidence/` no se toca en este plan (ver Anti-goals del spec).

## Review Focus

- Un `extracto` que ya no tiene nada que redactar (p. ej. `"200 OK (123b)"`
  de `http_inject.py`) debe quedar exactamente igual, no solo "sin el
  secreto" — una persona que compara el antes/después de un hallazgo
  inocuo no debe ver ningún cambio → Task 1, segundo test.
- Un `Finding` sin evidencia (`evidencia=[]`, el caso normal de
  `postexploitation.py`/`ffuf.py` cuando no hay nada que mostrar) no debe
  romper `redact_findings` con un `IndexError` o similar → Task 1, tercer
  test.
- El punto de integración en `collect()` tiene que ejecutarse con fuentes
  reales descubiertas por `discover()`, no solo con `Finding` construidos
  a mano — una regla de activación por `kind`/parser mal puesta dejaría el
  camino de verdad sin cubrir aunque el test unitario de `model.py` pasara
  → Task 2.
- El perfil `cliente`/`auditor` y el resto de `meta` (que no vienen de
  `scans/`, los pone el operador) no deben pasar por `redact()`: no es su
  superficie de riesgo y aplicarlo ahí sería ruido — confirmado leyendo
  `report_engine.py::run()`, donde `meta` nunca toca `Evidence`; no hace
  falta un test nuevo porque `redact_findings` solo recibe `list[Finding]`,
  nunca `meta`, por construcción de su firma.
- Dos hallazgos con la misma `key` que se fusionan en `merge_findings`
  (p. ej. dos ficheros nmap del mismo puerto) deben llegar ya redactados
  antes de fusionarse, para que la deduplicación por
  `(archivo, linea, extracto)` en `merge_findings` compare extractos ya
  redactados y no cree una entrada "duplicada" porque uno estaba redactado
  y el otro no → cubierto por el orden fijado en Architecture
  (`redact_findings` antes de `merge_findings` en el mismo paso), no por un
  test nuevo: es una propiedad del orden de llamadas, no de una rama de
  código que pueda tomar el camino equivocado.

---

### Task 1: `redact_findings` en `lib/model.py`

**Files:**
- Modify: `11_Reports/lib/model.py`
- Test: `tests/test_report_engine.py`

**Interfaces:**
- Produces: `redact_findings(findings: list[Finding]) -> list[Finding]` en
  `lib/model.py`, exportada en `__all__` si el módulo la declara (revisar:
  `model.py` no tiene `__all__` actualmente — no añadir uno nuevo, seguir
  el estilo del fichero).

- [ ] **Step 1: Write the failing tests** en `tests/test_report_engine.py`,
  nueva clase `RedactFindingsTests` (junto a `ModelTests`, reutilizando su
  helper `mk`):

  ```python
  from lib.model import redact_findings

  class RedactFindingsTests(unittest.TestCase):
      def mk(self, extracto):
          return Finding(rule="r", key="k", titulo="t", categoria="web",
                         severidad="alta", confianza="confirmado", activo="h",
                         tecnica="x", descripcion="d", impacto_cliente="i",
                         recomendacion="r", esfuerzo="medio", cve=None, cvss=None,
                         evidencia=[Evidence("a", 1, extracto)], referencias=[])

      def test_redacts_secret_in_evidence_extracto(self):
          out = redact_findings([self.mk("Authorization: Bearer abcdef1234567890ABCDEF")])
          self.assertNotIn("abcdef1234567890ABCDEF", out[0].evidencia[0].extracto)
          self.assertIn("[REDACTADO]", out[0].evidencia[0].extracto)

      def test_leaves_non_secret_extracto_unchanged(self):
          out = redact_findings([self.mk("200 OK (123b)")])
          self.assertEqual(out[0].evidencia[0].extracto, "200 OK (123b)")

      def test_finding_without_evidence_is_not_an_error(self):
          f = self.mk("x")
          f = replace(f, evidencia=[])
          out = redact_findings([f])
          self.assertEqual(out[0].evidencia, [])
  ```

  (`replace` ya está importado en `lib/model.py`; en el test, importar
  `from dataclasses import replace` junto a los demás imports del fichero
  si no está ya presente en `tests/test_report_engine.py`.)

- [ ] **Step 2: Run** (desde `CyberSecurity-Framework/`)
  `python3 tests/test_report_engine.py RedactFindingsTests 2>&1 | tail -20`
  → FALLA: `ImportError: cannot import name 'redact_findings'`.
- [ ] **Step 3: Implement** en `11_Reports/lib/model.py`. Al principio del
  fichero, junto a los imports existentes (`hashlib`, `dataclasses`,
  `pathlib`), añadir:

  ```python
  import sys as _sys
  _sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "00_Config" / "lib"))
  from ai.redact import redact as _redact
  ```

  y la función, cerca de `merge_findings` (misma sección del fichero):

  ```python
  def redact_findings(findings: list[Finding]) -> list[Finding]:
      """Redacta cada Evidence.extracto con ai.redact.redact (ver AGENTS.md:
      la misma función que usa el asistente IA, nunca reimplementada)."""
      return [
          replace(f, evidencia=[replace(e, extracto=_redact(e.extracto)) for e in f.evidencia])
          for f in findings
      ]
  ```

  Actualizar también el comentario de cabecera del módulo ("Solo biblioteca
  estándar...") con una frase corta aclarando que `ai.redact` es un módulo
  hermano del mismo repo, también solo `re`, no una dependencia externa.
- [ ] **Step 4: Run** `python3 tests/test_report_engine.py RedactFindingsTests -v 2>&1 | tail -20`
  → los tres tests nuevos PASAN; luego `python3 tests/test_report_engine.py 2>&1 | tail -10`
  (sin filtrar) para confirmar que el resto de la suite sigue en verde.
- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/model.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "feat(reports): redact_findings reutiliza ai.redact.redact sobre Evidence.extracto"
```

### Task 2: Integrar en `collect()` y test de extremo a extremo

**Files:**
- Modify: `11_Reports/lib/engine.py`
- Test: `tests/test_report_engine.py`

**Interfaces:**
- Consumes: `redact_findings` de Task 1.
- Produces: `collect()` devuelve un `Collected` cuyos `findings[*].evidencia[*].extracto`
  ya están redactados; sin cambio de firma.

- [ ] **Step 1: Write the failing test** en `tests/test_report_engine.py`,
  en `CollectTests` (reutiliza `tmp()` ya definido en el fichero):

  ```python
  def test_collect_redacts_secret_from_raw_scan_output(self):
      tmpdir = Path(tmp())
      scans = tmpdir / "scans"
      web = scans / "web"
      web.mkdir(parents=True)
      suf = "443_10.0.0.5"
      (web / f"security_headers_{suf}.txt").write_text(
          "Authorization: Bearer abcdef1234567890ABCDEF\n", encoding="utf-8")
      (web / f"headers_{suf}.txt").write_text("HTTP/1.1 200 OK\n", encoding="utf-8")
      c = collect(scans, tmpdir, "10.0.0.5")
      extractos = [e.extracto for f in c.findings for e in f.evidencia]
      self.assertTrue(extractos, "debe producir al menos un hallazgo con evidencia")
      self.assertFalse(any("abcdef1234567890ABCDEF" in texto for texto in extractos))
      self.assertTrue(any("[REDACTADO]" in texto for texto in extractos))
  ```

  (Fixture verificado a mano antes de escribir este plan: con el código
  actual, sin Task 2, `collect()` devuelve 4 hallazgos cuyo `extracto` es
  literalmente `"Authorization: Bearer abcdef1234567890ABCDEF"` — el test
  falla por la segunda aserción, no por falta de hallazgos.)

- [ ] **Step 2: Run** `python3 tests/test_report_engine.py CollectTests.test_collect_redacts_secret_from_raw_scan_output -v`
  → FALLA: `assertFalse` ve el secreto en claro.
- [ ] **Step 3: Implement.** En `11_Reports/lib/engine.py`:
  - Añadir `redact_findings` al import existente de `.model` (línea 15):
    `from .model import Finding, ParseResult, merge_findings, redact_findings, sort_findings, relpath`.
  - Cambiar la línea (actualmente):
    `all_findings = sort_findings(merge_findings(all_findings))`
    por:
    `all_findings = sort_findings(merge_findings(redact_findings(all_findings)))`
- [ ] **Step 4: Run** `python3 tests/test_report_engine.py CollectTests.test_collect_redacts_secret_from_raw_scan_output -v`
  → el test nuevo PASA; luego `python3 tests/test_report_engine.py 2>&1 | tail -10`
  para confirmar que el resto de la suite (`CollectTests`, `RenderTests`,
  `CliTests`, etc.) sigue en verde.
- [ ] **Step 5: Run la suite completa del módulo** `bash tests/run_reports.sh 2>&1 | tail -20`
  y `bash tests/run_reports_evidence.sh 2>&1 | tail -20` → sin fallos nuevos.
- [ ] **Step 6: Commit**

```bash
git add CyberSecurity-Framework/11_Reports/lib/engine.py CyberSecurity-Framework/tests/test_report_engine.py
git commit -m "fix(reports): collect() redacta la evidencia antes de fusionar y ordenar hallazgos"
```

### Task 3: Documentar `10_Evidence/` como decisión consciente

**Files:**
- Modify: `AGENTS.md`

**Interfaces:** ninguna (solo documentación).

- [ ] **Step 1: Actualizar `AGENTS.md`.** Añadir una nota fechada que
  cierre la brecha de `report_engine.py` (referenciando el commit de
  Task 2) y registre explícitamente que `10_Evidence/` queda fuera a
  propósito: `package.py` es custodia forense (hash SHA-256, detección de
  modificación) y la categoría `credentials/` guarda secretos a propósito,
  no por descuido — citando el spec
  (`docs/superpowers/specs/2026-11-18-redaccion-informes-design.md`,
  sección "Anti-goals") en vez de repetir el razonamiento completo.
- [ ] **Step 2: Commit**

```bash
git add AGENTS.md
git commit -m "docs: cierra la brecha de redacción en report_engine.py; 10_Evidence queda fuera a propósito"
```

---

## Self-Review

**Spec coverage:** Goals (punto de redacción único, reutilizar `redact()`,
cobertura de `findings.json` + informes) → Tasks 1–2. Anti-goals (no tocar
`10_Evidence/`) → Task 3 lo documenta explícitamente en vez de dejarlo
implícito. Constraints (no redactar plantillas/metadatos, no re-redactar en
`--desde-json`, no cambiar firmas) → ninguna task las viola; verificado
leyendo el diff final de cada task antes de commitear.

**Proportion:** dos tasks de código (una función de ~6 líneas + una línea
de integración) más una de documentación — proporcional a un spec corto
de alcance ya acotado por el usuario.
