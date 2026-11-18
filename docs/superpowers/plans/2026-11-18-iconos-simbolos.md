# Íconos Unicode simples — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sustituir los emojis a color por símbolos Unicode monocromos en el menú, la documentación y los scripts, con las suites de `tests/` en verde en cada fase.

**Architecture:** Un único conversor (`emoji_to_symbols.py`) con un mapa fijo y dos modos (código/menú: símbolo; docs: símbolo solo para estados, el resto se elimina). Se aplica solo a ficheros versionados (`git ls-files`), por fases; cada fase actualiza código y tests juntos para que las suites no queden rotas entre commits.

**Tech Stack:** Python 3 stdlib (conversor), Bash, `unittest` (patrón de `tests/test_*.py`).

**Spec:** `docs/superpowers/specs/2026-11-18-iconos-simbolos-design.md`

## Global Constraints

- Solo texto visible; sin cambios de lógica. No relajar aserciones de tests más allá del símbolo.
- Sin Nerd Font, sin cambios de colores ni de estructura del menú.
- Se elimina todo `U+FE0F` y `U+200D`.
- Rama `feat/iconos-simbolos` en worktree bajo `.worktrees/`, desde `develop`. Commits separados por fase. Sin push. Los cambios sin commit de `00_Config/scope.yaml` y `targets.txt` del checkout principal no se tocan ni se llevan.
- Nunca ejecutar suites en el checkout principal con datos: solo en el worktree. Guardas de hash de `scope.yaml`/`targets.txt` deben seguir intactas.
- Conservar finales de línea (LF) y bits de modo de cada fichero.
- Mensajes de commit terminan con `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## Mapa de sustitución (fuente de verdad)

Conservados tal cual (ya son glifos de texto): `→ ← ↳ ↔ ▶ ▼ ✓ ✗ ✔ ✖ ➜ ⚠ ⚙ ◎ ▪ ● › ℹ ◆`.

| Emoji | Modo código/menú | Modo docs |
|---|---|---|
| ✅ | `✔` | `✔` |
| ❌ | `✖` | `✖` |
| ➕ | `+` | `+` |
| 🚀 ℹ️ 💡 | `▶` / `ℹ` / `ℹ` | se eliminan |
| 🎯 | `◎` | se elimina |
| 📁 📂 | `▪` | se eliminan |
| 🛠 🔧 | `⚙` | se eliminan |
| 🔴 🟡 🟢 | `●` | se eliminan si hay etiqueta de texto al lado |
| cualquier otro emoji | se elimina junto con un espacio contiguo | igual |

`⚠️` → `⚠` en ambos modos (solo se quita el `U+FE0F`).

## Review Focus

- Código que compara contra el emoji (`grep`, `case`, `[[ == ]]`, `re.`, parsers de `phase_status`/`report_engine`): debe seguir casando tras el cambio.
- Cajas con bordes `║` y columnas alineadas del menú (emoji = 2 columnas, símbolo = 1): el banner no debe quedar torcido.
- Documentos que citan salida literal de un script ya cambiado: deben citar el texto nuevo.
- Fixtures de `tests/fixtures/` que simulan salida de herramientas: deben cambiar igual que el código que las parsea.
- Fichero con CRLF, sin permisos de escritura o ejecutable: el conversor no debe alterar saltos de línea ni modo.

---

### Task 1: Worktree, línea base y conversor

**Files:**
- Create: `/tmp/claude-1000/-home-kali-Documentos-CyberSecurity/7ef6a699-f2de-4b8f-afe9-d4d032f67034/scratchpad/emoji_to_symbols.py`
- Test: `/tmp/claude-1000/-home-kali-Documentos-CyberSecurity/7ef6a699-f2de-4b8f-afe9-d4d032f67034/scratchpad/test_emoji_to_symbols.py`

**Interfaces:**
- Produces (CLI): `python3 -I emoji_to_symbols.py [--docs] [--dry-run] [--check] PATH...` — reescribe cada `PATH` in situ; `--dry-run` solo imprime ficheros y nº de cambios; `--check` no escribe y sale 1 si queda algún emoji.
- Produces (módulo): `convert(text: str, docs: bool = False) -> str` y `find_emoji(text: str) -> list[str]` (emojis restantes, excluyendo los conservados).

- [ ] **Step 1: Crear el worktree** `git worktree add .worktrees/iconos -b feat/iconos-simbolos develop` y confirmar que `00_Config/scope.yaml` allí no tiene los cambios locales (`git -C .worktrees/iconos status --short` vacío).
- [ ] **Step 2: Línea base.** En el worktree, ejecutar cada suite segura y guardar rc y recuentos en `scratchpad/baseline.txt`: `run_smoke`, `run_config_menu`, `run_scanners_menu`, `run_wizard`, `run_e2e`, `run_keys`, `run_reports`, `run_ai`, `run_enumeration`, `run_osint`, `run_module_intro`, `run_dependencies`, `run_zap`, `run_evidence`, `run_wireless_maintenance`, `run_postexploitation`, `run_exploitation`, `run_forensics`, `run_tests`. Se esperan los 2 fallos preexistentes de `run_reports` (EXDEV). Cualquier otro rojo en la línea base se anota como preexistente; no se arregla aquí.
- [ ] **Step 3: Escribir tests del conversor** (`unittest`), con estas aserciones:
  - `convert("✅ ok ❌ mal ⚠️ aviso")` → `"✔ ok ✖ mal ⚠ aviso"`
  - `convert("🎯 Objetivo: x")` → `"◎ Objetivo: x"`; `convert("📁 3 archivos | 🛠️ 2 scripts")` → `"▪ 3 archivos | ⚙ 2 scripts"`
  - `convert("🔬 Título", docs=False)` → `"Título"` (emoji sin mapa se elimina con su espacio)
  - `convert("## 🚀 Uso", docs=True)` → `"## Uso"`; `convert("✅ Hecho", docs=True)` → `"✔ Hecho"`
  - Idempotencia: `convert(convert(s)) == convert(s)` para una cadena con todos los emojis del mapa
  - Conservados intactos: `convert("a → b ✓ ✗ ➜ ▶")` devuelve lo mismo
  - `find_emoji("📊 x ✔")` → `["📊"]`; `find_emoji("✔ → ⚠")` → `[]`
  - Fichero CRLF: reescribir un fichero con `\r\n` y comprobar que sigue con `\r\n`; un fichero ejecutable conserva su modo
- [ ] **Step 4: Ejecutar los tests y ver que fallan** (`python3 -I -m unittest test_emoji_to_symbols -v` → ImportError/FAIL).
- [ ] **Step 5: Implementar `emoji_to_symbols.py`** con el mapa de la tabla. Lectura/escritura con `newline=''` y `encoding='utf-8'`, escritura in situ (`open(path,'w')`) para preservar modo; ficheros que no decodifican como UTF-8 se saltan con aviso. Detección de emoji por rangos `U+1F000–1FAFF`, `U+2600–27BF`, `U+2B00–2BFF`, `U+2300–23FF` y `U+FE0F/U+200D`, menos el conjunto de conservados.
- [ ] **Step 6: Ejecutar los tests y ver que pasan.**
- [ ] **Step 7: Sin commit** (el conversor vive fuera del repo).

### Task 2: Menú del gestor y bibliotecas

**Files:**
- Modify: `CyberSecurity-Framework/cyber_framework.sh`, `CyberSecurity-Framework/00_Config/lib/*.bash` (los 12 con emojis)
- Modify: tests que comparan texto del menú: `tests/run_smoke.sh`, `run_e2e.sh`, `run_wizard.sh`, `run_tests.sh`, `run_dependencies.sh`, `test_config_menu.py`, `test_scanners_menu.py`, `test_ai_cli.py`, `test_postexploitation_runtime.py`, `test_enumeration_services.py`, `test_wireless_maintenance.py`, `test_cross_local.py`, `test_osint.py`, `test_report_engine.py`, `automation_menu_inventory.py` (lista a confirmar con `--check`)

**Interfaces:**
- Consumes: CLI de Task 1 (modo código).

- [ ] **Step 1: Previsualizar** con `--dry-run` sobre esos ficheros y revisar que solo tocan texto visible.
- [ ] **Step 2: Test de regresión de aspecto.** Añadir a `tests/run_smoke.sh` una aserción que, tras abrir el menú principal con entrada canalizada, compruebe que la salida no contiene ningún emoji fuera del conjunto conservado (`python3 -I` con el mismo criterio que `find_emoji`, copiado inline). Ejecutarla y ver que falla antes del cambio.
- [ ] **Step 3: Aplicar el conversor** (modo código) a los ficheros del menú, bibliotecas y tests de la lista.
- [ ] **Step 4: Revisar a mano el banner y las columnas** de `cyber_framework.sh:61-110`: ajustar espacios para que el borde `║` y las columnas de `archivos | scripts` queden alineados con símbolos de 1 columna. Es el único retoque manual permitido.
- [ ] **Step 5: Revisar el diff de líneas con `grep|case|\[\[|re\.`** que contuvieran emoji y confirmar que cada comparación sigue casando con el texto nuevo.
- [ ] **Step 6: `bash -n` capturando stderr** sobre `cyber_framework.sh` y `lib/*.bash` (sin avisos), y ejecutar las suites de la línea base afectadas: deben igualar o mejorar `baseline.txt`.
- [ ] **Step 7: Commit** `style(menu): símbolos Unicode simples en lugar de emojis en el gestor y sus bibliotecas`.

### Task 3: Documentación `.md`

**Files:**
- Modify: los ~91 `.md` versionados con emojis (README, `docs/`, specs, planes, README de módulos, `AGENTS.md`)
- Test: suites con comprobaciones documentales (`run_reports.sh`, `run_module_intro.sh`, `run_config_menu.sh`)

**Interfaces:**
- Consumes: CLI de Task 1 con `--docs`.

- [ ] **Step 1: `--dry-run --docs`** sobre todos los `.md` versionados; excluir `docs/superpowers/specs/2026-11-18-iconos-simbolos-design.md` y este plan (contienen la tabla de emojis a propósito, con sus emojis).
- [ ] **Step 2: Aplicar** `--docs`.
- [ ] **Step 3: Releer encabezados y listas** donde el emoji era el único marcador (p. ej. tablas con `✅`/`❌` en celdas): comprobar que siguen entendiéndose; donde un símbolo solo quede ambiguo, reescribir con palabra (OK/Error/Aviso). Citas de salida literal deben coincidir con el texto que imprimen ahora los scripts de Task 2 (los de Task 4 se re-sincronizan allí).
- [ ] **Step 4: `--check`** sobre los `.md` convertidos: salida 0.
- [ ] **Step 5: Ejecutar suites documentales** y comparar con la línea base.
- [ ] **Step 6: Commit** `docs: elimina emojis de la documentación y unifica los marcadores de estado`.

### Task 4: Scripts `.sh`/`.py` fuera del menú (01–05)

**Files:**
- Modify: ficheros versionados con emojis en `CyberSecurity-Framework/{01_OSINT,02_Recon,03_Scanners,04_Enumeration,05_Exploitation}` y sus tests/fixtures
- Test: `run_osint.sh`, `run_scanners_menu.sh`, `run_zap.sh`, `run_enumeration.sh`, `run_exploitation.sh`, `run_tests.sh`

**Interfaces:**
- Consumes: CLI de Task 1 (modo código).

- [ ] **Step 1: `--dry-run`** por carpeta; apartar cualquier script cuya salida sea leída por otro programa (parsers de informes, `phase_status`): revisarlos primero.
- [ ] **Step 2: Aplicar y re-sincronizar** las citas literales en los `.md` ya convertidos que mencionen mensajes de estos scripts.
- [ ] **Step 3: `bash -n`/`py_compile` capturando stderr** y suites del listado: igual o mejor que `baseline.txt`.
- [ ] **Step 4: Commit** `style(01-05): símbolos Unicode simples en los mensajes de los scripts`.

### Task 5: Scripts `.sh`/`.py` restantes (00, 06–13) y revisión final

**Files:**
- Modify: restantes con emojis: `00_Config/scripts`, `06_PostExploitation`…`13_Labs`, `tests/fixtures`
- Test: `run_postexploitation.sh`, `run_wireless_maintenance.sh`, `run_forensics.sh`, `run_evidence.sh`, `run_reports.sh`, `run_reports_evidence.sh`, `run_ai.sh`, `run_keys.sh`, `run_wizard.sh`, `run_dependencies.sh`, `run_module_intro.sh`

**Interfaces:**
- Consumes: CLI de Task 1.

- [ ] **Step 1: Aplicar** como en Task 4; en `11_Reports` y `report_engine.py`, comprobar si el motor emite emojis de severidad (🔴🟡🟢) a los informes: de ser así, el mapa los convierte a `●` y las suites de informes deben seguir verdes con la etiqueta de texto al lado; si no hay etiqueta, añadirla para no perder la distinción de severidad.
- [ ] **Step 2: `--check` global** sobre `git ls-files` (excluidos spec y este plan): salida 0.
- [ ] **Step 3: Verificación completa** — `bash -n` de todos los `.sh`/`.bash` y `py_compile` de todos los `.py` capturando stderr (sin avisos), todas las suites de `baseline.txt` en el worktree con resultado igual o mejor, y `md5sum` de `scope.yaml`/`targets.txt` del checkout principal sin cambios.
- [ ] **Step 4: Commit** `style(00,06-13): símbolos Unicode simples en los mensajes de los scripts`.
- [ ] **Step 5: Revisión final** de todo el diff (`git diff develop...feat/iconos-simbolos --stat` y revisión por un revisor independiente) y registro en `AGENTS.md` de una nota breve del cambio. La integración a `develop` queda a confirmación del usuario.
