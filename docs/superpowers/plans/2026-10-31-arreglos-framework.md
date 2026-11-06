# Arreglo de defectos del framework — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cerrar los ocho defectos que la prueba real destapó en el framework, eliminando los falsos positivos y las salidas silenciosamente incorrectas, cada uno con su test de regresión.

**Architecture:** Se añade una librería `00_Config/lib/scans.bash` con las primitivas de rutas, nombres y línea base; los scripts migrados pasan a usarla en vez de repetir `sed` y `2>/dev/null`. Los tests usan un `curl` falso en `PATH`, así que no hace falta red, servidor ni Python.

**Tech Stack:** Bash, `ffuf`, `curl`, `python3`; suites de shell en `tests/`.

**Spec:** `docs/superpowers/specs/2026-10-31-arreglos-framework-design.md`

## Global Constraints

- Sin `set -e`; los fallos se ocultan con `2>/dev/null` (salvo donde este plan lo prohíbe explícitamente).
- Mensajes al usuario en español.
- Nada de rutas absolutas ni dependencia del `cwd`: rutas desde `${BASH_SOURCE[0]:-$0}`.
- Ficheros `.sh` y `.bash` con LF.
- Las funciones que devuelven valor imprimen **solo** el valor por stdout; la interfaz va a stderr.
- La librería vive en `00_Config/lib/` con extensión `.bash`.
- `tests/run_tests.sh`, `run_e2e.sh`, `run_smoke.sh` y `run_wizard.sh` deben seguir corriendo sin terminal y sin red.

## Review Focus

- **Un servidor que responde `404` a todo** (no catch-all): la línea base debe ser "no hay relleno" y `sql_injection.sh` debe reportar cero. Es el caso que el diseño original no cubría.
- **Dos objetivos distintos, mismo puerto**: los archivos de salida no deben pisarse.
- **`zsh` sourceando la librería**: no debe escribir nada fuera de `00_Config/`.
- **Un escáner que falla al ejecutarse**: debe quedar rastro en `errores.log` y aviso en pantalla, no un falso "0 hallazgos".
- **`--output` con extensión distinta de `.html`**: no debe destruir el HTML.

---

### Task 1: Librería `scans.bash`

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/scans.bash`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (añadir sección al final)

**Interfaces:**
- Consumes: nada.
- Produces:
  - `scans_root()` → stdout `<repo>/scans`
  - `scans_dir <tool>` → stdout `<repo>/scans/<tool>`, crea el directorio; rc 1 si `<tool>` vacío
  - `scans_slug <objetivo>` → stdout objetivo con `:` y `/` sustituidos por `_`
  - `scans_baseline_size <url>` → stdout entero; `0` si la ruta aleatoria no devuelve relleno
  - `scans_signature <url>` → stdout `"<código>:<tamaño>"`

- [ ] **Step 1: Write the failing tests**

Añadir a `tests/run_tests.sh`, tras las secciones existentes. El stub de `curl` se crea una vez al principio de la sección:

```bash
section "scans.bash: rutas, nombres y línea base"
source "$FW/00_Config/lib/scans.bash"

STUBD="$(mktemp -d)"
cat > "$STUBD/curl" <<'EOS'
#!/bin/bash
echo "${STUB_CODE:-200}:${STUB_SIZE:-433}"
EOS
chmod +x "$STUBD/curl"

eq "scans_root termina en /scans" "$(basename "$(scans_root)")" "scans"
eq "scans_slug limpia : y /"      "$(scans_slug 'https://a.b:443/x')" "https___a.b_443_x"
scans_dir pruebatool >/dev/null
eq "scans_dir devuelve <scans>/pruebatool" "$(basename "$(scans_dir pruebatool)")" "pruebatool"
[ -d "$(scans_dir pruebatool)" ] && ok "scans_dir deja el directorio en disco" || bad "scans_dir no creó el directorio"

PATH="$STUBD:$PATH"
STUB_CODE=200 STUB_SIZE=433
eq "baseline con catch-all"        "$(scans_baseline_size https://x/)" "433"
STUB_CODE=404 STUB_SIZE=0
eq "baseline sin catch-all"        "$(scans_baseline_size https://x/)" "0"
STUB_CODE=200 STUB_SIZE=433
eq "signature devuelve código:tamaño" "$(scans_signature https://x/)" "200:433"
rm -rf "$STUBD" "$FW/../scans/pruebatool"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd CyberSecurity-Framework && bash tests/run_tests.sh 2>&1 | tail -15`
Expected: errores de `command not found` para `scans_root` y contadores `FALLO` en la nueva sección.

- [ ] **Step 3: Implement `00_Config/lib/scans.bash`**

Resolver la raíz como los demás archivos de la librería (`${BASH_SOURCE[0]:-$0}`, cinco niveles hasta la raíz del repo: `lib` → `00_Config` → framework → repo). `scans_baseline_size` pide `<url>/<token aleatorio>` y devuelve el tamaño solo si el código es `2xx` o `3xx`; en cualquier otro caso `0`. Toda la interfaz a stderr.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd CyberSecurity-Framework && bash tests/run_tests.sh 2>&1 | tail -15`
Expected: `pasan: 68  fallan: 0` (61 previos + 7 nuevos).

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/scans.bash CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(lib): add scans.bash with path, slug and baseline primitives"
```

---

### Task 2: Portabilidad de la librería bajo zsh

**Files:**
- Modify: `00_Config/lib/session.bash:7`, `params.bash:8`, `phase_status.bash:8`, `prompt.bash:14`
- Test: `tests/run_tests.sh`

**Interfaces:**
- Consumes: nada.
- Produces: los cinco archivos de `00_Config/lib/` resuelven su directorio sin `BASH_SOURCE`.

- [ ] **Step 1: Write the failing test**

```bash
section "Librería: portable bajo zsh"
if command -v zsh >/dev/null 2>&1; then
    for libf in session params phase_status prompt scans; do
        out=$(zsh -c "cd '$FW' && source '00_Config/lib/$libf.bash' 2>/dev/null; echo \$PWD" 2>&1)
        case "$out" in
            *"$FW"*) ok "zsh: $libf.bash no escribe fuera de 00_Config" ;;
            *) bad "zsh: $libf.bash resolvió mal la ruta" "$out" ;;
        esac
    done
else
    echo "  SKIP     zsh no instalado"
fi
```

Además, un test de no-regresión del síntoma real: tras sourcear desde `zsh`, no debe existir `<repo>/.session`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd CyberSecurity-Framework && bash tests/run_tests.sh 2>&1 | grep -A6 "portable bajo zsh"`
Expected: `FALLO` en al menos `session.bash` (hoy escribe `.session` en la raíz del repo).

- [ ] **Step 3: Apply the idiom to the four remaining files**

Sustituir `$(dirname "${BASH_SOURCE[0]}")` por `$(dirname "${BASH_SOURCE[0]:-$0}")` en los cuatro archivos. No tocar nada más.

- [ ] **Step 4: Run tests**

Run: `cd CyberSecurity-Framework && bash tests/run_tests.sh 2>&1 | tail -5`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/*.bash CyberSecurity-Framework/tests/run_tests.sh
git commit -m "fix(lib): resolve library paths without BASH_SOURCE so zsh does not misfile state"
```

---

### Task 3: `run_all_recon.sh` acepta objetivo

**Files:**
- Modify: `02_Recon/run_all_recon.sh:1-10`, `cyber_framework.sh:446-450` (comentario)
- Test: `tests/run_tests.sh`

**Interfaces:**
- Consumes: nada.
- Produces: `run_all_recon.sh [objetivo]` — con argumento escanea solo ese objetivo; sin argumento, las tres primeras líneas de `targets.txt`.

- [ ] **Step 1: Write the failing test**

Crear un `targets.txt` de fixture en `$TMPD` con `192.168.1.10` y lanzar el script con `192.0.2.99`; el stub de `nmap` en `PATH` escribe sus argumentos en un archivo. Asserts:

```bash
eq "run_all_recon: usa el objetivo recibido" "$(grep -c '192.0.2.99' "$TMPD/nmap_args")" "1"
eq "run_all_recon: no usa targets.txt"        "$(grep -c '192.168.1.10' "$TMPD/nmap_args")" "0"
```

Además, `eq "run_all_recon: tiene línea Uso" "$(params_mode "$FW/02_Recon/run_all_recon.sh")" "slots"`.

- [ ] **Step 2: Run test to verify it fails**

Expected: `FALLO` en los tres asserts (hoy no acepta argumento y `params_mode` devuelve `none`).

- [ ] **Step 3: Implement**

`TARGET="${1:-}"`; si viene, `TARGETS="$TARGET"`; si no, el `head -3` actual. Añadir cabecera con `Uso: ./run_all_recon.sh [objetivo]` y `Ejemplo: ./run_all_recon.sh 192.168.1.10`. Actualizar el comentario de `cyber_framework.sh` que hoy justifica usar `auto_recon.sh` para decir que `run_all_recon.sh` ya acepta objetivo pero la fase mantiene `auto_recon.sh` por decisión de alcance.

- [ ] **Step 4: Run tests**

Run: `cd CyberSecurity-Framework && bash tests/run_tests.sh 2>&1 | tail -5` y `bash tests/run_smoke.sh 2>&1 | tail -3`
Expected: sin fallos.

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(recon): run_all_recon accepts a target instead of scanning the first three lines of targets.txt"
```

---

### Task 4: Nombres de salida con el objetivo en web

**Files:**
- Modify: `04_Enumeration/web/enum_web.sh:29-62`, `04_Enumeration/web/enum_web_advanced.sh`, `04_Enumeration/web/deepseeenum_web.sh` (heredoc, en paralelo)
- Test: `tests/run_tests.sh`

**Interfaces:**
- Consumes: `scans_dir`, `scans_slug`, `scans_baseline_size` (Task 1).
- Produces: `enum_web.sh <IP> [PUERTO]` escribe `headers_<slug>_<puerto>.txt`, `technologies_<slug>_<puerto>.txt`, `robots_<slug>_<puerto>.txt`, `sitemap_<slug>_<puerto>.xml`, `ffuf_<slug>_<puerto>.json`.

- [ ] **Step 1: Write the failing test**

Con `curl` y `ffuf` falseados en `PATH`, ejecutar dos veces seguidas (`192.0.2.1` y `192.0.2.2`, puerto 443) contra el mismo `OUTPUT_DIR` temporal. Asserts:

```bash
eq "enum_web: no pisa la salida de otro objetivo" "$(ls "$TMPD/web" | grep -c 'headers_')" "2"
eq "enum_web: el nombre lleva el objetivo"        "$(ls "$TMPD/web" | grep -c 'headers_192.0.2.1_443')" "1"
eq "enum_web: ffuf filtra por tamaño base"        "$(grep -c -- '-fs 433' "$TMPD/ffuf_args")" "1"
```

- [ ] **Step 2: Run test to verify it fails**

Expected: el primer assert da `1` (se pisan) y el tercero `0` (no hay `-fs`).

- [ ] **Step 3: Implement**

Sustituir el cálculo de `SCANS_DIR`/`OUTPUT_DIR` por `scans_dir web`, y cada nombre por `..._[$(scans_slug "$TARGET")]_${PORT}....`. Añadir `-fs "$(scans_baseline_size "$URL")"` a `ffuf`, omitiendo la bandera si la base es `0`. Aplicar los mismos nombres en `enum_web_advanced.sh`. Replicar el script resultante íntegro dentro del heredoc de `deepseeenum_web.sh` para que regenerar no revierta el arreglo.

- [ ] **Step 4: Run tests**

Run: `bash tests/run_tests.sh 2>&1 | tail -5`
Expected: sin fallos.

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(enum): include target in web output names and filter ffuf by baseline size"
```

---

### Task 5: Nombres de salida en escáneres

**Files:**
- Modify: `03_Scanners/network_scanners/nmap/nmap_smart.sh`, `03_Scanners/web_scanners/nikto/nikto_scan.sh:31`, `nuclei/nuclei_scan.sh:31-35`, `nuclei/nuclei_cves.sh`
- Test: `tests/run_tests.sh`

**Interfaces:**
- Consumes: `scans_dir`, `scans_slug` (Task 1).
- Produces: mismos nombres de archivo que hoy en los escáneres web (`nuclei_https___host.txt`), y en `nmap_smart.sh` el archivo pasa de `smart_ports.nmap` a `smart_ports_<slug>.nmap`.

- [ ] **Step 1: Write the failing test**

```bash
eq "nmap_smart: el nombre lleva el objetivo" "$(ls "$TMPD/nmap" | grep -c 'smart_ports_192.0.2.1')" "1"
eq "nuclei: el nombre no cambia"             "$(ls "$TMPD/nuclei" | grep -c 'nuclei_https___192.0.2.1')" "1"
```

- [ ] **Step 2: Run test to verify it fails**

Expected: el primero da `0`.

- [ ] **Step 3: Implement**

`nmap_smart.sh` usa `scans_dir nmap` y `smart_ports_$(scans_slug "$TARGET").nmap`. Los tres escáneres web sustituyen el `${URL//[:\/]/_}` inline por `scans_slug "$URL"`; el nombre resultante debe quedar idéntico.

- [ ] **Step 4: Run tests**

Expected: sin fallos, y ninguna diferencia de nombre en los escáneres web (lo comprueba el segundo assert).

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(scanners): name output files with the target slug"
```

---

### Task 6: `sql_injection.sh` sin falsos positivos

**Files:**
- Modify: `05_Exploitation/web/sql_injection.sh:28-55`
- Test: `tests/run_tests.sh`

**Interfaces:**
- Consumes: `scans_dir`, `scans_signature` (Task 1).
- Produces: `sqli_findings.txt` solo con diferencias reales respecto a la firma benigna.

- [ ] **Step 1: Write the failing tests**

Dos escenarios con `curl` falseado:

```bash
# catch-all: toda respuesta idéntica
eq "sqli: catch-all no genera hallazgos" "$(wc -l < "$TMPD/web/sqli_findings.txt")" "0"
# servidor normal que cambia de tamaño solo con payload
eq "sqli: detecta la diferencia real"     "$(wc -l < "$TMPD/web2/sqli_findings.txt")" "1"
```

El segundo stub devuelve tamaño distinto cuando la URL contiene `%27`.

- [ ] **Step 2: Run test to verify it fails**

Expected: el primero da `90` (los falsos positivos actuales).

- [ ] **Step 3: Implement**

Por cada parámetro, calcular `base=$(scans_signature "$URL?$param=1")` una sola vez; para cada payload, `sig=$(scans_signature "$URL_TEST")`; reportar solo si `"$sig" != "$base"`. No reportar nada si el sitio tiene catch-all (todas las firmas iguales a la base del parámetro). Mantener el bloque de `sqlmap` sin cambios.

- [ ] **Step 4: Run tests**

Expected: `0` y `1`.

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(exploit): sql_injection reports only responses that differ from a benign baseline"
```

---

### Task 7: `stderr` visible en los escáneres

**Files:**
- Modify: los 8 escáneres hoja de `03_Scanners/` (`masscan_scan.sh`, `nmap_aggressive.sh`, `nmap_scripts.sh`, `nmap_smart.sh`, `rustscan_scan.sh`, `nikto_scan.sh`, `nuclei_scan.sh`, `nuclei_cves.sh`) y `03_Scanners/run_all_scanners.sh`
- Test: `tests/run_tests.sh`

**Interfaces:**
- Consumes: `scans_dir` (Task 1).
- Produces: cada escáner escribe `errores.log` en su `OUTPUT_DIR` y anuncia la ruta; `run_all_scanners.sh` resume qué logs quedaron con contenido.

- [ ] **Step 1: Write the failing test**

Con un `nmap` falso que escribe en `stderr` y sale con código 1:

```bash
eq "scanner: el error queda en el log" "$([ -s "$TMPD/nmap/errores.log" ] && echo si)" "si"
eq "scanner: avisa del log con contenido" "$(grep -c 'errores.log' "$TMPD/salida")" "1"
```

- [ ] **Step 2: Run test to verify it fails**

Expected: el primero vacío (hoy se descarta con `2>/dev/null`).

- [ ] **Step 3: Implement**

Sustituir `2>/dev/null` por `2>>"$OUTPUT_DIR/errores.log"` en los 8 escáneres (no en los `command -v`, que deben seguir silenciosos). Al final de cada uno, si el log no está vacío, imprimir `⚠️  Errores registrados en: <ruta>`. `run_all_scanners.sh` recorre los logs y lista los no vacíos.

- [ ] **Step 4: Run tests**

Run: `bash tests/run_tests.sh 2>&1 | tail -5` y `bash tests/run_smoke.sh 2>&1 | tail -3`
Expected: sin fallos.

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(scanners): log stderr to errores.log and announce it instead of discarding it"
```

---

### Task 8: `report_generator.py` deja de pisar el HTML

**Files:**
- Modify: `09_Automation/python/report_generator.py:305`
- Test: ejecución manual verificable (sin suite)

**Interfaces:**
- Consumes: nada.
- Produces: la ruta del JSON deja de depender de que `--output` termine en `.html`.

- [ ] **Step 1: Reproduce the bug**

Run: `python3 09_Automation/python/report_generator.py --input ../../scans --output /tmp/x.md`
Expected: `Reporte HTML generado: /tmp/x.md` y `Reporte JSON generado: /tmp/x.md`; sólo existe un archivo.

- [ ] **Step 2: Implement**

Sustituir `self.output_file.replace('.html', '.json')` por `os.path.splitext(self.output_file)[0] + ".json"` (importar `os` si falta).

- [ ] **Step 3: Verify**

Run: `python3 ... --output /tmp/y.md && ls /tmp/y.*`
Expected: `/tmp/y.md` y `/tmp/y.json`, ambos con contenido.

- [ ] **Step 4: Commit**

```bash
git commit -am "fix(reports): derive the JSON path with splitext so it cannot overwrite the HTML"
```

---

### Task 9: `report_generator.sh` honesto

**Files:**
- Modify: `11_Reports/report_generator.sh` (cabecera del informe y salida por pantalla)
- Test: `tests/run_smoke.sh` (assert simple)

**Interfaces:**
- Consumes: nada.
- Produces: el informe generado declara que es plantilla.

- [ ] **Step 1: Write the failing test**

```bash
printf '11\n2\n--executive\n\nQ\n' | bash ./cyber_framework.sh >/dev/null 2>&1
grep -q "PLANTILLA" 11_Reports/executive/executive_summary.md && ok "el informe se declara plantilla" || bad "el informe no se declara plantilla"
```

- [ ] **Step 2: Run test to verify it fails**

Expected: `FALLO`.

- [ ] **Step 3: Implement**

Añadir al principio de cada informe generado una línea `> ⚠️ PLANTILLA: no consume los resultados de \`scans/\`; rellenar a mano.` y un aviso equivalente por pantalla al terminar.

- [ ] **Step 4: Run test to verify it passes**

Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git commit -am "fix(reports): label generated reports as templates instead of implying they are automatic"
```

---

### Task 10: Informes generados fuera del índice

**Files:**
- Modify: `.gitignore`
- Remove from index: `11_Reports/executive/executive_summary.md`, `11_Reports/technical/technical_report.md`

**Interfaces:**
- Consumes: nada.
- Produces: el generador ya no ensucia el árbol de trabajo.

- [ ] **Step 1: Write the failing test**

```bash
git ls-files --error-unmatch CyberSecurity-Framework/11_Reports/executive/executive_summary.md >/dev/null 2>&1 \
  && bad "el informe sigue versionado" || ok "el informe no está versionado"
```

- [ ] **Step 2: Run test to verify it fails**

Expected: `FALLO` (hoy está versionado).

- [ ] **Step 3: Implement**

Añadir a `.gitignore`, junto a las reglas de `11_Reports`:

```
CyberSecurity-Framework/11_Reports/executive/*.md
CyberSecurity-Framework/11_Reports/technical/*.md
```

y ejecutar `git rm --cached` sobre los dos archivos (permanecen en disco; las plantillas reales están en `templates/`).

- [ ] **Step 4: Verify**

Run: `bash ./11_Reports/report_generator.sh --full && git status --porcelain -- CyberSecurity-Framework/11_Reports/`
Expected: sin líneas de salida.

- [ ] **Step 5: Commit**

```bash
git add .gitignore && git commit -m "chore(reports): untrack generated executive and technical reports"
```

---

### Task 11: Documentación y verificación final

**Files:**
- Modify: `AGENTS.md` (convención de nombres), `docs/` (nota de la sesión)

**Interfaces:**
- Consumes: todo lo anterior.
- Produces: la convención queda escrita para el próximo script.

- [ ] **Step 1: Document the convention**

En `AGENTS.md`, sección «Writing new scripts»: los nombres de salida incluyen `scans_slug` del objetivo; `stderr` va a `errores.log`, no a `/dev/null`; la línea base se calcula con `scans.bash`.

- [ ] **Step 2: Full verification**

```bash
cd CyberSecurity-Framework
for f in $(find . -name '*.sh'); do bash -n "$f" 2>>/tmp/syntax.err || echo "FALLO $f"; done; wc -l /tmp/syntax.err
bash tests/run_tests.sh 2>&1 | tail -3
bash tests/run_e2e.sh 2>&1 | tail -3
bash tests/run_smoke.sh 2>&1 | tail -3
bash tests/run_wizard.sh 2>&1 | tail -3
python3 -m py_compile 09_Automation/python/report_generator.py && echo "py OK"
```

Expected: `/tmp/syntax.err` vacío, `fallan: 0` en todas, `py OK`.

- [ ] **Step 3: Repeat the real-world cases**

Run `enum_web.sh` y `sql_injection.sh` contra un catch-all local: ambos deben reportar `0`.

- [ ] **Step 4: Commit**

```bash
git commit -am "docs: record output naming and stderr conventions"
```
