# OWASP ZAP como escáner automatizado (03_Scanners) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a real, automated OWASP ZAP scan (spider + passive, never Active Scan) to `03_Scanners`: a menu entry under "Analizar una URL", and chained into `run_all_scanners.sh`'s web-port loop alongside Nikto/Nuclei.

**Architecture:** A bash wrapper (`zap_scan.sh`, same header/`scanner_runtime.bash` shape as `nikto_scan.sh`/`nuclei_scan.sh`) owns the ZAP daemon's entire lifecycle (free port, isolated profile dir, start, wait-ready, `trap`-guarded shutdown) and shells out to a Python driver (`zap_driver.py`, same role as `report_engine.py`/`forensics_evidence.py`) that talks to the daemon's JSON API via the already-installed `python3-zapv2` client to run spider+passive and write the report. A shared test fixture (`zap_fake_api.py`) stands in for the real daemon everywhere, including a full wrapper-level end-to-end test, since `zaproxy` itself cannot be exercised in this environment.

**Tech Stack:** Bash (wrapper, menu, orchestrator chaining) + Python 3 / `python3-zapv2` (driver) + Python's `http.server` (test fixture only).

**Spec:** `docs/superpowers/specs/2026-11-17-zap-scanner-design.md` — read it in full; this plan does not repeat its rationale, only the values and interfaces it pins.

## Global Constraints

- Only `spider` (crawl) + `pscan` (passive) via ZAP's JSON API. Never `ascan` (Active Scan/injection) or `ajaxSpider`.
- Never a fixed ZAP port: always kernel-assigned (`bind(('127.0.0.1', 0))`), same technique as `tests/fixtures/http_target.py`.
- ZAP never writes to the real `$HOME`: each run gets its own temp profile dir via `-dir`, removed by the same cleanup that stops the daemon.
- Daemon shutdown is two-stage: `core.shutdown()` (API) first, then `SIGTERM`, then `SIGKILL` if still alive — via a `trap` on EXIT/INT/TERM. This is *best-effort* (does not survive `SIGKILL` of the wrapper itself or a dead parent) — documented, not a stronger guarantee.
- A wall-clock budget (`ZAP_MAX_SEG`, default 300) is shared across spider+passive; on expiry the scan is cut (`spider.stop()`), the report says so explicitly, and the script exits 1 — never a silent partial report presented as complete.
- `zap_scan.sh`/`zap_driver.py` never enter `dangerous.txt` (same class as `nikto_scan.sh`/`nuclei_scan.sh`, neither of which is there).
- No `set -e` anywhere; every failure path prints an explicit message, matching the rest of `03_Scanners`.
- Nothing here touches `00_Config/lib/consent/*` (the separate, unapproved "stable_cli.py" initiative).
- `zaproxy` itself is not installed in this environment (and is multi-hundred-MB); every test must run against `tests/fixtures/zap_fake_api.py`, never a real daemon.

## Review Focus

- **A target with 0 alerts must say "SIN HALLAZGOS" explicitly, not an empty report** — a reasonable person checking a clean scan expects confirmation it ran, not silence indistinguishable from a crash. Covered in Task 2.
- **A spider or passive scan that doesn't finish inside `ZAP_MAX_SEG` must exit 1 and mark the report as partial, never report success with incomplete data** — same principle `rate_limit_probe.sh`'s hard cap already established in this codebase; silent truncation is the exact bug class `AGENTS.md` records fixing elsewhere. Covered in Task 2.
- **A connection that never reaches the daemon (closed port, wrong host) must exit 1 without fabricating a report body** — a reasonable person must be able to tell "ZAP never answered" from "ZAP answered zero findings". Covered in Task 2.
- **An interrupted run (SIGINT mid-scan) must still kill the daemon and remove its temp profile directory, not leave a JVM and a directory behind** — the anti-goal the spec states explicitly; a reasonable person killing a stuck scan expects a clean machine afterward. Covered in Task 3.
- **The wrapper's own path/argument wiring (port, output dir, slug, URL) must be proven correct end-to-end, not only inside the Python driver in isolation** — the exact bug class (outputs depending on the caller's wiring) `AGENTS.md`'s 2026-10-31 session already hit nine times in this codebase; a driver that's individually correct is not evidence the wrapper calls it with the right arguments. Covered in Task 3.

---

## File Structure

- **Create** `tests/fixtures/zap_fake_api.py` — minimal `http.server`-based stand-in for ZAP's JSON API, configurable via env vars, reused by Task 2's driver tests and Task 3's wrapper end-to-end test.
- **Create** `00_Config/lib/zap/zap_driver.py` — talks to a running ZAP API (real or fake) via `python3-zapv2`: spider, wait for passive, write the report.
- **Create** `03_Scanners/web_scanners/zap/zap_scan.sh` — owns the daemon's lifecycle; calls the driver.
- **Create** `tests/run_zap.sh` — the suite for both of the above (built across Tasks 1–3).
- **Modify** `00_Config/lib/scanners_menu.bash` — `scanners_check_tools`'s tool list, and option 3's web-tool sub-menu.
- **Modify** `03_Scanners/run_all_scanners.sh` — one more `run_child` per discovered web port.
- **Modify** `tests/run_tests.sh` — one new assertion for the `run_all_scanners.sh` change (Task 5), reusing its existing `$RSTUB` stub pattern.
- **Modify** `tests/run_scanners_menu.sh` — the new third web-tool entry.
- **Create** `docs/ZAP-2026-11-17.md` — short user-facing doc, same role as `docs/DEPENDENCIAS-2026-11-17.md`.

---

### Task 1: `zap_fake_api.py` — fake ZAP JSON API fixture

**Files:**
- Create: `tests/fixtures/zap_fake_api.py`
- Test: `tests/run_zap.sh` (created here)

**Interfaces:**
- Produces: a standalone process, `python3 zap_fake_api.py <PUERTO> [FICHERO_READY]` (port `0` = kernel-assigned; with `FICHERO_READY`, writes `<pid> <puerto>\n` to it once bound and listening — identical contract to `tests/fixtures/http_target.py`, so tests resolve the real port the same way). Serves these paths (the `/JSON/...` suffix of ZAP's real API; the fixture must parse `self.path` with `urllib.parse.urlsplit` and match on `.path`, because `python3-zapv2` sends requests through a proxy, so the request line may carry the absolute form `http://zap/JSON/...` rather than a bare path):
  - `GET /JSON/core/view/version/` → `{"version": "fake"}`, always, immediately (readiness probe).
  - `GET /JSON/spider/action/scan/` (any `url`/`apikey` params) → `{"scan": "0"}`.
  - `GET /JSON/spider/view/status/` → one value from `ZAP_FAKE_SPIDER_STATUSES` (comma-separated ints, env var, default `"100"`) per call, advancing one step each call and holding on the last value once exhausted — response `{"status": "<value>"}`.
  - `GET /JSON/spider/action/stop/` → `{"Result": "OK"}`.
  - `GET /JSON/pscan/view/recordsToScan/` → same step/hold behavior over `ZAP_FAKE_PSCAN_COUNTS` (default `"0"`) — response `{"recordsToScan": "<value>"}`.
  - `GET /JSON/core/view/alerts/` → `{"alerts": <contents of the JSON file named by env var ZAP_FAKE_ALERTS_FILE, or [] if unset>}`.
  - `GET /JSON/core/action/shutdown/` → always responds `{"Result": "OK"}` first; then, unless env var `ZAP_FAKE_IGNORE_SHUTDOWN=1`, stops serving (e.g. call `self.server.shutdown()` from a short-lived thread, since calling it from the handler thread itself would deadlock `serve_forever()`).
  - Anything else → HTTP 404.

- [ ] **Step 1: Write `tests/fixtures/zap_fake_api.py`**

Base it directly on `tests/fixtures/http_target.py`'s structure (`ThreadingHTTPServer`, the same port-0 + ready-file bind/listen/write-ready sequence, the same `os.umask`-free simplicity — this fixture has no secrets to protect). Keep per-endpoint state (step counters for spider/pscan) as module-level globals, read once at startup from the env vars above; the step/hold algorithm is: each call to that endpoint consumes the next item of its list, or repeats the last item forever once the list is exhausted.

- [ ] **Step 2: Write `tests/run_zap.sh` with the harness header and fixture-only assertions**

```bash
#!/bin/bash
# Pruebas de ZAP — aisladas, nunca contra un daemon zaproxy real.
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAKE_API="$FW/tests/fixtures/zap_fake_api.py"
pasan=0; fallan=0
ok()  { echo "  ok   $1"; pasan=$((pasan+1)); }
ko()  { echo "  FALLO $1"; fallan=$((fallan+1)); }
eq()  { [[ "$2" == "$3" ]] && ok "$1" || ko "$1 (esperado '$3', obtenido '$2')"; }

echo "=== zap_fake_api.py ==="
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
READY="$TMPD/ready"
python3 "$FAKE_API" 0 "$READY" & FAKEPID=$!
for _ in $(seq 1 50); do [[ -s "$READY" ]] && break; sleep 0.05; done
read -r RPID RPORT < "$READY"
eq "fixture: version responde" \
    "$(curl -s "http://127.0.0.1:$RPORT/JSON/core/view/version/" | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])')" "fake"

eq "fixture: spider/status avanza y se queda en el último valor" \
    "$(for i in 1 2 3; do curl -s "http://127.0.0.1:$RPORT/JSON/spider/view/status/" | python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])'; done | tr '\n' ',')" \
    "100,100,100,"

ZAP_FAKE_SPIDER_STATUSES=0,50,100 READY2="$TMPD/ready2"
python3 "$FAKE_API" 0 "$READY2" & FAKEPID2=$!
# (repetir el patrón anterior con ZAP_FAKE_SPIDER_STATUSES=0,50,100 exportada
#  antes del arranque, comprobando la secuencia real 0,50,100,100)
kill "$FAKEPID2" 2>/dev/null; wait "$FAKEPID2" 2>/dev/null

curl -s "http://127.0.0.1:$RPORT/JSON/core/action/shutdown/" >/dev/null
sleep 0.2
curl -s --max-time 1 "http://127.0.0.1:$RPORT/JSON/core/view/version/" >/dev/null 2>&1
eq "fixture: tras shutdown deja de responder" "$?" "7"
wait "$FAKEPID" 2>/dev/null

echo ""; echo "Resultado: $pasan ok, $fallan fallos"
[[ $fallan -eq 0 ]]
```

(Fill in the `ZAP_FAKE_SPIDER_STATUSES=0,50,100` sequence assertion the same way as the first one, asserting the real sequence `0,50,100,100`; export the env var in the subshell that starts that second fixture instance so it doesn't affect the first one, which is still using the default.)

- [ ] **Step 3: Run it**

Run: `chmod +x tests/run_zap.sh && bash tests/run_zap.sh`
Expected: all `ok`, `0 fallos`, exit 0. (This is the first real run of the fixture; if a step fails, fix the fixture — there is no earlier "passing" state to compare against, so read the actual HTTP response bodies on failure.)

- [ ] **Step 4: Commit**

```bash
git add tests/fixtures/zap_fake_api.py tests/run_zap.sh
git commit -m "test(zap): fixture HTTP que imita la API JSON de ZAP"
```

---

### Task 2: `zap_driver.py` — spider + passive + report, against the fixture

**Files:**
- Create: `00_Config/lib/zap/zap_driver.py`
- Test: `tests/run_zap.sh`

**Interfaces:**
- Consumes: `tests/fixtures/zap_fake_api.py` from Task 1 (as a subprocess target, never imported).
- Produces: a CLI, `zap_driver.py --host HOST --port PUERTO --url URL --salida FICHERO [--max-seg SEGUNDOS]` (default `--max-seg 300`). Exit `0` if spider and passive both completed inside the budget (regardless of alert count); exit `1` on any API/connection error or on timeout (report is still written, marked partial). Internal functions other tasks don't call directly, but name for clarity: `conectar(host, port) -> ZAPv2`, `correr_spider(zap, url, limite) -> (completo: bool, parcial_pct: str)`, `esperar_pasivo(zap, limite) -> completo: bool`, `escribir_informe(path, url, spider_completo, spider_pct, pasivo_completo, alerts)`.

- [ ] **Step 1: Write the failing tests in `tests/run_zap.sh`**

```bash
echo "=== zap_driver.py ==="
DRIVER="$FW/00_Config/lib/zap/zap_driver.py"
start_fake() { # $1 =var de statuses spider, $2 = var de counts pscan, $3 = alerts json o vacío, $4 = ignore-shutdown 0/1
    local ready="$TMPD/ready_$RANDOM"
    ZAP_FAKE_SPIDER_STATUSES="$1" ZAP_FAKE_PSCAN_COUNTS="$2" ZAP_FAKE_ALERTS_FILE="$3" \
    ZAP_FAKE_IGNORE_SHUTDOWN="$4" python3 "$FAKE_API" 0 "$ready" & echo $!
    for _ in $(seq 1 50); do [[ -s "$ready" ]] && break; sleep 0.05; done
    read -r _ _PUERTO < "$ready"; printf '%s' "$_PUERTO" > "$TMPD/last_port"
}

PID=$(start_fake "100" "0" "" "0"); PUERTO=$(cat "$TMPD/last_port")
OUT="$TMPD/informe_vacio.txt"
python3 "$DRIVER" --host 127.0.0.1 --port "$PUERTO" --url http://obj.test/ --salida "$OUT" --max-seg 10
eq "driver: sin hallazgos sale 0" "$?" "0"
eq "driver: sin hallazgos lo dice" "$(grep -c 'SIN HALLAZGOS' "$OUT")" "1"
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

printf '[{"name":"X-Frame-Options ausente","risk":"Medium","confidence":"High","url":"http://obj.test/"}]' > "$TMPD/alertas.json"
PID=$(start_fake "100" "0" "$TMPD/alertas.json" "0"); PUERTO=$(cat "$TMPD/last_port")
OUT="$TMPD/informe_hallazgo.txt"
python3 "$DRIVER" --host 127.0.0.1 --port "$PUERTO" --url http://obj.test/ --salida "$OUT" --max-seg 10
eq "driver: con hallazgo sale 0" "$?" "0"
eq "driver: con hallazgo lo cuenta" "$(grep -c '1 hallazgo' "$OUT")" "1"
eq "driver: nombra el hallazgo" "$(grep -c 'X-Frame-Options ausente' "$OUT")" "1"
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

PID=$(start_fake "0,0,0,0,0,0,0,0,0,0" "0" "" "0"); PUERTO=$(cat "$TMPD/last_port")
OUT="$TMPD/informe_corto.txt"
python3 "$DRIVER" --host 127.0.0.1 --port "$PUERTO" --url http://obj.test/ --salida "$OUT" --max-seg 1
eq "driver: spider sin terminar sale 1" "$?" "1"
eq "driver: lo marca parcial" "$(grep -ci 'parcial' "$OUT")" "1"
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

PUERTO_CERRADO=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
OUT="$TMPD/informe_sin_conexion.txt"
python3 "$DRIVER" --host 127.0.0.1 --port "$PUERTO_CERRADO" --url http://obj.test/ --salida "$OUT" --max-seg 5
eq "driver: sin conexión sale 1" "$?" "1"
eq "driver: sin conexión no inventa hallazgos" "$(grep -ci 'hallazgo' "$OUT" 2>/dev/null)" "0"
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_zap.sh`
Expected: FAIL on all five new assertions (`zap_driver.py: no existe el fichero`, or Python `ModuleNotFoundError`/`FileNotFoundError`).

- [ ] **Step 3: Implement `00_Config/lib/zap/zap_driver.py`**

`argparse` for the four required flags plus `--max-seg` (default `300`). `conectar` builds `zapv2.ZAPv2(proxies={'http': f'http://{host}:{port}', 'https': f'http://{host}:{port}'})`. `correr_spider` calls `zap.spider.scan(url=url)`, then polls `zap.spider.status(scanid)` every ~0.5s; each loop checks `time.monotonic()` against the deadline computed from `--max-seg`; on reaching `"100"` returns `(True, "100")`; on deadline, calls `zap.spider.stop(scanid)` and returns `(False, last_status)`. `esperar_pasivo` only runs if the spider completed (`correr_spider`'s `completo`); polls `zap.pscan.records_to_scan` the same way against the *same original deadline* (not a fresh budget), returns `True`/`False`. `escribir_informe` always runs, even on spider failure, using whatever alerts could be fetched (skip `core.alerts` entirely if the spider never completed — there's nothing passive-scanned yet) — write: a header line with the URL, a `Spider: completo` / `Spider: parcial (<pct>%)` line, a `Pasivo: completo` / `Pasivo: parcial` line (omitted if spider never completed), a blank line, then `SIN HALLAZGOS` or `N hallazgo(s)` plus one line per alert (`risk | confidence | name | url`). Catch `requests.exceptions.RequestException` (connection refused, etc.) around the whole spider+passive block; on that exception, write a report saying the connection failed and return exit code `1` without calling `core.alerts`.

- [ ] **Step 4: Run to verify it passes**

Run: `bash tests/run_zap.sh`
Expected: all pass, `0 fallos`.

- [ ] **Step 5: Commit**

```bash
git add 00_Config/lib/zap/zap_driver.py tests/run_zap.sh
git commit -m "feat(scanners): driver ZAP — spider, pasivo e informe contra la API"
```

---

### Task 3: `zap_scan.sh` — daemon lifecycle, wrapper, end-to-end against the fixture

**Files:**
- Create: `03_Scanners/web_scanners/zap/zap_scan.sh`
- Test: `tests/run_zap.sh`

**Interfaces:**
- Consumes: `00_Config/lib/scanner_runtime.bash` (`scanner_url`, `scanner_require`, `scans_dir`, `scans_slug`, `scanner_run`), `00_Config/lib/zap/zap_driver.py` from Task 2.
- Produces: `./zap_scan.sh <URL>`, same exit-code/output shape as `nuclei_scan.sh` (0 success, 1 any failure; prints `✔ Ejecución completada.` and `Resultados: <path>` on success).

- [ ] **Step 1: Write the failing end-to-end test in `tests/run_zap.sh`** — a fake `zaproxy` binary that, given `-port N ... -dir DIR`, execs the Task 1 fixture bound to exactly `N`:

```bash
echo "=== zap_scan.sh ==="
STUBDIR="$(mktemp -d)"
cat > "$STUBDIR/zaproxy" <<EOF
#!/bin/bash
puerto=""
for ((i=1; i<=\$#; i++)); do [[ "\${!i}" == -port ]] && { j=\$((i+1)); puerto="\${!j}"; }; done
exec python3 "$FAKE_API" "\$puerto"
EOF
chmod +x "$STUBDIR/zaproxy"

URL_PRUEBA="http://obj.test/"
OUT=$(PATH="$STUBDIR:$PATH" bash "$FW/03_Scanners/web_scanners/zap/zap_scan.sh" "$URL_PRUEBA" 2>&1); RC=$?
eq "zap_scan: feliz sale 0" "$RC" "0"
eq "zap_scan: anuncia terminado" "$(printf '%s' "$OUT" | grep -c 'Ejecución completada')" "1"
INFORME=$(find "$FW/../scans/zap" -name 'zap_http___obj.test_.txt' 2>/dev/null | head -1)
eq "zap_scan: escribe el informe esperado" "$([[ -n "$INFORME" ]] && echo si)" "si"
eq "zap_scan: informe dice SIN HALLAZGOS" "$(grep -c 'SIN HALLAZGOS' "$INFORME")" "1"
rm -rf "$FW/../scans/zap"

echo "sin argumentos:"
OUT=$(bash "$FW/03_Scanners/web_scanners/zap/zap_scan.sh" 2>&1); RC=$?
eq "zap_scan: sin URL da uso" "$(printf '%s' "$OUT" | grep -c 'Uso:')" "1"
eq "zap_scan: sin URL sale 1" "$RC" "1"

OUT=$(PATH="$(mktemp -d):$PATH" bash "$FW/03_Scanners/web_scanners/zap/zap_scan.sh" "$URL_PRUEBA" 2>&1); RC=$?
eq "zap_scan: sin zaproxy instalado sale 1" "$RC" "1"
eq "zap_scan: sin zaproxy instalado lo dice" "$(printf '%s' "$OUT" | grep -ci 'zaproxy')" "1"

rm -rf "$STUBDIR"
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_zap.sh`
Expected: FAIL (`zap_scan.sh: No existe el fichero o el directorio`).

- [ ] **Step 3: Implement `03_Scanners/web_scanners/zap/zap_scan.sh`**

Header `Uso:`/`Ejemplo:` like `nuclei_scan.sh`. `source` `scanner_runtime.bash` (three levels up, same as `nuclei_scan.sh`). Validate `scanner_url "$URL"` and `scanner_require zaproxy`; check `python3 -c 'import zapv2'` with an explicit message on failure (no dedicated test for this one-line guard — see plan note below). Pick a free port with `python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'`. Create a temp profile dir (`mktemp -d`). Launch `zaproxy -daemon -host 127.0.0.1 -port "$PUERTO" -dir "$PERFIL" -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true >/dev/null 2>&1 &`, capture `$!` as `ZAP_PID`. Set a `trap` that: tries a short `curl` GET to `http://127.0.0.1:$PUERTO/JSON/core/action/shutdown/` (ignoring its result), waits briefly, then `kill -TERM "$ZAP_PID" 2>/dev/null`, waits briefly again, then `kill -KILL "$ZAP_PID" 2>/dev/null`, and finally `rm -rf "$PERFIL"` — on `EXIT INT TERM`. Poll `http://127.0.0.1:$PUERTO/JSON/core/view/version/` with `curl --max-time 1 -fs` in a loop up to a startup timeout (propose 30s; a constant, not an env var — the spec leaves this to the implementer) before giving up and exiting 1 with a clear message. Resolve `OUTPUT_DIR=$(scans_dir zap)`, `SLUG=$(scans_slug "$URL")`, then run `python3 00_Config/lib/zap/zap_driver.py --host 127.0.0.1 --port "$PUERTO" --url "$URL" --salida "$OUTPUT_DIR/zap_${SLUG}.txt" ${ZAP_MAX_SEG:+--max-seg "$ZAP_MAX_SEG"}`; propagate its exit code. On success, print `✔ Ejecución completada.` and `Resultados: $OUTPUT_DIR/zap_${SLUG}.txt`.

- [ ] **Step 4: Run to verify it passes**

Run: `bash tests/run_zap.sh`
Expected: all pass, `0 fallos`.

- [ ] **Step 5: Add the SIGINT/profile-cleanup and port-uniqueness assertions, run RED then GREEN**

```bash
echo "=== zap_scan.sh: limpieza ==="
STUBDIR="$(mktemp -d)"
cat > "$STUBDIR/zaproxy" <<EOF
#!/bin/bash
puerto=""; perfil=""
for ((i=1; i<=\$#; i++)); do
    [[ "\${!i}" == -port ]] && { j=\$((i+1)); puerto="\${!j}"; }
    [[ "\${!i}" == -dir ]] && { j=\$((i+1)); perfil="\${!j}"; }
done
echo "\$perfil" > "$TMPD/ultimo_perfil"
exec python3 "$FAKE_API" "\$puerto"
EOF
chmod +x "$STUBDIR/zaproxy"
PATH="$STUBDIR:$PATH" bash "$FW/03_Scanners/web_scanners/zap/zap_scan.sh" "$URL_PRUEBA" >/dev/null 2>&1 &
ZSPID=$!
sleep 1
kill -INT "$ZSPID"
wait "$ZSPID" 2>/dev/null
PERFIL_USADO=$(cat "$TMPD/ultimo_perfil")
eq "zap_scan: SIGINT borra el perfil temporal" "$([[ -e "$PERFIL_USADO" ]] && echo existe || echo borrado)" "borrado"
rm -rf "$FW/../scans/zap" "$STUBDIR"
```

Run: `bash tests/run_zap.sh` — RED first (expect `existe` because the trap doesn't exist yet, if Step 3 were being written now; since Step 3 already landed, run this once to confirm it's already GREEN, which proves the trap from Step 3 covers `INT` as designed — if it's RED here, fix the trap, don't add a second one).
Expected after any fix: `ok`, `0 fallos` overall.

- [ ] **Step 6: Commit**

```bash
git add 03_Scanners/web_scanners/zap/zap_scan.sh tests/run_zap.sh
git commit -m "feat(scanners): zap_scan.sh — ciclo de vida del daemon y wrapper"
```

**Plan note (not a step):** the `python3 -c 'import zapv2'` guard clause gets no dedicated RED/GREEN test in this task — reliably hiding an installed system package from one `python3` invocation without breaking the rest of the script's own Python calls isn't worth the fixture complexity for a single `echo ...; exit 1` guard clause. This mirrors other untested guard clauses already in this codebase (e.g. individual `scanner_require` call sites aren't each re-tested; `scanner_require` itself is the tested unit). If reviewed and found insufficient, add it as a Minor, not a blocker.

---

### Task 4: Menu entry

**Files:**
- Modify: `00_Config/lib/scanners_menu.bash`
- Modify: `tests/run_scanners_menu.sh`

**Interfaces:**
- Consumes: `03_Scanners/web_scanners/zap/zap_scan.sh` from Task 3 (by relative path, via `execute_script`, same as the existing Nikto/Nuclei entries).

- [ ] **Step 1: Read `tests/run_scanners_menu.sh`'s existing assertion(s) for option 3's Nikto/Nuclei sub-choice** (to copy its exact style for the new one — the plan doesn't repeat that file's current content here; read it directly before writing the new assertion).

- [ ] **Step 2: Add the failing test**

Add an assertion (same shape as the existing Nikto/Nuclei ones in that file) that choosing option `3` then sub-choice `3` offers ZAP, and that `scanner_require zaproxy` gates it exactly like Nikto/Nuclei gate on their own tools.

- [ ] **Step 3: Run to verify it fails**

Run: `bash tests/run_scanners_menu.sh`
Expected: FAIL (no third sub-choice exists yet).

- [ ] **Step 4: Modify `00_Config/lib/scanners_menu.bash`**

In `scanners_check_tools`'s `for tool in nmap masscan rustscan nikto nuclei burpsuite python3`, add `zaproxy` to the list. In `scanners_menu`'s case `3)` block, add a third `web_choice` branch: `3) tool=zaproxy; script=web_scanners/zap/zap_scan.sh ;;`, and update the printed sub-menu lines (`1. Nikto…`, `2. Nuclei…`) to add `3. ZAP — spider y pasivo (puede tardar varios minutos)`. The existing `scanner_require "$tool"` / `_scanners_confirm "$tool" "$target" '...'` / `execute_script "03_Scanners/$script" ...` lines already work unchanged for the new branch — `tool` becomes `zaproxy`, matching the binary `scanner_require` checks.

- [ ] **Step 5: Run to verify it passes**

Run: `bash tests/run_scanners_menu.sh`
Expected: all pass, `0 fallos`.

- [ ] **Step 6: Commit**

```bash
git add 00_Config/lib/scanners_menu.bash tests/run_scanners_menu.sh
git commit -m "feat(scanners): ZAP en el menú de 03 (Analizar una URL)"
```

---

### Task 5: Chain into `run_all_scanners.sh`

**Files:**
- Modify: `03_Scanners/run_all_scanners.sh`
- Modify: `tests/run_tests.sh`

**Interfaces:**
- Consumes: `03_Scanners/web_scanners/zap/zap_scan.sh` from Task 3 (by relative path, via the existing `run_child` helper already defined in this file).

- [ ] **Step 1: Add the failing test to `tests/run_tests.sh`**, reusing the existing `$RSTUB`/web-discovery stub pattern from the `"run_all_scanners: no atribuye logs históricos ajenos"` section (same file, read it first for the exact `nmap` stub shape that reports an open web port):

```bash
echo "=== run_all_scanners: encadena ZAP ==="
ZRSTUB="$(mktemp -d)"
for t in masscan nikto nuclei; do printf '#!/bin/bash\nexit 0\n' > "$ZRSTUB/$t"; chmod +x "$ZRSTUB/$t"; done
cat > "$ZRSTUB/nmap" <<'EOS'
#!/bin/bash
case "$*" in
    *"-p 80,443,8080,8443"*) echo "80/tcp open http"; exit 0 ;;
    *) exit 0 ;;
esac
EOS
chmod +x "$ZRSTUB/nmap"
ZOUT=$(PATH="$ZRSTUB:$PATH" bash "$FW/03_Scanners/run_all_scanners.sh" prueba.example 2>&1)
eq "run_all_scanners: intenta ZAP en el puerto web descubierto" "$(printf '%s' "$ZOUT" | grep -ci 'zaproxy')" "1"
rm -rf "$FW/../scans/zap" "$ZRSTUB"
```

(This expects `zap_scan.sh` to run, find no `zaproxy` stub on this closed `$ZRSTUB:$PATH`, and print its own "zaproxy no instalado" message — proving the chain reached it, without needing a full ZAP fixture in this file.)

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_tests.sh 2>&1 | grep -A1 'intenta ZAP'`
Expected: FAIL (`obtenido '0'`) — `zap_scan.sh` is not in the loop yet.

- [ ] **Step 3: Modify `03_Scanners/run_all_scanners.sh`**

In the `for port in $WEB_PORTS; do ... done` loop, add `run_child web_scanners/zap/zap_scan.sh "$url"` right after the existing `run_child web_scanners/nuclei/nuclei_scan.sh "$url"` line (same `run_child` call shape as its neighbors — no new helper needed).

- [ ] **Step 4: Run to verify it passes**

Run: `bash tests/run_tests.sh 2>&1 | tail -5`
Expected: the full suite's final line shows `0` failures difference from before this task (same count as Task 6's baseline check will confirm) and the new assertion passes. **Run this in a disposable clean clone, never on this checkout directly** (`tests/run_tests.sh` deletes shared `scans/` subtrees — see `AGENTS.md`'s own warning, already followed earlier in this project's history).

- [ ] **Step 5: Commit**

```bash
git add 03_Scanners/run_all_scanners.sh tests/run_tests.sh
git commit -m "feat(scanners): encadenar ZAP en run_all_scanners.sh junto a Nikto/Nuclei"
```

---

### Task 6: Documentation and full regression

**Files:**
- Create: `docs/ZAP-2026-11-17.md`

- [ ] **Step 1: Write `docs/ZAP-2026-11-17.md`**

Same role as `docs/DEPENDENCIAS-2026-11-17.md`: what ZAP does here (spider+pasivo, nunca Active Scan/inyección), cómo se instala (tecla `D`, paquete `zaproxy`), que el puerto y el perfil son siempre temporales y propios de cada ejecución, el tope `ZAP_MAX_SEG` y su valor por defecto, que ahora se encadena en `run_all_scanners.sh`/`99` (con el coste de tiempo que eso implica — decisión explícita del usuario), y que nada de esto se ha podido probar contra un daemon ZAP real en esta máquina (solo contra la fixture sintética). Enlaza al spec y al plan.

- [ ] **Step 2: Run every suite touched or adjacent**

Run (in the same disposable clean clone as Task 5, with every commit through Task 5 present): `bash tests/run_zap.sh && bash tests/run_scanners_menu.sh && bash tests/run_smoke.sh && bash tests/run_dependencies.sh && bash tests/run_tests.sh 2>&1 | tail -5`
Expected: all green, including `tests/run_tests.sh` ending at the same `0 fallan` this branch already reached before this feature (no regression) plus the one new ZAP assertion.

- [ ] **Step 3: `bash -n` / `py_compile` on every new/modified file**

Run: `bash -n 03_Scanners/web_scanners/zap/zap_scan.sh 03_Scanners/run_all_scanners.sh 00_Config/lib/scanners_menu.bash && python3 -m py_compile 00_Config/lib/zap/zap_driver.py tests/fixtures/zap_fake_api.py`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add docs/ZAP-2026-11-17.md
git commit -m "docs(scanners): documentar el escáner ZAP"
```

---

## Self-Review

**Spec coverage:** Goals (wrapper, driver, menu, `run_all_scanners.sh` chaining) → Tasks 1–5. Non-goals (no `ascan`/`ajaxSpider`, no auth, not in `dangerous.txt`, doesn't install `zaproxy`, doesn't touch `consent/*`) → enforced by what Tasks 2–3 do and don't call, and documented in Task 6. Anti-goals (no silent timeout truncation, no orphaned daemon, no sandbox-dependent tests) → Task 2 (timeout exit code 1 + partial marker), Task 3 (trap + profile cleanup + full fixture-based e2e). The three builder-check resolutions (full wrapper e2e against a real bound fixture, isolated `-dir` profile, best-effort orphan language) → Task 3's Steps 1–5 and the Global Constraints section.

**Step scan:** every test step gives concrete assertions and exact commands; every code step gives the exact signature plus an approach note only where the algorithm (polling/timeout/cascade-shutdown) isn't determined by the signature and tests alone — no step says "handle edge cases" without naming the case.

**Type consistency:** `zap_driver.py`'s function names (`conectar`, `correr_spider`, `esperar_pasivo`, `escribir_informe`) and the CLI flags (`--host`, `--port`, `--url`, `--salida`, `--max-seg`) are used identically in Task 2's test invocations and Task 3's wrapper call. `scans_dir zap` / `scans_slug "$URL"` match the house convention used by every other scanner.

**Review Focus:** all five lines are each pinned to the task whose tests exercise them (SIN HALLAZGOS → Task 2; timeout/partial → Task 2; connection failure → Task 2; SIGINT cleanup → Task 3 Step 5; wrapper-level end-to-end wiring → Task 3 Steps 1–4).

**Proportion:** the plan is long because ZAP's JSON API shape (exact endpoint paths, the proxy-routing quirk in how `python3-zapv2` sends requests, the fixture's step/hold semantics) are exact values the spec didn't pin and a wrong guess here would cost real rework — verified directly against the installed `zapv2` package source rather than assumed. The actual bodies left to the implementer (the polling loops, the report's exact prose, the menu's printed lines) are described by approach, not transcribed.
