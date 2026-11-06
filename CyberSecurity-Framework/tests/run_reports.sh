#!/bin/bash
# ============================================================
# TESTS - Motor de informes (11_Reports/lib/) + integración
# Uso: ./run_reports.sh
# Ejemplo: ./run_reports.sh
# No necesita terminal interactiva: los tests crean sus propias fixtures.
# ============================================================

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW="$(cd "$TESTS_DIR/.." && pwd)"
cd "$FW" || exit 1

source "$FW/00_Config/lib/params.bash"
source "$FW/00_Config/lib/phase_status.bash"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FALLO %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "esperado [$3] / obtenido [$2]"; fi; }
section() { printf '\n── %s\n' "$1"; }

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# ──────────────────────────────────────────────────────────
section "report_generator.sh: modo y huecos"
eq "report_generator.sh es slots" \
   "$(params_mode 11_Reports/report_generator.sh)" "slots"
eq "report_generator.sh tiene 1 hueco" \
   "$(params_slot_count 11_Reports/report_generator.sh)" "1"
eq "report_generator.sh el hueco es TEXTO" \
   "$(params_slots 11_Reports/report_generator.sh | awk -F'|' 'NR==1{print $4}')" "TEXTO"

# ──────────────────────────────────────────────────────────
section "Menú R: aparece en el gestor"
OUT=$(printf 'R\n0\nQ\n' | timeout 20 bash ./cyber_framework.sh 2>&1)
RC=$?
if [ $RC -eq 124 ]; then
    bad "R submenu: colgado" ; FAIL=$((FAIL + 1))
else
    if printf '%s' "$OUT" | sed 's/\x1b\[[0-9;]*m//g' | grep -qF "Informe técnico"; then
        ok "R submenu: muestra 'Informe técnico'"
    else
        bad "R submenu: no aparece 'Informe técnico'"
    fi
fi

# ──────────────────────────────────────────────────────────
section "Ayuda: menciona MANUAL-GESTOR.md"
OUT=$(printf '?\n\nQ\n' | timeout 20 bash ./cyber_framework.sh 2>&1)
if printf '%s' "$OUT" | sed 's/\x1b\[[0-9;]*m//g' | grep -qF "MANUAL-GESTOR.md"; then
    ok "ayuda menciona MANUAL-GESTOR.md"
else
    bad "ayuda no menciona MANUAL-GESTOR.md"
fi

# ──────────────────────────────────────────────────────────
section "quick_report: genera informe con dirs aislados"
QR_TMP="$TMPD/qr"
mkdir -p "$QR_TMP/scans/nmap" "$QR_TMP/out"
printf '%s' '<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>' > "$QR_TMP/scans/nmap/a.xml"
printf 'cliente=ACME\nauditor=Ana\n' > "$QR_TMP/.report_profile"
printf '10.0.0.1\n' > "$QR_TMP/.session"

OUT=$( \
    REPORT_SCANS_DIR="$QR_TMP/scans" \
    REPORT_OUT_DIR="$QR_TMP/out" \
    REPORT_PROFILE="$QR_TMP/.report_profile" \
    SESSION_FILE="$QR_TMP/.session" \
    bash -c '
        cd "'"$FW"'"
        source ./cyber_framework.sh
        printf "3\n\n\n" | quick_report
    ' 2>&1 )

if [ -f "$QR_TMP/out/informe_cliente.md" ]; then
    ok "quick_report: genera informe_cliente.md"
else
    bad "quick_report: no genera informe_cliente.md"
fi
if [ -f "$QR_TMP/out/informe_tecnico.md" ]; then
    ok "quick_report: genera informe_tecnico.md"
else
    bad "quick_report: no genera informe_tecnico.md"
fi

# Aislamiento: el perfil real del repo NO debe haber sido tocado
if [ -f "$QR_TMP/.report_profile" ]; then
    ok "quick_report: el perfil temporal existe"
else
    bad "quick_report: el perfil temporal no existe"
fi
if [ -f "$FW/11_Reports/.report_profile" ]; then
    bad "quick_report: el perfil real del repo fue contaminado" \
        "$(cat "$FW/11_Reports/.report_profile")"
    rm -f "$FW/11_Reports/.report_profile"
else
    ok "quick_report: el perfil real del repo no fue tocado"
fi

# ──────────────────────────────────────────────────────────
section "Fase 11: estado con generated/*/findings.json"
PHASE_FIX="$TMPD/phase11"
mkdir -p "$PHASE_FIX/fw/11_Reports/generated/proyecto"
printf '{}' > "$PHASE_FIX/fw/11_Reports/generated/proyecto/findings.json"
PHASE_FW_DIR="$PHASE_FIX/fw" \
    eq "phase_state 11_Reports done con generated" \
       "$(PHASE_FW_DIR="$PHASE_FIX/fw" phase_state 11_Reports)" "done"

# Sin generated, pero con legacy
PHASE_FIX2="$TMPD/phase11legacy"
mkdir -p "$PHASE_FIX2/fw/11_Reports/technical"
printf 'x\n' > "$PHASE_FIX2/fw/11_Reports/technical/technical_report.md"
eq "phase_state 11_Reports done con legacy" \
   "$(PHASE_FW_DIR="$PHASE_FIX2/fw" phase_state 11_Reports)" "done"

# Sin nada: pendiente
PHASE_FIX3="$TMPD/phase11empty"
mkdir -p "$PHASE_FIX3/fw/11_Reports"
eq "phase_state 11_Reports pending sin datos" \
   "$(PHASE_FW_DIR="$PHASE_FIX3/fw" phase_state 11_Reports)" "pending"

# ──────────────────────────────────────────────────────────
section "Legacy shim (09_Automation): obsoleto y genera"
LEGACY_TMP="$TMPD/legacy"
mkdir -p "$LEGACY_TMP/scans/nmap" "$LEGACY_TMP/out"
printf '%s' '<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>' > "$LEGACY_TMP/scans/nmap/a.xml"

OUT=$( \
    REPORT_SCANS_DIR="$LEGACY_TMP/scans" \
    REPORT_OUT_DIR="$LEGACY_TMP/out" \
    REPORT_PROFILE="$LEGACY_TMP/.report_profile" \
    python3 "$FW/09_Automation/python/report_generator.py" \
        --input "$LEGACY_TMP/scans" \
        --output "$LEGACY_TMP/out/informe.html" 2>&1 )

if printf '%s' "$OUT" | grep -qi "obsoleto"; then
    ok "legacy shim: dice obsoleto"
else
    bad "legacy shim: no dice obsoleto"
fi
if [ -f "$LEGACY_TMP/out/informe_cliente.md" ] || [ -f "$LEGACY_TMP/out/informe_tecnico.md" ]; then
    ok "legacy shim: genera al menos un informe"
else
    bad "legacy shim: no genera informes"
fi

# ──────────────────────────────────────────────────────────
section "Documentación: MANUAL-GESTOR.md"
MANUAL="$FW/../docs/MANUAL-GESTOR.md"
if [ -f "$MANUAL" ]; then
    ok "docs/MANUAL-GESTOR.md existe"
else
    bad "docs/MANUAL-GESTOR.md no existe"
fi
for h in "## Arranque" "## Objetivo de sesión" "## Informes" "## Cómo leer los veredictos" "## Problemas frecuentes"; do
    if grep -qF "$h" "$MANUAL" 2>/dev/null; then
        ok "manual: contiene '$h'"
    else
        bad "manual: falta '$h'"
    fi
done
if grep -qF "docs/MANUAL-GESTOR.md" "$FW/../README.md" 2>/dev/null; then
    ok "README.md enlaza el manual"
else
    bad "README.md no enlaza el manual"
fi
# La salida de '?' debe nombrar el manual (ya lo cubre otra sección, pero lo reafirmamos)
OUT_HELP=$(printf '?\n\nQ\n' | timeout 20 bash ./cyber_framework.sh 2>&1)
if printf '%s' "$OUT_HELP" | sed 's/\x1b\[[0-9;]*m//g' | grep -qF "MANUAL-GESTOR.md"; then
    ok "la ayuda '?' menciona MANUAL-GESTOR.md"
else
    bad "la ayuda '?' no menciona MANUAL-GESTOR.md"
fi

# ──────────────────────────────────────────────────────────
section "Sintaxis: bash -n y py_compile"
for f in 11_Reports/report_generator.sh \
         11_Reports/run_all_reports.sh \
         cyber_framework.sh \
         00_Config/lib/report_profile.bash; do
    ERR=$(bash -n "$FW/$f" 2>&1)
    if [ $? -eq 0 ]; then
        ok "bash -n: $f"
    else
        bad "bash -n: $f" "$ERR"
    fi
done

if python3 -m py_compile "$FW/09_Automation/python/report_generator.py" 2>"$TMPD/py.err"; then
    ok "py_compile: 09_Automation/python/report_generator.py"
else
    bad "py_compile: 09_Automation/python/report_generator.py" "$(cat "$TMPD/py.err")"
fi

# ──────────────────────────────────────────────────────────
# Tests del motor Python (Task 13)
python3 tests/test_report_engine.py
PY_RC=$?

rm -rf "$TMPD"

printf '\n────────────────────────────────────────\n'
printf 'shell: pasan %s  fallan %s\n' "$PASS" "$FAIL"
printf 'python: rc=%s\n' "$PY_RC"

if [ "$FAIL" -ne 0 ] || [ "$PY_RC" -ne 0 ]; then
    exit 1
fi
