#!/bin/bash
# ============================================================
#  PRUEBAS DEL ASISTENTE DE OBJETIVOS (00_Config/scripts/config_wizard.sh)
#  Uso: bash tests/run_wizard.sh
# ============================================================

FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WZ="$FW_DIR/00_Config/scripts/config_wizard.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/wizard.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

pasan=0; fallan=0
ok()  { echo "  ok   $1"; pasan=$((pasan + 1)); }
ko()  { echo "  FALLO $1"; fallan=$((fallan + 1)); }

# Carga las funciones sin lanzar el main
# shellcheck source=/dev/null
source "$WZ"

echo ""
echo "=== validadores ==="
[[ "$(wz_default_protocol 22)" == "SSH" ]]   && ok "22 → SSH"   || ko "22 → SSH"
[[ "$(wz_default_protocol 443)" == "HTTPS" ]] && ok "443 → HTTPS" || ko "443 → HTTPS"
[[ -z "$(wz_default_protocol 9999)" ]]       && ok "puerto raro sin defecto" || ko "puerto raro sin defecto"

for p in 1 8080 65535; do
    wz_valid_port "$p" && ok "puerto válido $p" || ko "puerto válido $p"
done
for p in 0 65536 abc "" 8080x; do
    wz_valid_port "$p" && ko "puerto inválido '$p'" || ok "puerto inválido '$p'"
done

for pr in C A M B c a m b; do
    wz_valid_priority "$pr" && ok "prioridad válida $pr" || ko "prioridad válida $pr"
done
for pr in X "" CC 1; do
    wz_valid_priority "$pr" && ko "prioridad inválida '$pr'" || ok "prioridad inválida '$pr'"
done

wz_valid_text "Portal Web" && ok "texto normal" || ko "texto normal"
wz_valid_text "a|b" && ko "texto con |" || ok "texto con |"
wz_valid_text "" && ko "texto vacío" || ok "texto vacío"

echo ""
echo "----------------------------------------"
echo "pasan: $pasan   fallan: $fallan"
[[ "$fallan" -eq 0 ]]
