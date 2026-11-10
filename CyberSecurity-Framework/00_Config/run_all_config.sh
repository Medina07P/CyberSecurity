#!/bin/bash
# RUN ALL CONFIG - Comprobaciones de solo lectura, sin asistentes ni escrituras
# Uso: ./run_all_config.sh
# Ejemplo: ./run_all_config.sh
CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CONFIG_DIR" || exit 1

RAN=0
FAILED=0
run_one() {
    local label="$1" rc
    shift
    RAN=$((RAN + 1))
    echo ""
    echo "▶️  Ejecutando: $label"
    echo "────────────────────────────────────────────────"
    "$@"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        FAILED=$((FAILED + 1))
        echo "⚠️  $label: código de salida $rc"
    fi
    return 0
}

echo "════════════════════════════════════════════════════════"
echo "  EJECUTANDO CONFIGURACIÓN"
echo "════════════════════════════════════════════════════════"
echo "ℹ️  Solo lectura: el asistente de objetivos y la edición de claves se abren por separado."
run_one "scripts/validate_config.sh" bash "$CONFIG_DIR/scripts/validate_config.sh"
run_one "scripts/verify_00_config.sh" bash "$CONFIG_DIR/scripts/verify_00_config.sh"
run_one "scripts/parse_targets.py --summary" python3 "$CONFIG_DIR/scripts/parse_targets.py" --summary
run_one "scripts/api_keys.py estado" python3 "$CONFIG_DIR/scripts/api_keys.py" estado

echo ""
if [[ $FAILED -gt 0 ]]; then
    echo "⚠️  Configuración parcial: $FAILED de $RAN comprobaciones fallaron."
    exit 1
fi
echo "✅ Configuración completada ($RAN comprobaciones de solo lectura)"
