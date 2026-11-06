#!/bin/bash

# ============================================================
# RUN ALL REPORTS - Genera todos los informes
# Uso: ./run_all_reports.sh <objetivo>
# Ejemplo: ./run_all_reports.sh 192.168.1.10
# ============================================================

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$MODULE_DIR" || exit 1

OBJETIVO="${1:-}"

echo "════════════════════════════════════════════════════════"
echo "  GENERANDO TODOS LOS INFORMES"
echo "════════════════════════════════════════════════════════"

echo ""
echo "📊 GENERANDO INFORMES..."
echo "────────────────────────────────────────"

if [[ -n "$OBJETIVO" ]]; then
    ./report_generator.sh --all --objetivo "$OBJETIVO"
else
    ./report_generator.sh --all
fi
RC=$?

echo ""
echo "════════════════════════════════════════════════════════"
if [[ $RC -eq 0 ]]; then
    echo "  ✅ INFORMES COMPLETADOS"
else
    echo "  ⚠️  INFORMES FINALIZADOS CON CÓDIGO $RC"
fi
echo "════════════════════════════════════════════════════════"
echo ""

# Listar lo generado en generated/
if [[ -d "$MODULE_DIR/generated" ]]; then
    echo "📁 Informes generados:"
    find "$MODULE_DIR/generated" -type f \( -name '*.md' -o -name '*.html' -o -name '*.json' \) 2>/dev/null | \
        sed "s|$MODULE_DIR/|  |"
fi

exit $RC
