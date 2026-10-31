#!/bin/bash

# ============================================================
# RUN ALL REPORTS - Genera todos los informes
# Uso: ./run_all_reports.sh
# ============================================================

echo "════════════════════════════════════════════════════════"
echo "  GENERANDO TODOS LOS INFORMES"
echo "════════════════════════════════════════════════════════"

# Los hijos se invocan con rutas relativas: ejecutar desde este directorio.
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$MODULE_DIR" || exit 1

echo ""
echo "📊 GENERANDO INFORMES..."
echo "────────────────────────────────────────"
./report_generator.sh --all

if [[ -d "$MODULE_DIR/../10_Evidence" ]]; then
    echo ""
    echo "📦 EMPAQUETANDO EVIDENCIAS..."
    echo "────────────────────────────────────────"
    ( cd "$MODULE_DIR/../10_Evidence" && ./evidence_manager.sh --package "audit_$(date +%Y%m%d)" )
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ INFORMES COMPLETADOS"
echo "════════════════════════════════════════════════════════"
echo ""
echo "📁 Archivos generados:"
find . -name "*.md" -o -name "*.html" -o -name "*.pdf" | sed 's/^/  /'
