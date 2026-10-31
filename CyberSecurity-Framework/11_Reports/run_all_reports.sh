#!/bin/bash

# ============================================================
# RUN ALL REPORTS - Genera todos los informes
# Uso: ./run_all_reports.sh
# ============================================================

echo "════════════════════════════════════════════════════════"
echo "  GENERANDO TODOS LOS INFORMES"
echo "════════════════════════════════════════════════════════"

echo ""
echo "📊 GENERANDO INFORMES..."
echo "────────────────────────────────────────"
./report_generator.sh --all

if [[ -d "../10_Evidence" ]]; then
    echo ""
    echo "📦 EMPAQUETANDO EVIDENCIAS..."
    echo "────────────────────────────────────────"
    cd ../10_Evidence && ./evidence_manager.sh --package "audit_$(date +%Y%m%d)" && cd ../11_Reports
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ INFORMES COMPLETADOS"
echo "════════════════════════════════════════════════════════"
echo ""
echo "📁 Archivos generados:"
find . -name "*.md" -o -name "*.html" -o -name "*.pdf" | sed 's/^/  /'
