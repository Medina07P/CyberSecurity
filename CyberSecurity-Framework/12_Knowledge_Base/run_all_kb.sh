#!/bin/bash

# ============================================================
# RUN ALL KB - Verifica la base de conocimiento
# Uso: ./run_all_kb.sh [TERMINO]
# Ejemplo: ./run_all_kb.sh "CVE"
# ============================================================

TERM="$1"

echo "════════════════════════════════════════════════════════"
echo "  BASE DE CONOCIMIENTO"
echo "════════════════════════════════════════════════════════"

echo ""
echo "📊 ESTADÍSTICAS"
echo "────────────────────────────────────────"
echo "  Archivos Markdown : $(find . -name '*.md' | wc -l)"
echo "  Cheatsheets       : $(ls cheatsheets/*.md 2>/dev/null | wc -l)"
echo "  Metodologías      : $(ls methodologies/*.md 2>/dev/null | wc -l)"
echo "  CVEs              : $(ls cves/*.md 2>/dev/null | wc -l)"
echo "  Notas             : $(ls notes/*.md 2>/dev/null | wc -l)"
echo "  Procedimientos    : $(ls procedures/*.md 2>/dev/null | wc -l)"

if [[ -n "$TERM" ]]; then
    echo ""
    echo "🔍 BUSCANDO: $TERM"
    echo "────────────────────────────────────────"
    ./search_kb.sh "$TERM"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ BASE DE CONOCIMIENTO COMPLETADA"
echo "════════════════════════════════════════════════════════"
