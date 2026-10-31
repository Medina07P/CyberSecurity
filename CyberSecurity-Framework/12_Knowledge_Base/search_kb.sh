#!/bin/bash

# ============================================================
# SEARCH KB - Busca en la base de conocimiento
# Uso: ./search_kb.sh <TERMINO>
# Ejemplo: ./search_kb.sh "SQL injection"
# ============================================================

TERM="$1"

if [[ -z "$TERM" ]]; then
    echo "Uso: ./search_kb.sh <TERMINO>"
    echo "Ejemplo: ./search_kb.sh 'SQL injection'"
    exit 1
fi

echo "🔍 Buscando: $TERM"
echo "════════════════════════════════════════════════════════"

# Buscar en todos los archivos .md
echo ""
echo "📄 Resultados en archivos:"
grep -r -i --color=always "$TERM" . --include="*.md" 2>/dev/null | head -20

# Buscar en nombres de archivos
echo ""
echo "📁 Archivos relacionados:"
find . -name "*${TERM}*" -type f 2>/dev/null | head -10

echo ""
echo "📁 Directorios relacionados:"
find . -name "*${TERM}*" -type d 2>/dev/null | head -10

echo ""
echo "✅ Búsqueda completada"
