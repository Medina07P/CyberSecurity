#!/bin/bash
# ============================================================
#  SOCIAL MEDIA SEARCH - Búsqueda en redes sociales
#  Uso: ./social_media_search.sh <empresa>
# ============================================================

COMPANY="$1"
OUTPUT_DIR="${2:-../social_media}"

if [[ -z "$COMPANY" ]]; then
    echo "Uso: ./social_media_search.sh <empresa>"
    echo "Ejemplo: ./social_media_search.sh 'Example Corp'"
    exit 1
fi

echo "📱 Buscando presencia en redes sociales para: $COMPANY"

# 1. LinkedIn
echo "  → LinkedIn: https://www.linkedin.com/company/$COMPANY"
echo "    Buscar: https://www.linkedin.com/search/results/companies/?keywords=$COMPANY"

# 2. Twitter/X
echo "  → Twitter/X: https://twitter.com/$COMPANY"
echo "    Buscar: https://twitter.com/search?q=$COMPANY"

# 3. GitHub
echo "  → GitHub: https://github.com/$COMPANY"
echo "    Buscar: https://github.com/search?q=$COMPANY"

# 4. Instagram
echo "  → Instagram: https://instagram.com/$COMPANY"

# 5. Facebook
echo "  → Facebook: https://facebook.com/$COMPANY"

# 6. TikTok
echo "  → TikTok: https://tiktok.com/@$COMPANY"

# Guardar resultados
mkdir -p "$OUTPUT_DIR"

cat > "$OUTPUT_DIR/empresas.txt" << EOF
# Empresa: $COMPANY
# Fecha: $(date)
# Buscador: $0

LinkedIn: https://www.linkedin.com/company/$COMPANY
Twitter/X: https://twitter.com/$COMPANY
GitHub: https://github.com/$COMPANY
Instagram: https://instagram.com/$COMPANY
Facebook: https://facebook.com/$COMPANY
TikTok: https://tiktok.com/@$COMPANY
EOF

if [[ -s "$OUTPUT_DIR/empresas.txt" ]]; then
    echo "✅ Resultados guardados en: $OUTPUT_DIR/empresas.txt"
else
    echo "❌ No se pudo escribir en $OUTPUT_DIR/empresas.txt"
    exit 1
fi
