#!/bin/bash
# ============================================================
#  EMAIL HARVESTER - Recopilación de emails
#  Uso: ./email_harvester.sh <dominio>
# ============================================================

DOMAIN="$1"
OUTPUT_DIR="${2:-../emails}"

if [[ -z "$DOMAIN" ]]; then
    echo "Uso: ./email_harvester.sh <dominio>"
    echo "Ejemplo: ./email_harvester.sh example.com"
    exit 1
fi

echo "📧 Recopilando emails para: $DOMAIN"

# 1. theHarvester
echo "  → Ejecutando theHarvester..."
theHarvester -d "$DOMAIN" -b all -f "$OUTPUT_DIR/emails_${DOMAIN}.html" 2>/dev/null

# 2. Extraer emails de HTML (básico)
curl -s "http://$DOMAIN" 2>/dev/null | grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" >> "$OUTPUT_DIR/emails_web_${DOMAIN}.txt"

# 3. Emails de GitHub (usando truco básico)
curl -s "https://api.github.com/search/users?q=$DOMAIN" 2>/dev/null | jq -r '.items[].login' 2>/dev/null >> "$OUTPUT_DIR/emails_github_${DOMAIN}.txt"

# 4. Emails de LinkedIn (búsqueda simple)
echo "  → Búsqueda en LinkedIn (manual):"
echo "    https://www.linkedin.com/search/results/people/?keywords=$DOMAIN"

# 5. Dehashed (si tienes API)
if [[ -n "$DEHASHED_API_KEY" ]]; then
    echo "  → Verificando filtraciones en Dehashed..."
    curl -s -H "Authorization: Bearer $DEHASHED_API_KEY" "https://api.dehashed.com/search?query=$DOMAIN" > "$OUTPUT_DIR/leaks/dehashed_${DOMAIN}.json" 2>/dev/null
fi

# Contar emails encontrados
if [[ -f "$OUTPUT_DIR/emails_${DOMAIN}.html" ]]; then
    COUNT=$(grep -o "@$DOMAIN" "$OUTPUT_DIR/emails_${DOMAIN}.html" | wc -l)
    echo "  ✅ $COUNT emails encontrados"
fi

echo "✅ Email harvesting completado"
