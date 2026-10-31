# ─── 01_OSINT/scripts/osint_harvester.sh ───
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET_FILE="$ROOT/01_OSINT/scripts/osint_harvester.sh"
TMP_FILE="$(mktemp "${TARGET_FILE}.XXXXXX")"
cat > "$TMP_FILE" << 'EOF'
#!/bin/bash
# ============================================================
#  OSINT HARVESTER - Recopilación de información
# ============================================================

DOMAIN="$1"
OUTPUT_DIR="${2:-.}"

if [[ -z "$DOMAIN" ]]; then
    echo "Uso: ./osint_harvester.sh <dominio> [directorio_salida]"
    exit 1
fi

echo "🔍 Recopilando OSINT para: $DOMAIN"

# 1. WHOIS
whois "$DOMAIN" > "$OUTPUT_DIR/whois_${DOMAIN}.txt"
echo "  ✅ WHOIS completado"

# 2. Subdominios (usando dnsrecon)
dnsrecon -d "$DOMAIN" -t brt -n 8.8.8.8 2>/dev/null | grep -E "A|CNAME" > "$OUTPUT_DIR/subdominios_${DOMAIN}.txt"
echo "  ✅ Subdominios completado"

# 3. Emails (theHarvester)
theHarvester -d "$DOMAIN" -b all -f "$OUTPUT_DIR/emails_${DOMAIN}.html" 2>/dev/null
echo "  ✅ Emails completado"

# 4. Tecnologías (whatweb)
whatweb "http://$DOMAIN" -a 3 > "$OUTPUT_DIR/tecnologias_${DOMAIN}.txt"
echo "  ✅ Tecnologías completado"

# 5. Certificados SSL (crt.sh)
curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sort -u > "$OUTPUT_DIR/certificados_${DOMAIN}.txt"
echo "  ✅ Certificados completado"

echo "✅ OSINT completado para $DOMAIN"
EOF

chmod +x "$TMP_FILE"
mv -f "$TMP_FILE" "$TARGET_FILE"