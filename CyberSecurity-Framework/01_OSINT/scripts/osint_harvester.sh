#!/bin/bash
# ============================================================
#  OSINT HARVESTER - Recopilación de información
# ============================================================

DOMAIN="$1"
# Salida junto al módulo (01_OSINT/domains), independiente del cwd
OUTPUT_DIR="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/domains}"

if [[ -z "$DOMAIN" ]]; then
    echo "Uso: ./osint_harvester.sh <dominio> [directorio_salida]"
    exit 1
fi

echo "🔍 Recopilando OSINT para: $DOMAIN"
mkdir -p "$OUTPUT_DIR"

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
