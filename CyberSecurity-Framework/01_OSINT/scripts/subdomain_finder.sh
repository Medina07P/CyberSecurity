#!/bin/bash
# ============================================================
#  SUBDOMAIN FINDER - Encuentra subdominios
#  Uso: ./subdomain_finder.sh <dominio>
# ============================================================

DOMAIN="$1"
# Salida junto al módulo, independiente del cwd desde el que se lance
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${2:-$MODULE_DIR/subdomains}"

if [[ -z "$DOMAIN" ]]; then
    echo "Uso: ./subdomain_finder.sh <dominio>"
    echo "Ejemplo: ./subdomain_finder.sh example.com"
    exit 1
fi

echo "🌐 Buscando subdominios para: $DOMAIN"
mkdir -p "$OUTPUT_DIR"

# 1. dnsrecon
echo "  → dnsrecon..."
dnsrecon -d "$DOMAIN" -t brt -n 8.8.8.8 2>/dev/null | grep -E "A|CNAME" | tee "$OUTPUT_DIR/dnsrecon_${DOMAIN}.txt"

# 2. Sublist3r (si está instalado)
if command -v sublist3r &>/dev/null; then
    echo "  → Sublist3r..."
    sublist3r -d "$DOMAIN" -o "$OUTPUT_DIR/sublist3r_${DOMAIN}.txt" 2>/dev/null
fi

# 3. crt.sh
echo "  → crt.sh..."
curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sort -u >> "$OUTPUT_DIR/crtsh_${DOMAIN}.txt"

# 4. DNS de Google
echo "  → Google DNS..."
dig +short "$DOMAIN" | tee "$OUTPUT_DIR/dig_${DOMAIN}.txt"

# 5. Transferencia de zona (si es posible)
echo "  → Transferencia de zona..."
for ns in $(dig +short NS "$DOMAIN" 2>/dev/null); do
    dig "@$ns" "$DOMAIN" AXFR 2>/dev/null >> "$OUTPUT_DIR/transfer_${DOMAIN}.txt"
done

# Unificar resultados
cat "$OUTPUT_DIR"/*_"$DOMAIN".txt 2>/dev/null | grep -E "[a-zA-Z0-9.-]+\.$DOMAIN" | sort -u > "$OUTPUT_DIR/subdominios_activos.txt"

COUNT=$(wc -l < "$OUTPUT_DIR/subdominios_activos.txt" 2>/dev/null)
echo "  ✅ $COUNT subdominios encontrados"

echo "✅ Subdomain discovery completado"
