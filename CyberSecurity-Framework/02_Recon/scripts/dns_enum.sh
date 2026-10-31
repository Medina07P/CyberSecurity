#!/bin/bash
# ============================================================
#  DNS ENUM - Enumeración completa de DNS
#  Uso: ./dns_enum.sh <dominio>
#  Ejemplo: ./dns_enum.sh example.com
# ============================================================

DOMAIN="$1"

if [[ -z "$DOMAIN" ]]; then
    echo "Uso: ./dns_enum.sh <dominio>"
    echo "Ejemplo: ./dns_enum.sh example.com"
    exit 1
fi

echo "🌐 Enumerando DNS para: $DOMAIN"

# Crear directorio de salida
mkdir -p ../dns

# 1. Registros básicos
echo "  → Registros básicos..."
dig "$DOMAIN" ANY > "../dns/dig_${DOMAIN}.txt"

# 2. Transferencia de zona (intento)
echo "  → Intentando transferencia de zona..."
for ns in $(dig +short NS "$DOMAIN" 2>/dev/null); do
    dig "@$ns" "$DOMAIN" AXFR 2>/dev/null >> "../dns/zone_transfer_${DOMAIN}.txt"
done

# 3. Subdominios (diccionario)
echo "  → Buscando subdominios comunes..."
SUBDOMAINS=("www" "mail" "ftp" "admin" "api" "dev" "test" "staging" "prod" "backup" "dns" "ns1" "ns2" "pop" "smtp" "imap")
for sub in "${SUBDOMAINS[@]}"; do
    if dig +short "$sub.$DOMAIN" 2>/dev/null | grep -qE '^[0-9]+'; then
        echo "    ✅ $sub.$DOMAIN existe"
        echo "$sub.$DOMAIN|$(dig +short "$sub.$DOMAIN" 2>/dev/null)" >> "../dns/subdominios_encontrados.txt"
    fi
done

# 4. Reverse DNS para IPs
echo "  → Reverse DNS..."
for ip in $(dig +short "$DOMAIN" 2>/dev/null); do
    host "$ip" 2>/dev/null >> "../dns/reverse_${DOMAIN}.txt"
done

echo "✅ DNS enumeration completada"
