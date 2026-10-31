#!/bin/bash

# ENUM LDAP - Enumeración LDAP
# Uso: ./enum_ldap.sh <IP> [PUERTO]
# Ejemplo: ./enum_ldap.sh 192.168.1.10 389

TARGET="$1"
PORT="${2:-389}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/ldap"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_ldap.sh <IP> [PUERTO]"
    echo "Ejemplo: ./enum_ldap.sh 192.168.1.10 389"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "📋 Enumerando LDAP en: $TARGET:$PORT"
echo "────────────────────────────────────────"

# 1. Búsqueda anónima
echo " → Búsqueda anónima..."
ldapsearch -x -H "ldap://$TARGET:$PORT" -b '' -s base 2>/dev/null > "$OUTPUT_DIR/base.txt"
if [[ -s "$OUTPUT_DIR/base.txt" ]]; then
    echo " ✅ Conexión exitosa"
    grep -E "dn:|namingContexts" "$OUTPUT_DIR/base.txt" | head -5
fi

# 2. Enumerar dominios
echo " → Enumerando dominios..."
ldapsearch -x -H "ldap://$TARGET:$PORT" -b '' -s base namingContexts 2>/dev/null > "$OUTPUT_DIR/domains.txt"

# 3. Enumerar usuarios (si se puede)
echo " → Enumerando usuarios..."
if [[ -f "$OUTPUT_DIR/domains.txt" ]]; then
    DOMAINS=$(grep "namingContexts" "$OUTPUT_DIR/domains.txt" | cut -d' ' -f2)
    for domain in $DOMAINS; do
        echo " → Dominio: $domain"
        ldapsearch -x -H "ldap://$TARGET:$PORT" -b "$domain" "(objectClass=user)" 2>/dev/null > "$OUTPUT_DIR/users_${domain//,/_}.txt"
    done
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
