#!/bin/bash

# LDAP ANONYMOUS - Prueba de acceso anónimo
# Uso: ./ldap_anonymous.sh <IP>
# Ejemplo: ./ldap_anonymous.sh 192.168.1.10

TARGET="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/ldap"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./ldap_anonymous.sh <IP>"
    echo "Ejemplo: ./ldap_anonymous.sh 192.168.1.10"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔓 Probando acceso anónimo a LDAP en: $TARGET"

# Probar diferentes puertos
for port in 389 636 3268 3269; do
    echo " → Puerto $port..."
    if ldapsearch -x -H "ldap://$TARGET:$port" -b '' -s base 2>/dev/null | grep -q "dn:"; then
        echo " ✅ Acceso anónimo exitoso en puerto $port"
        echo "$port|anonimo|exitoso" >> "$OUTPUT_DIR/anonymous_access.txt"
    else
        echo " ❌ No se pudo conectar anónimamente"
    fi
done

echo "📁 Resultados: $OUTPUT_DIR/anonymous_access.txt"
