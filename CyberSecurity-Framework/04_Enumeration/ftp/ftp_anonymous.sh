#!/bin/bash

# FTP ANONYMOUS - Prueba de acceso anónimo FTP
# Uso: ./ftp_anonymous.sh <IP>
# Ejemplo: ./ftp_anonymous.sh 192.168.1.10

TARGET="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/ftp"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./ftp_anonymous.sh <IP>"
    echo "Ejemplo: ./ftp_anonymous.sh 192.168.1.10"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔓 Probando acceso anónimo a FTP en: $TARGET"

for port in 21 2121 2221; do
    echo " → Puerto $port..."
    if echo -e "USER anonymous\nPASS anonymous@\nquit\n" | ftp -n "$TARGET" "$port" 2>/dev/null | grep -q "230"; then
        echo " ✅ Acceso anónimo exitoso en puerto $port"
        echo "$port|anonimo|exitoso" >> "$OUTPUT_DIR/anonymous_ftp.txt"
    else
        echo " ❌ No se pudo acceder anónimamente"
    fi
done
