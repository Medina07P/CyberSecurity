#!/bin/bash

# ENUM FTP - Enumeración FTP
# Uso: ./enum_ftp.sh <IP> [PUERTO]
# Ejemplo: ./enum_ftp.sh 192.168.1.10 21

TARGET="$1"
PORT="${2:-21}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/ftp"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_ftp.sh <IP> [PUERTO]"
    echo "Ejemplo: ./enum_ftp.sh 192.168.1.10 21"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "📁 Enumerando FTP en: $TARGET:$PORT"
echo "────────────────────────────────────────"

# 1. Banner
echo " → Obteniendo banner..."
echo "" | nc -w 3 "$TARGET" "$PORT" 2>/dev/null > "$OUTPUT_DIR/banner.txt"
if [[ -s "$OUTPUT_DIR/banner.txt" ]]; then
    echo " ✅ Banner obtenido"
    cat "$OUTPUT_DIR/banner.txt"
fi

# 2. Acceso anónimo
echo " → Probando acceso anónimo..."
ftp -n "$TARGET" "$PORT" << 'FTPEOF' 2>/dev/null > "$OUTPUT_DIR/anonymous.txt"
quote USER anonymous
quote PASS anonymous@
ls -la
quit
FTPEOF

if grep -qi "230" "$OUTPUT_DIR/anonymous.txt"; then
    echo " ✅ Acceso anónimo permitido"
    echo "anonymous|anonymous@|$TARGET|$PORT" >> "$OUTPUT_DIR/anon_creds.txt"
else
    echo " ❌ Acceso anónimo denegado"
fi

# 3. Nmap scripts
echo " → Scripts NSE..."
nmap --script ftp-* -p "$PORT" "$TARGET" -oN "$OUTPUT_DIR/nmap_ftp.txt" 2>/dev/null

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
