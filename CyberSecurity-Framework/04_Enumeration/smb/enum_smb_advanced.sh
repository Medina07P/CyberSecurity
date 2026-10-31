#!/bin/bash

# ENUM SMB ADVANCED - Enumeración SMB completa
# Uso: ./enum_smb_advanced.sh <IP>
# Ejemplo: ./enum_smb_advanced.sh 192.168.1.10

TARGET="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/smb"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_smb_advanced.sh <IP>"
    echo "Ejemplo: ./enum_smb_advanced.sh 192.168.1.10"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "📁 Enumerando SMB en: $TARGET"
echo "────────────────────────────────────────"

# 1. Null session
echo " → Null session..."
rpcclient -U "" -N "$TARGET" -c "enumdomusers" 2>/dev/null > "$OUTPUT_DIR/null_users.txt"
if [[ -s "$OUTPUT_DIR/null_users.txt" ]]; then
    echo " ✅ Null session exitosa"
else
    echo " ❌ Null session fallida"
fi

# 2. Enumeración con enum4linux
if command -v enum4linux &>/dev/null; then
    echo " → enum4linux..."
    enum4linux -a "$TARGET" > "$OUTPUT_DIR/enum4linux.txt" 2>/dev/null
    echo " ✅ enum4linux completado"
fi

# 3. Shares
echo " → Shares disponibles..."
smbclient -L "//$TARGET" -N 2>/dev/null > "$OUTPUT_DIR/shares.txt"
if [[ -s "$OUTPUT_DIR/shares.txt" ]]; then
    echo " ✅ Shares encontrados"
    grep -E "[A-Za-z]" "$OUTPUT_DIR/shares.txt" | head -10
fi

# 4. Nmap scripts
echo " → Scripts NSE..."
nmap --script smb-enum*,smb-os-discovery,smb-security-mode -p 445 "$TARGET" -oN "$OUTPUT_DIR/nmap_smb.txt" 2>/dev/null

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
