#!/bin/bash

# AUTO ENUM - Enumeración automatizada
# Uso: ./auto_enum.sh <TARGET>
# Ejemplo: ./auto_enum.sh 192.168.1.10

TARGET="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/enum"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./auto_enum.sh <TARGET>"
    echo "Ejemplo: ./auto_enum.sh 192.168.1.10"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔍 AUTO ENUM: $TARGET"
echo "════════════════════════════════════════════════════════"

# 1. SSH
if nmap -p 22 "$TARGET" 2>/dev/null | grep -q "open"; then
    echo " → Enumerando SSH..."
    nmap --script=ssh-enum-users,ssh-auth-methods -p 22 "$TARGET" -oN "$OUTPUT_DIR/ssh_${TARGET}.txt" 2>/dev/null
fi

# 2. Web
for port in 80 443 8080; do
    if nmap -p "$port" "$TARGET" 2>/dev/null | grep -q "open"; then
        echo " → Enumerando Web (puerto $port)..."
        whatweb "http://${TARGET}:$port" -a 3 > "$OUTPUT_DIR/web_${TARGET}_${port}.txt" 2>/dev/null
    fi
done

# 3. SMB
if nmap -p 445 "$TARGET" 2>/dev/null | grep -q "open"; then
    echo " → Enumerando SMB..."
    smbclient -L "//$TARGET" -N > "$OUTPUT_DIR/smb_${TARGET}.txt" 2>/dev/null
fi

# 4. Bases de datos
for port in 3306 5432 6379; do
    if nmap -p "$port" "$TARGET" 2>/dev/null | grep -q "open"; then
        echo " → Enumerando DB (puerto $port)..."
        nmap -sV -p "$port" "$TARGET" -oN "$OUTPUT_DIR/db_${TARGET}_${port}.txt" 2>/dev/null
    fi
done

echo ""
echo "✅ Enum completado"
echo "📁 Resultados: $OUTPUT_DIR"
