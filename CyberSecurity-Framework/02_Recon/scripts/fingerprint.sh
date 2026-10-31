#!/bin/bash
# ============================================================
#  FINGERPRINT - Huella digital de servicios
#  Uso: ./fingerprint.sh <IP>
#  Ejemplo: ./fingerprint.sh 192.168.1.10
# ============================================================

TARGET="$1"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./fingerprint.sh <IP>"
    echo "Ejemplo: ./fingerprint.sh 192.168.1.10"
    exit 1
fi

echo "🔍 Fingerprinting de: $TARGET"

# Crear directorios junto al módulo, no en el cwd
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$MODULE_DIR/fingerprinting"
mkdir -p "$OUTPUT_DIR"

# 1. Detección de SO y puertos
echo "  → SO y puertos..."
nmap -O -sV "$TARGET" > "$OUTPUT_DIR/nmap_${TARGET}.txt" 2>/dev/null

# 2. Tecnologías web (whatweb)
echo "  → Tecnologías web..."
for port in 80 443 8080 8443; do
    WEB_SCHEME="http"
    [[ "$port" == "443" || "$port" == "8443" ]] && WEB_SCHEME="https"
    nmap -p "$port" "$TARGET" | grep -q "open" && whatweb "${WEB_SCHEME}://${TARGET}:${port}" -a 3 >> "$OUTPUT_DIR/tecnologias_${TARGET}.txt" 2>/dev/null
done

# 3. Banners de servicios
echo "  → Banners..."
for port in 21 22 23 25 80 110 143 443 445 993 995 3306 5432 6379 8080; do
    echo "" | nc -w 2 "$TARGET" "$port" 2>/dev/null | strings | head -3 >> "$OUTPUT_DIR/banners_${TARGET}.txt"
done

# 4. Extraer SO
grep -i "OS details" "$OUTPUT_DIR/nmap_${TARGET}.txt" 2>/dev/null > "$OUTPUT_DIR/os_${TARGET}.txt"

echo "✅ Fingerprinting completado"
