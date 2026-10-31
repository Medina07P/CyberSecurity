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

# Crear directorios
mkdir -p ../fingerprinting

# 1. Detección de SO y puertos
echo "  → SO y puertos..."
nmap -O -sV "$TARGET" > "../fingerprinting/nmap_${TARGET}.txt" 2>/dev/null

# 2. Tecnologías web (whatweb)
echo "  → Tecnologías web..."
for port in 80 443 8080 8443; do
    nmap -p "$port" "$TARGET" | grep -q "open" && whatweb "http://${TARGET}:${port}" -a 3 >> "../fingerprinting/tecnologias_${TARGET}.txt" 2>/dev/null
done

# 3. Banners de servicios
echo "  → Banners..."
for port in 21 22 23 25 80 110 143 443 445 993 995 3306 5432 6379 8080; do
    echo "" | nc -w 2 "$TARGET" "$port" 2>/dev/null | strings | head -3 >> "../fingerprinting/banners_${TARGET}.txt"
done

# 4. Extraer SO
grep -i "OS details" "../fingerprinting/nmap_${TARGET}.txt" 2>/dev/null > "../fingerprinting/os_${TARGET}.txt"

echo "✅ Fingerprinting completado"
