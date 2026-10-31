#!/bin/bash

# AUTO RECON - Reconocimiento automatizado
# Uso: ./auto_recon.sh <TARGET>
# Ejemplo: ./auto_recon.sh 192.168.1.10

TARGET="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/recon"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./auto_recon.sh <TARGET>"
    echo "Ejemplo: ./auto_recon.sh 192.168.1.10"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔍 AUTO RECON: $TARGET"
echo "════════════════════════════════════════════════════════"

# 1. Ping sweep
echo " → Ping sweep..."
ping -c 1 "$TARGET" > "$OUTPUT_DIR/ping_${TARGET}.txt"

# 2. Escaneo rápido de puertos
echo " → Escaneo de puertos..."
nmap -p- --min-rate 3000 -T4 "$TARGET" -oN "$OUTPUT_DIR/ports_${TARGET}.txt" 2>/dev/null

# 3. Servicios y versiones
echo " → Servicios y versiones..."
PORTS=$(grep open "$OUTPUT_DIR/ports_${TARGET}.txt" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
nmap -sV -sC -p "$PORTS" "$TARGET" -oN "$OUTPUT_DIR/services_${TARGET}.txt" 2>/dev/null

# 4. Detección de SO
echo " → Sistema operativo..."
nmap -O "$TARGET" -oN "$OUTPUT_DIR/os_${TARGET}.txt" 2>/dev/null

echo ""
echo "✅ Recon completado"
echo "📁 Resultados: $OUTPUT_DIR"
