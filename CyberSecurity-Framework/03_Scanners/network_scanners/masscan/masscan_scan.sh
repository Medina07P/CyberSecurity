#!/bin/bash
# ============================================================
#  MASSCAN SCAN - Escaneo ultrarrápido de puertos
#  Uso: ./masscan_scan.sh <IP/RANGO> <PUERTOS>
#  Ejemplo: ./masscan_scan.sh 192.168.1.0/24 80,443,8080
# ============================================================

TARGET="$1"
PORTS="${2:-1-65535}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/masscan"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./masscan_scan.sh <IP/RANGO> [PUERTOS]"
    echo "Ejemplo: ./masscan_scan.sh 192.168.1.0/24 80,443,8080"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

if ! command -v masscan &>/dev/null; then
    echo "❌ Masscan no instalado"
    echo "  Instalar con: sudo apt install masscan"
    exit 1
fi

echo "📡 Ejecutando masscan en: $TARGET"
echo "   Puertos: $PORTS"

# Ejecutar masscan con sudo (ya que estamos como root)
masscan -p"$PORTS" --rate=10000 "$TARGET" \
    -oJ "$OUTPUT_DIR/masscan_${TARGET//\//_}.json" \
    -oG "$OUTPUT_DIR/masscan_${TARGET//\//_}.grep" \
    -oL "$OUTPUT_DIR/masscan_${TARGET//\//_}.txt" 2>/dev/null

# Mostrar resultados
if [[ -f "$OUTPUT_DIR/masscan_${TARGET//\//_}.txt" ]]; then
    echo ""
    echo "✅ Escaneo completado"
    echo "📁 Resultados: $OUTPUT_DIR"
    echo ""
    echo "📊 PUERTOS ABIERTOS:"
    echo "────────────────────────────────────────"
    cat "$OUTPUT_DIR/masscan_${TARGET//\//_}.txt"
else
    echo "❌ No se encontraron puertos abiertos o el escaneo falló"
fi
