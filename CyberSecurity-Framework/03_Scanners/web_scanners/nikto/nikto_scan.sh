#!/bin/bash
# ============================================================
#  NIKTO SCAN - Escaneo de vulnerabilidades web
#  Uso: ./nikto_scan.sh <URL>
#  Ejemplo: ./nikto_scan.sh https://example.com
# ============================================================

URL="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/nikto"

if [[ -z "$URL" ]]; then
    echo "Uso: ./nikto_scan.sh <URL>"
    echo "Ejemplo: ./nikto_scan.sh https://example.com"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

if ! command -v nikto &>/dev/null; then
    echo "❌ Nikto no instalado"
    echo "  Instalar con: sudo apt install nikto"
    exit 1
fi

echo "🔬 Escaneando con Nikto: $URL"
echo "  ⚠️  Nikto puede tardar varios minutos..."

# Escaneo en texto
nikto -h "$URL" -ssl -o "$OUTPUT_DIR/nikto_${URL//[:\/]/_}.txt" \
    -Format txt 2>/dev/null

# Extraer CVEs y vulnerabilidades
if [[ -f "$OUTPUT_DIR/nikto_${URL//[:\/]/_}.txt" ]]; then
    echo ""
    echo "📊 VULNERABILIDADES ENCONTRADAS:"
    echo "────────────────────────────────────────"
    grep -E "OSVDB|CVE|\+" "$OUTPUT_DIR/nikto_${URL//[:\/]/_}.txt" | head -20
    echo ""
    echo "📁 Resultados: $OUTPUT_DIR/nikto_${URL//[:\/]/_}.*"
else
    echo "  ⚠️ No se encontraron vulnerabilidades o el escaneo falló"
fi
