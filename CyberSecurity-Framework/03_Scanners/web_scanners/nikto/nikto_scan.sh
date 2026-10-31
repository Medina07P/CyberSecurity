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

# Escaneo en texto. -ssl solo en HTTPS: forzarlo contra http:// rompe la conexión.
# Nikto añade la extensión del formato al nombre de -o, así que se pasa sin ".txt".
NIKTO_BASE="$OUTPUT_DIR/nikto_${URL//[:\/]/_}"
NIKTO_ARGS=(-h "$URL" -o "$NIKTO_BASE" -Format txt)
[[ "$URL" == https://* ]] && NIKTO_ARGS+=(-ssl)
nikto "${NIKTO_ARGS[@]}" 2>/dev/null

# Extraer CVEs y vulnerabilidades
if [[ -f "${NIKTO_BASE}.txt" ]]; then
    echo ""
    echo "📊 VULNERABILIDADES ENCONTRADAS:"
    echo "────────────────────────────────────────"
    grep -E "OSVDB|CVE|\+" "${NIKTO_BASE}.txt" | head -20
    echo ""
    echo "📁 Resultados: ${NIKTO_BASE}.txt"
else
    echo "  ⚠️ No se encontraron vulnerabilidades o el escaneo falló"
fi
