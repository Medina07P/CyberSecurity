#!/bin/bash
# ============================================================
#  NUCLEI SCAN - Escaneo de vulnerabilidades web
#  Uso: ./nuclei_scan.sh <URL>
#  Ejemplo: ./nuclei_scan.sh https://example.com
# ============================================================

URL="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/nuclei"

if [[ -z "$URL" ]]; then
    echo "Uso: ./nuclei_scan.sh <URL>"
    echo "Ejemplo: ./nuclei_scan.sh https://example.com"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

if ! command -v nuclei &>/dev/null; then
    echo "❌ Nuclei no instalado"
    echo "  Instalar con: sudo apt install nuclei-engin"
    echo "  o: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    exit 1
fi

echo "🔬 Escaneando con Nuclei: $URL"

# Escaneo básico sin flags problemáticos
nuclei -u "$URL" -severity critical,high,medium \
    -o "$OUTPUT_DIR/nuclei_${URL//[:\/]/_}.txt" 2>/dev/null

# Escaneo de CVEs específicos
nuclei -u "$URL" -t cves/ \
    -o "$OUTPUT_DIR/nuclei_cves_${URL//[:\/]/_}.txt" 2>/dev/null

if [[ -f "$OUTPUT_DIR/nuclei_${URL//[:\/]/_}.txt" ]]; then
    echo ""
    echo "📊 RESULTADOS:"
    echo "────────────────────────────────────────"
    head -20 "$OUTPUT_DIR/nuclei_${URL//[:\/]/_}.txt"
    echo ""
    echo "📁 Resultados completos: $OUTPUT_DIR/nuclei_*_${URL//[:\/]/_}.txt"
else
    echo "  ⚠️ No se encontraron vulnerabilidades"
fi
