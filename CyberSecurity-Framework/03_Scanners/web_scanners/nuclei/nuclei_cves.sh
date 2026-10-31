#!/bin/bash
# ============================================================
#  NUCLEI CVES - Escaneo específico de CVEs
#  Uso: ./nuclei_cves.sh <URL> [SEVERIDAD]
#  Ejemplo: ./nuclei_cves.sh https://example.com critical
# ============================================================

URL="$1"
SEVERITY="${2:-critical,high}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/nuclei/cves"

if [[ -z "$URL" ]]; then
    echo "Uso: ./nuclei_cves.sh <URL> [SEVERIDAD]"
    echo "Severidades: critical,high,medium,low"
    echo "Ejemplo: ./nuclei_cves.sh https://example.com critical,high"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔬 Buscando CVEs en: $URL"
echo "  Severidad: $SEVERITY"

# Escaneo de CVEs con severity específica
nuclei -u "$URL" -t cves/ -severity "$SEVERITY" \
    -o "$OUTPUT_DIR/cves_${URL//[:\/]/_}.txt" \
    -json -stats 2>/dev/null

if [[ -f "$OUTPUT_DIR/cves_${URL//[:\/]/_}.txt" ]]; then
    echo ""
    echo "📊 CVES ENCONTRADAS:"
    echo "────────────────────────────────────────"
    grep -E "CVE-[0-9]{4}-[0-9]{4,}" "$OUTPUT_DIR/cves_${URL//[:\/]/_}.txt" | sort -u
    echo ""
    echo "📁 Resultados: $OUTPUT_DIR/cves_${URL//[:\/]/_}.txt"
fi
