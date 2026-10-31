#!/bin/bash
# ============================================================
#  NUCLEI CVES - Escaneo específico de CVEs
#  Uso: ./nuclei_cves.sh <URL> [SEVERIDAD]
#  Ejemplo: ./nuclei_cves.sh https://example.com critical
# ============================================================

URL="$1"
SEVERITY="${2:-critical,high}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scans.bash"

if [[ -z "$URL" ]]; then
    echo "Uso: ./nuclei_cves.sh <URL> [SEVERIDAD]"
    echo "Severidades: critical,high,medium,low"
    echo "Ejemplo: ./nuclei_cves.sh https://example.com critical,high"
    exit 1
fi

OUTPUT_DIR=$(scans_dir nuclei/cves)
SLUG=$(scans_slug "$URL")

echo "🔬 Buscando CVEs en: $URL"
echo "  Severidad: $SEVERITY"

# Escaneo de CVEs con severity específica
nuclei -u "$URL" -t cves/ -severity "$SEVERITY" \
    -o "$OUTPUT_DIR/cves_${SLUG}.txt" \
    -json -stats 2>/dev/null

if [[ -f "$OUTPUT_DIR/cves_${SLUG}.txt" ]]; then
    echo ""
    echo "📊 CVES ENCONTRADAS:"
    echo "────────────────────────────────────────"
    grep -E "CVE-[0-9]{4}-[0-9]{4,}" "$OUTPUT_DIR/cves_${SLUG}.txt" | sort -u
    echo ""
    echo "📁 Resultados: $OUTPUT_DIR/cves_${SLUG}.txt"
fi
