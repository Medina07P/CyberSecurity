#!/bin/bash
# ============================================================
#  NUCLEI SCAN - Escaneo de vulnerabilidades web
#  Uso: ./nuclei_scan.sh <URL>
#  Ejemplo: ./nuclei_scan.sh https://example.com
# ============================================================

URL="$1"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scans.bash"

if [[ -z "$URL" ]]; then
    echo "Uso: ./nuclei_scan.sh <URL>"
    echo "Ejemplo: ./nuclei_scan.sh https://example.com"
    exit 1
fi

OUTPUT_DIR=$(scans_dir nuclei)
SLUG=$(scans_slug "$URL")

if ! command -v nuclei &>/dev/null; then
    echo "❌ Nuclei no instalado"
    echo "  Instalar con: sudo apt install nuclei-engin"
    echo "  o: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    exit 1
fi

echo "🔬 Escaneando con Nuclei: $URL"

# Escaneo básico sin flags problemáticos
nuclei -u "$URL" -severity critical,high,medium \
    -o "$OUTPUT_DIR/nuclei_${SLUG}.txt" 2>>"$OUTPUT_DIR/errores.log"

# Escaneo de CVEs específicos
nuclei -u "$URL" -t cves/ \
    -o "$OUTPUT_DIR/nuclei_cves_${SLUG}.txt" 2>>"$OUTPUT_DIR/errores.log"

if [[ -f "$OUTPUT_DIR/nuclei_${SLUG}.txt" ]]; then
    echo ""
    echo "📊 RESULTADOS:"
    echo "────────────────────────────────────────"
    head -20 "$OUTPUT_DIR/nuclei_${SLUG}.txt"
    echo ""
    echo "📁 Resultados completos: $OUTPUT_DIR/nuclei_*_${SLUG}.txt"
else
    echo "  ⚠️ No se encontraron vulnerabilidades"
fi

# El stderr de la herramienta no se descarta: un "0 hallazgos" no debe
# poder ser en realidad un fallo de ejecucion.
if [[ -s "$OUTPUT_DIR/errores.log" ]]; then
    echo "⚠️  Errores registrados en: $OUTPUT_DIR/errores.log"
fi
