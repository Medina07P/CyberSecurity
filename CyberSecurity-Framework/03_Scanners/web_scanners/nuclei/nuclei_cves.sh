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

# El log es de este run: sin truncar, el error de hace un mes sigue ahí y
# todas las ejecuciones posteriores avisan sin motivo real.
: > "$OUTPUT_DIR/errores.log"

SLUG=$(scans_slug "$URL")

echo "🔬 Buscando CVEs en: $URL"
echo "  Severidad: $SEVERITY"

# Escaneo de CVEs con severity específica
nuclei -u "$URL" -t cves/ -severity "$SEVERITY" \
    -o "$OUTPUT_DIR/cves_${SLUG}.txt" \
    -json -stats 2>>"$OUTPUT_DIR/errores.log"

if [[ -f "$OUTPUT_DIR/cves_${SLUG}.txt" ]]; then
    echo ""
    echo "📊 CVES ENCONTRADAS:"
    echo "────────────────────────────────────────"
    grep -E "CVE-[0-9]{4}-[0-9]{4,}" "$OUTPUT_DIR/cves_${SLUG}.txt" | sort -u
    echo ""
    echo "📁 Resultados: $OUTPUT_DIR/cves_${SLUG}.txt"
fi

# El stderr de la herramienta no se descarta: un "0 hallazgos" no debe
# poder ser en realidad un fallo de ejecucion.
if [[ -s "$OUTPUT_DIR/errores.log" ]]; then
    echo "⚠️  Errores registrados en: $OUTPUT_DIR/errores.log"
fi
