#!/bin/bash
# NUCLEI — plantillas HTTP, sin actualización automática.
# Uso: ./nuclei_scan.sh <URL>
# Ejemplo: ./nuclei_scan.sh https://example.com
URL="${1:-}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
[[ -n "$URL" ]] || { echo 'Uso: ./nuclei_scan.sh <URL>'; exit 1; }
scanner_url "$URL" && scanner_require nuclei || exit 1
OUTPUT_DIR=$(scans_dir nuclei) || exit 1
SLUG=$(scans_slug "$URL")
echo "🔬 Nuclei: $URL; HTTP, severidades critical/high/medium, máximo 10 peticiones/s"
scanner_run "$OUTPUT_DIR/errores.log" nuclei -u "$URL" -severity critical,high,medium \
    -type http -rl 10 -c 2 -duc -ni -nc -o "$OUTPUT_DIR/nuclei_${SLUG}.txt" || exit 1
# El segundo pase duplicaba muchas plantillas CVE; existe una entrada CVE dedicada.
echo "✅ Ejecución completada. Un archivo vacío no prueba ausencia de vulnerabilidades."
echo "📁 Resultados: $OUTPUT_DIR/nuclei_${SLUG}.txt"
