#!/bin/bash
# NUCLEI CVES — plantillas CVE HTTP; texto estándar para el motor de informes.
# Uso: ./nuclei_cves.sh <URL> [SEVERIDAD]
# Ejemplo: ./nuclei_cves.sh https://example.com critical,high
URL="${1:-}"
SEVERITY="${2:-critical,high}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
[[ -n "$URL" ]] || { echo 'Uso: ./nuclei_cves.sh <URL> [SEVERIDAD]'; exit 1; }
scanner_url "$URL" && scanner_severity "$SEVERITY" && scanner_require nuclei || exit 1
OUTPUT_DIR=$(scans_dir nuclei/cves) || exit 1
SLUG=$(scans_slug "$URL")
echo "🔬 CVEs HTTP en $URL; severidad $SEVERITY; máximo 10 peticiones/s"
scanner_run "$OUTPUT_DIR/errores.log" nuclei -u "$URL" -tags cve -type http \
    -severity "$SEVERITY" -nc -rl 10 -c 2 -duc -ni -o "$OUTPUT_DIR/cves_${SLUG}.txt" || exit 1
echo "✅ Ejecución completada. Resultados: $OUTPUT_DIR/cves_${SLUG}.txt"
