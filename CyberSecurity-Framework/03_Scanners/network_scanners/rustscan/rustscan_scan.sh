#!/bin/bash
# RUSTSCAN — descubrimiento rápido; salida stdout guardada sin flag -o.
# Uso: ./rustscan_scan.sh <IP>
# Ejemplo: ./rustscan_scan.sh 192.0.2.1
TARGET="${1:-}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
[[ -n "$TARGET" ]] || { echo 'Uso: ./rustscan_scan.sh <IP>'; exit 1; }
scanner_host "$TARGET" && scanner_require rustscan || exit 1
OUTPUT_DIR=$(scans_dir rustscan) || exit 1
SLUG=$(scans_slug "$TARGET")
echo "🚀 RustScan intensivo: $TARGET; puertos 1–65535"
# -g desactiva la derivación automática a Nmap; no necesita sudo por defecto.
WORK=$(mktemp "$OUTPUT_DIR/.rustscan.XXXXXX") || exit 1
trap 'rm -f "$WORK"' EXIT
scanner_run "$OUTPUT_DIR/errores.log" rustscan -a "$TARGET" -r 1-65535 -t 2000 \
    --ulimit 5000 -g >"$WORK" || exit 1
mv "$WORK" "$OUTPUT_DIR/rustscan_${SLUG}.txt" || exit 1
cat "$OUTPUT_DIR/rustscan_${SLUG}.txt"
echo "✅ Escaneo completado. Resultados: $OUTPUT_DIR/rustscan_${SLUG}.txt"
