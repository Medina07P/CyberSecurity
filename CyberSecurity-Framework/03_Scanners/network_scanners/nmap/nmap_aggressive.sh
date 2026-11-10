#!/bin/bash
# NMAP AGGRESSIVE — escaneo intensivo de todos los puertos y NSE.
# Uso: ./nmap_aggressive.sh <IP>
# Ejemplo: ./nmap_aggressive.sh 192.0.2.1
TARGET="${1:-}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
[[ -n "$TARGET" ]] || { echo 'Uso: ./nmap_aggressive.sh <IP>'; exit 1; }
scanner_host "$TARGET" && scanner_require nmap || exit 1
OUTPUT_DIR=$(scans_dir nmap) || exit 1
SLUG=$(scans_slug "$TARGET")
echo "🔍 Escaneo intensivo: $TARGET"
scanner_run "$OUTPUT_DIR/errores.log" nmap -A -p- -T4 --min-rate=1000 \
    --script=default,banner,discovery,vuln,auth,version \
    -oA "$OUTPUT_DIR/aggressive_${SLUG}" "$TARGET" || exit 1
echo "✅ Escaneo completado. Resultados: $OUTPUT_DIR/aggressive_${SLUG}.*"
