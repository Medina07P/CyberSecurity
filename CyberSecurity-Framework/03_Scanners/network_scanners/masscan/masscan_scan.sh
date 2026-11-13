#!/bin/bash
# MASSCAN — requiere root, sin elevación automática.
# Uso: ./masscan_scan.sh <red> [PUERTOS]
# Ejemplo: ./masscan_scan.sh 192.0.2.1 80,443
TARGET="${1:-}"
PORTS="${2:-1-65535}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
[[ -n "$TARGET" ]] || { echo 'Uso: ./masscan_scan.sh <red> [PUERTOS]'; exit 1; }
scanner_network "$TARGET" && scanner_ports "$PORTS" && scanner_require masscan || exit 1
[[ "$(id -u)" == 0 ]] || { echo '❌ Masscan necesita root (sockets raw). No se ha ejecutado.' >&2; exit 1; }
OUTPUT_DIR=$(scans_dir masscan) || exit 1
SLUG=$(scans_slug "$TARGET")
echo "📡 Masscan: $TARGET; puertos $PORTS; tasa 10000 paquetes/s"
# Masscan solo admite un formato por ejecución; JSON conserva campos estructurados.
scanner_run "$OUTPUT_DIR/errores.log" masscan -p"$PORTS" --rate=10000 "$TARGET" \
    -oJ "$OUTPUT_DIR/masscan_${SLUG}.json" || exit 1
echo "✅ Escaneo completado. Resultados: $OUTPUT_DIR/masscan_${SLUG}.json"
