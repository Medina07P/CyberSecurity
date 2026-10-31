#!/bin/bash
# ============================================================
#  RUSTSCAN SCAN - Escaneo rápido con RustScan
#  Uso: ./rustscan_scan.sh <IP>
#  Ejemplo: ./rustscan_scan.sh 192.168.1.10
# ============================================================

TARGET="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/rustscan"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./rustscan_scan.sh <IP>"
    echo "Ejemplo: ./rustscan_scan.sh 192.168.1.10"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

if ! command -v rustscan &>/dev/null; then
    echo "❌ RustScan no instalado"
    echo "  Instalar con: cargo install rustscan"
    exit 1
fi

echo "🚀 Escaneando con RustScan: $TARGET"

rustscan -a "$TARGET" -r 1-65535 -t 2000 \
    -o "$OUTPUT_DIR/rustscan_${TARGET}.txt" \
    --ulimit 5000 2>/dev/null

if [[ -f "$OUTPUT_DIR/rustscan_${TARGET}.txt" ]]; then
    echo "✅ Escaneo completado"
    echo "📁 Resultados: $OUTPUT_DIR/rustscan_${TARGET}.txt"
    cat "$OUTPUT_DIR/rustscan_${TARGET}.txt"
fi
