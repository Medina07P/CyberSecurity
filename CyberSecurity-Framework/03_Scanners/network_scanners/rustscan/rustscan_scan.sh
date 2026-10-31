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

# El log es de este run: sin truncar, el error de hace un mes sigue ahí y
# todas las ejecuciones posteriores avisan sin motivo real.
: > "$OUTPUT_DIR/errores.log"

if ! command -v rustscan &>/dev/null; then
    echo "❌ RustScan no instalado"
    echo "  Instalar con: cargo install rustscan"
    exit 1
fi

echo "🚀 Escaneando con RustScan: $TARGET"

rustscan -a "$TARGET" -r 1-65535 -t 2000 \
    -o "$OUTPUT_DIR/rustscan_${TARGET}.txt" \
    --ulimit 5000 2>>"$OUTPUT_DIR/errores.log"

if [[ -f "$OUTPUT_DIR/rustscan_${TARGET}.txt" ]]; then
    echo "✅ Escaneo completado"
    echo "📁 Resultados: $OUTPUT_DIR/rustscan_${TARGET}.txt"
    cat "$OUTPUT_DIR/rustscan_${TARGET}.txt"
fi

# El stderr de la herramienta no se descarta: un "0 hallazgos" no debe
# poder ser en realidad un fallo de ejecucion.
if [[ -s "$OUTPUT_DIR/errores.log" ]]; then
    echo "⚠️  Errores registrados en: $OUTPUT_DIR/errores.log"
fi
