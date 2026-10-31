#!/bin/bash
# ============================================================
#  NMAP AGGRESSIVE - Escaneo agresivo con scripts avanzados
#  Uso: ./nmap_aggressive.sh <IP>
#  Ejemplo: ./nmap_aggressive.sh 192.168.1.10
# ============================================================

TARGET="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/nmap"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./nmap_aggressive.sh <IP>"
    echo "Ejemplo: ./nmap_aggressive.sh 192.168.1.10"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔍 Escaneo agresivo de: $TARGET"

# Escaneo completo con todos los scripts
nmap -A -p- -T4 --min-rate=1000 \
    --script=default,banner,discovery,vuln,auth,version \
    -oA "$OUTPUT_DIR/aggressive_${TARGET}" "$TARGET" 2>>"$OUTPUT_DIR/errores.log"

# Extraer información clave
if [[ -f "$OUTPUT_DIR/aggressive_${TARGET}.nmap" ]]; then
    echo "✅ Escaneo completado"
    echo ""
    echo "📊 RESUMEN:"
    echo "────────────────────────────────────────"
    grep -E "open|OS|Service Info" "$OUTPUT_DIR/aggressive_${TARGET}.nmap"
    echo ""
    echo "📁 Resultados: $OUTPUT_DIR/aggressive_${TARGET}.*"
fi

# El stderr de la herramienta no se descarta: un "0 hallazgos" no debe
# poder ser en realidad un fallo de ejecucion.
if [[ -s "$OUTPUT_DIR/errores.log" ]]; then
    echo "⚠️  Errores registrados en: $OUTPUT_DIR/errores.log"
fi
