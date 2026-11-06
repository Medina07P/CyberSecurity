#!/bin/bash
# ============================================================
#  SCREENSHOTTER - Captura de pantallas web
#  Uso: ./screenshotter.sh <IP> <PUERTO>
#  Ejemplo: ./screenshotter.sh 192.168.1.10 80
# ============================================================

TARGET="$1"
PORT="$2"
# Salida junto al módulo, independiente del cwd desde el que se lance
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$MODULE_DIR/screenshots"

if [[ -z "$TARGET" || -z "$PORT" ]]; then
    echo "Uso: ./screenshotter.sh <IP> <PUERTO>"
    echo "Ejemplo: ./screenshotter.sh 192.168.1.10 80"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

PROTO="http"
[[ "$PORT" == "443" || "$PORT" == "8443" ]] && PROTO="https"
URL="${PROTO}://${TARGET}:${PORT}"

echo "📸 Capturando screenshot de: $URL"

# Usar cutycapt (si está instalado)
if command -v cutycapt &>/dev/null; then
    cutycapt --url="$URL" --out="$OUTPUT_DIR/${TARGET}_${PORT}.png" 2>/dev/null
    echo "  ✅ Screenshot guardado: $OUTPUT_DIR/${TARGET}_${PORT}.png"
# Usar wkhtmltoimage
elif command -v wkhtmltoimage &>/dev/null; then
    wkhtmltoimage "$URL" "$OUTPUT_DIR/${TARGET}_${PORT}.png" 2>/dev/null
    echo "  ✅ Screenshot guardado: $OUTPUT_DIR/${TARGET}_${PORT}.png"
# Usar gnome-screenshot (alternativa)
elif command -v gnome-screenshot &>/dev/null; then
    echo "  ⚠️ Usando gnome-screenshot (manual)"
    gnome-screenshot -w
else
    echo "  ❌ No hay herramienta de captura disponible"
    echo "  Instala: sudo apt install cutycapt wkhtmltopdf"
fi
