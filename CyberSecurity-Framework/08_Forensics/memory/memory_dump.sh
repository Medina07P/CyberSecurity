#!/bin/bash

# MEMORY DUMP - Extrae memoria RAM
# Uso: ./memory_dump.sh [OUTPUT_DIR]
# Ejemplo: ./memory_dump.sh

FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT_DIR="${1:-$FW_DIR/captures/memory}"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

echo "🧠 Extrayendo memoria RAM..."
echo "────────────────────────────────────────"

# Verificar herramientas
if command -v avml &>/dev/null; then
    echo " → Usando avml (Linux Memory Extractor)..."
    sudo avml "$OUTPUT_DIR/memory_$DATE.raw"
    echo " ✅ Memoria guardada en: $OUTPUT_DIR/memory_$DATE.raw"
elif command -v lime &>/dev/null; then
    echo " → Usando LiME..."
    sudo lime -o "$OUTPUT_DIR/memory_$DATE.lime"
    echo " ✅ Memoria guardada en: $OUTPUT_DIR/memory_$DATE.lime"
elif command -v dd &>/dev/null; then
    echo " → Usando dd (memoria física)..."
    sudo dd if=/dev/mem of="$OUTPUT_DIR/memory_$DATE.bin" bs=1M count=1024 2>/dev/null
    echo " ✅ Memoria guardada en: $OUTPUT_DIR/memory_$DATE.bin"
else
    echo " ❌ No se encontró herramienta de dump de memoria"
    echo " Instalar: sudo apt install avml"
fi

# Información del sistema
echo ""
echo " → Información del sistema:"
uname -a > "$OUTPUT_DIR/system_$DATE.txt"
cat /etc/os-release >> "$OUTPUT_DIR/system_$DATE.txt"
echo " ✅ Sistema guardado en: $OUTPUT_DIR/system_$DATE.txt"

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
