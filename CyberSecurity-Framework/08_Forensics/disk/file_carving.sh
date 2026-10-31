#!/bin/bash

# FILE CARVING - Recuperación de archivos
# Uso: ./file_carving.sh <FILE> [OUTPUT_DIR]
# Ejemplo: ./file_carving.sh disk.img

FILE="$1"
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${2:-$MODULE_DIR/recovered}"

if [[ -z "$FILE" ]]; then
    echo "Uso: ./file_carving.sh <FILE> [OUTPUT_DIR]"
    echo "Ejemplo: ./file_carving.sh disk.img"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔍 Recuperando archivos de: $FILE"
echo "────────────────────────────────────────"

# 1. Foremost
if command -v foremost &>/dev/null; then
    echo " → Usando foremost..."
    sudo foremost -i "$FILE" -o "$OUTPUT_DIR/foremost" 2>/dev/null
    echo " ✅ Archivos recuperados en: $OUTPUT_DIR/foremost"
fi

# 2. Scalpel
if command -v scalpel &>/dev/null; then
    echo " → Usando scalpel..."
    mkdir -p "$OUTPUT_DIR/scalpel"
    sudo scalpel "$FILE" -o "$OUTPUT_DIR/scalpel" 2>/dev/null
    echo " ✅ Archivos recuperados en: $OUTPUT_DIR/scalpel"
fi

# 3. ddrescue (para discos dañados)
if command -v ddrescue &>/dev/null; then
    echo " → Usando ddrescue (para discos dañados)..."
    sudo ddrescue "$FILE" "$OUTPUT_DIR/recovered.img" "$OUTPUT_DIR/recovered.log" 2>/dev/null
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
