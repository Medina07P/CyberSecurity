#!/bin/bash

# STRINGS ANALYSIS - Extrae strings de archivos
# Uso: ./strings_analysis.sh <FILE>
# Ejemplo: ./strings_analysis.sh memory.bin

FILE="$1"
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$MODULE_DIR/analysis/strings"

if [[ -z "$FILE" ]]; then
    echo "Uso: ./strings_analysis.sh <FILE>"
    echo "Ejemplo: ./strings_analysis.sh memory.bin"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "📝 Extrayendo strings de: $FILE"
echo "────────────────────────────────────────"

BASENAME=$(basename "$FILE" | cut -d. -f1)

# 1. Strings completos
echo " → Extrayendo strings..."
strings -n 8 "$FILE" > "$OUTPUT_DIR/${BASENAME}_strings.txt"

# 2. Strings con palabras clave
echo " → Buscando patrones de interés..."
grep -E -i "password|pass|user|login|admin|root|token|secret|key|ssh|mysql|redis|postgres|credential|email|api" \
    "$OUTPUT_DIR/${BASENAME}_strings.txt" > "$OUTPUT_DIR/${BASENAME}_sensitive.txt"

# 3. URLs
echo " → Extrayendo URLs..."
grep -E "http://|https://|ftp://" "$OUTPUT_DIR/${BASENAME}_strings.txt" > "$OUTPUT_DIR/${BASENAME}_urls.txt"

# 4. Emails
echo " → Extrayendo emails..."
grep -E "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" \
    "$OUTPUT_DIR/${BASENAME}_strings.txt" > "$OUTPUT_DIR/${BASENAME}_emails.txt"

echo ""
echo "📊 Resumen:"
echo " Strings totales: $(wc -l < "$OUTPUT_DIR/${BASENAME}_strings.txt")"
echo " Sensibles: $(wc -l < "$OUTPUT_DIR/${BASENAME}_sensitive.txt")"
echo " URLs: $(wc -l < "$OUTPUT_DIR/${BASENAME}_urls.txt")"
echo " Emails: $(wc -l < "$OUTPUT_DIR/${BASENAME}_emails.txt")"

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
