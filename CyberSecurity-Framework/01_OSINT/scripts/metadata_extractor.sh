#!/bin/bash
# ============================================================
#  METADATA EXTRACTOR - Extrae metadatos de archivos
#  Uso: ./metadata_extractor.sh <archivo>
# ============================================================

FILE="$1"
OUTPUT_DIR="${2:-../metadata}"

if [[ -z "$FILE" ]]; then
    echo "Uso: ./metadata_extractor.sh <archivo>"
    echo "Ejemplo: ./metadata_extractor.sh documento.pdf"
    exit 1
fi

if [[ ! -f "$FILE" ]]; then
    echo "❌ Archivo no encontrado: $FILE"
    exit 1
fi

echo "📄 Extrayendo metadatos de: $FILE"

# Detectar tipo de archivo
TYPE=$(file -b "$FILE" | cut -d' ' -f1)

case "$TYPE" in
    PDF)
        echo "  → PDF..."
        pdfinfo "$FILE" > "$OUTPUT_DIR/metadatos_$(basename "$FILE").txt"
        ;;
    JPEG|PNG|TIFF)
        echo "  → Imagen..."
        exiftool "$FILE" > "$OUTPUT_DIR/exif_$(basename "$FILE").txt"
        ;;
    DOCX|XLSX|PPTX)
        echo "  → Office..."
        zipinfo -v "$FILE" > "$OUTPUT_DIR/office_$(basename "$FILE").txt"
        ;;
    *)
        echo "  → Desconocido, usando strings..."
        strings "$FILE" | head -50 > "$OUTPUT_DIR/strings_$(basename "$FILE").txt"
        ;;
esac

echo "✅ Metadatos extraídos en: $OUTPUT_DIR"
