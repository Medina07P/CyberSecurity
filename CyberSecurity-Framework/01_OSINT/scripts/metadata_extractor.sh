#!/bin/bash
# ============================================================
#  METADATA EXTRACTOR - Extrae metadatos de archivos
#  Uso: ./metadata_extractor.sh <archivo>
# ============================================================

FILE="$1"
# Salida junto al módulo, independiente del cwd desde el que se lance
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${2:-$MODULE_DIR/metadata}"

if [[ -z "$FILE" ]]; then
    echo "Uso: ./metadata_extractor.sh <archivo>"
    echo "Ejemplo: ./metadata_extractor.sh documento.pdf"
    exit 1
fi

if [[ ! -f "$FILE" ]]; then
    case "$FILE" in
        /*) RUTA_BUSCADA="$FILE" ;;
        *)  RUTA_BUSCADA="$PWD/$FILE" ;;
    esac
    echo "❌ Archivo no encontrado: $FILE"
    echo "   Se buscó en: $RUTA_BUSCADA"
    echo "   Las rutas relativas se resuelven desde el directorio en el que se ejecuta"
    echo "   el script; también puedes pasar una ruta absoluta."
    exit 1
fi

echo "📄 Extrayendo metadatos de: $FILE"
mkdir -p "$OUTPUT_DIR"

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
