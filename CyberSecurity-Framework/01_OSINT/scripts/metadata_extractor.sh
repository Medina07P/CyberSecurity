#!/bin/bash
# METADATA EXTRACTOR - Archivos locales; fallos del extractor explícitos
# Uso: ./metadata_extractor.sh <archivo> [directorio_salida]
# Ejemplo: ./metadata_extractor.sh documento.pdf
FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$FW_DIR/00_Config/lib${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m osint.cli metadata "$@"
