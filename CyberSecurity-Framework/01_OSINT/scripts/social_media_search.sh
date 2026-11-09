#!/bin/bash
# SOCIAL MEDIA SEARCH - Perfiles observados, no URLs inventadas
# Uso: ./social_media_search.sh <empresa> [directorio_salida] [dominio]
# Ejemplo: ./social_media_search.sh 'Example Corp'
# Sin dominio de referencia, las coincidencias son candidatos sin atribución.
FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$FW_DIR/00_Config/lib${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m osint.cli social "$@"
