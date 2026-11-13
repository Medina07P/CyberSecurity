#!/bin/bash
# EMAIL HARVESTER - Direcciones publicadas y APIs configuradas
# Uso: ./email_harvester.sh <dominio> [directorio_salida]
# Ejemplo: ./email_harvester.sh example.com
FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$FW_DIR/00_Config/lib${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m osint.cli emails "$@"
