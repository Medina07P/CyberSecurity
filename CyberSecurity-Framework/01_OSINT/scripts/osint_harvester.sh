#!/bin/bash
# OSINT HARVESTER - WHOIS, web, correos, certificados y DNS compartidos
# Uso: ./osint_harvester.sh <dominio> [directorio_salida]
# Ejemplo: ./osint_harvester.sh example.com
FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$FW_DIR/00_Config/lib${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m osint.cli domains "$@"
