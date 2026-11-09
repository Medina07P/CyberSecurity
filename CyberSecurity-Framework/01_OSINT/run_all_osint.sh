#!/bin/bash
# RUN ALL OSINT - Una sesión coordinada, sin duplicar fuentes
# Uso: ./run_all_osint.sh <dominio> [archivo] [empresa]
# Ejemplo: ./run_all_osint.sh example.com
# Metadatos solo con archivo local. Sin fuerza bruta ni AXFR automáticos.
# Para dar empresa sin archivo: ./run_all_osint.sh example.com '' 'Example Corp'
FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$FW_DIR/00_Config/lib${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m osint.cli all "$@"
