#!/bin/bash
# SMB estable: preview por defecto; ejecución y generación separadas.
# Uso: ./enum_smb.sh <HOST> [PREFIJO] [--execute]
# Generación opcional: ./enum_smb.sh --generate DESTINO
LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../00_Config/lib" && pwd)" || exit 1
exec python3 -I -B "$LIB/consent/stable_cli.py" smb "$@"
