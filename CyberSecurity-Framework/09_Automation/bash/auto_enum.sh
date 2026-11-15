#!/bin/bash
# Uso: ./auto_enum.sh <target> [opciones]
# Preview por defecto; usuarios y acceso anónimo requieren gates separados.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
if [[ $# -eq 0 ]]; then
    echo 'Uso: ./auto_enum.sh <target> [opciones]' >&2
    exit 2
fi
TARGET="$1"
shift
exec python3 -I "$ROOT/python/orchestrator.py" --target "$TARGET" --phase enum "$@"
