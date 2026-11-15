#!/bin/bash
# Uso: ./auto_recon.sh <target> [opciones]
# Preview por defecto; ejecución y permisos explícitos mediante flags separados.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
if [[ $# -eq 0 ]]; then
    echo 'Uso: ./auto_recon.sh <target> [opciones]' >&2
    exit 2
fi
TARGET="$1"
shift
exec python3 -I "$ROOT/python/orchestrator.py" --target "$TARGET" --phase recon "$@"
