#!/bin/bash
# Uso: ./run_all_automation.sh [target] [opciones]
# Sin argumentos abre menú; target solo produce preview quick, nunca flujo99.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
if [[ $# -eq 0 ]]; then
    exec python3 -I "$ROOT/python/orchestrator.py" --menu
fi
if [[ "$1" != -* ]]; then
    TARGET="$1"
    shift
    exec python3 -I "$ROOT/python/orchestrator.py" --target "$TARGET" "$@"
fi
exec python3 -I "$ROOT/python/orchestrator.py" "$@"
