#!/bin/bash
# Coordinación explícita; sin ejecución de hermanos ni captura implícita.
# Uso: ./run_all_evidence.sh [OPCIONES]
# Ejemplo: ./run_all_evidence.sh --offline

EVIDENCE_DIR="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)" || exit 1
HELPER="$EVIDENCE_DIR/../00_Config/lib/evidence/cli.py"
if ! command -v python3 >/dev/null 2>&1; then
    echo 'ERROR: Python 3 no disponible' >&2
    exit 1
fi
if [[ ! -f "$HELPER" || -L "$HELPER" ]]; then
    echo 'ERROR: auxiliar de evidencias no disponible' >&2
    exit 1
fi
exec python3 -B "$HELPER" --root "$EVIDENCE_DIR" run "$@"
