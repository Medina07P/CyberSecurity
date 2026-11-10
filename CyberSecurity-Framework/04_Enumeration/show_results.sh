#!/bin/bash
# Visor local: sin argumentos usa sesión; si no existe, muestra todo etiquetado.
# Uso: ./show_results.sh [objetivo]
# Ejemplo: ./show_results.sh example.com
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../00_Config/lib" && pwd)"
source "$LIB/scans.bash"
source "$LIB/session.bash"
TARGET="${1:-$(session_target)}"
python3 "$LIB/enumeration_evidence.py" list --root "$(scans_root)" --host "$TARGET"
