#!/bin/bash
# Solo pruebas aisladas de la UI de mantenimiento; no validación operacional.
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR=/tmp/opencode
python3 -B -m unittest discover -s "$FW/tests" -p test_wireless_maintenance.py -v
status=$?
exit "$status"
