#!/bin/bash
# RUN ALL REPORTS — Solo lectura de evidencias, sin ejecutar módulos ni empaquetar.
# Uso: ./run_all_reports.sh <objetivo>
# Ejemplo: ./run_all_reports.sh example.invalid

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
if [[ $# -ne 1 || -z "$1" ]]; then
    echo 'Uso: ./run_all_reports.sh <objetivo>' >&2
    exit 1
fi

echo 'GENERANDO INFORMES DESDE EVIDENCIAS EXISTENTES'
result="$(bash "$MODULE_DIR/report_generator.sh" ambos --objetivo "$1" --json)"
rc=$?
if [[ $rc -eq 0 || $rc -eq 3 ]]; then
    printf '%s' "$result" | python3 -c '
import json, sys
data = json.load(sys.stdin)
print("Informes escritos en esta ejecución:")
for path in data["archivos"]:
    print("  " + path)
' || exit 1
fi
if [[ $rc -eq 0 ]]; then
    echo '✔ INFORMES COMPLETADOS (consulte cobertura y limitaciones)'
elif [[ $rc -eq 3 ]]; then
    echo '⚠ Informes escritos sin fuentes evaluables; no implica ausencia de vulnerabilidades.' >&2
else
    echo "Error al generar informes (código $rc); no se presentan informes históricos." >&2
fi
exit "$rc"
