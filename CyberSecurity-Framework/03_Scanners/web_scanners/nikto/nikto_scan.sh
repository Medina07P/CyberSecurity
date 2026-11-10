#!/bin/bash
# NIKTO — análisis activo del servidor web.
# Uso: ./nikto_scan.sh <URL>
# Ejemplo: ./nikto_scan.sh https://example.com
URL="${1:-}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
[[ -n "$URL" ]] || { echo 'Uso: ./nikto_scan.sh <URL>'; exit 1; }
scanner_url "$URL" && scanner_require nikto || exit 1
# Nikto divide -h por comas ANTES de analizar la URL: una coma en la ruta
# podría convertir una única URL confirmada en una lista de otros objetivos.
[[ "$URL" != *,* ]] || { echo '❌ Nikto no admite comas literales en la URL; usa %2C si corresponde.' >&2; exit 1; }
OUTPUT_DIR=$(scans_dir nikto) || exit 1
SLUG=$(scans_slug "$URL")
NIKTO_BASE="$OUTPUT_DIR/nikto_${SLUG}"
WORK=$(mktemp -d "$OUTPUT_DIR/.nikto.XXXXXX") || exit 1
trap 'rm -f "$WORK/console" "$WORK/report.txt"; rmdir "$WORK" 2>/dev/null' EXIT
NIKTO_ARGS=(-h "$URL" -o "$WORK/report" -Format txt)
[[ "$URL" == https://* ]] && NIKTO_ARGS+=(-ssl)
echo "🔬 Nikto: $URL (puede tardar varios minutos)"
rc=0
scanner_run "$OUTPUT_DIR/errores.log" nikto "${NIKTO_ARGS[@]}" >"$WORK/console" || rc=1
cat "$WORK/console"
(( rc == 0 )) || exit 1
# Nikto puede salir 0 sin conectar, o tras agotar el límite de errores.
# Exigir su resumen de UNA evaluación completa y comprobar errores propios,
# no palabras sueltas en respuestas ni stderr informativo.
if ! grep -Eq '^\+ 1 host\(s\) tested[[:space:]]*$' "$WORK/console" ||
   grep -Eiq '^\+ (ERROR:|Scan terminated:|[0-9]+ requests: [1-9][0-9]* errors?)' "$WORK/console" ||
   [[ ! -f "$WORK/report.txt" ]]; then
    {
        printf '\n[%s] nikto — evaluación incompleta (rc=0)\n' "$(date -Is)"
        cat "$WORK/console"
    } >>"$OUTPUT_DIR/errores.log"
    echo "❌ Nikto no completó la evaluación. NO DETERMINADO. Diagnóstico: $OUTPUT_DIR/errores.log" >&2
    exit 1
fi
mv "$WORK/report.txt" "${NIKTO_BASE}.txt" || exit 1
echo "✅ Ejecución completada. Revisa la evidencia, no toda línea es un hallazgo: ${NIKTO_BASE}.txt"
