#!/bin/bash
# STRINGS ANALYSIS — indicadores textuales, no incidentes probados.
# Uso: ./strings_analysis.sh <FILE>
# Ejemplo: ./strings_analysis.sh memory.bin
LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB_DIR/forensics_runtime.bash" || exit 2
TEXT_HELPER="$LIB_DIR/forensics_timeline.py"
[[ $# = 1 ]] || { printf 'Uso: ./strings_analysis.sh <FILE>\n' >&2; exit 2; }
input=$1
[[ $input = /* ]] || input="$PWD/$input"
forensics_require strings || exit 2
forensics_require grep || exit 2
python3 -B "$TEXT_HELPER" validate --work "$input" --kind file --root "${FORENSICS_ANALYSIS_ROOT:-$_FORENSICS_MODULE/analysis}/runs" || exit 2
printf 'Se copiará y verificará íntegramente la entrada; requiere espacio y tiempo.\n' >&2
forensics_begin strings offline || exit $?
work=$(forensics_stage "$input") || { forensics_finish; exit 1; }
text_filter() { python3 -B "$TEXT_HELPER" filter --filter "$1" --work "$2"; }
text_summary() { python3 -B "$TEXT_HELPER" summary --run "$FORENSICS_RUN_DIR" --work "$1"; }
export TEXT_HELPER
forensics_capture strings strings -n 8 -- "$work"
rc=$?
if (( rc != 0 )); then
    forensics_complete_step strings FALLIDO strings_extraction_failed || :
    forensics_finish; exit 1
fi
strings_output=$FORENSICS_STEP_OUT
forensics_complete_step strings COMPLETADO strings_extracted || { forensics_finish; exit 1; }
for name in sensitive urls emails; do
    forensics_capture "$name" text_filter "$name" "$strings_output"
    rc=$?
    state=COMPLETADO; coverage=text_filter_evaluated
    if (( rc != 0 )); then state=FALLIDO; coverage=text_filter_failed; fi
    forensics_complete_step "$name" "$state" "$coverage" || { forensics_finish; exit 1; }
done
forensics_capture summary text_summary "$work"
rc=$?
state=COMPLETADO; (( rc == 0 )) || state=FALLIDO
forensics_complete_step summary "$state" private_counts || { forensics_finish; exit 1; }
forensics_finish
exit $?
