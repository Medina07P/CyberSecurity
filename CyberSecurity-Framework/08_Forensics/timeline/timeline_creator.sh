#!/bin/bash
# TIMELINE CREATOR — fuentes seleccionadas; no prueba una cronología.
# Uso: ./timeline_creator.sh [OUTPUT_DIR] [--journal FILE] [--auth FILE] [--syslog FILE] [--dpkg FILE] [--wtmp FILE] [--tree DIR] [--year YYYY] [--timezone IANA] [--local]
# Ejemplo: ./timeline_creator.sh --journal journal.jsonl --timezone UTC
LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB_DIR/forensics_runtime.bash" || exit 2
TIMELINE_HELPER="$LIB_DIR/forensics_timeline.py"
usage() {
    printf 'Uso: ./timeline_creator.sh [OUTPUT_DIR] [--journal FILE] [--auth FILE] [--syslog FILE] [--dpkg FILE] [--wtmp FILE] [--tree DIR] [--year YYYY] [--timezone IANA] [--local]\n' >&2
    printf 'Sin fuentes: NO_EVALUABLE. --local requiere LOCAL_SI y consulta fragmentos históricos del host.\n' >&2
}
output_root="${FORENSICS_ANALYSIS_ROOT:-$LIB_DIR/../../08_Forensics/analysis}/runs"
if (( $# )) && [[ $1 != --* ]]; then output_root=$1; shift; fi
mode=offline
declare -a kinds=() sources=() works=() options=()
while (( $# )); do
    case $1 in
        --journal|--auth|--syslog|--dpkg|--wtmp|--tree)
            (( $# >= 2 )) || { usage; exit 2; }
            kinds+=("${1#--}"); sources+=("$2"); shift 2 ;;
        --year|--timezone)
            (( $# >= 2 )) || { usage; exit 2; }
            options+=("$1" "$2"); shift 2 ;;
        --local) mode=local; shift ;;
        --help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done
if [[ $mode = local ]]; then
    (( ${#sources[@]} == 0 )) || { usage; exit 2; }
    printf 'Modo local: journal 24h/100, last20, SSH20, find / modificado24h/20, dpkg10. Datos sensibles; cobertura fragmentaria. Escriba LOCAL_SI: ' >&2
    IFS= read -r answer || exit 2
    [[ $answer = LOCAL_SI ]] || exit 2
    kinds=(journal wtmp auth tree dpkg)
elif (( ${#sources[@]} == 0 )); then usage; exit 2
fi
python3 -B "$TIMELINE_HELPER" validate "${options[@]}" || exit 2
if [[ $mode = offline ]]; then
    for i in "${!sources[@]}"; do
        [[ ${sources[i]} = /* ]] || sources[i]="$PWD/${sources[i]}"
        if [[ ${kinds[i]} = wtmp ]]; then forensics_require last || exit 2; fi
        python3 -B "$TIMELINE_HELPER" validate --work "${sources[i]}" --kind "${kinds[i]}" --root "$output_root" || exit 2
    done
fi
printf 'Se copiarán y verificarán las fuentes offline completas; requiere espacio y tiempo.\n' >&2
forensics_begin timeline "$mode" "$output_root" || exit $?
if [[ $mode = offline ]]; then
    for i in "${!sources[@]}"; do
        kind=file; [[ ${kinds[i]} != tree ]] || kind=tree
        work=$(forensics_stage "${sources[i]}" "$kind") || { forensics_finish; exit 1; }
        works+=("$work")
    done
fi
timeline_source() { python3 -B "$TIMELINE_HELPER" "$@"; }
export TIMELINE_HELPER
declare -a results=() names=()
successes=0
for i in "${!kinds[@]}"; do
    name="source_${i}_${kinds[i]}"; names+=("$name")
    if [[ $mode = offline ]]; then
        forensics_capture "$name" timeline_source source --run "$FORENSICS_RUN_DIR" --kind "${kinds[i]}" --work "${works[i]}" "${options[@]}"
    else
        forensics_capture "$name" timeline_source local --kind "${kinds[i]}" "${options[@]}"
    fi
    rc=$?; results+=("$rc")
    (( rc != 0 )) || ((successes+=1))
done
for i in "${!names[@]}"; do
    state=COMPLETADO; coverage=selected_source_evaluated
    if (( results[i] != 0 )); then
        state=FALLIDO; (( successes == 0 )) || state=PARCIAL
        coverage=selected_source_failed
    elif [[ $mode = local ]]; then state=PARCIAL; coverage=historical_fragment; fi
    forensics_complete_step "${names[i]}" "$state" "$coverage" || { forensics_finish; exit 1; }
done
python3 -B "$TIMELINE_HELPER" assemble --run "$FORENSICS_RUN_DIR" "${options[@]}" || { _forensics_block; forensics_finish; exit 1; }
forensics_finish
exit $?
