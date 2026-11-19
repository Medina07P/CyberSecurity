#!/bin/bash

# Triaje de archivos recuperados: hash, familia y metadatos opcionales.
# Uso: ./iot_triage.sh <DIR> [--investigator NOMBRE] [--exiftool] [--exiftool-limit N]
# Ejemplo: ./iot_triage.sh recovered/run-0123456789abcdef0123456789abcdef
# El directorio se copia y verifica íntegro antes de analizarlo: prever espacio.
# Un hash o una firma no demuestran autoría, intención ni malware.
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
source "$script_dir/../../00_Config/lib/forensics_iot.bash" || exit 2
usage() {
    printf 'Uso: iot_triage.sh <DIR> [--investigator NOMBRE] [--exiftool] [--exiftool-limit N]\n' \
        'Ejemplo: iot_triage.sh recovered/run-<32hex>\n' \
        'Genera report.json y report.md privados en analysis/ del run.\n' >&2
}
root=; investigator=; use_exiftool=0; exiftool_limit=200
while (( $# )); do
    case "$1" in
        --investigator) (( $# >= 2 )) && [[ -n $2 ]] || { usage; exit 2; }; investigator=$2; shift ;;
        --exiftool) use_exiftool=1 ;;
        --exiftool-limit) (( $# >= 2 )) && [[ $2 =~ ^[0-9]+$ ]] || { usage; exit 2; }; exiftool_limit=$2; shift ;;
        --help) usage; exit 0 ;;
        --*) usage; exit 2 ;;
        *) [[ -z $root ]] || { usage; exit 2; }; root=$1 ;;
    esac
    shift
done
[[ -n $root ]] || { usage; exit 2; }
[[ $root = /* ]] || root="$PWD/$root"
[[ -d $root ]] || { printf 'NO_EVALUABLE: el directorio no existe.\n' >&2; exit 2; }
forensics_require python3 || exit 2
if (( use_exiftool )); then
    forensics_require exiftool || {
        printf 'NO_EVALUABLE: --exiftool solicitado y exiftool no está disponible.\n' >&2
        exit 2
    }
fi
printf 'Se copiará y verificará el árbol completo; requiere espacio y tiempo.\n' >&2
forensics_begin triage offline || exit $?
work=$(forensics_stage "$root" tree) || { forensics_finish; exit 1; }
report_json=$(_iot_analysis_file report.json) || { forensics_finish; exit 1; }
report_md=$(_iot_analysis_file report.md) || { forensics_finish; exit 1; }
iot_triage_step() {
    local helper=$1 root=$2 json=$3 md=$4 investigator=$5 limit=$6 exiftool=$7
    local -a extra=()
    (( exiftool )) && extra=(--exiftool)
    python3 -B "$helper" triage --root "$root" --json "$json" --md "$md" \
        --investigator "$investigator" --exiftool-limit "$limit" "${extra[@]}"
}
forensics_capture triage iot_triage_step "$_FORENSICS_IOT_HELPER" "$work" \
    "$report_json" "$report_md" "$investigator" "$exiftool_limit" "$use_exiftool"
status=$?
(( ${_FORENSICS_CANCELLED:-0} == 0 )) || exit 1
failed=0
state=COMPLETADO; coverage=triage_completed
if (( status != 0 )); then state=FALLIDO; coverage=triage_failed; failed=1; fi
# Un árbol vacío es un resultado legítimo pero no evaluable como triaje útil.
total=$(python3 -B -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["resumen"]["total"])
except (OSError,ValueError,KeyError,TypeError): print(-1)' "$report_json" 2>/dev/null)
[[ $total =~ ^[0-9]+$ ]] || total=-1
if (( total == 0 )); then state=NO_EVALUABLE; coverage=empty_tree; failed=1; fi
forensics_complete_step triage "$state" "$coverage" || { forensics_finish; exit 1; }
report_bytes=$(python3 -B -c 'import os,sys
try: print(sum(os.stat(p).st_size for p in sys.argv[1:]))
except OSError: print(0)' "$report_json" "$report_md" 2>/dev/null)
if [[ $state = FALLIDO ]]; then
    printf 'Triaje fallido: no se publican informes incompletos.\n' >&2
    failed=1
elif [[ ${report_bytes:-0} =~ ^[1-9][0-9]*$ ]]; then
    _iot_publish triage_report "$state" triage_report "$report_json" "$report_md" || {
        _forensics_block; failed=1;
    }
else
    printf 'El triaje no produjo informes utilizables; no se publican artefactos.\n' >&2
    failed=1
fi
printf 'Informe privado: %s\n' "$report_md"
forensics_finish || failed=1
(( failed == 0 ))
