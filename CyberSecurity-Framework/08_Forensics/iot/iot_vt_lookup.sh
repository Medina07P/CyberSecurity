#!/bin/bash

# Consulta VirusTotal v3 SOLO con hashes de un triaje ya validado.
# Uso: ./iot_vt_lookup.sh <RUN_DIR> [--limit N] [--delay SEGUNDOS]
# Ejemplo: ./iot_vt_lookup.sh analysis/runs/run-0123456789abcdef0123456789abcdef
# Requiere VT_API_KEY en el entorno; nunca se guarda ni se imprime.
# Salida a un tercero: confirma que puedes compartir esos hashes.
# La API pública limita a 4 consultas/minuto; --delay por defecto 16 segundos.
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
source "$script_dir/../../00_Config/lib/forensics_iot.bash" || exit 2
usage() {
    printf 'Uso: iot_vt_lookup.sh <RUN_DIR> [--limit N] [--delay SEGUNDOS] [--api-base URL]\n' \
        'Ejemplo: iot_vt_lookup.sh analysis/runs/run-<32hex>\n' \
        'El run debe ser un triaje finalizado con report.json. VT_API_KEY es obligatoria.\n' \
        '--limit 0 consulta todos los hashes; --api-base solo admite VirusTotal o loopback.\n' >&2
}
run=; limit=4; delay=16; api_base=https://www.virustotal.com/api/v3
while (( $# )); do
    case "$1" in
        --limit) (( $# >= 2 )) && [[ $2 =~ ^[0-9]+$ ]] || { usage; exit 2; }; limit=$2; shift ;;
        --delay) (( $# >= 2 )) && [[ $2 =~ ^[0-9]+([.][0-9]+)?$ ]] || { usage; exit 2; }; delay=$2; shift ;;
        --api-base) (( $# >= 2 )) && [[ -n $2 ]] || { usage; exit 2; }; api_base=$2; shift ;;
        --help) usage; exit 0 ;;
        --*) usage; exit 2 ;;
        *) [[ -z $run ]] || { usage; exit 2; }; run=$1 ;;
    esac
    shift
done
[[ -n $run ]] || { usage; exit 2; }
[[ $run = /* ]] || run="$PWD/$run"
forensics_require python3 || exit 2
_forensics_helper validate --run "$run" >/dev/null || {
    printf 'NO_EVALUABLE: el run no es válido o no es un triaje finalizado.\n' >&2
    exit 2
}
report=$(_iot_python report-path --run "$run") || exit 2
if [[ -z ${VT_API_KEY:-} ]]; then
    printf 'NO_EVALUABLE: falta VT_API_KEY en el entorno; no se consulta nada.\n' >&2
    exit 2
fi
_iot_confirm CONSULTAR_VIRUSTOTAL || exit 2
_iot_python vt-check --api-base "$api_base" --delay "$delay" >/dev/null || {
    printf 'NO_EVALUABLE: destino de API no admisible; no se consulta nada.\n' >&2
    exit 2
}
[[ -f $report ]] || { printf 'NO_EVALUABLE: report.json ausente.\n' >&2; exit 2; }
forensics_begin lookup network || exit $?
vt_json=$(_iot_analysis_file vt.json) || { forensics_finish; exit 1; }
vt_md=$(_iot_analysis_file vt.md) || { forensics_finish; exit 1; }
iot_vt_step() {
    local helper=$1 report=$2 json=$3 md=$4 api=$5 delay=$6 limit=$7
    python3 -B "$helper" vt --report "$report" --json "$json" --md "$md" \
        --api-base "$api" --delay "$delay" --limit "$limit"
}
forensics_capture virustotal iot_vt_step "$_FORENSICS_IOT_HELPER" "$report" \
    "$vt_json" "$vt_md" "$api_base" "$delay" "$limit"
status=$?
(( ${_FORENSICS_CANCELLED:-0} == 0 )) || exit 1
failed=0
state=COMPLETADO; coverage=virustotal_completed
case "$status" in
    0) ;;
    1) state=PARCIAL; coverage=virustotal_partial; failed=1 ;;
    *) state=FALLIDO; coverage=virustotal_failed; failed=1 ;;
esac
forensics_complete_step virustotal "$state" "$coverage" || { forensics_finish; exit 1; }
report_bytes=$(python3 -B -c 'import os,sys
try: print(sum(os.stat(p).st_size for p in sys.argv[1:]))
except OSError: print(0)' "$vt_json" "$vt_md" 2>/dev/null)
if [[ ${report_bytes:-0} =~ ^[1-9][0-9]*$ ]]; then
    _iot_publish virustotal_report "$state" "$coverage" "$vt_json" "$vt_md" || {
        _forensics_block; failed=1;
    }
else
    printf 'Sin informe utilizable: no se publican artefactos de la consulta.\n' >&2
    failed=1
fi
printf 'Informe privado: %s\n' "$vt_md"
forensics_finish || failed=1
(( failed == 0 ))
