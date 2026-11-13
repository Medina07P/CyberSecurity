#!/bin/bash
# Flujo por fuentes elegidas. No IP, glob, adquisición ni lectura local implícita.
# Uso: ./run_all_forensics.sh [--memory FILE] [--log FILE] [--pcap FILE] [--disk FILE] [--timeline-auth FILE] [--local]
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
module_dir=$(CDPATH= cd -- "$script_dir" && pwd) || exit 2
helper="$module_dir/../00_Config/lib/forensics_evidence.py"
usage() {
    printf 'Uso: run_all_forensics.sh [--memory FILE] [--log FILE] [--pcap FILE] [--disk FILE] [--timeline-auth FILE] [--local]\nSin fuentes no hay trabajo. Seleccione archivos offline en el menú 08. --memory ejecuta strings; Volatility Windows se selecciona aparte con perfil/símbolos locales.\n--local: adquisición RAM, strings sobre producto validado, log del host y timeline local; confirmaciones separadas.\n' >&2
}
local_mode=0
declare -a flags=() sources=()
while (( $# )); do
    case $1 in
        --memory|--log|--pcap|--disk|--timeline-auth)
            (( $# >= 2 )) && [[ -n $2 ]] || { usage; exit 2; }
            for flag in "${flags[@]}"; do [[ $flag != "$1" ]] || { usage; exit 2; }; done
            flags+=("$1"); sources+=("$2"); shift 2 ;;
        --local) (( local_mode == 0 )) || { usage; exit 2; }; local_mode=1; shift ;;
        --help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done
(( local_mode || ${#sources[@]} )) || { usage; exit 2; }
# Preflight metadata only. An invalid source blocks itself, not independent
# selected files; if none can start, return 2 without creating a fake run/log.
declare -a valid=() valid_sources=()
invalid_count=0
for i in "${!sources[@]}"; do
    [[ ${sources[i]} = /* ]] || sources[i]="$PWD/${sources[i]}"
    if python3 -B "$helper" probe-source --source="${sources[i]}" --kind file >/dev/null; then
        valid+=(1); valid_sources+=("${sources[i]}")
    else
        valid+=(0); (( invalid_count+=1 ))
    fi
done
(( local_mode || ${#valid_sources[@]} )) || exit 2
if (( local_mode )); then
    printf 'FLUJO LOCAL: datos sensibles del host; RAM nueva obligatoria antes de logs/timeline. Escriba FLUJO_LOCAL: ' >&2
    IFS= read -r answer && [[ $answer = FLUJO_LOCAL ]] || exit 2
fi
umask 077
# No fake forensic run for the coordinator: only a private, unique transcript.
workflow_dir=$(python3 -B - "$helper" "${FORENSICS_ANALYSIS_ROOT:-$module_dir/analysis}" "${valid_sources[@]}" <<'PY'
import os, sys, tempfile, types
from pathlib import Path
e=types.ModuleType('e'); e.__file__=sys.argv[1]
exec(compile(Path(sys.argv[1]).read_bytes(),sys.argv[1],'exec'),e.__dict__)
try:
    parent=e._path(sys.argv[2])/'workflows'
    for source in sys.argv[3:]:
        e._require(not e._overlaps(parent,e._path(source)))
    e._mkdir(parent)
    path=Path(tempfile.mkdtemp(prefix='flow-',dir=parent))
    fd=os.open(path/'workflow.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    os.close(fd)
    print(path)
except (OSError,ValueError):
    print('NO_EVALUABLE: destino de flujo inválido.',file=sys.stderr); sys.exit(2)
PY
) || exit 2
log="$workflow_dir/workflow.log"
executed=0; failed=$invalid_count; omitted=$((5 - ${#sources[@]} + invalid_count)); attempted=0; began=0
(( invalid_count == 0 )) || printf 'selected_source precondition_failed=%d\n' "$invalid_count" >>"$log"
flow_step() {
    local label=$1 leaf=$2 status
    shift 2
    (( attempted+=1 ))
    bash "$module_dir/$leaf" "$@" >>"$log" 2>&1
    status=$?
    (( executed+=1 ))
    (( status == 2 )) || (( began+=1 ))
    (( status == 0 )) || (( failed+=1 ))
    printf '%s rc=%d\n' "$label" "$status" >>"$log"
    return "$status"
}
if (( local_mode )); then
    # A new, isolated analysis root makes this acquisition unambiguous. Never
    # search the historical RAM tree. The leaf receives stdin directly.
    (( attempted+=1 ))
    FORENSICS_ANALYSIS_ROOT="$workflow_dir/acquisition" bash "$module_dir/memory/memory_dump.sh" >>"$log"
    status=$?; (( executed+=1 ))
    (( status == 2 )) || (( began+=1 ))
    printf 'memory_acquisition rc=%d\n' "$status" >>"$log"
    ram=
    if (( status == 0 )); then
        ram=$(python3 -B - "$helper" "$workflow_dir/acquisition/runs" <<'PY'
import json, sys, types
from pathlib import Path
e=types.ModuleType('e'); e.__file__=sys.argv[1]
exec(compile(Path(sys.argv[1]).read_bytes(),sys.argv[1],'exec'),e.__dict__)
try:
    runs=list(e._path(sys.argv[2]).iterdir())
    e._require(len(runs)==1)
    run=runs[0]; data=e.read_run(run)  # authenticates roots, refs, hashes/sidecars
    e._require(data['operation']=='memory' and data['mode']=='local' and
               data['finished'] is not None and data['complete'] and data['rc']==0 and
               not data['dependents_blocked'])
    acquire=[s for s in data['steps'] if s['name']=='acquire']
    products=[s for s in data['steps'] if s['name']=='memory_product']
    e._require(len(acquire)==len(products)==1 and acquire[0]['state']=='COMPLETADO' and
               acquire[0]['rc']==0 and products[0]['state']=='COMPLETADO')
    refs=products[0]['artifacts']
    raw=[r for r in refs if r['root']=='captures' and r['path']=='memory.raw']
    meta=[r for r in refs if r['root']=='captures' and r['path']=='memory.json']
    e._require(len(raw)==len(meta)==1 and raw[0]['size']>0)
    roots=e._artifact_roots(run,data)
    metadata=e._load(roots['captures']/meta[0]['path'])
    e._require(set(metadata)=={'method','bytes','completitud_memoria','sample'} and
               metadata['method'] in ('avml','lime') and metadata['sample'] is False and
               type(metadata['bytes']) is int and metadata['bytes']==raw[0]['size'] and
               metadata['completitud_memoria']=='no_verificada')
    print(roots['captures']/raw[0]['path'])
except (ValueError,OSError,KeyError,TypeError):
    print('NO_EVALUABLE: RAM nueva no validada; dependientes locales bloqueados.',file=sys.stderr)
    sys.exit(1)
PY
) || status=1
    fi
    if (( status != 0 )); then
        (( failed+=1 )); (( omitted+=3 ))
        printf 'RAM denegada/fallida: no se consultan logs ni timeline del host.\n' >&2
    else
        # Linux RAM is not a supported Windows Volatility image by assumption.
        flow_step acquired_strings memory/strings_analysis.sh "$ram" || :
        printf 'Lectura del log del host /var/log/syslog. Escriba LEER_LOG_LOCAL: ' >&2
        if IFS= read -r answer && [[ $answer = LEER_LOG_LOCAL ]]; then
            flow_step host_log logs/log_analyzer.sh /var/log/syslog || :
            # The timeline leaf obtains its OWN LOCAL_SI confirmation directly.
            (( attempted+=1 ))
            bash "$module_dir/timeline/timeline_creator.sh" --local >>"$log"
            status=$?; (( executed+=1 )); (( status == 0 )) || (( failed+=1 ))
            (( status == 2 )) || (( began+=1 ))
            printf 'local_timeline rc=%d\n' "$status" >>"$log"
        else
            (( failed+=1 )); (( omitted+=2 ))
        fi
    fi
else
    (( omitted+=4 ))
fi
for i in "${!sources[@]}"; do
    [[ ${valid[i]} = 1 ]] || continue
    case ${flags[i]} in
        --memory) flow_step strings memory/strings_analysis.sh "${sources[i]}" || : ;;
        --log) flow_step logs logs/log_analyzer.sh "${sources[i]}" || : ;;
        --pcap) flow_step pcap pcaps/pcap_analyzer.sh "${sources[i]}" || : ;;
        --disk) flow_step disk disk/disk_forensics.sh "${sources[i]}" || : ;;
        --timeline-auth) flow_step timeline timeline/timeline_creator.sh --auth "${sources[i]}" || : ;;
    esac
done
printf 'Flujo: ejecutadas=%d fallidas=%d omitidas=%d. Diagnósticos privados en analysis/workflows; no equivalen a hallazgos.\n' "$executed" "$failed" "$omitted" >&2
printf 'ejecutadas=%d fallidas=%d omitidas=%d\n' "$executed" "$failed" "$omitted" >>"$log"
(( began > 0 )) || exit 2
(( failed == 0 && attempted > 0 ))
