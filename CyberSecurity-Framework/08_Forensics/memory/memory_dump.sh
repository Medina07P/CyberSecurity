#!/bin/bash

# Adquisición LOCAL explícita; no demuestra una instantánea íntegra de RAM.
# Uso: ./memory_dump.sh [OUTPUT_DIR] [--method METODO]
# Ejemplo: ./memory_dump.sh --method avml
# METODO: auto, avml, lime o dd. OUTPUT_DIR es padre, nunca un destino reutilizado.
# dd es exclusivamente una muestra histórica de hasta 1GiB, siempre PARCIAL.
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
source "$script_dir/../../00_Config/lib/forensics_runtime.bash" || exit 2
method=auto; parent=
while (( $# )); do
    case "$1" in
        --method) (( $# >= 2 )) || exit 2; method=$2; shift ;;
        --*) exit 2 ;;
        *) [[ -z $parent ]] || exit 2; parent=$1 ;;
    esac
    shift
done
case "$method" in auto|avml|lime|dd) ;; *) exit 2 ;; esac
printf 'Adquisición local privilegiada; RAM completa no verificada. dd: muestra 1GiB.\nEscribe ADQUIRIR_MEMORIA para continuar: ' >&2
IFS= read -r answer && [[ $answer = ADQUIRIR_MEMORIA ]] || exit 2

# Conservar privilegio histórico, solo dentro de la acción confirmada. Sin
# password interactivo, instalación, carga de módulo ni escalada alternativa.
privileged=()
if ! (( EUID == 0 )); then
    forensics_preflight privilege sudo -n true
    probe_status=$?
    (( ${FORENSICS_PREFLIGHT_CANCELLED:-0} == 0 )) || exit 1
    (( probe_status == 0 )) || {
        printf 'NO_EVALUABLE: faltan privilegios preparados.\n' >&2; exit "$probe_status";
    }
    privileged=(sudo -n)
fi

# Una CLI preparada debe identificarse y publicar la sintaxis que invocaremos.
# Un módulo LiME o un ejecutable homónimo NO acredita una CLI compatible.
recognize_memory_backend() {
    local help
    command -v "$1" >/dev/null 2>&1 || return 2
    forensics_preflight compatibility "$1" --help
    probe_status=$?
    # Cancellation/timeout/control failure are terminal, never auto-fallback.
    (( ${FORENSICS_PREFLIGHT_CANCELLED:-0} == 0 )) || exit 1
    (( ${FORENSICS_PREFLIGHT_TIMED_OUT:-0} == 0 )) || exit 2
    (( probe_status != 1 )) || exit 1
    (( probe_status == 0 )) || return 2
    help=$FORENSICS_PREFLIGHT_OUTPUT
    case "$1" in
        avml) [[ ${help,,} = *avml* && ${help,,} = *usage:* &&
                  ( $help = *'<FILENAME>'* || $help = *'<OUTPUT>'* ) ]] ;;
        lime) [[ $help = *LiME* && ${help,,} = *usage:* &&
                  $help = *'-o <OUTPUT>'* ]] ;;
        *) return 2 ;;
    esac
}
if [[ $method = auto ]]; then
    if recognize_memory_backend avml; then method=avml
    elif recognize_memory_backend lime; then method=lime
    else printf 'NO_EVALUABLE: AVML/LiME preparados no disponibles; dd solo explícito.\n' >&2; exit 2; fi
elif [[ $method = dd ]]; then
    forensics_require dd || exit 2
else
    recognize_memory_backend "$method" || {
        printf 'NO_EVALUABLE: backend ausente o CLI no reconocida.\n' >&2; exit 2;
    }
fi
forensics_require uname || exit 2
forensics_require cat || exit 2
forensics_begin memory local || exit $?
products=$(forensics_register_root captures "${parent:-$FORENSICS_MEMORY_ROOT}") || exit $?
ram="$products/memory.raw"
# Reserve privately before handing a NEW path to the selected writer.
python3 -B - "$ram" <<'PY'
import os, sys
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
os.close(fd)
PY
if (( $? != 0 )); then _forensics_block; exit 1; fi
case "$method" in
    avml) forensics_capture acquire "${privileged[@]}" avml "$ram" ;;
    lime) forensics_capture acquire "${privileged[@]}" lime -o "$ram" ;;
    dd) forensics_capture acquire "${privileged[@]}" dd if=/dev/mem of="$ram" bs=1M count=1024 ;;
esac
capture_status=$?
# A cancellation may have closed the run. Never publish over finalized streams.
(( ${_FORENSICS_CANCELLED:-0} == 0 )) || exit 1
backend_rc=$FORENSICS_STEP_RC
state=$(python3 -B - "$ram" "$products/memory.json" "$method" "$backend_rc" <<'PY'
import json, os, stat, sys
from pathlib import Path
p=Path(sys.argv[1]); method=sys.argv[3]; rc=int(sys.argv[4]); size=None
try:
    s=p.lstat()
    if stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==os.getuid(): size=s.st_size
except FileNotFoundError: pass
metadata=dict(method=method,bytes=size,completitud_memoria='no_verificada',sample=method=='dd')
fd=os.open(sys.argv[2],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f: json.dump(metadata,f)
print('FALLIDO' if rc else 'NO_EVALUABLE' if not size or method=='dd' and size>1073741824 else 'PARCIAL' if method=='dd' else 'COMPLETADO')
PY
) || { _forensics_block; exit 1; }
failed=0
if (( capture_status != 0 )); then failed=1; state=FALLIDO; fi
forensics_complete_step acquire "$state" memory_structure_checked || failed=1
# Product publication is independent of the sealed stdout/stderr capture.
# Invalid/missing RAM is NOT published as a usable memory image.
artifacts=(--artifact "$products/memory.json")
if [[ $state = COMPLETADO || $state = PARCIAL ]]; then artifacts+=(--artifact "$ram"); fi
_forensics_helper step --run "$FORENSICS_RUN_DIR" --name memory_product --tool memory_product \
    --state COMPLETADO --complete --rc 0 --coverage-code memory_metadata "${artifacts[@]}" >/dev/null || {
        _forensics_block; failed=1;
    }

memory_system_information() {
    local status=0 cat_status=0
    uname -a || status=$?
    cat /etc/os-release || cat_status=$?
    (( status != 0 )) || status=$cat_status
    return "$status"
}
forensics_capture system_information memory_system_information || failed=1
(( ${_FORENSICS_CANCELLED:-0} == 0 )) || exit 1
if (( FORENSICS_STEP_RC == 0 )); then system_state=COMPLETADO; else system_state=FALLIDO; fi
forensics_complete_step system_information "$system_state" local_system_information || failed=1
printf 'Método: %s; RAM: %s; completitud_memoria=no_verificada.\n' "$method" "$state"
forensics_finish || failed=1
(( failed == 0 ))
