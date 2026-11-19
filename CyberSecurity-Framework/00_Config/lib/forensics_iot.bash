# Module 08 IoT/portable support. Source, never execute as a leaf.
# Reuses the module runtime: private runs, sealed captures, no implicit privilege.
_FORENSICS_IOT_SOURCE="${BASH_SOURCE[0]:-$0}"
_FORENSICS_IOT_LIB="$(CDPATH= cd -- "${_FORENSICS_IOT_SOURCE%/*}" && pwd)"
source "$_FORENSICS_IOT_LIB/forensics_runtime.bash" || return 2
_FORENSICS_IOT_HELPER="$_FORENSICS_IOT_LIB/forensics_iot.py"

_iot_python() {
    python3 -B "$_FORENSICS_IOT_HELPER" "$@"
}

_iot_field() {
    printf '%s' "$1" | python3 -B -c 'import json,sys
try: print(json.load(sys.stdin)[sys.argv[1]])
except (ValueError,KeyError,TypeError): sys.exit(1)' "$2"
}

# Token directo por acción destructiva o con salida a terceros. Nunca se
# reutiliza el valor del Ejemplo ni se acepta Enter vacío.
_iot_confirm() {
    local answer
    printf 'Acción sensible explícita; escriba %s para continuar: ' "$1" >&2
    IFS= read -r answer || return 2
    [[ $answer = "$1" ]] || return 2
}

# Mismo criterio que memory_dump: root ya disponible o sudo -n preparado.
# Sin password interactivo, instalación ni escalada alternativa.
_iot_privilege() {
    IOT_PRIVILEGED=()
    (( EUID == 0 )) && return 0
    forensics_preflight privilege sudo -n true
    local status=$?
    (( ${FORENSICS_PREFLIGHT_CANCELLED:-0} == 0 )) || return 1
    if (( status != 0 )); then
        printf 'NO_EVALUABLE: se requieren privilegios ya preparados; sin escalada automática.\n' >&2
        return 2
    fi
    IOT_PRIVILEGED=(sudo -n)
}

_iot_mkdir() {
    _iot_python mkdir --path "$1"
}

_iot_reserve() {
    _iot_python reserve --path "$1"
}

# Publica un artefacto privado ya validado. El hash se calcula aquí y el lector
# lo vuelve a comprobar; el coste es deliberado.
_iot_publish() {
    local name=$1 state=$2 coverage=$3
    shift 3
    local -a artifacts=() complete=()
    local artifact
    [[ $state != COMPLETADO ]] || complete=(--complete)
    for artifact in "$@"; do
        [[ -z $artifact ]] || artifacts+=(--artifact "$artifact")
    done
    _forensics_helper step --run "$FORENSICS_RUN_DIR" --name "$name" --tool internal \
        --rc 0 --state "$state" --coverage-code "$coverage" \
        "${complete[@]}" "${artifacts[@]}" >/dev/null
}

# Guarda de dispositivo compartida por adquisición y esterilización. Rechaza
# dispositivos virtuales, montados, con particiones montadas o con tamaño
# distinto al declarado. Nunca monta, desmonta ni escribe.
_iot_device_guard() {
    local mode=$1 source=$2 size_mib=${3:-}
    local -a extra=()
    [[ -z $size_mib ]] || extra=(--size-mib "$size_mib")
    IOT_DEVICE_JSON=$(_iot_python device-guard --mode "$mode" --source "$source" "${extra[@]}") || return 2
    IOT_DEVICE_MIB=$(_iot_field "$IOT_DEVICE_JSON" size_mib) || return 1
    IOT_DEVICE_SIZE=$(_iot_field "$IOT_DEVICE_JSON" size_bytes) || return 1
    IOT_DEVICE_NAME=$(_iot_field "$IOT_DEVICE_JSON" name) || return 1
}

# Las rutas de informe viven siempre en analysis/ del run privado.
_iot_analysis_file() {
    local name=$1
    [[ $name != */* && -n $name ]] || return 2
    printf '%s/analysis/%s\n' "$FORENSICS_RUN_DIR" "$name"
}

_iot_utc_stamp() {
    date -u +%Y%m%dT%H%M%SZ 2>/dev/null || python3 -B -c \
        'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))'
}
