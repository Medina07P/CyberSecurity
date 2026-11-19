#!/bin/bash

# Esterilización de un soporte portátil: borrado y, opcional, formateo FAT.
# Uso: ./iot_sterilize.sh <DEVICE> --size-mib N [--wipe zeros|urandom|both] [--passes N] [--filesystem none|vfat]
# Ejemplo: ./iot_sterilize.sh /dev/sdb --size-mib 14901
# DESTRUCTIVO e IRREVERSIBLE. No es análisis forense ni custodia; tampoco
# certifica un borrado seguro normativo (NIST/DoD). Requiere root preparado,
# soporte desmontado y token ESTERILIZAR_SOPORTE.
# No se crea un run de evidencia: el recibo privado vive en analysis/sterilizations.
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
source "$script_dir/../../00_Config/lib/forensics_iot.bash" || exit 2
usage() {
    printf 'Uso: iot_sterilize.sh <DEVICE> [--size-mib N] [--wipe zeros|urandom|both] [--passes N] [--filesystem none|vfat]\n' \
        'Ejemplo: iot_sterilize.sh /dev/sdb --size-mib 14901\n' \
        'Sin --size-mib no se escribe nada: el error indica el valor exacto observado.\n' \
        'Destructivo: exige token ESTERILIZAR_SOPORTE y soporte desmontado.\n' >&2
}
source_path=; size_mib=; wipe=zeros; passes=1; filesystem=none
while (( $# )); do
    case "$1" in
        --size-mib) (( $# >= 2 )) && [[ $2 =~ ^[0-9]+$ ]] || { usage; exit 2; }; size_mib=$2; shift ;;
        --wipe) (( $# >= 2 )) && [[ $2 =~ ^(zeros|urandom|both)$ ]] || { usage; exit 2; }; wipe=$2; shift ;;
        --passes) (( $# >= 2 )) && [[ $2 =~ ^[1-7]$ ]] || { usage; exit 2; }; passes=$2; shift ;;
        --filesystem) (( $# >= 2 )) && [[ $2 =~ ^(none|vfat)$ ]] || { usage; exit 2; }; filesystem=$2; shift ;;
        --help) usage; exit 0 ;;
        --*) usage; exit 2 ;;
        *) [[ -z $source_path ]] || { usage; exit 2; }; source_path=$1 ;;
    esac
    shift
done
[[ -n $source_path ]] || { usage; exit 2; }
[[ $source_path = /* ]] || source_path="$PWD/$source_path"
forensics_require dd || exit 2
forensics_require python3 || exit 2
_iot_confirm ESTERILIZAR_SOPORTE || exit 2
_iot_privilege || exit $?
_iot_device_guard sterilize "$source_path" "$size_mib" || exit $?
if [[ $filesystem = vfat ]]; then
    forensics_require mkfs.vfat || exit 2
fi
receipt_root=${FORENSICS_ANALYSIS_ROOT:-$_FORENSICS_MODULE/analysis}/sterilizations
receipt_dir=$(_iot_mkdir "$receipt_root") || exit 2
stamp=$(_iot_utc_stamp)
receipt="$receipt_dir/sterilize-${IOT_DEVICE_NAME}-${stamp}.json"
receipt_log="$receipt_dir/sterilize-${IOT_DEVICE_NAME}-${stamp}.log"
_iot_reserve "$receipt_log" || exit 2
declare -a phases=() details=()
receipt_written=0
note() {
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)" "$*" >>"$receipt_log"
}
write_receipt() {
    local state=$1
    local -a records=()
    local phase
    (( receipt_written == 0 )) || return 0
    for phase in "${phases[@]}"; do records+=(--phase "$phase"); done
    for phase in "${details[@]}"; do records+=(--detail "$phase"); done
    if _iot_python receipt --out "$receipt" --device "$IOT_DEVICE_NAME" \
        --size-mib "$IOT_DEVICE_MIB" --state "$state" "${records[@]}"; then
        receipt_written=1
    fi
}
sterilize_cancel() {
    trap '' INT TERM
    note "cancelado por señal; el soporte puede quedar en estado intermedio"
    write_receipt CANCELADO
    printf 'Esterilización cancelada; NO se formatea y el soporte queda en estado intermedio.\n' >&2
    exit 1
}
trap 'sterilize_cancel' INT TERM
note "inicio dispositivo=$IOT_DEVICE_NAME size_mib=$IOT_DEVICE_MIB rdev=$(_iot_field "$IOT_DEVICE_JSON" rdev)"
failed=0
for (( pass = 1; pass <= passes; pass++ )); do
    if [[ $wipe = zeros || $wipe = both ]]; then
        note "pass=$pass wipe=zeros inicio"
        "${IOT_PRIVILEGED[@]}" dd if=/dev/zero of="$source_path" bs=4M conv=fsync status=none
        phase_rc=$?
        phases+=("zeros_${pass}=${phase_rc}")
        note "pass=$pass wipe=zeros rc=$phase_rc"
        if (( phase_rc != 0 )); then
            failed=1; details+=("paso zeros $pass falló")
            break
        fi
        if ! _iot_python zero-check --source "$source_path" >/dev/null 2>&1; then
            phases+=("verificacion_${pass}=1")
            failed=1; details+=("verificación de ceros falló en el paso $pass")
            note "pass=$pass zero-check=fallo"
            break
        fi
        phases+=("verificacion_${pass}=0")
        note "pass=$pass zero-check=ok"
    fi
    if [[ $wipe = urandom || $wipe = both ]]; then
        note "pass=$pass wipe=urandom inicio"
        "${IOT_PRIVILEGED[@]}" dd if=/dev/urandom of="$source_path" bs=4M conv=fsync status=none
        phase_rc=$?
        phases+=("urandom_${pass}=${phase_rc}")
        note "pass=$pass wipe=urandom rc=$phase_rc"
        if (( phase_rc != 0 )); then
            failed=1; details+=("paso urandom $pass falló")
            break
        fi
    fi
done
if (( failed == 0 )) && [[ $filesystem = vfat ]]; then
    note "formato=vfat inicio"
    "${IOT_PRIVILEGED[@]}" mkfs.vfat -I -F 32 "$source_path"
    phase_rc=$?
    phases+=("formato_vfat=${phase_rc}")
    note "formato=vfat rc=$phase_rc"
    if (( phase_rc != 0 )); then
        failed=1; details+=("mkfs.vfat falló")
    elif ! _iot_python fs-check --source "$source_path" --expected vfat >/dev/null 2>&1; then
        phases+=("formato_verificacion=1")
        failed=1; details+=("la firma FAT no se pudo verificar")
        note "formato=vfat verificacion=fallo"
    else
        phases+=("formato_verificacion=0")
        note "formato=vfat verificacion=ok"
    fi
fi
trap - INT TERM
state=COMPLETADO
(( failed == 0 )) || state=PARCIAL
if [[ $filesystem = none ]] && (( failed == 0 )); then
    details+=("sin sistema de archivos: el soporte queda sin formatear")
fi
write_receipt "$state"
if (( receipt_written == 0 )); then
    printf 'No se pudo escribir el recibo privado; el estado del soporte es el de los pasos del log.\n' >&2
    printf 'Log: %s\n' "$receipt_log" >&2
    exit 1
fi
printf 'Estado: %s. Recibo privado: %s\n' "$state" "$receipt"
printf 'Log: %s\n' "$receipt_log"
(( failed == 0 ))
