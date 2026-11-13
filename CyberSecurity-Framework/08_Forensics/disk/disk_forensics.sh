#!/bin/bash

# Uso: ./disk_forensics.sh <DISK_IMAGE> [--physical] [--mount-copy] [--offset BYTES --length BYTES]
# Ejemplo: ./disk_forensics.sh imagen.img
# Metadata por defecto; montaje solo de copia explícita. Sin sudo automático.
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
source "$script_dir/../../00_Config/lib/forensics_disk.bash" || exit 2
[[ $# -gt 0 ]] || { printf 'Uso: disk_forensics.sh <DISK_IMAGE> [--physical] [--mount-copy] [--offset BYTES --length BYTES]\n' >&2; exit 2; }
source_path=$1; shift
physical=0; mount_copy=0; offset=; length=
while (( $# )); do
    case "$1" in
        --physical) physical=1; shift ;;
        --mount-copy) mount_copy=1; shift ;;
        --offset) [[ $# -gt 1 && -z $offset ]] || exit 2; offset=$2; shift 2 ;;
        --length) [[ $# -gt 1 && -z $length ]] || exit 2; length=$2; shift 2 ;;
        *) exit 2 ;;
    esac
done
if (( physical )); then
    (( mount_copy == 0 )) && [[ -z $offset && -z $length ]] || exit 2
    _forensics_disk_confirm INSPECCIONAR_FISICO || exit 2
    _forensics_disk_privilege || exit 2
    metadata=$(_forensics_helper probe-source --source="$source_path" --kind device) || exit 2
    source_path=$(printf '%s' "$metadata" | _forensics_field source) || exit 2
    mode=physical
else
    source_path=$(_forensics_disk_python file "$source_path") || exit 2
    [[ -z $offset && -z $length ]] || {
        (( mount_copy )) && _forensics_disk_python range "$source_path" "$offset" "$length" || exit 2
    }
    if (( mount_copy )); then
        _forensics_disk_confirm MONTAR_COPIA || exit 2
        _forensics_disk_privilege || exit 2
        for dependency in mount umount losetup findmnt; do forensics_require "$dependency" || exit 2; done
    fi
    mode=offline
fi
forensics_begin disk "$mode" || exit $?
if (( physical )); then
    forensics_observe_device "$source_path" || exit $?
    copy=$source_path
else
    printf 'Se copiará y verificará la imagen íntegra; requiere tiempo y espacio.\n' >&2
    copy=$(forensics_stage "$source_path") || exit $?
fi
trap '_forensics_disk_cancel 2' INT
trap '_forensics_disk_cancel 15' TERM
_FORENSICS_DISK_REQUEST_FAILED=0
if (( mount_copy )); then forensics_register_cleanup forensics_disk_finalize || exit $?; fi
failed=0
for tool in file fdisk blkid; do
    if ! command -v "$tool" >/dev/null 2>&1; then forensics_skip "$tool" dependency_missing || :; failed=1; continue; fi
    case "$tool" in
        file) args=(-b -- "$copy") ;;
        fdisk) args=(-l -- "$copy") ;;
        blkid) args=(-p -o value -s TYPE -- "$copy") ;;
    esac
    forensics_capture "$tool" "$tool" "${args[@]}" || failed=1
    _forensics_disk_complete "$tool" disk_metadata || failed=1
done
if (( mount_copy )); then
    if [[ -z $offset ]]; then forensics_disk_mount "$copy" || failed=1
    else forensics_disk_mount "$copy" "$offset" "$length" || failed=1; fi
    _FORENSICS_DISK_REQUEST_FAILED=$failed
fi
# Autopsy remains a manual optional method, never auto-launched.
command -v autopsy >/dev/null 2>&1 && printf 'Autopsy disponible para apertura manual de una copia.\n' >&2
forensics_finish || failed=1
(( failed == 0 ))
