#!/bin/bash

# Uso: ./file_carving.sh <FILE> [OUTPUT_DIR] [--physical]
# Ejemplo: ./file_carving.sh imagen.img
# OUTPUT_DIR sigue siendo raíz, ahora con subdirectorio privado nuevo por run.
# Físico: exclusivamente ddrescue, sin hash/copia exhaustivos del soporte.
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
source "$script_dir/../../00_Config/lib/forensics_disk.bash" || exit 2
[[ $# -gt 0 ]] || { printf 'Uso: file_carving.sh <FILE> [OUTPUT_DIR] [--physical]\n' >&2; exit 2; }
source_path=$1; shift
parent=; physical=0
while (( $# )); do
    case "$1" in
        --physical) physical=1 ;;
        --*) exit 2 ;;
        *) [[ -z $parent ]] || exit 2; parent=$1 ;;
    esac
    shift
done
if (( physical )); then
    _forensics_disk_confirm RECUPERAR_FISICO || exit 2
    _forensics_disk_privilege || exit 2
    metadata=$(_forensics_helper probe-source --source="$source_path" --kind device) || exit 2
    source_path=$(printf '%s' "$metadata" | _forensics_field source) || exit 2
    mode=physical
else
    source_path=$(_forensics_disk_python file "$source_path") || exit 2
    mode=offline
fi
forensics_begin carving "$mode" || exit $?
if (( physical )); then
    forensics_observe_device "$source_path" || exit $?
    expected=$FORENSICS_DEVICE_SIZE
else
    printf 'Cada backend obtiene copia íntegra independiente; requiere tiempo y espacio.\n' >&2
    # Stage all copies BEFORE any step. Never share mutable analyzer copies.
    foremost_copy=$(forensics_stage "$source_path") || exit $?
    scalpel_copy=$(forensics_stage "$source_path") || exit $?
    rescue_copy=$(forensics_stage "$source_path") || exit $?
    expected=$(python3 -B -c 'import os,sys; print(os.stat(sys.argv[1]).st_size)' "$rescue_copy") || exit 1
fi
recovered=$(forensics_register_root recovered "${parent:-$FORENSICS_RECOVERED_ROOT}") || exit $?
failed=0
if (( physical == 0 )); then
    for tool in foremost scalpel; do
        if ! command -v "$tool" >/dev/null 2>&1; then forensics_skip "$tool" dependency_missing || :; failed=1; continue; fi
        destination=$(_forensics_disk_python mkdir "$recovered/$tool") || exit 1
        if [[ $tool = foremost ]]; then copy=$foremost_copy; else copy=$scalpel_copy; fi
        forensics_capture "$tool" "$tool" -i "$copy" -o "$destination" || failed=1
        _forensics_disk_complete "$tool" carving_backend || failed=1
        if ! _forensics_disk_python products "$destination" >/dev/null; then _forensics_block; failed=1
        else _forensics_disk_record_products "$tool" COMPLETADO "$destination" || failed=1; fi
    done
fi
if ! command -v ddrescue >/dev/null 2>&1; then
    forensics_skip ddrescue dependency_missing || :; failed=1
else
    destination=$(_forensics_disk_python mkdir "$recovered/ddrescue") || exit 1
    if (( physical )); then copy=$source_path; else copy=$rescue_copy; fi
    forensics_capture ddrescue ddrescue "$copy" "$destination/recovered.img" "$destination/recovery.map"
    backend_status=$?
    if (( FORENSICS_STEP_RC != 0 || backend_status != 0 )); then state=FALLIDO
    else state=$(_forensics_disk_python map "$destination/recovery.map" "$destination/recovered.img" "$expected") || state=NO_EVALUABLE; fi
    forensics_complete_step ddrescue "$state" recovery_map_evaluated || failed=1
    [[ $state = COMPLETADO ]] || failed=1
    if ! _forensics_disk_python products "$destination" >/dev/null; then _forensics_block; failed=1
    else _forensics_disk_record_products ddrescue COMPLETADO "$destination" || failed=1; fi
fi
forensics_finish || failed=1
(( failed == 0 ))
