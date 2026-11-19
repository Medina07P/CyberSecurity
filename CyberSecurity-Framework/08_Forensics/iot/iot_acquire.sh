#!/bin/bash

# Adquisición de una imagen de soporte portátil (USB/SD), sin montarla.
# Uso: ./iot_acquire.sh <DEVICE> [OUTPUT_DIR] [--size-mib N]
# Ejemplo: ./iot_acquire.sh /dev/sdb
# OUTPUT_DIR es la raíz padre del run de recuperación; nunca se reutiliza.
# La imagen se hashea varias veces (publicación + cierre): coste deliberado.
# PhotoRec 7.2 no admite modo por lotes fiable: el carving automático se hace
# después con disk/file_carving.sh (Foremost/Scalpel); PhotoRec queda guiado.
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
source "$script_dir/../../00_Config/lib/forensics_iot.bash" || exit 2
usage() {
    printf 'Uso: iot_acquire.sh <DEVICE> [OUTPUT_DIR] [--size-mib N]\n' \
        'Ejemplo: iot_acquire.sh /dev/sdb\n' \
        'Requiere root ya disponible (o sudo -n preparado), soporte desmontado y token ADQUIRIR_SOPORTE.\n' \
        'La imagen queda en recovered/run-<id>/image.dd con su SHA-256 y sus metadatos.\n' >&2
}
source_path=; parent=; size_mib=
while (( $# )); do
    case "$1" in
        --size-mib) (( $# >= 2 )) && [[ $2 =~ ^[0-9]+$ ]] || { usage; exit 2; }; size_mib=$2; shift ;;
        --help) usage; exit 0 ;;
        --*) usage; exit 2 ;;
        *) if [[ -z $source_path ]]; then source_path=$1
           elif [[ -z $parent ]]; then parent=$1
           else usage; exit 2; fi ;;
    esac
    shift
done
[[ -n $source_path ]] || { usage; exit 2; }
[[ $source_path = /* ]] || source_path="$PWD/$source_path"
forensics_require dd || exit 2
forensics_require sha256sum || exit 2
forensics_require python3 || exit 2
_iot_confirm ADQUIRIR_SOPORTE || exit 2
_iot_privilege || exit $?
_iot_device_guard acquire "$source_path" "$size_mib" || exit $?
source_path=$(_iot_field "$IOT_DEVICE_JSON" source) || exit 2
printf 'Imagen de %s MiB desde %s; no se monta ni se escribe en el soporte.\n' \
    "$IOT_DEVICE_MIB" "$IOT_DEVICE_NAME" >&2
forensics_begin acquisition physical || exit $?
forensics_observe_device "$source_path" || { forensics_finish; exit 1; }
observed=$FORENSICS_DEVICE_SIZE
[[ $observed != None ]] || observed=
products=$(forensics_register_root recovered "${parent:-$FORENSICS_RECOVERED_ROOT}") || exit $?
image="$products/image.dd"
_iot_reserve "$image" || { forensics_finish; exit 1; }
failed=0
# dd con sync rellena bloques ilegibles: PARCIAL, nunca imagen "completa".
forensics_capture dd_image "${IOT_PRIVILEGED[@]}" dd if="$source_path" of="$image" \
    bs=1M conv=noerror,sync status=none
dd_status=$?
dd_rc=$FORENSICS_STEP_RC
if (( ${_FORENSICS_CANCELLED:-0} != 0 )); then exit 1; fi
if (( dd_status != 0 )); then
    printf 'La captura no se pudo completar; el run queda bloqueado y sin imagen usable.\n' >&2
    forensics_finish || :
    exit 1
fi
failed=0
image_state=PARCIAL
(( dd_rc == 0 )) && image_state=COMPLETADO
forensics_complete_step dd_image "$image_state" image_written || failed=1
forensics_capture image_hash sha256sum -- "$image"
hash_status=$?
image_hash=
if (( hash_status == 0 && FORENSICS_STEP_RC == 0 )); then
    read -r image_hash _rest <"$FORENSICS_STEP_OUT" || image_hash=
fi
if [[ ${#image_hash} = 64 ]]; then hash_state=COMPLETADO; else hash_state=FALLIDO; failed=1; fi
forensics_complete_step image_hash "$hash_state" image_hashed || failed=1
image_bytes=$(python3 -B -c 'import os,sys
try: print(os.stat(sys.argv[1]).st_size)
except OSError: sys.exit(1)' "$image") || { _forensics_block; forensics_finish; exit 1; }
metadata=$(_iot_analysis_file image.json) || { _forensics_block; forensics_finish; exit 1; }
python3 -B - "$metadata" "$image" "$observed" "$image_hash" "$dd_rc" <<'PY' || { _forensics_block; forensics_finish; exit 1; }
import json, os, sys
out, image, observed, digest, rc = sys.argv[1:6]
size = os.stat(image).st_size
payload = dict(tool='dd', bytes=size, sha256=digest if len(digest) == 64 else None,
               device_bytes=int(observed) if observed.isdigit() else None,
               dd_rc=int(rc), completitud_soporte='no_verificada',
               detalle=('dispositivo físico leído en vivo; bloques ilegibles se '
                        'rellenan y el resultado es PARCIAL'))
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w') as stream:
    json.dump(payload, stream, sort_keys=True)
    stream.write('\n')
PY
product_state=$image_state
if [[ $hash_state != COMPLETADO ]]; then product_state=FALLIDO; fi
if [[ $product_state = COMPLETADO ]]; then
    # Sin tamaño observado no se puede afirmar que la imagen esté completa.
    if [[ -z $observed || $image_bytes != "$observed" ]]; then product_state=PARCIAL; fi
fi
_iot_publish image_product "$product_state" image_published "$image" "$metadata" || {
    _forensics_block; failed=1;
}
if [[ $product_state = COMPLETADO ]]; then
    printf 'Imagen: %s\nSHA-256: %s\nBytes: %s\n' "$image" "$image_hash" "$image_bytes"
else
    printf 'Imagen conservada como parcial/fallida: %s (estado %s)\n' "$image" "$product_state" >&2
fi
printf 'Siguiente paso: disk/file_carving.sh %q (Foremost/Scalpel).\n' "$image" >&2
printf 'PhotoRec 7.2 no tiene lote fiable: si lo usas, hazlo de forma guiada.\n' >&2
forensics_finish || failed=1
(( failed == 0 ))
