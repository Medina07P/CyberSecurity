#!/bin/bash

# Uso: ./requirements.sh [--check]
# Instalación explícita: ./requirements.sh --install (confirmación directa).
# command-v acredita presencia, NO versión compatible, permisos ni cobertura.
packages=(volatility autopsy foremost scalpel tcpdump wireshark)
case "${1:---check}" in
    --check)
        (( $# <= 1 )) || exit 2
        for tool in volatility autopsy foremost scalpel tcpdump wireshark avml lime dd; do
            if command -v "$tool" >/dev/null 2>&1; then availability=disponible; else availability=ausente; fi
            printf '%s: %s (versión/compatibilidad no verificadas)\n' "$tool" "$availability"
        done
        printf 'Instalación opcional: requirements.sh --install; no instala AVML/LiME ni carga módulos.\n'
        exit 0 ;;
    --install) (( $# == 1 )) || exit 2 ;;
    *) exit 2 ;;
esac
printf 'Paquetes históricos solicitados: %s\n' "${packages[*]}"
printf 'La disponibilidad de paquetes/versiones depende del repositorio configurado.\nEscribe INSTALAR_DEPENDENCIAS para continuar: ' >&2
IFS= read -r answer && [[ $answer = INSTALAR_DEPENDENCIAS ]] || exit 2
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
source "$script_dir/../00_Config/lib/forensics_runtime.bash" || exit 2
forensics_require sudo || exit 2
forensics_require apt || exit 2
forensics_begin dependencies local || exit $?
forensics_capture install sudo apt install -y "${packages[@]}"
status=$?
(( ${_FORENSICS_CANCELLED:-0} == 0 )) || exit 1
if (( FORENSICS_STEP_RC == 0 && status == 0 )); then state=COMPLETADO; else state=FALLIDO; fi
forensics_complete_step install "$state" historical_packages_install || exit 1
# CLI08 = 0/1; apt's exact rc remains the install step rc, never replaced by it.
forensics_finish
