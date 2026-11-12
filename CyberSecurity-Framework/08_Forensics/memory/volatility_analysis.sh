#!/bin/bash
# VOLATILITY — Windows offline; tablas no prueban ausencia de intrusión.
# Uso: ./volatility_analysis.sh <MEMORY_FILE> [--backend auto|v2|v3] [--profile PROFILE] [--symbols DIR]
# Ejemplo: ./volatility_analysis.sh memoria.raw --backend v2 --profile Win7SP1x64
LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB_DIR/forensics_volatility.bash" || exit 2
usage() { printf 'Uso: ./volatility_analysis.sh <MEMORY_FILE> [--backend auto|v2|v3] [--profile PROFILE] [--symbols DIR]\n' >&2; }
(( $# >= 1 )) || { usage; exit 2; }
input=$1; shift
backend=auto; profile=; symbols=
while (( $# )); do
    [[ $# -ge 2 && -n $2 ]] || { usage; exit 2; }
    case $1 in --backend) backend=$2;; --profile) profile=$2;; --symbols) symbols=$2;; *) usage; exit 2;; esac
    shift 2
done
[[ $backend = auto || $backend = v2 || $backend = v3 ]] || { usage; exit 2; }
[[ -z $profile || $profile =~ ^Win[A-Za-z0-9_]+$ ]] || { printf 'Perfil Windows no válido.\n' >&2; exit 2; }
[[ $input = /* ]] || input="$PWD/$input"
forensics_offline_validate "$input" || exit 2
if [[ -n $symbols ]]; then
    [[ $symbols = /* ]] || symbols="$PWD/$symbols"
    forensics_offline_validate "$symbols" tree || exit 2
fi
available=0
for tool in volatility vol vol.py; do if command -v -- "$tool" >/dev/null 2>&1; then available=1; fi; done
(( available )) || { printf 'Falta backend Volatility; no se instala automáticamente.\n' >&2; exit 2; }
printf 'Se copiarán y verificarán íntegramente las fuentes; requiere espacio y tiempo.\n' >&2
forensics_begin volatility offline || exit $?
FORENSICS_VOL_WORK=$(forensics_stage "$input") || { forensics_finish; exit 1; }
FORENSICS_VOL_SYMBOLS=
if [[ -n $symbols ]]; then
    FORENSICS_VOL_SYMBOLS=$(forensics_stage "$symbols" tree) || { forensics_finish; exit 1; }
fi
# All writable backend state is confined to this private run, never real HOME.
export FORENSICS_VOL_WORK FORENSICS_VOL_SYMBOLS
forensics_adapter_private_home || { forensics_finish; exit 1; }
forensics_volatility_detect "$backend" || { forensics_finish; exit 1; }
if [[ $FORENSICS_VOL_FAMILY = v3 ]]; then
    if [[ -n $profile ]]; then
        printf 'Volatility v3 no admite --profile; seleccione símbolos locales.\n' >&2
        forensics_adapter_noeval imageinfo profile_not_supported
        forensics_finish; exit 1
    fi
    if [[ -z $FORENSICS_VOL_SYMBOLS ]] || ! forensics_adapter_inspect symbols "$FORENSICS_VOL_SYMBOLS" || \
        ! forensics_adapter_inspect vol_has "$FORENSICS_VOL_HELP" --offline --symbol-dirs --cache-path; then
        printf 'Volatility v3 requiere símbolos locales y CLI offline reconocida.\n' >&2
        forensics_adapter_noeval imageinfo offline_symbols_unavailable
        forensics_finish; exit 1
    fi
    info=windows.info.Info
else
    info=imageinfo
fi
# Missing identification plugin cannot authorize dependent Windows analyses.
if ! forensics_adapter_inspect vol_has "$FORENSICS_VOL_HELP" "$info"; then
    forensics_adapter_noeval imageinfo identification_unavailable
    forensics_finish; exit 1
fi
forensics_volatility_run imageinfo "$info"
rc=$?; state=COMPLETADO; coverage=windows_identified
FORENSICS_VOL_PROFILE=$profile
if (( rc == 0 )); then
    if [[ $FORENSICS_VOL_FAMILY = v2 ]]; then
        detected=$(forensics_adapter_inspect profile "$FORENSICS_STEP_OUT")
        if [[ -z $profile && -z $detected ]] || ! forensics_adapter_inspect not_linux "$FORENSICS_STEP_OUT"; then state=NO_EVALUABLE; fi
        [[ -n $FORENSICS_VOL_PROFILE ]] || FORENSICS_VOL_PROFILE=$detected
    elif ! forensics_adapter_inspect windows "$FORENSICS_STEP_OUT"; then state=NO_EVALUABLE
    fi
    if forensics_adapter_inspect requirements "$FORENSICS_STEP_OUT" "$FORENSICS_STEP_ERR"; then state=NO_EVALUABLE; fi
fi
[[ $state = COMPLETADO ]] || coverage=unsupported_image_family
forensics_adapter_complete imageinfo "$rc" "$state" "$coverage" || { forensics_finish; exit 1; }
if (( rc != 0 )) || [[ $state != COMPLETADO ]]; then
    printf 'Imagen o perfil Windows no evaluable; no se ejecutan plugins dependientes.\n' >&2
    forensics_finish; exit 1
fi
export FORENSICS_VOL_PROFILE
for name in pslist pstree netscan dlllist cmdscan consoles; do
    plugin=$name
    if [[ $FORENSICS_VOL_FAMILY = v3 ]]; then
        case $name in pslist) plugin=windows.pslist.PsList;; pstree) plugin=windows.pstree.PsTree;; netscan) plugin=windows.netscan.NetScan;; dlllist) plugin=windows.dlllist.DllList;; cmdscan) plugin=windows.cmdscan.CmdScan;; consoles) plugin=windows.consoles.Consoles;; esac
    fi
    forensics_volatility_run "$name" "$plugin"
    if [[ ${_FORENSICS_FAILED:-1} != 0 || ${_FORENSICS_CANCELLED:-0} != 0 ]]; then forensics_finish; exit 1; fi
done
forensics_finish
exit $?
