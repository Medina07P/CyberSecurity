# Module 08 navigation. UI on stderr; prepared arguments never use the session.
_FORENSICS_MENU_SOURCE=${BASH_SOURCE[0]:-$0}
_FORENSICS_MENU_LIB=$(CDPATH= cd -- "${_FORENSICS_MENU_SOURCE%/*}" && pwd)

# Fixed source inventory: evidence/recovered files are never runnable tools.
forensics_original_entries() {
    printf '%s\n' run_all_forensics.sh disk/disk_forensics.sh disk/file_carving.sh \
        logs/log_analyzer.sh memory/memory_dump.sh memory/strings_analysis.sh \
        memory/volatility_analysis.sh pcaps/pcap_analyzer.sh requirements.sh \
        show_results.sh timeline/timeline_creator.sh
}

# One line is ONE value, including spaces. No sensitive example defaults.
forensics_read() {
    local value
    printf '%s (0/! cancelar): ' "$1" >&2
    IFS= read -r value || return 1
    [[ $value != 0 && $value != '!' ]] || return 1
    [[ -n $value || ${2:-required} = optional ]] || return 1
    [[ $value != *[$'\001'-$'\037'$'\177']* ]] || return 1
    printf '%s\n' "$value"
}

# Quoted advanced CLI arguments preserve every historical method. shlex only
# tokenizes, never evaluates commands. Ordinary file prompts do not tokenize.
forensics_options() {
    local line values
    line=$(forensics_read 'Opciones adicionales según la CLI (comillas para espacios; vacío ninguna)' optional) || return 1
    values=$(python3 -B -c 'import shlex,sys
try:
 args=shlex.split(sys.argv[1])
 if any(not x or any(ord(c)<32 or ord(c)==127 for c in x) for x in args): raise ValueError()
 print("\n".join(args),end="")
except ValueError: sys.exit(2)' "$line") || return 1
    if [[ -n $values ]]; then
        local -a extra=()
        mapfile -t extra <<< "$values"
        FORENSICS_ARGS+=("${extra[@]}")
    fi
}

forensics_offline_selection() {
    local flag value
    for flag in memory log pcap disk timeline-auth; do
        value=$(forensics_read "Archivo --$flag; vacío omitir" optional) || return 1
        [[ -z $value ]] || FORENSICS_ARGS+=("--$flag" "$value")
    done
    (( ${#FORENSICS_ARGS[@]} > 0 ))
}

forensics_prepare() {
    local path=$1 value choice
    case "$path" in
        */requirements.sh)
            choice=$(forensics_read '1 comprobar (no ejecuta binarios); 2 instalar explícitamente') || return 1
            case $choice in 1) FORENSICS_ARGS=(--check) ;; 2) FORENSICS_ARGS=(--install) ;; *) return 1 ;; esac ;;
        */run_all_forensics.sh) forensics_offline_selection || return 1 ;;
        */show_results.sh) : ;;
        */memory_dump.sh)
            printf 'Adquisición local; OUTPUT_DIR es raíz nueva por run; métodos auto/avml/lime/dd (dd muestra parcial).\n' >&2
            forensics_options || return 1 ;;
        */timeline_creator.sh)
            choice=$(forensics_read 'Fuente offline: journal/auth/syslog/dpkg/wtmp/tree') || return 1
            case $choice in journal|auth|syslog|dpkg|wtmp|tree) ;; *) return 1 ;; esac
            value=$(forensics_read 'Ruta explícita de la fuente offline') || return 1
            FORENSICS_ARGS=("--$choice" "$value")
            printf 'Opciones: --year YYYY --timezone IANA; sin ellas fechas no resueltas no se inventan.\n' >&2
            forensics_options || return 1 ;;
        *)
            value=$(forensics_read 'Archivo explícito (no objetivo IP; se copiará íntegro)') || return 1
            FORENSICS_ARGS=("$value")
            case "$path" in
                */volatility_analysis.sh)
                    printf 'Solo Windows offline. Opciones: --backend auto/v2/v3 --profile Win... --symbols DIR local. Sin descargas.\n' >&2
                    forensics_options || return 1 ;;
                */disk_forensics.sh)
                    printf 'Metadata sin montaje. Opciones: --mount-copy [--offset BYTES --length BYTES]; físico solo explícito --physical.\n' >&2
                    forensics_options || return 1 ;;
                */file_carving.sh)
                    printf 'Foremost/Scalpel/ddrescue; OUTPUT_DIR opcional; --physical solo ddrescue con confirmación directa.\n' >&2
                    forensics_options || return 1 ;;
            esac ;;
    esac
}

forensics_execute_script() {
    local path=$1 mode=${3:-} status
    local -a FORENSICS_ARGS=()
    local entry allowed=0
    while IFS= read -r entry; do
        [[ $path != "08_Forensics/$entry" ]] || allowed=1
    done < <(forensics_original_entries)
    (( allowed )) || return 2
    if [[ $mode = --prepared ]]; then FORENSICS_ARGS=("${@:4}")
    else forensics_prepare "$path" || return 0; fi
    # Keep dangerous.txt protections even for original-list and prepared calls.
    # A pure availability check is the only exemption; leaf confirmations remain.
    if ! { [[ $path = 08_Forensics/requirements.sh && ${#FORENSICS_ARGS[@]} = 1 && ${FORENSICS_ARGS[0]} = --check ]]; }; then
        if params_is_dangerous "$path"; then
            ask_confirm '¿Confirmas el uso local sensible y autorizado de esta acción forense?' >&2 || return 0
        fi
    fi
    printf 'Acción forense: %s (argumentos privados).\n' "${path##*/}" >&2
    bash "$FRAMEWORK_DIR/$path" "${FORENSICS_ARGS[@]}"
    status=$?
    (( status == 0 )) || printf 'Acción no completada; rc=%d. Consulte metadata y diagnósticos privados.\n' "$status" >&2
    return "$status"
}

forensics_menu() {
    local choice action path value
    while :; do
        printf '\nFORENSE 08 — identidad por evidencia, no IP de sesión\n1) Dependencias (solo disponibilidad)\n2) Strings offline\n3) Log offline\n4) PCAP offline\n5) Volatility Windows offline\n6) Disco/recuperación\n7) Timeline offline\n8) Adquisición/local explícitos\n9) Flujo offline por fuentes elegidas\n10) Visor (metadata, sin cuerpos)\n11) Diez entradas originales + visor\n0) Volver\nSelección: ' >&2
        IFS= read -r choice || return 0
        case $choice in
            0|'!') return 0 ;;
            1) execute_script '08_Forensics/requirements.sh' '08_Forensics' --prepared --check || : ;;
            2) execute_script '08_Forensics/memory/strings_analysis.sh' '08_Forensics' || : ;;
            3) execute_script '08_Forensics/logs/log_analyzer.sh' '08_Forensics' || : ;;
            4) execute_script '08_Forensics/pcaps/pcap_analyzer.sh' '08_Forensics' || : ;;
            5) execute_script '08_Forensics/memory/volatility_analysis.sh' '08_Forensics' || : ;;
            6)
                action=$(forensics_read '1 metadata disco; 2 recuperación de archivo (sin soporte físico implícito)') || continue
                case $action in 1) path=disk/disk_forensics.sh ;; 2) path=disk/file_carving.sh ;; *) continue ;; esac
                execute_script "08_Forensics/$path" '08_Forensics' || : ;;
            7) execute_script '08_Forensics/timeline/timeline_creator.sh' '08_Forensics' || : ;;
            8)
                action=$(forensics_read 'LOCAL SENSIBLE: 1 RAM; 2 timeline del host; 3 flujo local; 4 instalar dependencias; 5 metadata física; 6 recuperación física') || continue
                case $action in
                    1) execute_script '08_Forensics/memory/memory_dump.sh' '08_Forensics' || : ;;
                    2) execute_script '08_Forensics/timeline/timeline_creator.sh' '08_Forensics' --prepared --local || : ;;
                    3) execute_script '08_Forensics/run_all_forensics.sh' '08_Forensics' --prepared --local || : ;;
                    4) execute_script '08_Forensics/requirements.sh' '08_Forensics' --prepared --install || : ;;
                    5|6)
                        value=$(forensics_read 'Dispositivo físico explícito; no se monta ni hashea íntegro') || continue
                        path=disk/disk_forensics.sh; [[ $action != 6 ]] || path=disk/file_carving.sh
                        execute_script "08_Forensics/$path" '08_Forensics' --prepared "$value" --physical || : ;;
                esac ;;
            9) execute_script '08_Forensics/run_all_forensics.sh' '08_Forensics' || : ;;
            10) execute_script '08_Forensics/show_results.sh' '08_Forensics' --prepared || : ;;
            11) run_module_scripts '08_Forensics' '08_Forensics — originales y visor' >&2 ;;
            *) printf 'Opción inválida; no se ejecuta ninguna herramienta.\n' >&2 ;;
        esac
    done
}
