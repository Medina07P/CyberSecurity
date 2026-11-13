# Module 10: inert UI; file identities and explicit selections, never session IP.
evidence_original_entries() {
    printf '%s\n' run_all_evidence.sh auto_capture.sh evidence_manager.sh
}

evidence_read() {
    local value
    printf '%s (0/! cancelar): ' "$1" >&2
    IFS= read -r value || return 1
    [[ $value != 0 && $value != '!' ]] || return 1
    [[ -n $value || ${2:-required} = optional ]] || return 1
    [[ $value != *[$'\001'-$'\037'$'\177']* ]] || return 1
    printf '%s\n' "$value"
}

evidence_capture_selection() {
    local value selected=0
    printf 'Acciones explícitas: web, tráfico acotado, escaneo basic/full, contexto local. Sin valores de sesión.\n' >&2
    value=$(evidence_read '¿Seleccionar web? s/n') || return 1
    case $value in
        s) value=$(evidence_read 'URL HTTP/HTTPS explícita') || return 1
           EVIDENCE_ARGS+=(--web "$value"); selected=1 ;;
        n) ;; *) return 1 ;;
    esac
    value=$(evidence_read '¿Seleccionar tráfico? s/n') || return 1
    case $value in
        s)
            value=$(evidence_read 'Host único de tráfico') || return 1
            EVIDENCE_ARGS+=(--traffic "$value")
            value=$(evidence_read 'Interfaz explícita') || return 1
            EVIDENCE_ARGS+=(--interface "$value")
            value=$(evidence_read 'Duración en segundos (1–300)') || return 1
            EVIDENCE_ARGS+=(--duration "$value")
            value=$(evidence_read 'Límite de paquetes (1–10000)') || return 1
            EVIDENCE_ARGS+=(--packet-limit "$value"); selected=1 ;;
        n) ;; *) return 1 ;;
    esac
    value=$(evidence_read '¿Seleccionar escaneo? s/n') || return 1
    case $value in
        s)
            value=$(evidence_read 'Host único de escaneo') || return 1
            EVIDENCE_ARGS+=(--scan "$value")
            value=$(evidence_read 'Perfil explícito basic/full (full incluye NSE y más tráfico)') || return 1
            case $value in basic|full) ;; *) return 1 ;; esac
            EVIDENCE_ARGS+=(--scan-profile "$value"); selected=1 ;;
        n) ;; *) return 1 ;;
    esac
    value=$(evidence_read '¿Seleccionar contexto local del operador --system? s/n') || return 1
    case $value in s) EVIDENCE_ARGS+=(--system); selected=1 ;; n) ;; *) return 1 ;; esac
    (( selected ))
}

evidence_import_selection() {
    local kind file description value
    kind=$(evidence_read 'Tipo: screenshot/pcap/credential/finding/proof') || return 1
    case $kind in screenshot|pcap|credential|finding|proof) ;; *) return 1 ;; esac
    file=$(evidence_read 'Archivo local explícito (línea completa)') || return 1
    description=$(evidence_read 'Descripción; vacío ninguna' optional) || return 1
    value=$(evidence_read 'Etiqueta de objetivo explícita; vacío ninguna' optional) || return 1
    EVIDENCE_ARGS=(--add "$kind" "$file" "$description")
    [[ -z $value ]] || EVIDENCE_ARGS+=(--target "$value")
    return 0
}

evidence_prepare() {
    local path=$1 choice value
    case $path in
        10_Evidence/evidence_manager.sh)
            choice=$(evidence_read '1 importar; 2 listar; 3 verificar; 4 empaquetar; 5 ayuda') || return 1
            case $choice in
                1) evidence_import_selection || return 1 ;;
                2) EVIDENCE_ARGS=(--list) ;;
                3) EVIDENCE_ARGS=(--verify) ;;
                4)
                    value=$(evidence_read 'Nombre del paquete; vacío automático' optional) || return 1
                    EVIDENCE_ARGS=(--package)
                    [[ -z $value ]] || EVIDENCE_ARGS+=("$value") ;;
                5) EVIDENCE_ARGS=(--help) ;;
                *) return 1 ;;
            esac ;;
        10_Evidence/auto_capture.sh) evidence_capture_selection || return 1 ;;
        10_Evidence/run_all_evidence.sh)
            choice=$(evidence_read '1 flujo offline (listar/verificar); 2 captura seleccionada y flujo; 3 ayuda') || return 1
            case $choice in
                1) EVIDENCE_ARGS=(--offline) ;;
                2) EVIDENCE_ARGS=(--capture); evidence_capture_selection || return 1 ;;
                3) EVIDENCE_ARGS=(--help) ;;
                *) return 1 ;;
            esac ;;
        *) return 1 ;;
    esac
}

# Check every ancestor, including the supplied framework root, before dispatch.
evidence_safe_leaf() {
    local path=$1 parent
    case $path in
        10_Evidence/evidence_manager.sh|10_Evidence/auto_capture.sh|10_Evidence/run_all_evidence.sh) ;;
        *) return 1 ;;
    esac
    [[ $FRAMEWORK_DIR = /* && -f $FRAMEWORK_DIR/$path && ! -L $FRAMEWORK_DIR/$path ]] || return 1
    parent=$FRAMEWORK_DIR/10_Evidence
    while [[ $parent != / ]]; do
        [[ -d $parent && ! -L $parent ]] || return 1
        parent=${parent%/*}
        [[ -n $parent ]] || parent=/
    done
}

evidence_execute_script() {
    local path=$1 arg status network=0 package=0 scan_profile=none traffic=0 web=0
    local -a EVIDENCE_ARGS=() clean=()
    evidence_safe_leaf "$path" || return 2
    if [[ ${3:-} = --prepared ]]; then EVIDENCE_ARGS=("${@:4}")
    else evidence_prepare "$path" || return 0; fi
    # Even prepared calls must confirm. Strip pre-existing authorization and only
    # add it after confirmation; CLI remains responsible for validating syntax.
    if [[ $path != 10_Evidence/evidence_manager.sh ]]; then
        for arg in "${EVIDENCE_ARGS[@]}"; do
            case $arg in
                --authorize-network) continue ;;
                --web|--web=*) network=1; web=1 ;;
                --traffic|--traffic=*) network=1; traffic=1 ;;
                --scan|--scan=*) network=1 ;;
            esac
            clean+=("$arg")
        done
        EVIDENCE_ARGS=("${clean[@]}")
        for ((status=0; status<${#EVIDENCE_ARGS[@]}; status++)); do
            case ${EVIDENCE_ARGS[status]} in
                --scan-profile) scan_profile=${EVIDENCE_ARGS[status+1]:-missing} ;;
                --scan-profile=*) scan_profile=${EVIDENCE_ARGS[status]#*=} ;;
            esac
        done
        if (( network )); then
            # Do not echo user strings (URLs may contain credentials).
            case $scan_profile in basic|full|none) ;; *) scan_profile=invalid ;; esac
            printf 'Red seleccionada: web=%d tráfico=%d; perfil escaneo=%s. Tráfico: 1–300 s, 1–10000 paquetes; full incluye NSE.\n' "$web" "$traffic" "$scan_profile" >&2
            ask_confirm '¿Autorizas las acciones de red seleccionadas y sus límites?' >&2 || return 0
            EVIDENCE_ARGS+=(--authorize-network)
        fi
    else
        for arg in "${EVIDENCE_ARGS[@]}"; do
            case $arg in --package|--package=*) package=1 ;; esac
        done
        if (( package )); then
            ask_confirm '¿Confirmas exportar evidencia que puede incluir credenciales, confidencial y SIN CIFRAR?' >&2 || return 0
        fi
    fi
    evidence_safe_leaf "$path" || return 2
    printf 'Acción de evidencia: %s (argumentos privados).\n' "${path##*/}" >&2
    bash "$FRAMEWORK_DIR/$path" "${EVIDENCE_ARGS[@]}"
    status=$?
    (( status == 0 )) || printf 'Acción no completada; rc=%d. Consulte diagnósticos privados.\n' "$status" >&2
    return "$status"
}

evidence_menu() {
    local choice tool value
    local -a EVIDENCE_ARGS=()
    while :; do
        printf '\n━━━ EVIDENCIA 10 — identidad explícita, no objetivo de sesión ━━━\n' >&2
        if declare -F module_intro >/dev/null; then module_intro 10_Evidence >&2; fi
        printf '1) Disponibilidad local\n2) Importar\n3) Listar\n4) Verificar\n5) Empaquetar\n6) Captura seleccionada\n7) Flujo offline\n8) Guía local\n9) Tres entradas originales\n0) Volver\nSelección: ' >&2
        IFS= read -r choice || return 0
        case $choice in
            0|'!') return 0 ;;
            1)
                for tool in python3 cutycapt tcpdump nmap; do
                    if command -v "$tool" >/dev/null 2>&1; then printf '%s: disponible (no ejecutado)\n' "$tool" >&2
                    else printf '%s: ausente\n' "$tool" >&2; fi
                done ;;
            2)
                EVIDENCE_ARGS=()
                evidence_import_selection || continue
                evidence_execute_script 10_Evidence/evidence_manager.sh 10_Evidence --prepared "${EVIDENCE_ARGS[@]}" || : ;;
            3) evidence_execute_script 10_Evidence/evidence_manager.sh 10_Evidence --prepared --list || : ;;
            4) evidence_execute_script 10_Evidence/evidence_manager.sh 10_Evidence --prepared --verify || : ;;
            5)
                value=$(evidence_read 'Nombre de paquete; vacío automático' optional) || continue
                if [[ -n $value ]]; then
                    evidence_execute_script 10_Evidence/evidence_manager.sh 10_Evidence --prepared --package "$value" || :
                else evidence_execute_script 10_Evidence/evidence_manager.sh 10_Evidence --prepared --package || :; fi ;;
            6) evidence_execute_script 10_Evidence/auto_capture.sh 10_Evidence || : ;;
            7) evidence_execute_script 10_Evidence/run_all_evidence.sh 10_Evidence --prepared --offline || : ;;
            8) printf 'Guía local: 10_Evidence/USE.md. Importar copia archivos; listar no verifica; verificar lee contenido; paquetes confidenciales sin cifrar. Capturas solo explícitas. Asterisco 10: presencia reconocible, no integridad ni custodia legal.\n' >&2 ;;
            9) run_module_scripts 10_Evidence '10_Evidence — originales' >&2 ;;
            *) printf 'Opción inválida; ninguna acción.\n' >&2 ;;
        esac
    done
}
