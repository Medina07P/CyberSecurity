#!/bin/bash

# ─── CYBER FRAMEWORK - Manager Universal ────────────────────
# Versión: 12.0 - Ejecuta cualquier script con parámetros
# Uso: ./cyber_framework.sh

# ─── Configuración ──────────────────────────────────────────
FRAMEWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$FRAMEWORK_DIR" || exit 1

# Librería del gestor: parser de Uso:, sesión del objetivo, estado de fases
LIB_DIR="$FRAMEWORK_DIR/00_Config/lib"
if [[ ! -f "$LIB_DIR/prompt.bash" ]]; then
    echo "❌ Falta la librería del gestor en $LIB_DIR" >&2
    exit 1
fi
source "$LIB_DIR/params.bash"
source "$LIB_DIR/session.bash"
source "$LIB_DIR/phase_status.bash"
source "$LIB_DIR/prompt.bash"
source "$LIB_DIR/report_profile.bash"
source "$LIB_DIR/scans.bash"
source "$LIB_DIR/module_intro.bash"
source "$LIB_DIR/scanners_menu.bash"
source "$LIB_DIR/exploitation_menu.bash"
source "$LIB_DIR/enumeration_menu.bash"
source "$LIB_DIR/postexploitation_menu.bash"
source "$LIB_DIR/wireless_menu.bash"
source "$LIB_DIR/forensics_menu.bash"
source "$LIB_DIR/automation_menu.bash"
source "$LIB_DIR/evidence_menu.bash"
source "$LIB_DIR/dependencies.bash"
source "$LIB_DIR/ai_menu.bash"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# ─── Funciones de Utilidad ──────────────────────────────────

clear_screen() {
    clear
}

show_banner() {
    local tgt
    tgt=$(session_target)

    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo -e "║     🛡️  ${WHITE}CYBERSECURITY FRAMEWORK - Manager Universal${CYAN}     ║"
    echo "║                                                                   ║"
    echo -e "║     ${DIM}Ejecución guiada por fases del framework${CYAN}               ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if [[ -n "$tgt" ]]; then
        echo -e "  ${WHITE}🎯 Objetivo:${NC} ${GREEN}${tgt}${NC}"
    else
        echo -e "  ${WHITE}🎯 Objetivo:${NC} ${YELLOW}sin definir${NC} ${DIM}(pulsa T para elegirlo)${NC}"
    fi
    show_phase_line
    echo ""
}

show_module_status() {
    echo -e "${YELLOW}━━━ MÓDULOS DISPONIBLES ━━━${NC}"
    echo ""
    
    count_files() {
        if [[ -d "$1" ]]; then
            find "$1" -type f 2>/dev/null | wc -l
        else
            echo "0"
        fi
    }
    
    count_scripts() {
        if [[ -d "$1" ]]; then
            find "$1" -name "*.sh" -o -name "*.py" -o -name "*.ps1" 2>/dev/null | wc -l
        else
            echo "0"
        fi
    }
    
    echo -e "  ${GREEN}00_Config${NC}        📁 $(count_files 00_Config) archivos  |  🛠️  $(count_scripts 00_Config) scripts"
    echo -e "  ${GREEN}01_OSINT${NC}          📁 $(count_files 01_OSINT) archivos  |  🛠️  $(count_scripts 01_OSINT) scripts"
    echo -e "  ${GREEN}02_Recon${NC}          📁 $(count_files 02_Recon) archivos  |  🛠️  $(count_scripts 02_Recon) scripts"
    echo -e "  ${GREEN}03_Scanners${NC}       📁 $(count_files 03_Scanners) archivos |  🛠️  $(count_scripts 03_Scanners) scripts"
    echo -e "  ${GREEN}04_Enumeration${NC}    📁 $(count_files 04_Enumeration) archivos |  🛠️  $(count_scripts 04_Enumeration) scripts"
    echo -e "  ${GREEN}05_Exploitation${NC}   📁 $(count_files 05_Exploitation) archivos |  🛠️  $(count_scripts 05_Exploitation) scripts"
    echo -e "  ${GREEN}06_PostExploitation${NC} 📁 $(count_files 06_PostExploitation) archivos |  🛠️  $(count_scripts 06_PostExploitation) scripts"
    echo -e "  ${GREEN}07_Wireless${NC}       📁 $(count_files 07_Wireless) archivos |  🛠️  $(count_scripts 07_Wireless) scripts"
    echo -e "  ${GREEN}08_Forensics${NC}      📁 $(count_files 08_Forensics) archivos |  🛠️  $(count_scripts 08_Forensics) scripts"
    echo -e "  ${GREEN}09_Automation${NC}     📁 $(count_files 09_Automation) archivos |  🛠️  $(count_scripts 09_Automation) scripts"
    echo -e "  ${GREEN}10_Evidence${NC}       📁 $(count_files 10_Evidence) archivos |  🛠️  $(count_scripts 10_Evidence) scripts"
    echo -e "  ${GREEN}11_Reports${NC}        📁 $(count_files 11_Reports) archivos |  🛠️  $(count_scripts 11_Reports) scripts"
    echo -e "  ${GREEN}12_Knowledge_Base${NC} 📁 $(count_files 12_Knowledge_Base) archivos |  🛠️  $(count_scripts 12_Knowledge_Base) scripts"
    echo -e "  ${GREEN}13_Labs${NC}           📁 $(count_files 13_Labs) archivos |  🛠️  $(count_scripts 13_Labs) scripts"
    echo ""
}

# ─── Utilidades ────────────────────────────────────────────

pause() {
    echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
    IFS= read -r _ || return 0
}

# Confirmación explícita. Devuelve 1 si dice que no o si se cierra la entrada.
ask_confirm() {
    local question="$1" answer
    echo -ne "${WHITE}${question} (s/N): ${NC}"
    IFS= read -r answer || return 1
    case "$answer" in
        s|S|si|Si|SI|sí|Sí) return 0 ;;
        *) return 1 ;;
    esac
}

# Estado de las fases que se pueden deducir de la evidencia en disco
show_phase_line() {
    local p key state out=""
    for p in 00_Config 02_Recon 03_Scanners 04_Enumeration 10_Evidence 11_Reports; do
        key="${p%%_*}"
        state=$(phase_state "$p")
        case "$state" in
            done)    out="${out}${GREEN}*${NC}${key}  " ;;
            pending) out="${out}${DIM}.${NC}${key}  " ;;
        esac
    done
    echo -e "  ${DIM}Fases:${NC} ${out}${DIM}(* hecha, . pendiente; 10: presencia, no integridad)${NC}"
}

# ─── Objetivo de la sesión ─────────────────────────────────

change_target() {
    clear_screen
    echo -e "${CYAN}${BOLD}━━━ OBJETIVO DE TRABAJO ━━━${NC}"
    echo ""

    local actual
    actual=$(session_target)
    if [[ -n "$actual" ]]; then
        echo -e "  Actual: ${GREEN}${actual}${NC}"
    else
        echo -e "  Actual: ${DIM}(sin definir)${NC}"
    fi
    echo ""

    local -a lista=()
    mapfile -t lista < <(targets_from_config)

    local nuevo="" sel="" entry="" i=1
    if [[ ${#lista[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Objetivos de 00_Config/targets.txt:${NC}"
        echo ""
        for entry in "${lista[@]}"; do
            printf '  %2d) %-24s %s\n' "$i" "${entry%%|*}" "${entry#*|}"
            i=$((i + 1))
        done
        echo ""
        echo -e "  ${GREEN}0${NC}) Escribir otro objetivo"
        echo ""
        echo -ne "${BOLD}Elige un número, o pulsa Enter para escribirlo: ${NC}"
        IFS= read -r sel || return 0

        if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#lista[@]} )); then
            entry="${lista[$((sel - 1))]}"
            if session_set_target "${entry%%|*}"; then
                echo -e "\n${GREEN}✅ Objetivo guardado: ${entry%%|*}${NC}"
            fi
            pause
            return 0
        fi
    else
        echo -e "${DIM}No hay objetivos en targets.txt.${NC}"
        echo ""
    fi

    printf 'Nuevo objetivo (IP o dominio): '
    IFS= read -r nuevo || return 0
    if session_set_target "$nuevo"; then
        echo -e "\n${GREEN}✅ Objetivo guardado: $nuevo${NC}"
    else
        echo -e "\n${RED}❌ No es una IP ni un dominio válido: '$nuevo'${NC}"
        echo -e "${DIM}   Sin espacios ni símbolos. Ejemplos: 192.168.1.10, example.com${NC}"
    fi
    pause
}

# ─── FUNCIÓN PARA EJECUTAR SCRIPTS ─────────────────────────

# Display policy only: never rewrite the argv delivered to the selected leaf.
script_arguments_summary() {
    local script_path="$1" url='' proxy_port='' verify=0
    shift
    if [[ $# -eq 0 ]]; then
        echo -e "${DIM}Ejecución directa; sigue las indicaciones de la herramienta.${NC}"
        return
    fi
    case "$script_path" in
        06_PostExploitation/lateral_movement/ps_exec.sh)
            echo -e "${DIM}Argumentos: [ocultos: contienen credenciales]${NC}"
            ;;
        03_Scanners/web_scanners/burpsuite/burp_launcher.sh)
            # Never print raw Burp arguments, even malformed/manual ones.
            while (( $# )); do
                case "$1" in
                    --verificar) verify=1; url="${2:-}"; (( $# < 2 )) || shift ;;
                    --proxy-port) proxy_port="${2:-}"; (( $# < 2 )) || shift ;;
                esac
                shift
            done
            if (( verify )); then
                python3 -I -B -X utf8 - "$url" "$proxy_port" <<'PY'
import re
import sys
from urllib.parse import urlsplit
try:
    value, proxy = sys.argv[1:]
    parsed = urlsplit(value)
    host = parsed.hostname or ''
    port = parsed.port
    proxy = int(proxy)
    if (parsed.scheme not in ('http', 'https') or parsed.username is not None or
            parsed.password is not None or not re.fullmatch(r'[A-Za-z0-9.:-]+', host) or
            any(ord(c) < 33 or ord(c) == 127 for c in value) or
            (port is not None and not 1 <= port <= 65535) or not 1 <= proxy <= 65535):
        raise ValueError
    authority = '[' + host + ']' if ':' in host else host
    origin = parsed.scheme + '://' + authority + (':' + str(port) if port is not None else '')
    print(f'GET | Proxy: 127.0.0.1:{proxy} | Destino: {origin} (sin ruta/query)')
except ValueError:
    print('GET | Proxy/destino: NO_DETERMINADO (argumentos omitidos)')
PY
            else
                echo 'Burp: argumentos omitidos (apertura/estado/parada; sin URL publicada).'
            fi
            ;;
        *) echo -e "${DIM}Argumentos: $*${NC}" ;;
    esac
}

execute_script() {
    # Module 10 is a fixed inventory even for direct/prepared calls. Route before
    # generic cd/chmod/argument UI; noncanonical paths are rejected, not resolved.
    case "/$1/" in
        */10_Evidence/*) evidence_execute_script "$@"; return $? ;;
    esac
    case "/${2:-}/" in
        */10_Evidence/*) evidence_execute_script "$@"; return $? ;;
    esac
    # 08 has file identities, never session targets or example defaults. This
    # also protects the original listing, not just the new guided menu.
    case "$1" in
        08_Forensics/*) forensics_execute_script "$@"; return $? ;;
    esac
    local script_path="$1"   # ruta relativa al framework
    local module_dir="$2"
    local original_dir="$PWD"
    local rel_path values rc rc_run
    local -a argv=()
    # Solo llamadas internas del menú guiado, con datos ya validados y confirmados.
    local prepared=0 basic_scanner=0
    if [[ "${3:-}" == --prepared ]]; then
        prepared=1
        argv=("${@:4}")
        if [[ "$script_path" == '03_Scanners/network_scanners/nmap/nmap_smart.sh' &&
              ${#argv[@]} -eq 2 && "${argv[1]}" == basico ]]; then
            basic_scanner=1
        fi
    fi

    # Es una CLI con subcomandos, no una herramienta que funcione vacía.
    # Reutilizar K evita pedir comandos manuales o claves por argv. El subshell
    # permite llamarlo también desde otro cwd sin alterar el del llamador.
    case "$script_path" in
        "00_Config/scripts/api_keys.py"|"$FRAMEWORK_DIR/00_Config/scripts/api_keys.py")
            (cd "$FRAMEWORK_DIR" && keys_menu "módulo de configuración")
            return $?
            ;;
    esac

    cd "$module_dir" || {
        echo -e "${RED}❌ Error: No se pudo acceder a $module_dir${NC}"
        return 1
    }

    rel_path="${script_path#$module_dir/}"

    echo -e "\n${GREEN}▶️  Ejecutando: ${rel_path}${NC}"
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    [[ -x "$rel_path" ]] || chmod +x "$rel_path" 2>/dev/null

    if params_is_generator "$rel_path"; then
        echo -e "${YELLOW}ℹ️  Es un GENERADOR: escribe otro script, no escanea nada.${NC}"
    fi

    if (( ! basic_scanner )) && params_is_dangerous "$script_path"; then
        echo -e "${RED}⚠️  Herramienta intrusiva (escaneo intensivo / fuerza bruta / explotación / persistencia).${NC}"
        if ! ask_confirm "¿Confirmas que el objetivo está dentro de tu alcance autorizado?"; then
            echo -e "${YELLOW}Cancelado${NC}"
            cd "$original_dir" || exit 1
            return 0
        fi
    fi

    # Los datos que pide el script salen de su propia línea Uso:
    rc=0
    if (( ! prepared )); then
        values=$(prompt_for_slots "$rel_path" "$script_path")
        rc=$?
    fi

    if [[ $rc -ne 0 ]]; then
        case "$rc" in
            1) echo -e "${YELLOW}Cancelado: no se ha ejecutado nada.${NC}" ;;
            2) echo -e "${RED}Entrada cerrada: no se ha ejecutado nada.${NC}" ;;
        esac
        cd "$original_dir" || exit 1
        return 0
    fi

    if (( ! prepared )) && [[ -n "$values" ]]; then
        mapfile -t argv <<< "$values"
    fi

    script_arguments_summary "$script_path" "${argv[@]}"
    echo ""

    if [[ "$rel_path" == *.py ]]; then
        if command -v python3 >/dev/null 2>&1; then
            python3 "$rel_path" "${argv[@]}"
        else
            python "$rel_path" "${argv[@]}"
        fi
    elif [[ "$rel_path" == *.ps1 ]]; then
        pwsh "$rel_path" "${argv[@]}" 2>/dev/null || powershell.exe "$rel_path" "${argv[@]}"
    else
        ./"$rel_path" "${argv[@]}"
    fi
    rc_run=$?

    cd "$original_dir" || exit 1

    echo -e "\n${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    [[ $rc_run -ne 0 ]] && echo -e "${YELLOW}Código de salida: $rc_run${NC}"
    pause
}

# ─── Función para navegar en un módulo ─────────────────────

run_module_scripts() {
    local module_dir="$1"
    local module_name="$2"

    while true; do
        clear_screen
        echo -e "${CYAN}${BOLD}━━━ MÓDULO $module_name ━━━${NC}"
        echo ""
        module_intro "$module_dir"

        if [[ ! -d "$module_dir" ]]; then
            echo -e "${RED}❌ Módulo no encontrado: $module_dir${NC}"
            pause
            return
        fi

        echo -e "${YELLOW}📂 Directorio: $PWD/$module_dir${NC}"
        echo ""

        local -a scripts=() categories=()
        local script rel_path choice

        if [[ "$module_dir" == 10_Evidence ]]; then
            while IFS= read -r rel_path; do
                script="$module_dir/$rel_path"
                evidence_safe_leaf "$script" || continue
                scripts+=("$script")
                if [[ $rel_path == run_all_evidence.sh ]]; then categories+=(run_all)
                else categories+=(script); fi
            done < <(evidence_original_entries)
        elif [[ "$module_dir" == 08_Forensics ]]; then
            # Do not recursively discover executable-looking recovered evidence.
            while IFS= read -r rel_path; do
                script="$module_dir/$rel_path"
                [[ -f "$script" && ! -L "$script" ]] || continue
                scripts+=("$script")
                if [[ $rel_path == run_all_forensics.sh ]]; then categories+=(run_all)
                else categories+=(script); fi
            done < <(forensics_original_entries)
        else
        while IFS= read -r script; do
            [[ -f "$script" ]] || continue
            scripts+=("$script"); categories+=("run_all")
        done < <(find "$module_dir" -name "run_all_*.sh" -type f -not -path "*/lib/*" -not -path "*/tests/*" 2>/dev/null | sort)

        while IFS= read -r script; do
            [[ -f "$script" ]] || continue
            case "$script" in *run_all*|*.bak) continue ;; esac
            scripts+=("$script"); categories+=("script")
        done < <(find "$module_dir" -name "*.sh" -type f -not -path "*/lib/*" -not -path "*/tests/*" 2>/dev/null | sort)

        while IFS= read -r script; do
            [[ -f "$script" ]] || continue
            scripts+=("$script"); categories+=("python")
        done < <(find "$module_dir" -name "*.py" -type f -not -path "*/lib/*" -not -path "*/tests/*" 2>/dev/null | sort)

        while IFS= read -r script; do
            [[ -f "$script" ]] || continue
            scripts+=("$script"); categories+=("powershell")
        done < <(find "$module_dir" -name "*.ps1" -type f -not -path "*/lib/*" -not -path "*/tests/*" 2>/dev/null | sort)
        fi

        if [[ ${#scripts[@]} -eq 0 ]]; then
            echo -e "${YELLOW}⚠️  No se encontraron scripts ejecutables en este módulo${NC}"
            pause
            return
        fi

        echo -e "${GREEN}✅ Se encontraron ${#scripts[@]} scripts disponibles:${NC}"
        echo ""

        local current_cat="" i num marca
        for i in "${!scripts[@]}"; do
            num=$((i + 1))
            rel_path="${scripts[$i]#$module_dir/}"

            if [[ "${categories[$i]}" != "$current_cat" ]]; then
                current_cat="${categories[$i]}"
                case "$current_cat" in
                    "run_all")    echo -e "${CYAN}━━━ Scripts Principales ━━━${NC}" ;;
                    "script")     echo -e "${CYAN}━━━ Scripts Bash ━━━${NC}" ;;
                    "python")     echo -e "${CYAN}━━━ Scripts Python ━━━${NC}" ;;
                    "powershell") echo -e "${CYAN}━━━ Scripts PowerShell ━━━${NC}" ;;
                esac
            fi

            marca=""
            params_is_dangerous "${scripts[$i]}" && marca="${marca}${RED}[intrusiva] ${NC}"
            [[ "$(params_mode "${scripts[$i]}")" == "manual" ]] && marca="${marca}${CYAN}[manual] ${NC}"
            params_is_generator "${scripts[$i]}" && marca="${marca}${YELLOW}[generador] ${NC}"

            echo -e "  ${GREEN}${num}.${NC} ${WHITE}${rel_path}${NC}  ${marca}"
        done

        echo ""
        echo -e "  ${GREEN}0.${NC} ${YELLOW}Volver al menú principal${NC}"
        echo -e "  ${GREEN}R.${NC} ${YELLOW}Recargar la lista de scripts${NC}"
        echo ""
        echo -ne "${BOLD}${WHITE}➜ Selecciona un script [0-${#scripts[@]}, R]: ${NC}"

        if ! IFS= read -r choice; then
            return
        fi

        if [[ "$choice" == "0" ]]; then
            return
        elif [[ "$choice" == "R" || "$choice" == "r" ]]; then
            continue
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#scripts[@]} )); then
            local idx=$((choice - 1))
            if [[ "$module_dir" == 08_Forensics || "$module_dir" == 10_Evidence ]]; then
                # Its coordinator only runs selected sources; original-list
                # calls use the same file prompts and dangerous gate as 08.
                execute_script "${scripts[$idx]}" "$module_dir"
            elif [[ "${categories[$idx]}" == "run_all" ]]; then
                echo ""
                echo -e "${YELLOW}⚠️  Este script ejecuta TODOS los scripts del módulo${NC}"
                if ask_confirm "¿Deseas continuar?"; then
                    execute_script "${scripts[$idx]}" "$module_dir"
                else
                    echo -e "${YELLOW}Operación cancelada${NC}"
                    sleep 1
                fi
            else
                # http_inject/rate_limit/sqlmap/web_login_bruteforce no deducen
                # el esquema del puerto (443/8443 no acredita TLS) y aquí no hay
                # slot para pedirlo: la opción por entorno queda fuera de la línea
                # Uso: a propósito. Sin este empujón el script corta con
                # "Selecciona X_ESQUEMA=..." y parece roto. Se pide una vez, solo
                # para esta ejecución, y no se guarda ni se reutiliza en la
                # siguiente selección.
                local esquema_var="" esquema_val=""
                case "${scripts[$idx]}" in
                    */web/http_inject.sh) esquema_var=HTTP_INJECT_ESQUEMA ;;
                    */web/rate_limit_probe.sh) esquema_var=RATE_LIMIT_ESQUEMA ;;
                    */web/sqlmap_request.sh) esquema_var=SQLMAP_ESQUEMA ;;
                    */web/web_login_bruteforce.sh) esquema_var=BRUTE_ESQUEMA ;;
                esac
                if [[ -n "$esquema_var" ]]; then
                    echo ""
                    echo -e "${YELLOW}ℹ️  Este script no deduce el esquema del puerto.${NC}"
                    echo -ne "${BOLD}${WHITE}Esquema real del servicio http|https (Enter = no fijarlo): ${NC}"
                    IFS= read -r esquema_val
                    case "$esquema_val" in
                        http|https|"") ;;
                        *) echo -e "${RED}❌ Esquema no válido: '${esquema_val}'; se continúa sin fijarlo.${NC}"
                           esquema_val="" ;;
                    esac
                fi
                [[ -n "$esquema_var" && -n "$esquema_val" ]] && export "$esquema_var=$esquema_val"

                # web_login_bruteforce.sh no tiene slot para el tope de
                # intentos (BRUTE_MAX): es por entorno, igual que el esquema
                # de arriba. Se pide una vez, solo para esta ejecución, y no
                # se guarda ni se reutiliza en la siguiente selección. Enter
                # deja el valor por defecto del script (200); no hay tope
                # duro que el menú deba respetar.
                local max_val=""
                if [[ "${scripts[$idx]}" == */web/web_login_bruteforce.sh ]]; then
                    echo ""
                    echo -ne "${BOLD}${WHITE}Número de intentos (Enter = por defecto del script): ${NC}"
                    IFS= read -r max_val
                    if [[ -n "$max_val" ]] && ! [[ "$max_val" =~ ^[0-9]+$ && "$max_val" -ge 1 ]]; then
                        echo -e "${RED}❌ Tiene que ser un entero > 0: '${max_val}'; se continúa con el valor por defecto.${NC}"
                        max_val=""
                    fi
                fi
                [[ -n "$max_val" ]] && export BRUTE_MAX="$max_val"

                # Tipo de diccionario: tampoco tiene slot (es BRUTE_DICC_TIPO,
                # por entorno). En combo el usuario lo trae cada línea
                # (usuario:contraseña), así que el slot [usuario] genérico no
                # tiene sentido y no se pregunta; se recogen fichero y
                # diccionario a mano y se llama --prepared con solo esos dos.
                # En claves sigue el camino genérico de siempre (pide
                # fichero, diccionario y el [usuario] fijo opcional).
                local dicc_tipo="" dicc_prepared=0 dicc_fichero="" dicc_diccionario="" dicc_cancelado=0
                if [[ "${scripts[$idx]}" == */web/web_login_bruteforce.sh ]]; then
                    echo ""
                    echo -e "${BOLD}${WHITE}Tipo de diccionario:${NC}"
                    echo "   1) claves — una contraseña por línea, mismo usuario en todos los intentos"
                    echo "   2) combo  — una credencial por línea, usuario:contraseña (ej. prueba@gmail.com:123456)"
                    echo -ne "${BOLD}${WHITE}Elige [1-2] (Enter = 1): ${NC}"
                    IFS= read -r dicc_tipo
                    case "$dicc_tipo" in
                        ""|1) dicc_tipo="claves" ;;
                        2) dicc_tipo="combo" ;;
                        *)
                            echo -e "${RED}❌ Opción no válida: '${dicc_tipo}'; se continúa con «claves».${NC}"
                            dicc_tipo="claves"
                            ;;
                    esac
                    if [[ "$dicc_tipo" == "combo" ]]; then
                        dicc_prepared=1
                        export BRUTE_DICC_TIPO=combo
                        echo -ne "${BOLD}${WHITE}Ruta de la petición capturada .req (o «manual»): ${NC}"
                        IFS= read -r dicc_fichero
                        echo -ne "${BOLD}${WHITE}Ruta del diccionario combinado (usuario:contraseña): ${NC}"
                        IFS= read -r dicc_diccionario
                        if [[ -z "$dicc_fichero" || -z "$dicc_diccionario" ]]; then
                            echo -e "${YELLOW}Cancelado: falta el fichero o el diccionario.${NC}"
                            dicc_cancelado=1
                        fi
                    fi
                fi

                if (( dicc_cancelado )); then
                    :
                elif (( dicc_prepared )); then
                    execute_script "${scripts[$idx]}" "$module_dir" --prepared "$dicc_fichero" "$dicc_diccionario"
                else
                    execute_script "${scripts[$idx]}" "$module_dir"
                fi
                [[ -n "$esquema_var" ]] && unset "$esquema_var"
                [[ -n "$max_val" ]] && unset BRUTE_MAX
                [[ -n "$dicc_tipo" ]] && unset BRUTE_DICC_TIPO
            fi
        else
            echo -e "${RED}❌ Opción inválida${NC}"
            sleep 1
        fi
    done
}

# ─── Funciones para módulos específicos ─────────────────────

module_config() {
    run_module_scripts "00_Config" "00_Configuración"
}

module_osint() {
    run_module_scripts "01_OSINT" "01_OSINT"
}

module_recon() {
    run_module_scripts "02_Recon" "02_Recon"
}

module_scanners() {
    scanners_menu
}

module_enumeration() {
    enumeration_menu
}

module_exploitation() {
    exploitation_menu
}

module_postexploitation() {
    postexploitation_menu
}

module_wireless() {
    wireless_menu
}

module_forensics() {
    forensics_menu
}

module_automation() {
    automation_menu
}

module_evidence() {
    evidence_menu
}

module_reports() {
    run_module_scripts "11_Reports" "11_Reports"
}

module_knowledge() {
    run_module_scripts "12_Knowledge_Base" "12_Knowledge_Base"
}

module_labs() {
    clear_screen
    echo -e "${GREEN}${BOLD}━━━ 13_LABS ━━━${NC}"
    echo ""
    
    if [[ -f "13_Labs/main.sh" ]]; then
        echo -e "${YELLOW}Abriendo menú de laboratorios...${NC}"
        sleep 1
        (cd 13_Labs && ./main.sh)
    else
        run_module_scripts "13_Labs" "13_Labs"
    fi
}

# ─── Flujo Completo ──────────────────────────────────────────

# La fase de reconocimiento se lanza con auto_recon.sh, no con
# run_all_recon.sh: este último ya acepta objetivo desde 2026-10-31, pero
# encadena los seis scripts del módulo y multiplicaría por seis lo que hace
# la opción 99. Se mantiene auto_recon.sh por alcance, no por limitación.
run_recon_phase() {
    local script="02_Recon/scripts/auto_recon.sh"
    if [[ ! -f "$script" ]]; then
        echo -e "${YELLOW}⚠️  No se encontró $script; se salta la fase.${NC}"
        return 1
    fi
    execute_script "$script" "02_Recon"
}

full_workflow() {
    clear_screen
    echo -e "${CYAN}${BOLD}━━━ FLUJO COMPLETO DE AUDITORÍA ━━━${NC}"
    echo ""

    local target
    target=$(session_target)
    if [[ -z "$target" ]]; then
        echo -e "${RED}❌ No hay objetivo definido.${NC}"
        echo -e "${YELLOW}Primero elige el objetivo con la opción T.${NC}"
        pause
        return
    fi

    echo -e "  Objetivo: ${GREEN}${target}${NC}"
    echo ""
    echo -e "${YELLOW}Fases que se ejecutarán, en orden:${NC}"
    echo -e "  ${GREEN}1.${NC} Configuración    (00_Config)"
    echo -e "  ${GREEN}2.${NC} OSINT            (01_OSINT)"
    echo -e "  ${GREEN}3.${NC} Reconocimiento   (02_Recon)"
    echo -e "  ${GREEN}4.${NC} Escaneo          (03_Scanners)"
    echo -e "  ${GREEN}5.${NC} Enumeración      (04_Enumeration)"
    echo -e "  ${GREEN}6.${NC} Explotación      (05_Exploitation)"
    echo -e "  ${GREEN}7.${NC} Post-explotación (06_PostExploitation)"
    echo -e "  ${GREEN}8.${NC} Evidencia        (10_Evidence)"
    echo -e "  ${GREEN}9.${NC} Reporte          (11_Reports)"
    echo ""
    echo -e "${RED}${BOLD}⚠️  Incluye fuerza bruta; persistencia y limpieza quedan excluidas por sus coordinadores.${NC}"
    echo -e "${RED}   Solo contra equipos propios o con autorización escrita.${NC}"
    echo ""

    local scope
    scope_allows "$target"
    case $? in
        0) echo -e "${GREEN}✔ $target está dentro del alcance de scope.yaml${NC}" ;;
        1) echo -e "${RED}✖ $target NO aparece en scope.yaml${NC}" ;;
        *) echo -e "${YELLOW}? No se pudo interpretar scope.yaml; revísalo a mano.${NC}" ;;
    esac
    echo ""

    if ! ask_confirm "¿Ejecutar el flujo completo contra $target?"; then
        echo -e "${YELLOW}Operación cancelada${NC}"
        sleep 1
        return
    fi

    local phase run_script
    for phase in "00_Config" "01_OSINT" "02_Recon" "03_Scanners" "04_Enumeration" \
                 "05_Exploitation" "06_PostExploitation" "10_Evidence" "11_Reports"; do
        if [[ ! -d "$phase" ]]; then
            echo -e "${RED}❌ Fase $phase no encontrada${NC}"
            continue
        fi

        echo -e "\n${CYAN}▶️  Fase: $phase${NC}"

        if [[ "$phase" == "02_Recon" ]]; then
            run_recon_phase
            continue
        fi

        run_script=$(find "$phase" -maxdepth 1 -name "run_all_*.sh" -type f 2>/dev/null | head -1)
        if [[ -z "$run_script" ]]; then
            echo -e "${YELLOW}⚠️  No hay run_all_*.sh en $phase; se salta.${NC}"
            sleep 1
            continue
        fi
        execute_script "$run_script" "$phase"
    done

    echo -e "\n${GREEN}✅ Flujo de auditoría completado${NC}"
    pause
}

# ─── Informe rápido (acción R) ──────────────────────────────

quick_report() {
    local eleccion tipo cliente auditor target per_file
    local save_cliente=0 save_auditor=0
    local result rc html_file='' f
    local -a report_files=()
    local -a engine_args=()

    clear_screen
    echo -e "${CYAN}${BOLD}━━━ INFORME RÁPIDO ━━━${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}) Informe técnico"
    echo -e "  ${GREEN}2${NC}) Informe de cliente"
    echo -e "  ${GREEN}3${NC}) Ambos informes"
    echo -e "  ${GREEN}0${NC}) Volver al menú principal"
    echo ""
    echo -ne "${BOLD}➜ Elige tipo de informe [0-3]: ${NC}"
    if ! IFS= read -r eleccion; then
        return 0
    fi

    case "$eleccion" in
        0) return 0 ;;
        1) tipo="tecnico" ;;
        2) tipo="cliente" ;;
        3) tipo="ambos" ;;
        *)
            echo -e "${RED}❌ Opción inválida${NC}"
            pause
            return 0
            ;;
    esac

    # Perfil: si falta cliente o auditor, preguntar
    per_file="$(report_profile_path)"
    cliente="$(report_profile_get cliente)"
    auditor="$(report_profile_get auditor)"

    if [[ -z "$cliente" ]]; then
        echo ""
        echo -ne "${BOLD}➜ Nombre del cliente (Enter = vacío): ${NC}"
        IFS= read -r cliente || return 0
        if [[ -n "$cliente" ]]; then
            save_cliente=1
        fi
    fi

    if [[ -z "$auditor" ]]; then
        echo ""
        echo -ne "${BOLD}➜ Nombre del auditor (Enter = $(whoami)): ${NC}"
        IFS= read -r auditor || return 0
        if [[ -z "$auditor" ]]; then
            auditor="$(whoami)"
        fi
        save_auditor=1
    fi

    # No persistir una selección incompleta si EOF cancela el perfil.
    if [[ $save_cliente -eq 1 ]]; then report_profile_set cliente "$cliente" || return 1; fi
    if [[ $save_auditor -eq 1 ]]; then report_profile_set auditor "$auditor" || return 1; fi

    # Construir argumentos del motor
    if [[ -n "$cliente" ]]; then
        engine_args+=(--cliente "$cliente")
    fi
    if [[ -n "$auditor" ]]; then
        engine_args+=(--auditor "$auditor")
    fi

    target="$(session_target)"
    if [[ -n "$target" ]]; then
        engine_args+=(--objetivo "$target")
    fi

    echo ""
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Generando informe $tipo...${NC}"
    echo ""

    result="$(bash 11_Reports/report_generator.sh "$tipo" "${engine_args[@]}" --json)"
    rc=$?

    echo ""
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # El recibo del motor es la única autoridad: no adivinar rutas ni listar
    # archivos históricos, tampoco tras un fallo o una salida personalizada.
    if [[ $rc -eq 0 || $rc -eq 3 ]]; then
        mapfile -d '' -t report_files < <(printf '%s' "$result" | python3 -c '
import json, sys
for path in json.load(sys.stdin)["archivos"]:
    sys.stdout.write(path + "\0")
')
        echo -e "${GREEN}📁 Informes escritos en esta ejecución${NC}:"
        for f in "${report_files[@]}"; do
            printf '  %s\n' "$f"
            if [[ -z "$html_file" && "$f" == *.html ]]; then
                html_file="$f"
            fi
        done
    fi
    if [[ -n "$html_file" ]]; then
        echo ""
        echo -ne "${BOLD}¿Abrir informe HTML? (s/N): ${NC}"
        local abrir=""
        IFS= read -r abrir || abrir=""
        case "$abrir" in
            s|S|si|Si|SI|sí|Sí)
                xdg-open "$html_file" 2>/dev/null || true
                ;;
        esac
    fi

    if [[ $rc -ne 0 ]]; then
        echo ""
        echo -e "${YELLOW}⚠️  Código de salida del motor: $rc${NC}"
    fi

    pause
}

# ─── Ayuda ───────────────────────────────────────────────────

show_help() {
    clear_screen
    echo -e "${CYAN}${BOLD}━━━ AYUDA ━━━${NC}"
    echo ""
    echo -e "${YELLOW}📋 MÓDULOS DEL FRAMEWORK:${NC}"
    echo ""
    echo -e "  ${GREEN}00_Config${NC}       Configuración, alcance y lista de objetivos"
    echo -e "  ${GREEN}01_OSINT${NC}        Inteligencia de fuentes abiertas"
    echo -e "  ${GREEN}02_Recon${NC}        Reconocimiento y fingerprinting"
    echo -e "  ${GREEN}03_Scanners${NC}     Escáneres (Nmap, Masscan, Nuclei, Nikto)"
    echo -e "  ${GREEN}04_Enumeration${NC}  Enumeración de servicios"
    echo -e "  ${GREEN}05_Exploitation${NC} Explotación de vulnerabilidades"
    echo -e "  ${GREEN}06_PostExploitation${NC} Post-explotación"
    echo -e "  ${GREEN}07_Wireless${NC}     Seguridad inalámbrica"
    echo -e "  ${GREEN}08_Forensics${NC}    Análisis forense"
    echo -e "  ${GREEN}09_Automation${NC}   Automatización y workflows"
    echo -e "  ${GREEN}10_Evidence${NC}     Gestión de evidencia"
    echo -e "  ${GREEN}11_Reports${NC}      Generación de reportes"
    echo -e "  ${GREEN}12_Knowledge_Base${NC} Base de conocimiento"
    echo -e "  ${GREEN}13_Labs${NC}         Laboratorios de práctica"
    echo ""
    echo -e "${YELLOW}💡 ORDEN RECOMENDADO:${NC}"
    echo -e "  ${GREEN}1.${NC} 00_Config      valida el alcance y los objetivos"
    echo -e "  ${GREEN}2.${NC} 02_Recon       descubre qué hay vivo"
    echo -e "  ${GREEN}3.${NC} 03_Scanners    busca servicios y vulnerabilidades"
    echo -e "  ${GREEN}4.${NC} 04_Enumeration saca detalles de cada servicio"
    echo -e "  ${GREEN}5.${NC} 05 y 06        solo si tienes autorización"
    echo -e "  ${GREEN}6.${NC} 10_Evidence y 11_Reports recogen y documentan"
    echo ""
    echo -e "${YELLOW}🎯 OBJETIVO:${NC}"
    echo -e "  Con ${GREEN}T${NC} eliges el equipo o dominio de la sesión. Se guarda en"
    echo -e "  ${DIM}00_Config/.session${NC} y se propone como valor por defecto en"
    echo -e "  todos los scripts que piden un host. Si defines varios en"
    echo -e "  ${DIM}00_Config/targets.txt${NC}, te los ofrece como lista."
    echo ""
    echo -e "${YELLOW}⌨️  ATAJOS:${NC}"
    echo -e "  ${GREEN}T${NC}   Cambiar objetivo"
    echo -e "  ${GREEN}R${NC}   Informe rápido (técnico, cliente o ambos)"
    echo -e "  ${GREEN}K${NC}   Claves de API (pide y guarda las que falten)"
    echo -e "  ${GREEN}D${NC}   Dependencias (ver qué falta e instalarlo)"
    echo -e "  ${GREEN}I${NC}   Asistente IA local (explica hallazgos y responde sobre el framework)"
    echo -e "  ${GREEN}0${NC}   Volver al menú principal"
    echo -e "  ${GREEN}Q${NC}   Salir"
    echo ""
    echo -e "${YELLOW}📝 INFORMES:${NC}"
    echo -e "  Con ${GREEN}R${NC} generas los informes técnico y de cliente desde lo ya escaneado."
    echo ""
    echo -e "${YELLOW}📖 DOCUMENTACIÓN:${NC}"
    echo -e "  Manual completo del gestor: ${DIM}../docs/MANUAL-GESTOR.md${NC}"
    echo -e "  ${DIM}(o ejecuta desde la raíz del repo: less docs/MANUAL-GESTOR.md)${NC}"
    echo ""
    echo -e "${YELLOW}ℹ️  MARCAS EN LA LISTA:${NC}"
    echo -e "  ${RED}[intrusiva]${NC}  pide confirmación extra antes de ejecutarse"
    echo -e "  ${CYAN}[manual]${NC}     usa banderas o subcomandos; escribes los argumentos"
    echo -e "  ${YELLOW}[generador]${NC}  escribe otro script, no escanea nada"
    echo ""
    pause
}

# ─── Menú Principal ──────────────────────────────────────────

main_menu() {
    local target next
    target=$(session_target)

    clear_screen
    show_banner
    show_module_status

    echo -e "${BOLD}${WHITE}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${WHITE}│  SELECCIONA UN MÓDULO                                  │${NC}"
    echo -e "${BOLD}${WHITE}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "  ${CYAN}00${NC}  ${WHITE}⚙️  Configuración y Setup${NC}"
    echo -e "  ${CYAN}01${NC}  ${WHITE}🔍 OSINT - Inteligencia de código abierto${NC}"
    echo -e "  ${CYAN}02${NC}  ${WHITE}📡 Reconocimiento y Fingerprinting${NC}"
    echo -e "  ${CYAN}03${NC}  ${WHITE}🔬 Escáneres (Nmap, Masscan, Nuclei)${NC}"
    echo -e "  ${CYAN}04${NC}  ${WHITE}📋 Enumeración de servicios${NC}"
    echo -e "  ${CYAN}05${NC}  ${WHITE}💀 Explotación de vulnerabilidades${NC}"
    echo -e "  ${CYAN}06${NC}  ${WHITE}🎯 Post-Explotación${NC}"
    echo -e "  ${CYAN}07${NC}  ${WHITE}📶 Wireless - WiFi y Bluetooth${NC}"
    echo -e "  ${CYAN}08${NC}  ${WHITE}🔎 Forense y Análisis${NC}"
    echo -e "  ${CYAN}09${NC}  ${WHITE}🤖 Automatización y Workflows${NC}"
    echo -e "  ${CYAN}10${NC}  ${WHITE}📦 Evidencia y Capturas${NC}"
    echo -e "  ${CYAN}11${NC}  ${WHITE}📊 Generación de Reportes${NC}"
    echo -e "  ${CYAN}12${NC}  ${WHITE}📚 Base de Conocimiento${NC}"
    echo -e "  ${CYAN}13${NC}  ${WHITE}🧪 Laboratorios (HTB/THM/AD)${NC}"
    echo ""
    echo -e "  ${CYAN}99${NC}  ${WHITE}🚀 Ejecutar Flujo Completo${NC}"
    echo -e "  ${CYAN}R ${NC}  ${WHITE}📊 Informe rápido${NC}"
    echo -e "  ${CYAN}T ${NC}  ${WHITE}🎯 Cambiar objetivo${NC} ${DIM}(actual: ${target:-sin definir})${NC}"
    echo -e "  ${CYAN}K ${NC}  ${WHITE}🔑 Claves de API${NC} ${DIM}($(keys_resumen_line))${NC}"
    echo -e "  ${CYAN}D ${NC}  ${WHITE}📦 Dependencias${NC} ${DIM}($(dependencies_resumen_line))${NC}"
    echo -e "  ${CYAN}I ${NC}  ${WHITE}🤖 Asistente IA${NC}"
    echo -e "  ${CYAN}? ${NC}  ${WHITE}📖 Ayuda y Comandos Útiles${NC}"
    echo -e "  ${CYAN}Q ${NC}  ${RED}Salir${NC}"
    echo ""

    next=$(next_suggested_phase)
    if [[ -n "$next" ]]; then
        echo -e "  ${DIM}Siguiente paso sugerido:${NC} ${YELLOW}${next}${NC}"
    fi
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -ne "${BOLD}${WHITE}➜ Selecciona un módulo [00-13, 99, R, T, K, D, I, ?, Q]: ${NC}"
}

# ─── Claves de API ───────────────────────────────────────────

keys_helper() {
    python3 00_Config/scripts/api_keys.py "$@"
}

# Resumen de una línea para el menú principal (nunca muestra valores)
keys_resumen_line() {
    keys_helper estado --json 2>/dev/null | python3 -c '
import json, sys
try:
    datos = json.load(sys.stdin)["herramientas"]
except Exception:
    print("registro no disponible")
    raise SystemExit
con_claves = sum(1 for h in datos if h["puestas"] > 0)
sin_claves = len(datos) - con_claves
print(f"{len(datos)} herramientas · {con_claves} con claves · {sin_claves} sin claves")
'
}

# Lista numerada; el nombre elegido queda en KEYS_ELECCION (vacío si no hay)
keys_elegir_herramienta() {
    local -a herramientas=(theharvester shodan h8mail amass recon-ng spiderfoot)
    local i numero
    KEYS_ELECCION=""
    for i in "${!herramientas[@]}"; do
        numero=$((i + 1))
        echo -e "  ${GREEN}${numero}${NC}) ${herramientas[$i]}"
    done
    echo ""
    echo -ne "${BOLD}➜ Herramienta [1-${#herramientas[@]}, 0 = volver]: ${NC}"
    if ! IFS= read -r numero; then
        return 0
    fi
    case "$numero" in
        0|"") return 0 ;;
    esac
    if [[ "$numero" =~ ^[0-9]+$ ]] && (( numero >= 1 && numero <= ${#herramientas[@]} )); then
        KEYS_ELECCION="${herramientas[$((numero - 1))]}"
    fi
    return 0
}

keys_menu() {
    local eleccion herramienta
    local volver_a="${1:-menú principal}"

    clear_screen
    echo -e "${CYAN}${BOLD}━━━ CLAVES DE API ━━━${NC}"
    echo ""
    keys_helper estado | sed 's/^/  /'
    echo ""
    echo -e "  ${GREEN}1${NC}) Pedir las claves que falten en cada herramienta"
    echo -e "  ${GREEN}2${NC}) Pedir las claves de una herramienta"
    echo -e "  ${GREEN}3${NC}) Ver el estado detallado"
    echo -e "  ${GREEN}4${NC}) Sincronizar el registro con las herramientas"
    echo -e "  ${GREEN}5${NC}) Importar lo que ya tienen las herramientas"
    echo -e "  ${GREEN}0${NC}) Volver al ${volver_a}"
    echo ""
    echo -e "  ${DIM}Enter deja la clave como está; '-' la borra.${NC}"
    echo ""
    echo -ne "${BOLD}➜ Elige una opción [0-5]: ${NC}"
    if ! IFS= read -r eleccion; then
        return 0
    fi

    case "$eleccion" in
        0) return 0 ;;
        1)
            local t
            for t in theharvester shodan h8mail amass recon-ng spiderfoot; do
                echo ""
                echo -e "${BOLD}▶ ${t}${NC}"
                keys_helper pedir "$t"
            done
            ;;
        2)
            echo ""
            keys_elegir_herramienta
            herramienta="$KEYS_ELECCION"
            if [[ -z "$herramienta" ]]; then
                pause
                return 0
            fi
            keys_helper pedir "$herramienta"
            ;;
        3) keys_helper estado ;;
        4) keys_helper sincronizar ;;
        5)
            echo ""
            keys_elegir_herramienta
            herramienta="$KEYS_ELECCION"
            if [[ -z "$herramienta" ]]; then
                pause
                return 0
            fi
            keys_helper importar "$herramienta"
            ;;
        *)
            echo -e "${RED}❌ Opción inválida${NC}"
            ;;
    esac
    pause
}

# ─── Dependencias ────────────────────────────────────────────

dependencies_menu() {
    local -a faltan
    local eleccion seleccion i idx
    local -a elegidos

    clear_screen
    echo -e "${CYAN}${BOLD}━━━ DEPENDENCIAS ━━━${NC}"
    echo ""
    dependencies_status
    echo ""
    mapfile -t faltan < <(dependencies_missing_with_package)
    if [[ ${#faltan[@]} -eq 0 ]]; then
        echo -e "  ${DIM}No falta nada instalable por apt.${NC}"
    else
        echo -e "${YELLOW}Paquetes que faltan e instalan por apt:${NC}"
        for i in "${!faltan[@]}"; do
            printf '  %d) %s\n' "$((i + 1))" "${faltan[$i]}"
        done
    fi
    echo ""
    echo -e "  ${GREEN}1${NC}) Instalar dependencias (elegir de la lista)"
    echo -e "  ${GREEN}0${NC}) Volver al menú principal"
    echo ""
    echo -ne "${BOLD}➜ Elige una opción [0-1]: ${NC}"
    if ! IFS= read -r eleccion; then
        return 0
    fi
    case "$eleccion" in
        0|'') return 0 ;;
        1)
            if [[ ${#faltan[@]} -eq 0 ]]; then
                echo -e "${DIM}Nada que instalar.${NC}"; pause; return 0
            fi
            echo -ne "${BOLD}➜ Números a instalar (espacio entre varios, 'todas', 0 o ! cancela): ${NC}"
            if ! IFS= read -r seleccion || [[ "$seleccion" == '0' || "$seleccion" == '!' || -z "$seleccion" ]]; then
                pause; return 0
            fi
            local resuelto rc_resuelto
            resuelto=$(dependencies_resolve_selection "$seleccion" "${faltan[@]}")
            rc_resuelto=$?
            if [[ $rc_resuelto -ne 0 ]]; then
                echo -e "${RED}Selección inválida.${NC}"; pause; return 0
            fi
            elegidos=()
            mapfile -t elegidos <<< "$resuelto"
            dependencies_install "${elegidos[@]}"
            ;;
        *) echo -e "${RED}❌ Opción inválida${NC}" ;;
    esac
    pause
}

# ─── Bucle Principal ─────────────────────────────────────────

main() {
    local choice
    while true; do
        main_menu

        if ! IFS= read -r choice; then
            echo ""
            echo -e "${GREEN}👋 Entrada cerrada. ¡Hasta luego!${NC}"
            exit 0
        fi

        # Aceptar "3" además de "03"
        case "$choice" in
            [0-9]) choice="0$choice" ;;
        esac

        case "$choice" in
            00) module_config ;;
            01) module_osint ;;
            02) module_recon ;;
            03) module_scanners ;;
            04) module_enumeration ;;
            05) module_exploitation ;;
            06) module_postexploitation ;;
            07) module_wireless ;;
            08) module_forensics ;;
            09) module_automation ;;
            10) module_evidence ;;
            11) module_reports ;;
            12) module_knowledge ;;
            13) module_labs ;;
            99) full_workflow ;;
            R|r) quick_report ;;
            T|t) change_target ;;
            K|k) keys_menu ;;
            D|d) dependencies_menu ;;
            I|i) ai_menu ;;
            \?|\?\?|help|HELP|H|h) show_help ;;
            Q|q|salir|exit)
                echo -e "\n${GREEN}👋 ¡Hasta luego!${NC}"
                exit 0
                ;;
            "") : ;;
            *)
                echo -e "\n${RED}❌ Opción inválida: '$choice'${NC}"
                echo -e "${YELLOW}Prueba con 00-13, 99, R, T, K, D, I, ? o Q.${NC}"
                pause
                ;;
        esac
    done
}

# ─── Iniciar ─────────────────────────────────────────────────

if [[ ! -d "00_Config" ]]; then
    echo -e "${RED}❌ Error: No se encuentra el directorio 00_Config${NC}"
    echo -e "${YELLOW}ℹ️  Ejecuta desde la raíz del framework:${NC}"
    echo -e "${GREEN}cd \"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)\"${NC}"
    echo -e "${GREEN}./cyber_framework.sh${NC}"
    exit 1
fi

# Solo arranca el menú si se ejecuta; los tests lo cargan con source.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
