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
    echo -e "  ${DIM}Fases:${NC} ${out}${DIM}(* hecha, . pendiente)${NC}"
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

execute_script() {
    local script_path="$1"   # ruta relativa al framework
    local module_dir="$2"
    local original_dir="$PWD"
    local rel_path values rc rc_run
    local -a argv=()

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

    if params_is_dangerous "$script_path"; then
        echo -e "${RED}⚠️  Herramienta intrusiva (fuerza bruta / explotación / persistencia).${NC}"
        if ! ask_confirm "¿Confirmas que el objetivo está dentro de tu alcance autorizado?"; then
            echo -e "${YELLOW}Cancelado${NC}"
            cd "$original_dir" || exit 1
            return 0
        fi
    fi

    # Los datos que pide el script salen de su propia línea Uso:
    values=$(prompt_for_slots "$rel_path" "$script_path")
    rc=$?

    if [[ $rc -ne 0 ]]; then
        case "$rc" in
            1) echo -e "${YELLOW}Cancelado: no se ha ejecutado nada.${NC}" ;;
            2) echo -e "${RED}Entrada cerrada: no se ha ejecutado nada.${NC}" ;;
        esac
        cd "$original_dir" || exit 1
        return 0
    fi

    [[ -n "$values" ]] && mapfile -t argv <<< "$values"

    if [[ ${#argv[@]} -gt 0 ]]; then
        echo -e "${DIM}Argumentos: ${argv[*]}${NC}"
    else
        echo -e "${DIM}Sin argumentos${NC}"
    fi
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

        if [[ ! -d "$module_dir" ]]; then
            echo -e "${RED}❌ Módulo no encontrado: $module_dir${NC}"
            pause
            return
        fi

        echo -e "${YELLOW}📂 Directorio: $PWD/$module_dir${NC}"
        echo ""

        local -a scripts=() categories=()
        local script rel_path choice

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
            if [[ "${categories[$idx]}" == "run_all" ]]; then
                echo ""
                echo -e "${YELLOW}⚠️  Este script ejecuta TODOS los scripts del módulo${NC}"
                if ask_confirm "¿Deseas continuar?"; then
                    execute_script "${scripts[$idx]}" "$module_dir"
                else
                    echo -e "${YELLOW}Operación cancelada${NC}"
                    sleep 1
                fi
            else
                execute_script "${scripts[$idx]}" "$module_dir"
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
    run_module_scripts "03_Scanners" "03_Scanners"
}

module_enumeration() {
    run_module_scripts "04_Enumeration" "04_Enumeration"
}

module_exploitation() {
    run_module_scripts "05_Exploitation" "05_Exploitation"
}

module_postexploitation() {
    run_module_scripts "06_PostExploitation" "06_PostExploitation"
}

module_wireless() {
    run_module_scripts "07_Wireless" "07_Wireless"
}

module_forensics() {
    run_module_scripts "08_Forensics" "08_Forensics"
}

module_automation() {
    run_module_scripts "09_Automation" "09_Automation"
}

module_evidence() {
    run_module_scripts "10_Evidence" "10_Evidence"
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

# La fase de reconocimiento se lanza con auto_recon.sh, que sí acepta el
# objetivo. run_all_recon.sh ignora sus argumentos y usa los tres primeros
# de 00_Config/targets.txt, así que no sirve para un objetivo de sesión.
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
    echo -e "${RED}${BOLD}⚠️  Incluye fuerza bruta, persistencia y limpieza.${NC}"
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
    echo -e "  ${GREEN}R${NC}   Recargar la lista de scripts de un módulo"
    echo -e "  ${GREEN}0${NC}   Volver al menú principal"
    echo -e "  ${GREEN}Q${NC}   Salir"
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
    echo -e "  ${CYAN}T ${NC}  ${WHITE}🎯 Cambiar objetivo${NC} ${DIM}(actual: ${target:-sin definir})${NC}"
    echo -e "  ${CYAN}??${NC}  ${WHITE}📖 Ayuda y Comandos Útiles${NC}"
    echo -e "  ${CYAN}Q ${NC}  ${RED}Salir${NC}"
    echo ""

    next=$(next_suggested_phase)
    if [[ -n "$next" ]]; then
        echo -e "  ${DIM}Siguiente paso sugerido:${NC} ${YELLOW}${next}${NC}"
    fi
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -ne "${BOLD}${WHITE}➜ Selecciona un módulo [00-13, 99, T, ?, Q]: ${NC}"
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
            T|t) change_target ;;
            \?|help|HELP|H|h) show_help ;;
            Q|q|salir|exit)
                echo -e "\n${GREEN}👋 ¡Hasta luego!${NC}"
                exit 0
                ;;
            "") : ;;
            *)
                echo -e "\n${RED}❌ Opción inválida: '$choice'${NC}"
                echo -e "${YELLOW}Prueba con 00-13, 99, T, ? o Q.${NC}"
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
