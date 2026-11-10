#!/bin/bash
# Menú del módulo 03. Solo lo carga el gestor; no es un script ejecutable.
SCANNERS_MENU_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "$SCANNERS_MENU_DIR/scanner_runtime.bash"

scanners_check_tools() {
    local tool
    echo '━━━ COMPROBACIÓN LOCAL — sin tráfico de red ━━━'
    for tool in nmap masscan rustscan nikto nuclei burpsuite python3; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '  ✓ %s disponible\n' "$tool"
        else
            printf '  — %s no instalado\n' "$tool"
        fi
    done
    echo 'Masscan necesita root; el menú no ejecuta sudo.'
    echo 'Nmap básico no necesita root; algunos perfiles avanzados sí.'
    if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        echo 'Burp: entorno gráfico declarado; Community requiere interacción manual.'
    else
        echo 'Burp: sin entorno gráfico declarado (DISPLAY/WAYLAND_DISPLAY).'
    fi
    echo 'No se han instalado herramientas ni actualizado plantillas.'
}

# stdout: exclusivamente el valor; stderr: toda la pregunta.
_scanners_read_target() {
    local kind="$1" def="${2:-}" value
    if [[ "$kind" == url ]]; then
        printf 'URL completa HTTP(S), con puerto/ruta si corresponde (0 o ! cancela): ' >&2
    else
        printf 'Host o IP único' >&2
        [[ -z "$def" ]] || printf ' [%s]' "$def" >&2
        printf ' (0 o ! cancela): ' >&2
    fi
    IFS= read -r value || return 2
    [[ "$value" != '!' && "$value" != 0 ]] || return 1
    value="${value:-$def}"
    [[ -n "$value" ]] || return 1
    _prompt_validate "${kind^^}" "$value" || { echo 'Entrada no válida.' >&2; return 1; }
    if [[ "$kind" == url ]]; then
        scanner_url "$value" || return 1
    else
        scanner_host "$value" || return 1
    fi
    printf '%s\n' "$value"
}

_scanners_confirm() {
    printf '\nResumen previo\n  Herramienta: %s\n  Objetivo: %s\n  Intensidad: %s\n' "$1" "$2" "$3"
    echo 'La autorización debe existir; el objetivo de sesión no la sustituye.'
    ask_confirm '¿Confirmas el alcance autorizado y deseas ejecutar?'
}

scanners_menu() {
    local choice target web_choice tool script
    while :; do
        clear_screen
        target=$(session_target)
        echo '━━━ 03 · ESCÁNERES — MENÚ GUIADO ━━━'
        printf 'Objetivo de sesión: %s\n\n' "${target:-sin definir}"
        echo '  1. Comprobar herramientas (local, sin escanear)'
        echo '  2. Puertos y servicios básicos (100 puertos TCP, sin NSE)'
        echo '  3. Analizar una URL (Nikto o Nuclei; tráfico activo)'
        echo '  4. Abrir Burp (captura manual, no escáner Community)'
        echo '  5. Herramientas avanzadas (todos los puertos, NSE, Masscan…)'
        echo '  0. Volver al menú principal'
        printf '\nSelecciona [0–5]: '
        IFS= read -r choice || return 0
        case "$choice" in
            0) return 0 ;;
            1) scanners_check_tools; pause ;;
            2)
                scanner_require nmap || { pause; continue; }
                target=$(_scanners_read_target host "$target") || continue
                _scanners_confirm 'Nmap básico' "$target" '100 puertos TCP y servicios ligeros; sin NSE ni detección de SO' || continue
                execute_script '03_Scanners/network_scanners/nmap/nmap_smart.sh' '03_Scanners' --prepared "$target" basico
                ;;
            3)
                echo '  1. Nikto — servidor web (puede tardar varios minutos)'
                echo '  2. Nuclei — plantillas HTTP medium/high/critical, máximo 10 peticiones/s'
                echo '  0. Cancelar'
                printf 'Herramienta: '
                IFS= read -r web_choice || return 0
                case "$web_choice" in
                    0) continue ;;
                    1) tool=nikto; script=web_scanners/nikto/nikto_scan.sh ;;
                    2) tool=nuclei; script=web_scanners/nuclei/nuclei_scan.sh ;;
                    *) echo 'Opción no válida.'; continue ;;
                esac
                scanner_require "$tool" || { pause; continue; }
                target=$(_scanners_read_target url) || continue
                _scanners_confirm "$tool" "$target" 'Análisis HTTP activo; no es una comprobación pasiva' || continue
                execute_script "03_Scanners/$script" '03_Scanners' --prepared "$target"
                ;;
            4)
                echo 'Burp Community: abrir GUI y capturar manualmente; no escanea ni guarda proyectos.'
                ask_confirm '¿Deseas abrir Burp y seguir su asistente de proxy?' || continue
                execute_script '03_Scanners/web_scanners/burpsuite/burp_launcher.sh' '03_Scanners'
                ;;
            5)
                echo 'Avanzado: Smart completo/NSE/Masscan/RustScan generan tráfico intensivo.'
                run_module_scripts '03_Scanners' '03_Scanners · AVANZADO'
                ;;
            *) echo 'Opción no válida. Elige entre 0 y 5.' ;;
        esac
    done
}
