# Puente exclusivo 09; nunca consulta ni registra el objetivo de sesión.
automation_menu() {
    local framework
    framework="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)" || return 1
    # Standalone: cargar solo el helper informativo, nunca sesión ni gestor.
    if ! declare -F module_intro >/dev/null; then
        if [[ ! -f "$framework/00_Config/lib/module_intro.bash" || -L "$framework/00_Config/lib/module_intro.bash" ]]; then
            printf 'Error: ficha09 no disponible; no se abre el menú.\n' >&2
            return 1
        fi
        source "$framework/00_Config/lib/module_intro.bash" || return 1
    fi
    if ! declare -F module_intro >/dev/null; then
        printf 'Error: helper de ficha09 inválido; no se abre el menú.\n' >&2
        return 1
    fi
    module_intro 09_Automation || return 1
    bash "$framework/09_Automation/run_all_automation.sh"
}
