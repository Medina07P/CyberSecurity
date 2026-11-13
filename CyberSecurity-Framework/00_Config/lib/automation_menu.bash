# Puente exclusivo 09; nunca consulta ni registra el objetivo de sesión.
automation_menu() {
    local framework
    framework="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)" || return 1
    bash "$framework/09_Automation/run_all_automation.sh"
}
