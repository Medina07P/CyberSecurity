#!/bin/bash
# UI de mantenimiento de 07. Solo lo carga el gestor; no opera la radio.

wireless_check_tools() {
    local tool
    echo '━━━ COMPROBACIÓN LOCAL — sin ejecutar herramientas ━━━'
    for tool in sudo ip iw airodump-ng aireplay-ng aircrack-ng hcitool bluetoothctl sdptool gatttool; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '  ✓ %s disponible\n' "$tool"
        else
            printf '  — %s no instalado\n' "$tool"
        fi
    done
    echo 'La disponibilidad no verifica adaptadores, permisos ni funcionamiento operacional.'
}

wireless_maintenance_guide() {
    echo '━━━ GUÍA DE MANTENIMIENTO — sin operaciones inalámbricas ━━━'
    echo 'La entrada handshake es una guía: no prueba captura ni verificación de un handshake.'
    echo 'Este menú no lee capturas ni valida evidencia operacional.'
    echo 'No instala dependencias, cambia interfaces o servicios ni transmite por radio.'
    echo 'La lista original conserva sus diez entradas; no se declara integrado el flujo completo.'
    echo 'Cualquier uso operacional requiere alcance autorizado y revisión específica.'
}

wireless_menu() {
    local choice
    while :; do
        clear_screen
        echo '━━━ 07 · WIRELESS — MANTENIMIENTO ━━━'
        echo '  1. Comprobar herramientas (local, sin ejecutar)'
        echo '  2. Guía y límites de mantenimiento'
        echo ' 11. Lista original de scripts (diez entradas conservadas)'
        echo '  0. Volver al menú principal'
        printf '\nSelecciona [0, 1, 2, 11]: '
        IFS= read -r choice || return 0
        case "$choice" in
            0) return 0 ;;
            1) wireless_check_tools; pause ;;
            2) wireless_maintenance_guide; pause ;;
            11) run_module_scripts '07_Wireless' '07_Wireless' ;;
            *) echo 'Opción no válida.' ;;
        esac
    done
}
