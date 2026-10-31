#!/bin/bash
# ============================================================
#  CONFIG WIZARD - Alta guiada de objetivos en targets.txt
#  Uso: ./config_wizard.sh
#  Ejemplo: ./config_wizard.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=../lib/session.bash
source "$CONFIG_DIR/lib/session.bash"
TARGETS_FILE="$SESSION_TARGETS_FILE"

# ─── Validadores ───────────────────────────────────────────

# Protocolo sugerido para un puerto conocido. Sin salida si no lo conoce.
wz_default_protocol() {
    case "$1" in
        21)   printf 'FTP\n' ;;
        22)   printf 'SSH\n' ;;
        25)   printf 'SMTP\n' ;;
        53)   printf 'DNS\n' ;;
        80)   printf 'HTTP\n' ;;
        443)  printf 'HTTPS\n' ;;
        445)  printf 'SMB\n' ;;
        3306) printf 'MySQL\n' ;;
        3389) printf 'RDP\n' ;;
        5432) printf 'PostgreSQL\n' ;;
        6379) printf 'Redis\n' ;;
        8080) printf 'HTTP\n' ;;
    esac
    return 0
}

# Puerto válido: entero entre 1 y 65535.
wz_valid_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] || return 1
    (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

# Prioridad válida: C, A, M o B (sin distinguir mayúsculas).
wz_valid_priority() {
    [[ "$1" =~ ^[CcAaMmBb]$ ]]
}

# Texto válido: no vacío, sin el separador del formato y sin caracteres de control.
wz_valid_text() {
    [[ -n "$1" ]] || return 1
    [[ "$1" != *"|"* ]] || return 1
    [[ "$1" != *[[:cntrl:]]* ]] || return 1
    return 0
}

# ─── Flujo principal ───────────────────────────────────────

main() {
    :
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
