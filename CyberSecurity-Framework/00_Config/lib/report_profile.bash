#!/bin/bash
# ============================================================
#  REPORT_PROFILE - Perfil de cliente/auditor para informes
#  Uso: source 00_Config/lib/report_profile.bash
#  El perfil se guarda en 11_Reports/.report_profile.
#  Las funciones que devuelven un valor imprimen SOLO el valor
#  por stdout; la interfaz va por stderr.
# ============================================================

REPORT_PROFILE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPORT_PROFILE_FW_DIR="$(cd "$REPORT_PROFILE_LIB_DIR/../.." && pwd)"
REPORT_PROFILE_FILE="${REPORT_PROFILE:-${REPORT_PROFILE_FILE:-$REPORT_PROFILE_FW_DIR/11_Reports/.report_profile}}"

# report_profile_path → imprime la ruta del fichero de perfil
report_profile_path() {
    printf '%s\n' "$REPORT_PROFILE_FILE"
}

# report_profile_get <clave> → imprime el valor (stdout), vacío si no existe
report_profile_get() {
    local clave="$1" valor=""
    [[ -z "$clave" ]] && return 0
    [[ -f "$REPORT_PROFILE_FILE" ]] || return 0
    while IFS= read -r linea; do
        # Saltar comentarios y líneas vacías
        case "$linea" in
            '#'*|'') continue ;;
        esac
        case "$linea" in
            "$clave"=*)
                valor="${linea#*=}"
                ;;
        esac
    done < "$REPORT_PROFILE_FILE"
    printf '%s' "$valor"
}

# report_profile_set <clave> <valor> → actualiza o añade una entrada
report_profile_set() {
    local clave="$1" valor="$2"
    [[ -z "$clave" ]] && return 1

    local tmp="${REPORT_PROFILE_FILE}.tmp"
    local encontrado=0

    if [[ -f "$REPORT_PROFILE_FILE" ]]; then
        while IFS= read -r linea; do
            case "$linea" in
                "$clave"=*)
                    printf '%s\n' "$clave=$valor"
                    encontrado=1
                    ;;
                *)
                    printf '%s\n' "$linea"
                    ;;
            esac
        done < "$REPORT_PROFILE_FILE" > "$tmp"
    else
        : > "$tmp"
    fi

    if [[ "$encontrado" -eq 0 ]]; then
        printf '%s\n' "$clave=$valor" >> "$tmp"
    fi

    mv -f "$tmp" "$REPORT_PROFILE_FILE"
}
