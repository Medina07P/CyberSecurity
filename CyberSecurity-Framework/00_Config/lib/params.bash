#!/bin/bash
# ============================================================
#  PARAMS - Interpreta la línea Uso:/Ejemplo: de un script
#  Uso: source 00_Config/lib/params.sh
#  Solo lee el fichero: no ejecuta nada del script analizado.
# ============================================================

PARAMS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# ─── Lectura de la línea de uso ────────────────────────────

# params_usage <script> → la primera línea Uso:/Usage:, limpia.
params_usage() {
    local line
    line=$(grep -m1 -E 'Uso:|Usage:' "$1" 2>/dev/null) || return 1
    [[ -z "$line" ]] && return 1
    line=${line#*Uso:}
    line=${line#*Usage:}
    line=${line%\"*}      # resto de un echo "..."
    line=${line%;}
    line=${line%\}}
    line=$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
    [[ -z "$line" ]] && return 1
    printf '%s\n' "$line"
}

# params_rest <script> → lo que va DESPUÉS del nombre del script
params_rest() {
    local line rest
    line=$(params_usage "$1") || return 1
    rest=$(printf '%s' "$line" | sed -E 's/^.*\.(sh|py|ps1)//')
    [[ "$rest" == "$line" ]] && return 1
    printf '%s\n' "$rest"
}

# params_example <script> → la primera línea Ejemplo:/Example:, limpia.
params_example() {
    local line
    line=$(grep -m1 -E 'Ejemplo:|Example:' "$1" 2>/dev/null) || return 1
    [[ -z "$line" ]] && return 1
    line=${line#*Ejemplo:}
    line=${line#*Example:}
    line=${line%\"*}
    line=${line%;}
    line=$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
    [[ -z "$line" ]] && return 1
    printf '%s\n' "$line"
}

# ─── Tipos ─────────────────────────────────────────────────

# params_type_of <nombre-de-hueco> → uno de los tipos conocidos
params_type_of() {
    local up
    up=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')
    case "$up" in
        */*) printf 'TEXTO\n'; return ;;   # IP/RANGO, ruta/algo
    esac
    case "$up" in
        IP|HOST|TARGET|RHOST|LHOST|OBJETIVO|SERVIDOR|HOSTNAME|IP_OBJETIVO)
            printf 'IP\n' ;;
        DOMINIO|DOMAIN|SUBDOMINIO|SUBDOMAIN)
            printf 'DOMINIO\n' ;;
        URL|URI|ENDPOINT)
            printf 'URL\n' ;;
        PUERTO|PUERTOS|PORT|PORTS|LPORT|RPORT|LOCAL_PORT|REMOTE_PORT|PUERTO_LOCAL|PUERTO_REMOTO)
            printf 'PUERTO\n' ;;
        USUARIO|USER|USERNAME|LOGIN)
            printf 'USUARIO\n' ;;
        PASS|PASSWORD|PASSWD|CONTRASENA|CONTRASEÑA|CLAVE)
            printf 'CONTRASENA\n' ;;
        FILE|FICHERO|ARCHIVO|WORDLIST|HANDSHAKE_FILE|OUTPUT_DIR|DIR|RUTA|PATH|DICCIONARIO)
            printf 'FICHERO\n' ;;
        INTERFAZ|INTERFACE|IFACE|WLAN|ETH)
            printf 'INTERFAZ\n' ;;
        *)
            printf 'TEXTO\n' ;;
    esac
}

# ─── Huecos ────────────────────────────────────────────────

# params_slots <script> → una línea por hueco: "posicion|nombre|obligatorio|tipo"
params_slots() {
    local rest tok name kind pos=0
    rest=$(params_rest "$1") || return 1
    [[ -z "$rest" ]] && return 1
    while IFS= read -r tok; do
        [[ -z "$tok" ]] && continue
        pos=$((pos + 1))
        case "$tok" in
            '<'*'>')
                kind="obligatorio"
                name=${tok#<}; name=${name%>}
                ;;
            '['*']')
                kind="opcional"
                name=${tok#\[}; name=${name%\]}
                ;;
            *) continue ;;
        esac
        printf '%s|%s|%s|%s\n' "$pos" "$name" "$kind" "$(params_type_of "$name")"
    done < <(printf '%s' "$rest" | grep -oE '<[^>]+>|\[[^]]+\]')
    return 0
}

# params_slot_count <script> → número de huecos (0 si ninguno)
params_slot_count() {
    params_slots "$1" 2>/dev/null | wc -l | tr -d ' '
}

# ─── Modo de invocación ────────────────────────────────────

# params_mode <script> → none | manual | slots
params_mode() {
    local rest first name up slots
    rest=$(params_rest "$1") || { printf 'none\n'; return; }
    [[ -z "$rest" ]] && { printf 'none\n'; return; }

    if ! printf '%s' "$rest" | grep -qE '<[^>]+>|\[[^]]+\]'; then
        printf 'none\n'; return
    fi

    # Bandera larga en cualquier punto de la línea
    if printf '%s' "$rest" | grep -qE '(^|[[:space:]])--[a-zA-Z]'; then
        printf 'manual\n'; return
    fi

    first=$(printf '%s' "$rest" | awk '{print $1}')

    # El primer token no es un hueco → es un subcomando (interface_manager monitor)
    case "$first" in
        '<'*'>'|'['*']') : ;;
        *) printf 'manual\n'; return ;;
    esac

    # Huecos con nombre de "cajón de sastre"
    name=${first#<}; name=${name%>}
    name=${name#\[}; name=${name%\]}
    up=$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')
    case "$up" in
        COMANDO|COMMAND|OPCIONES|OPTIONS|ACCION|ACTION|MODO|MODE)
            printf 'manual\n'; return ;;
    esac

    slots=$(params_slot_count "$1")
    if [[ "${slots:-0}" -eq 0 ]]; then
        printf 'none\n'
    else
        printf 'slots\n'
    fi
}

# ─── Valores por defecto desde el Ejemplo: ─────────────────

# params_example_values <script> → los valores del Ejemplo:, uno por línea.
# Devuelve 1 si el número de tokens no cuadra exactamente con los huecos.
params_example_values() {
    local rest slots count
    rest=$(params_rest "$1") || return 1
    slots=$(params_slot_count "$1")
    [[ "${slots:-0}" -eq 0 ]] && return 1

    rest=$(params_example "$1") || return 1
    rest=$(printf '%s' "$rest" | sed -E 's/^.*\.(sh|py|ps1)//')
    [[ -z "$rest" ]] && return 1

    count=$(printf '%s' "$rest" | awk '{print NF}')
    [[ "$count" -ne "$slots" ]] && return 1

    printf '%s\n' "$rest" | tr -s '[:space:]' '\n' | sed '/^$/d'
    return 0
}

# ─── Scripts que solo generan otro script ──────────────────

# params_is_generator <script> → 0 si es un generador (escribe un script)
params_is_generator() {
    grep -qE "^[[:space:]]*cat[[:space:]]*>[[:space:]]*['\"]?\\\$?T?" "$1" 2>/dev/null &&
        grep -qE "^[[:space:]]*mv[[:space:]]+-f" "$1" 2>/dev/null
}

# ─── Lista de herramientas peligrosas ──────────────────────

# params_is_dangerous <ruta-relativa-al-framework> → 0 si está en dangerous.txt
params_is_dangerous() {
    local list="$PARAMS_LIB_DIR/dangerous.txt"
    [[ -f "$list" ]] || return 1
    grep -qxF -- "$1" "$list" 2>/dev/null
}
