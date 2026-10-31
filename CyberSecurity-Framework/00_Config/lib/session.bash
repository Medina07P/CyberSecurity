#!/bin/bash
# ============================================================
#  SESSION - Objetivo de trabajo de la sesión
#  Uso: source 00_Config/lib/session.bash
# ============================================================

SESSION_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SESSION_CONFIG_DIR="$(cd "$SESSION_LIB_DIR/.." && pwd)"
SESSION_FW_DIR="$(cd "$SESSION_CONFIG_DIR/.." && pwd)"
SESSION_REPO_DIR="$(cd "$SESSION_FW_DIR/.." && pwd)"
SESSION_FILE="${SESSION_FILE:-$SESSION_CONFIG_DIR/.session}"
SESSION_TARGETS_FILE="${SESSION_TARGETS_FILE:-$SESSION_CONFIG_DIR/targets.txt}"

# ─── Validación ────────────────────────────────────────────

# validate_target <valor> → 0 si es un IPv4 o un nombre de dominio aceptable.
# Rechaza espacios, rutas y cualquier metacaracter de shell.
validate_target() {
    local t="$1" o
    [[ -z "$t" ]] && return 1
    [[ ${#t} -gt 253 ]] && return 1

    case "$t" in
        *[!A-Za-z0-9.:_-]*) return 1 ;;
    esac

    if [[ "$t" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for o in "${BASH_REMATCH[@]:1:4}"; do
            [[ "$o" =~ ^[0-9]+$ ]] || return 1
            (( o >= 0 && o <= 255 )) || return 1
        done
        return 0
    fi

    [[ "$t" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
}

# ─── Sesión ────────────────────────────────────────────────

session_target() {
    [[ -f "$SESSION_FILE" ]] || return 0
    head -1 "$SESSION_FILE" 2>/dev/null | tr -d '\r\n'
}

session_set_target() {
    validate_target "$1" || return 1
    printf '%s\n' "$1" > "$SESSION_FILE"
}

session_clear() {
    rm -f "$SESSION_FILE"
}

session_has_target() {
    local t
    t=$(session_target)
    [[ -n "$t" ]]
}

# ─── Objetivos de targets.txt ──────────────────────────────

# targets_from_config → "ip|descripcion" por línea, sin duplicados y sin EXCLUIDO
targets_from_config() {
    local line ip rest desc seen=" "
    [[ -f "$SESSION_TARGETS_FILE" ]] || return 1

    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *"|"* ]] || continue
        [[ "${line^^}" == *EXCLUIDO* ]] && continue

        ip="${line%%|*}"
        rest="${line#*|}"
        desc=$(printf '%s' "$rest" | cut -d'|' -f3)
        ip=$(printf '%s' "$ip" | tr -d '[:space:]')
        desc=$(printf '%s' "$desc" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')

        [[ -z "$ip" ]] && continue
        validate_target "$ip" || continue

        case "$seen" in *" $ip "*) continue ;; esac
        seen="$seen$ip "
        printf '%s|%s\n' "$ip" "$desc"
    done < "$SESSION_TARGETS_FILE"
}

# ─── Comprobación de alcance (mejor esfuerzo) ──────────────

# _ip_to_int <a.b.c.d> → entero de 32 bits
_ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    [[ -n "$d" ]] || return 1
    printf '%s\n' "$(( (a << 24) + (b << 16) + (c << 8) + d ))"
}

# scope_allows <objetivo> → 0 si encaja en scope.yaml, 1 si no, 2 si no se puede interpretar
scope_allows() {
    local target="$1" scope="$SESSION_CONFIG_DIR/scope.yaml"
    [[ -f "$scope" ]] || return 2

    local allowed
    allowed=$(grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?' "$scope" 2>/dev/null)
    [[ -z "$allowed" ]] && return 2

    local t_int cidr base bits mask
    if validate_target "$target" && [[ "$target" =~ ^[0-9] ]]; then
        t_int=$(_ip_to_int "$target") || return 2
        local entry
        while IFS= read -r entry; do
            if [[ "$entry" == */* ]]; then
                base="${entry%/*}"; bits="${entry#*/}"
            else
                base="$entry"; bits=32
            fi
            [[ "$bits" =~ ^[0-9]+$ ]] || continue
            (( bits >= 0 && bits <= 32 )) || continue
            local b_int
            b_int=$(_ip_to_int "$base") || continue
            if (( bits == 0 )); then
                mask=0
            else
                mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
            fi
            (( (t_int & mask) == (b_int & mask) )) && return 0
        done <<< "$allowed"
        return 1
    fi

    # Dominio: comparación por sufijo con comodín
    local dom
    while IFS= read -r dom; do
        [[ "$dom" == *"*"* ]] || continue
        dom="${dom#\*.}"
        [[ "$target" == *".$dom" || "$target" == "$dom" ]] && return 0
    done <<< "$(grep -oE '[A-Za-z0-9*.-]+\.(com|net|org|local|lan|io)' "$scope" 2>/dev/null)"
    return 2
}
