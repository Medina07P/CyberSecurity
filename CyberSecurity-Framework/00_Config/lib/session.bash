#!/bin/bash
# ============================================================
#  SESSION - Objetivo de trabajo de la sesión
#  Uso: source 00_Config/lib/session.bash
# ============================================================

SESSION_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SESSION_CONFIG_DIR="${SESSION_CONFIG_DIR:-$(cd "$SESSION_LIB_DIR/.." && pwd)}"
SESSION_FW_DIR="$(cd "$SESSION_CONFIG_DIR/.." && pwd)"
SESSION_REPO_DIR="$(cd "$SESSION_FW_DIR/.." && pwd)"
SESSION_FILE="${SESSION_FILE:-$SESSION_CONFIG_DIR/.session}"
SESSION_TARGETS_FILE="${SESSION_TARGETS_FILE:-$SESSION_CONFIG_DIR/targets.txt}"
SESSION_SCOPE_FILE="${SESSION_SCOPE_FILE:-$SESSION_CONFIG_DIR/scope.yaml}"

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
    printf '%s\n' "$1" > "$SESSION_FILE" || return 1

    # El registro es informativo: si falla, la sesión sigue siendo válida.
    local rc_scope=0 rc_targets=0
    scope_add_target "$1" || rc_scope=$?
    targets_add_entry "$1" || rc_targets=$?
    (( rc_scope == 0 ))   || printf '⚠️  No se pudo registrar en scope.yaml (código %s)\n' "$rc_scope" >&2
    (( rc_targets == 0 )) || printf '⚠️  No se pudo registrar en targets.txt (código %s)\n' "$rc_targets" >&2
    return 0
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

# _scope_normalize <línea o valor de scope.yaml> → valor sin comillas ni comentario
_scope_normalize() {
    local v="$1"
    v=${v%%#*}
    v=${v//$'\r'/}
    v=$(printf '%s' "$v" | sed -E "s/^[[:space:]]*-[[:space:]]*//; s/^[\"']//; s/[\"'][[:space:]]*$//; s/[[:space:]]+$//")
    printf '%s' "$v"
}

# _scope_block_values <clave> → líneas "- ..." de targets.<clave>
# Solo las de primer nivel dentro de targets: una clave anidada (por ejemplo
# targets.excluded.domains) no cuenta, y tampoco el email de contacto.
_scope_block_values() {
    local f="${2:-$SESSION_SCOPE_FILE}"
    awk -v key="$1" '
        function indent() { match($0, /^[[:space:]]*/); return RLENGTH }
        BEGIN { intargets = 0; cind = -1; inkey = 0 }
        /^targets:[[:space:]]*$/ { intargets = 1; next }
        !intargets { next }
        /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
        {
            ind = indent()
            if (cind < 0) {
                if (ind == 0) { intargets = 0; next }
                cind = ind
            }
            if (ind < cind) { intargets = 0; inkey = 0; next }
            if (ind == cind && $0 ~ ("^[[:space:]]*" key ":[[:space:]]*$")) { inkey = 1; next }
            if (inkey && ind > cind && $0 ~ /^[[:space:]]*-/) { print; next }
            if (ind <= cind) inkey = 0
        }
    ' "$f"
}
# La sangría se toma de la última entrada de la clave; si está vacía, la de
# la clave más dos. Vacío si la clave no existe dentro de targets.
_scope_insert_point() {
    awk -v key="$1" '
        function indent() { match($0, /^[[:space:]]*/); return RLENGTH }
        BEGIN { intargets = 0; cind = -1; inkey = 0; last = 0; pad = "" }
        /^targets:[[:space:]]*$/ { intargets = 1; next }
        !intargets { next }
        /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
        {
            ind = indent()
            if (cind < 0) {
                if (ind == 0) { intargets = 0; next }
                cind = ind
            }
            if (ind < cind) { intargets = 0; inkey = 0; next }
            if (ind == cind && $0 ~ ("^[[:space:]]*" key ":[[:space:]]*$")) {
                inkey = 1; last = NR
                pad = sprintf("%" (ind + 2) "s", "")
                next
            }
            if (inkey && ind > cind && $0 ~ /^[[:space:]]*-/) {
                last = NR
                pad = substr($0, 1, ind)
                next
            }
            if (ind <= cind) inkey = 0
        }
        END { if (last) printf "%d|%s\n", last, pad }
    ' "$SESSION_SCOPE_FILE"
}

# scope_add_target <ip|dominio>
#   0 añadido o ya estaba · 1 valor no válido · 2 no se pudo escribir
# Un dominio añade dos entradas: él mismo y su comodín *.dominio, que es lo
# que scope_allows necesita para autorizar sus subdominios.
scope_add_target() {
    local value="$1" key ins ins_line pad tmp e have found i
    local -a entries=() existing=() missing=()
    validate_target "$value" || return 1
    [[ -f "$SESSION_SCOPE_FILE" ]] || return 2

    if [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        key="ips"
        entries=("$value")
    else
        key="domains"
        entries=("$value" "*.$value")
    fi

    # Lectura línea a línea: esta librería se sourcea también desde zsh, donde
    # mapfile no existe.
    local linea
    while IFS= read -r linea; do
        [[ -n "$linea" ]] && existing+=("$linea")
    done < <(_scope_block_values "$key")

    for e in "${entries[@]}"; do
        found=0
        for have in "${existing[@]}"; do
            have=$(_scope_normalize "$have")
            if [[ "${have,,}" == "${e,,}" ]]; then found=1; break; fi
        done
        (( found )) || missing+=("$e")
    done
    ((${#missing[@]})) || return 0

    ins=$(_scope_insert_point "$key")
    [[ -n "$ins" ]] || return 2
    ins_line="${ins%%|*}"
    pad="${ins#*|}"

    tmp="$SESSION_SCOPE_FILE.auto.tmp"
    if ! awk -v ins="$ins_line" -v pad="$pad" -v add="$(printf '%s\n' "${missing[@]}")" '
        { print }
        NR == ins {
            n = split(add, a, "\n")
            for (i = 1; i <= n; i++) if (a[i] != "") printf "%s- \"%s\"\n", pad, a[i]
        }
    ' "$SESSION_SCOPE_FILE" > "$tmp"; then
        rm -f "$tmp"
        return 2
    fi

    # No es lo mismo «el YAML está roto» que «no hay con qué mirarlo».
    local puede_validar=0
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c 'import yaml' >/dev/null 2>&1; then
            puede_validar=1
        else
            printf '   ⚠️  PyYAML no está: no se pudo validar scope.yaml\n' >&2
        fi
    else
        printf '   ⚠️  python3 no está: no se pudo validar scope.yaml\n' >&2
    fi
    if (( puede_validar )); then
        if ! python3 -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' "$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"
            return 2
        fi
    fi

    # La copia se hace justo antes de sustituir: .bak es siempre el estado
    # previo al último cambio bueno, no el de un intento fallido.
    cp -f "$SESSION_SCOPE_FILE" "$SESSION_SCOPE_FILE.bak" || { rm -f "$tmp"; return 2; }
    chmod --reference="$SESSION_SCOPE_FILE" "$tmp" 2>/dev/null
    mv -f "$tmp" "$SESSION_SCOPE_FILE" || return 2

    for i in "${missing[@]}"; do
        printf '   ➕ scope.yaml: %s\n' "$i" >&2
    done
    return 0
}

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

# targets_add_entry <host>
#   0 añadido o ya estaba · 1 valor no válido · 2 no se pudo escribir
# El puerto y el protocolo van como «—» (desconocido para parse_targets.py):
# al fijar el objetivo no se sabe qué servicio corre ahí.
targets_add_entry() {
    local host="$1" f="$SESSION_TARGETS_FILE" fecha patron
    validate_target "$host" || return 1

    patron="^$(printf '%s' "$host" | sed 's/\./\\./g')\|"
    if [[ -f "$f" ]] && grep -qiE "$patron" "$f"; then
        return 0
    fi

    fecha=$(date '+%Y-%m-%d')
    mkdir -p "$(dirname "$f")" || return 2

    {
        if [[ ! -s "$f" ]]; then
            printf '# ============================================================\n'
            printf '#  LISTA DE OBJETIVOS\n'
            printf '#  Formato: IP|PUERTO|PROTOCOLO|DESCRIPCIÓN|PRIORIDAD\n'
            printf '# ============================================================\n'
            printf '#  PRIORIDAD: C = Crítica, A = Alta, M = Media, B = Baja\n'
            printf '# ============================================================\n\n'
        elif [[ -n "$(tail -c1 "$f")" ]]; then
            printf '\n'
        fi
        # Una cabecera por tanda, no una por objetivo.
        if ! grep -qF "# ─── AÑADIDOS POR EL GESTOR ($fecha" "$f" 2>/dev/null; then
            printf '# ─── AÑADIDOS POR EL GESTOR (%s %s) ───\n' "$fecha" "$(date '+%H:%M')"
        fi
        printf '%s|—|—|Registrado al fijar el objetivo|B\n' "$host"
    } >> "$f" || return 2

    printf '   ➕ targets.txt: %s\n' "$host" >&2
    return 0
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
    local target="$1" scope="$SESSION_SCOPE_FILE"
    [[ -f "$scope" ]] || return 2

    local allowed domains="" d
    allowed=$(grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?' "$scope" 2>/dev/null)
    # Los dominios salen solo de targets.domains: una regla excluida o el email
    # de contacto no autorizan nada.
    while IFS= read -r d; do
        d=$(_scope_normalize "$d")
        [[ -n "$d" ]] && domains+="$d"$'\n'
    done < <(_scope_block_values domains "$scope")

    # Sin ninguna regla interpretable no se puede opinar (2 = no determinado).
    [[ -z "$allowed" && -z "$domains" ]] && return 2

    local t_int cidr base bits mask
    if validate_target "$target" && [[ "$target" =~ ^[0-9] ]]; then
        [[ -z "$allowed" ]] && return 2
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

    # Dominio: coincidencia exacta para las entradas peladas y por sufijo
    # para las que llevan comodín (*.dominio).
    local dom
    while IFS= read -r dom; do
        [[ -z "$dom" ]] && continue
        if [[ "$dom" == *"*"* ]]; then
            dom="${dom#\*.}"
            [[ "${target,,}" == *".${dom,,}" || "${target,,}" == "${dom,,}" ]] && return 0
        else
            [[ "${target,,}" == "${dom,,}" ]] && return 0
        fi
    done <<< "$domains"
    # Había reglas y ninguna encaja: está fuera (1), no «no determinado» (2).
    [[ -n "$domains" ]] && return 1
    return 2
}
