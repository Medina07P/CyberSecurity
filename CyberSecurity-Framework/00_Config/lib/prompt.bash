#!/bin/bash
# ============================================================
#  PROMPT - Pregunta los datos de un script leyendo su Uso:
#  Uso: source 00_Config/lib/prompt.bash
#
#  CONTRATO IMPORTANTE:
#    - toda la interfaz (avisos, preguntas, errores) va a STDERR
#    - por STDOUT solo salen los valores, uno por línea
#  Ese contrato es el que se rompió en la versión anterior del
#  gestor: imprimía el prompt a stdout y el llamante capturaba
#  el prompt entero como si fuera el parámetro.
# ============================================================

PROMPT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
[[ -n "${PARAMS_LIB_DIR:-}" ]] || source "$PROMPT_LIB_DIR/params.bash"
[[ -n "${SESSION_LIB_DIR:-}" ]] || source "$PROMPT_LIB_DIR/session.bash"

# ─── Partir una línea de argumentos respetando comillas ────

# split_args <línea> → un token por línea
split_args() {
    local s="$1" out=() cur="" q="" c i
    for (( i = 0; i < ${#s}; i++ )); do
        c="${s:i:1}"
        if [[ -n "$q" ]]; then
            if [[ "$c" == "$q" ]]; then
                q=""
            else
                cur+="$c"
            fi
        else
            case "$c" in
                '"')  q='"' ;;
                "'")  q="'" ;;
                ' '|$'\t')
                    if [[ -n "$cur" ]]; then
                        out+=("$cur")
                        cur=""
                    fi
                    ;;
                *) cur+="$c" ;;
            esac
        fi
    done
    [[ -n "$cur" ]] && out+=("$cur")
    ((${#out[@]})) || return 0
    printf '%s\n' "${out[@]}"
}

# ─── Etiqueta en castellano para cada tipo ─────────────────

_prompt_label() {
    local name="$1" type="$2"
    case "$type" in
        IP)         printf 'Equipo o IP (%s)' "$name" ;;
        DOMINIO)    printf 'Dominio (%s)' "$name" ;;
        URL)        printf 'URL completa (%s)' "$name" ;;
        PUERTO)     printf 'Puerto (%s)' "$name" ;;
        USUARIO)    printf 'Usuario (%s)' "$name" ;;
        CONTRASENA) printf 'Contraseña, no se muestra (%s)' "$name" ;;
        FICHERO)    printf 'Ruta de fichero (%s)' "$name" ;;
        INTERFAZ)   printf 'Interfaz de red (%s)' "$name" ;;
        *)          printf '%s' "$name" ;;
    esac
}

# ─── Validación ────────────────────────────────────────────

# Regla universal para cualquier valor tecleado.
_prompt_universal_ok() {
    local v="$1"
    [[ -z "$v" ]] && return 1
    [[ ${#v} -gt 512 ]] && return 1
    [[ "$v" == *$'\n'* || "$v" == *$'\r'* ]] && return 1
    [[ "$v" == -* ]] && return 1
    return 0
}

# Validación por tipo. IP y DOMINIO solo se validan como objetivo de sesión:
# hay huecos como <red> o <IP/RANGO> que no son una IP y no deben rechazarse.
_prompt_type_ok() {
    local type="$1" v="$2" part
    local -a parts
    case "$type" in
        PUERTO)
            [[ "$v" =~ ^[0-9]+([,-][0-9]+)*$ ]] || return 1
            IFS=',-' read -r -a parts <<< "$v"
            for part in "${parts[@]}"; do
                [[ "$part" =~ ^[0-9]+$ ]] || return 1
                (( part >= 1 && part <= 65535 )) || return 1
            done
            ;;
    esac
    return 0
}

_prompt_validate() {
    local type="$1" v="$2"
    _prompt_universal_ok "$v" || return 1
    _prompt_type_ok "$type" "$v" || return 1
    return 0
}

# ─── Lectura de los datos ──────────────────────────────────

# Literal input boundary: no echo for secrets; no whitespace trimming/splitting.
# The destination is a caller-local variable (Bash dynamic scope).
_prompt_read_literal() {
    if [[ "$1" == CONTRASENA ]]; then
        local read_rc
        IFS= read -r -s "$2"
        read_rc=$?
        printf '\n' >&2
        return "$read_rc"
    fi
    IFS= read -r "$2"
}

# Closed SMB/PSExec full-list adapter. Selecting an entry never grants execution.
# stdout is exclusively argv (one literal field per line), like prompt_for_slots.
_prompt_stable_tool() {
    local script="$1" rel="$2" choice value line pos name kind type target def identity
    local -a out=() slotlines=()
    printf '\n1. Preview sin operación (predeterminado)\n2. Ejecutar con posiciones explícitas\n3. Generar lanzador NUEVO\n0. Cancelar\nModo [1]: ' >&2
    IFS= read -r choice || return 2
    case "$choice" in
        ''|1) printf '%s\n' --preview; return 0 ;;
        0|'!') return 1 ;;
        3)
            printf 'Destino NUEVO fuera del framework (0 o ! cancela): ' >&2
            _prompt_read_literal FICHERO value || return 2
            [[ "$value" != 0 && "$value" != '!' ]] || return 1
            _prompt_universal_ok "$value" || return 1
            printf '%s\n' --generate "$value"
            return 0 ;;
        2) : ;;
        *) printf 'Modo no válido.\n' >&2; return 1 ;;
    esac
    target=$(session_target)
    mapfile -t slotlines < <(params_slots "$script")
    # Same strictly lexical identity as params_mode: './'-prefixed or duplicated
    # '/' forms select the adapter AND satisfy its position contract.
    identity=$(_params_stable_identity "$rel")
    case "$identity:${#slotlines[@]}" in
        04_Enumeration/smb/enum_smb.sh:2|06_PostExploitation/lateral_movement/ps_exec.sh:5) : ;;
        *) printf 'Contrato de posiciones no válido.\n' >&2; return 1 ;;
    esac
    for line in "${slotlines[@]}"; do
        IFS='|' read -r pos name kind type <<< "$line"
        # The session target is OFFERED explicitly; never substituted invisibly.
        def=''
        [[ "$pos" == 1 ]] && def="$target"
        if [[ -n "$def" ]]; then
            printf '➜ %s [%s] (0 o ! cancela): ' "$(_prompt_label "$name" "$type")" "$def" >&2
        else
            printf '➜ %s (0 o ! cancela): ' "$(_prompt_label "$name" "$type")" >&2
        fi
        value=''
        _prompt_read_literal "$type" value || return 2
        [[ "$value" != 0 && "$value" != '!' ]] || return 1
        [[ "$pos" != 1 || -n "$value" ]] || value="$def"
        if [[ -z "$value" && "$kind" == opcional ]]; then
            continue
        fi
        # Password/command may begin with '-' and contain literal spaces. This
        # exception is ONLY for this closed adapter; leaf validation stays final.
        if [[ "$type" == CONTRASENA || "$name" == COMANDO ]]; then
            [[ -n "$value" && ! "$value" =~ [[:cntrl:]] ]] || return 1
        else
            _prompt_validate "$type" "$value" || return 1
        fi
        out+=("$value")
    done
    printf '%s\n' "${out[@]}" --execute
}

# prompt_for_slots <script> <ruta-relativa>
#   stdout: valores, uno por línea
#   return: 0 ok | 1 cancelado por el usuario | 2 fin de entrada
prompt_for_slots() {
    local script="$1" rel="$2"
    local mode usage example target def value prompt attempt
    local pos name kind type line

    mode=$(params_mode "$script" "$rel")
    if [[ "$mode" == stable ]]; then
        _prompt_stable_tool "$script" "$rel"
        return $?
    fi
    # A closed consumer under any other lexical identity (absolute path, extra
    # prefix) must never fall into the generic slot loop: that loop echoes the
    # secret and trims whitespace. Refuse explicitly instead of degrading mode.
    if params_is_stable_identity "${rel:-$script}"; then
        printf '✖ %s: identidad no canónica; usa la ruta relativa exacta al framework. No se piden credenciales por la vía genérica.\n' \
            "${rel:-$script}" >&2
        return 1
    fi
    [[ "$mode" == "none" ]] && return 0

    usage=$(params_usage "$script" 2>/dev/null) || usage=""
    example=$(params_example "$script" 2>/dev/null) || example=""

    {
        printf '\n📌 Este script necesita datos\n'
        printf -- '────────────────────────────────────────────────────────\n'
        [[ -n "$usage" ]] && printf '  Uso: %s\n' "$usage"
        [[ -n "$example" ]] && printf '  Ej.: %s\n' "$example"
        printf '\n'
    } >&2

    # ─── Modo manual: el script usa banderas o subcomandos ───
    if [[ "$mode" == "manual" ]]; then
        printf '➜ Escribe los argumentos completos (vacío para cancelar): ' >&2
        if ! IFS= read -r line; then
            return 2
        fi
        line=$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
        [[ -z "$line" ]] && return 1
        split_args "$line"
        return 0
    fi

    # ─── Valores por defecto del Ejemplo: ───────────────────
    local -a defaults=()
    local has_example=0
    if ! params_is_dangerous "$rel"; then
        if mapfile -t defaults < <(params_example_values "$script"); then
            has_example=1
        else
            defaults=()
            has_example=0
        fi
    fi

    target=$(session_target)

    local -a slotlines=() out=()
    mapfile -t slotlines < <(params_slots "$script")
    ((${#slotlines[@]})) || return 0

    for line in "${slotlines[@]}"; do
        IFS='|' read -r pos name kind type <<< "$line"

        def=""
        [[ "$has_example" == "1" ]] && def="${defaults[$((pos - 1))]:-}"

        case "$type" in
            IP|DOMINIO)
                [[ -n "$target" ]] && def="$target"
                ;;
            URL)
                [[ -n "$target" ]] && def="http://$target"
                ;;
        esac

        prompt=$(_prompt_label "$name" "$type")

        if [[ -n "$def" ]]; then
            printf '➜ %s [%s]: ' "$prompt" "$def" >&2
        else
            printf '➜ %s: ' "$prompt" >&2
        fi

        attempt=0
        value=""
        while :; do
            if ! IFS= read -r value; then
                return 2
            fi
            value=$(printf '%s' "$value" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
            [[ -z "$value" ]] && value="$def"

            if [[ -z "$value" ]]; then
                if [[ "$kind" == "opcional" ]]; then
                    break
                fi
                printf '  ✖ Hace falta un valor.\n' >&2
            elif ! _prompt_validate "$type" "$value"; then
                printf '  ✖ Valor no admitido para %s.\n' "$name" >&2
            else
                break
            fi

            attempt=$((attempt + 1))
            if (( attempt >= 3 )); then
                printf '  ✖ Demasiados intentos, cancelado.\n' >&2
                return 1
            fi
            printf '➜ %s: ' "$prompt" >&2
        done

        # Un opcional vacío entre dos valores conserva su posición (p. ej.
        # dominio, archivo vacío, empresa). Omitirlo desplaza los argumentos.
        out+=("$value")
    done

    # No añadir argumentos vacíos al final a scripts que no los necesitan.
    while ((${#out[@]})) && [[ -z "${out[${#out[@]}-1]}" ]]; do
        unset 'out[${#out[@]}-1]'
    done
    ((${#out[@]})) || return 0
    printf '%s\n' "${out[@]}"
    return 0
}
