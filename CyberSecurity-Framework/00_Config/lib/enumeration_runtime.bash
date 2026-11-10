#!/bin/bash
# Runtime de 04: validación, captura nueva, clasificación y publicación explícita.
ENUM_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "$ENUM_LIB_DIR/scanner_runtime.bash"

enum_init() {
    local service="$1" host="$2" port="$3"
    [[ "$service" =~ ^[a-z_]+$ ]] || return 1
    scanner_host "$host" && scanner_ports "$port" || return 1
    [[ "$port" =~ ^[0-9]+$ ]] || { echo 'Se requiere un solo puerto.' >&2; return 1; }
    [[ "${ENUM_STEP_TIMEOUT:-30}" =~ ^[1-9][0-9]{0,3}$ ]] || { echo 'ENUM_STEP_TIMEOUT no válido.' >&2; return 1; }
    ENUM_DIR=$(scans_dir "$service") || return 1
    ENUM_HOST="${host,,}"; ENUM_HOST="${ENUM_HOST%.}"
    ENUM_PORT="$port"; ENUM_TOOL="$service"; ENUM_URL=""
    ENUM_LOG="$ENUM_DIR/errores.log"
    ENUM_WORK=$(mktemp -d "$ENUM_DIR/.enum.XXXXXX") || return 1
    ENUM_FAILED=0
    trap 'rm -f "$ENUM_WORK"/*.data "$ENUM_WORK"/*.err; rmdir "$ENUM_WORK" 2>/dev/null' EXIT
}

enum_path() {
    local filename
    filename=$(python3 "$ENUM_LIB_DIR/enumeration_evidence.py" name --prefix "$1" --host "$ENUM_HOST" --port "$ENUM_PORT" --url "$ENUM_URL") || return 1
    printf '%s/%s\n' "$ENUM_DIR" "$filename"
}

enum_publish() {
    local name="$1" state="$2" dest
    dest=$(enum_path "$name") || return 1
    python3 "$ENUM_LIB_DIR/enumeration_evidence.py" publish --source "$ENUM_WORK/$name.data" \
        --dest "$dest" --host "$ENUM_HOST" --port "$ENUM_PORT" --url "$ENUM_URL" \
        --tool "$ENUM_TOOL" --state "$state" --rc "${ENUM_RC:-0}"
}

enum_capture() {
    local name="$1"
    shift
    [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] || return 1
    ENUM_RC=0
    if ! command -v "$1" >/dev/null 2>&1; then
        printf '%s no instalado\n' "$1" >"$ENUM_WORK/$name.err"
        : >"$ENUM_WORK/$name.data"
        ENUM_RC=127
    else
        timeout "${ENUM_STEP_TIMEOUT:-30}" "$@" >"$ENUM_WORK/$name.data" 2>"$ENUM_WORK/$name.err"
        ENUM_RC=$?
    fi
    if [[ -s "$ENUM_WORK/$name.err" || "$ENUM_RC" != 0 ]]; then
        { printf '\n[%s] %s/%s rc=%s\n' "$(date -Is)" "$ENUM_HOST" "$name" "$ENUM_RC"; cat "$ENUM_WORK/$name.err"; } >>"$ENUM_LOG"
        printf 'Diagnóstico actual: %s (código %s)\n' "$ENUM_LOG" "$ENUM_RC" >&2
    fi
    if (( ENUM_RC )); then
        enum_publish "$name" NO_DETERMINADO || return 1
        return 1
    fi
    return 0
}

enum_step() {
    local name="$1" kind="$2" state
    shift 2
    enum_capture "$name" "$@" || :
    state=$(python3 "$ENUM_LIB_DIR/enumeration_evidence.py" classify --host "$ENUM_HOST" --port "$ENUM_PORT" \
        --source "$ENUM_WORK/$name.data" --error "$ENUM_WORK/$name.err" --rc "$ENUM_RC" --kind "$kind") || state=NO_DETERMINADO
    enum_publish "$name" "$state" || state=NO_DETERMINADO
    printf '  %s: %s\n' "$name" "$state"
    if [[ "$state" == NO_DETERMINADO ]]; then
        ENUM_FAILED=$((ENUM_FAILED + 1))
        return 1
    fi
    return 0
}

enum_nse() {
    local name="$1" script="$2"
    if ! enum_capture "help_$name" nmap --script-help "$script"; then
        echo "  $script no disponible: NO_DETERMINADO"
        ENUM_FAILED=$((ENUM_FAILED + 1))
        ENUM_RC=1
        enum_publish "$name" NO_DETERMINADO
        return 1
    fi
    enum_step "$name" nmap nmap -Pn -sV -p "$ENUM_PORT" --script "$script" "$ENUM_HOST"
}

enum_finish() {
    printf 'Resultados: %s — operaciones no determinadas: %s\n' "$ENUM_DIR" "$ENUM_FAILED"
    (( ENUM_FAILED == 0 ))
}
