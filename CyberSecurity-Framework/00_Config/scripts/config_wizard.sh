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

# ─── Entrada y apoyo ───────────────────────────────────────

# wz_ask <texto> [defecto] → el texto por stderr; el valor por stdout.
# Con Enter devuelve el defecto. Devuelve 1 si la entrada se ha cerrado.
wz_ask() {
    local texto="$1" defecto="${2-}" resp
    if [[ -n "$defecto" ]]; then
        printf '%s [%s]: ' "$texto" "$defecto" >&2
    else
        printf '%s: ' "$texto" >&2
    fi
    IFS= read -r resp || return 1
    [[ -z "$resp" ]] && resp="$defecto"
    printf '%s\n' "$resp"
}

# wz_yes <respuesta> → 0 si es afirmativa (s, si, sí, y, yes)
wz_yes() {
    [[ "${1,,}" =~ ^(s|si|sí|y|yes)$ ]]
}

# Objetivos actuales, en tabla compacta.
wz_show_targets() {
    local linea host puerto proto desc prio encontrado=0
    if [[ -s "$TARGETS_FILE" ]]; then
        while IFS= read -r linea; do
            linea="${linea%$'\r'}"
            [[ "$linea" =~ ^[[:space:]]*# ]] && continue
            [[ "$linea" == *"|"* ]] || continue
            [[ "${linea^^}" == *EXCLUIDO* ]] && continue
            IFS='|' read -r host puerto proto desc prio <<< "$linea"
            printf '  %-16s %-6s %-12s %s\n' "$host" "$puerto" "$proto" "$prio"
            encontrado=1
        done < "$TARGETS_FILE"
    fi
    [[ "$encontrado" -eq 0 ]] && echo "  (lista de objetivos vacía)"
    return 0
}

# wz_exists <host> <puerto> → 0 si ya está en el fichero o en el lote actual.
wz_exists() {
    local host="$1" puerto="$2" linea
    if [[ -s "$TARGETS_FILE" ]]; then
        while IFS= read -r linea; do
            [[ "$linea" =~ ^[[:space:]]*# ]] && continue
            [[ "$linea" == "$host|$puerto|"* ]] && return 0
            [[ "$linea" == "$host|$puerto" ]] && return 0
        done < "$TARGETS_FILE"
    fi
    for linea in "${WZ_LINES[@]}"; do
        [[ "$linea" == "$host|$puerto|"* ]] && return 0
    done
    return 1
}

# ─── Flujo principal ───────────────────────────────────────

WZ_LINES=()
WZ_MODE=""

# ─── Escritura ─────────────────────────────────────────────

# Cabecera estándar de targets.txt, idéntica a la del fichero del repo.
wz_header() {
    cat <<'EOF'
# ============================================================
#  LISTA DE OBJETIVOS
#  Formato: IP|PUERTO|PROTOCOLO|DESCRIPCIÓN|PRIORIDAD
# ============================================================
#  PRIORIDAD: C = Crítica, A = Alta, M = Media, B = Baja
# ============================================================

EOF
}

# Vuelca WZ_LINES al fichero según WZ_MODE (1 añadir / 2 lista nueva).
# Todo el contenido se compone en un temporal y solo al final sustituye al
# original: o se escribe entero, o no se escribe nada.
wz_write() {
    local f="$TARGETS_FILE" tmp="$TARGETS_FILE.wz.tmp" linea rc

    mkdir -p "$(dirname "$f")" 2>/dev/null

    {
        if [[ "$WZ_MODE" == "2" ]]; then
            wz_header
        elif [[ -s "$f" ]]; then
            cat "$f"
            # El fichero no acaba en salto: la línea nueva no debe pegarse.
            [[ "$(tail -c1 "$f")" != "" ]] && echo
            printf '# ─── AÑADIDOS POR config_wizard (%s) ───\n' "$(date '+%Y-%m-%d %H:%M')"
        else
            wz_header
            printf '# ─── AÑADIDOS POR config_wizard (%s) ───\n' "$(date '+%Y-%m-%d %H:%M')"
        fi
        for linea in "${WZ_LINES[@]}"; do
            printf '%s\n' "$linea"
        done
    } > "$tmp"
    rc=$?
    if [[ "$rc" -ne 0 || ! -s "$tmp" ]]; then
        echo "❌ No se pudo preparar el contenido nuevo en $tmp"
        rm -f "$tmp"
        return 1
    fi

    if [[ "$WZ_MODE" == "2" && -f "$f" ]]; then
        if [[ -e "$f.bak" && ! -f "$f.bak" ]]; then
            echo "❌ $f.bak existe y no es un fichero; no se ha modificado $f"
            rm -f "$tmp"
            return 1
        fi
        if ! cp -f "$f" "$f.bak"; then
            echo "❌ No se pudo crear la copia de seguridad $f.bak"
            echo "   $f no se ha modificado."
            rm -f "$tmp"
            return 1
        fi
        echo "   Copia de la lista anterior: $f.bak"
    fi

    if ! mv -f "$tmp" "$f"; then
        echo "❌ No se pudo sustituir $f"
        rm -f "$tmp"
        return 1
    fi

    echo ""
    echo "✅ Objetivos escritos en $f"

    if command -v python3 >/dev/null 2>&1; then
        # Ruta absoluta: parse_targets.py resuelve las relativas contra su directorio.
        python3 "$SCRIPT_DIR/parse_targets.py" --input "$f" --summary 2>/dev/null
    fi

    echo ""
    echo "Recuerda validar la configuración: $SCRIPT_DIR/validate_config.sh"
}

main() {
    local host puerto proto defecto desc prio linea resp rc

    echo "════════════════════════════════════════════════════════"
    echo "  ASISTENTE DE OBJETIVOS - 00_Config"
    echo "════════════════════════════════════════════════════════"
    echo ""
    echo "📋 Objetivos actuales ($TARGETS_FILE):"
    wz_show_targets
    echo ""

    while :; do
        resp=$(wz_ask "¿Añadir a la lista actual (1) o empezar una nueva (2)? (0 = salir)" "1") \
            || { echo "Nada se ha modificado."; return 0; }
        case "$resp" in
            1|2) WZ_MODE="$resp"; break ;;
            0)   echo "Nada se ha modificado."; return 0 ;;
            *)   echo "❌ Opción no válida: $resp" >&2 ;;
        esac
    done
    echo ""

    while :; do
        host=$(wz_ask "Host o IP (vacío para terminar)") \
            || { echo "Nada se ha modificado."; return 0; }
        [[ -z "$host" ]] && break
        if ! validate_target "$host"; then
            echo "❌ Host no válido: $host" >&2
            continue
        fi

        while :; do
            puerto=$(wz_ask "Puerto (1-65535)") \
                || { echo "Nada se ha modificado."; return 0; }
            wz_valid_port "$puerto" && break
            echo "❌ Puerto no válido: $puerto" >&2
        done

        defecto=$(wz_default_protocol "$puerto")
        while :; do
            proto=$(wz_ask "Protocolo" "$defecto") \
                || { echo "Nada se ha modificado."; return 0; }
            if [[ -z "$proto" ]]; then
                echo "❌ Protocolo obligatorio para el puerto $puerto" >&2
                continue
            fi
            wz_valid_text "$proto" && break
            echo "❌ Protocolo no válido (sin '|'): $proto" >&2
        done

        while :; do
            desc=$(wz_ask "Descripción" "$proto") \
                || { echo "Nada se ha modificado."; return 0; }
            desc="${desc:-$proto}"
            wz_valid_text "$desc" && break
            echo "❌ Descripción no válida (sin '|'): $desc" >&2
        done

        while :; do
            prio=$(wz_ask "Prioridad C/A/M/B" "M") \
                || { echo "Nada se ha modificado."; return 0; }
            prio="${prio:-M}"
            wz_valid_priority "$prio" && { prio="${prio^^}"; break; }
            echo "❌ Prioridad no válida: $prio" >&2
        done

        if wz_exists "$host" "$puerto"; then
            resp=$(wz_ask "⚠️  Ya existe ${host}:${puerto}. ¿Añadir igualmente? (s/n)" "n") \
                || { echo "Nada se ha modificado."; return 0; }
            if ! wz_yes "$resp"; then
                echo "  (descartado)"
                resp=$(wz_ask "¿Otro objetivo? (s/n)" "s") \
                    || { echo "Nada se ha modificado."; return 0; }
                wz_yes "$resp" && continue
                break
            fi
        fi

        linea="${host}|${puerto}|${proto}|${desc}|${prio}"
        printf '  → %s\n' "$linea" >&2
        resp=$(wz_ask "¿Correcto? (s/n)" "s") || { echo "Nada se ha modificado."; return 0; }
        if wz_yes "$resp"; then
            WZ_LINES+=("$linea")
        fi

        resp=$(wz_ask "¿Otro objetivo? (s/n)" "s") \
            || { echo "Nada se ha modificado."; return 0; }
        wz_yes "$resp" || break
    done

    echo ""
    if [[ ${#WZ_LINES[@]} -eq 0 ]]; then
        echo "No se ha añadido nada. Nada se ha modificado."
        return 0
    fi

    echo "📋 Resumen de lo que se va a escribir:"
    for linea in "${WZ_LINES[@]}"; do
        echo "  → $linea"
    done
    echo ""

    resp=$(wz_ask "¿Escribir ${#WZ_LINES[@]} objetivo(s)? (s/n)" "s") \
        || { echo "Nada se ha modificado."; return 0; }
    if ! wz_yes "$resp"; then
        echo "Nada se ha modificado."
        return 0
    fi

    wz_write
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
