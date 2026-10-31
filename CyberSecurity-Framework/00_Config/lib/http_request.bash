#!/bin/bash
# ============================================================
#  HTTP_REQUEST - Leer una petición HTTP cruda y construir su URL
#  Uso: source 00_Config/lib/http_request.bash
#
#  Contrato: quien devuelve un valor imprime SOLO el valor por stdout.
#  Los avisos (Content-Length recalculado, tipo de cuerpo no soportado)
#  van por stderr. hr_load deja el resultado en globales HR_*.
# ============================================================

HR_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# ─── Lectura de la petición ────────────────────────────────

# hr_load <fichero> → 0 ok · 1 no legible · 2 mal formada · 3 cuerpo no soportado
# Deja: HR_METHOD HR_TARGET HR_VERSION HR_HOST HR_HEADERS[] HR_BODY HR_CT
hr_load() {
    local fichero="$1"
    local line i n body_start=-1 ultimo bytes declarado calculado aviso=""

    HR_METHOD=""; HR_TARGET=""; HR_VERSION=""; HR_HOST=""; HR_CT=""; HR_BODY=""
    HR_HEADERS=()

    [[ -n "$fichero" && -r "$fichero" ]] || {
        echo "No se puede leer la petición: ${fichero:-<vacío>}" >&2
        return 1
    }

    # Se lee línea a línea quitando el CR de CRLF. El cuerpo se reconstruye
    # después; el último \n se recupera del fichero porque read lo consume.
    local -a lines=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        lines+=("${line%$'\r'}")
    done < "$fichero"
    n=${#lines[@]}

    # Primera línea: MÉTODO ruta VERSIÓN
    local -a primera=()
    read -r -a primera <<< "${lines[0]:-}"
    if [[ ${#primera[@]} -lt 3 || "${primera[2]:-}" != HTTP/* ]]; then
        echo "La primera línea no es una petición HTTP: ${lines[0]:-<vacío>}" >&2
        return 2
    fi
    HR_METHOD="${primera[0]}"
    HR_TARGET="${primera[1]}"
    HR_VERSION="${primera[2]}"

    # Cabeceras hasta la primera línea vacía
    for (( i = 1; i < n; i++ )); do
        line="${lines[$i]}"
        if [[ -z "$line" ]]; then
            body_start=$((i + 1))
            break
        fi
        HR_HEADERS+=("$line")
        local nombre="${line%%:*}"
        nombre=$(printf '%s' "$nombre" | tr '[:upper:]' '[:lower:]')
        case "$nombre" in
            host) HR_HOST="${line#*:}"; HR_HOST="${HR_HOST#"${HR_HOST%%[![:space:]]*}"}" ;;
            content-type)
                HR_CT="${line#*:}"
                HR_CT="${HR_CT#"${HR_CT%%[![:space:]]*}"}"
                HR_CT=$(printf '%s' "$HR_CT" | tr '[:upper:]' '[:lower:]')
                HR_CT="${HR_CT%%;*}"
                HR_CT="${HR_CT%"${HR_CT##*[![:space:]]}"}"
                ;;
            content-length) declarado="${line#*:}"; declarado="${declarado//[[:space:]]/}" ;;
            transfer-encoding)
                if printf '%s' "${line#*:}" | grep -qi 'chunked'; then
                    echo "Cuerpo no soportado: Transfer-Encoding chunked" >&2
                    return 3
                fi
                ;;
        esac
    done

    if [[ "$HR_CT" == multipart/form-data* ]]; then
        echo "Cuerpo no soportado: multipart/form-data" >&2
        return 3
    fi

    # Cuerpo: todo lo que va tras la línea en blanco
    if (( body_start >= 0 && body_start < n )); then
        for (( i = body_start; i < n; i++ )); do
            [[ $i -gt $body_start ]] && HR_BODY+=$'\n'
            HR_BODY+="${lines[$i]}"
        done
        ultimo=$(tail -c 1 "$fichero" 2>/dev/null | od -An -tx1 | tr -d ' \n')
        [[ "$ultimo" == "0a" ]] && HR_BODY+=$'\n'
    fi

    # Content-Length se recalcula siempre: un valor heredado de Burp tras
    # editar el cuerpo haría que el servidor leyera de menos o de más.
    bytes=$(printf '%s' "$HR_BODY" | LC_ALL=C wc -c | tr -d ' ')
    calculado="$bytes"
    if [[ -n "$declarado" && "$declarado" != "$calculado" ]]; then
        aviso="Content-Length declarado ($declarado) no cuadra con el cuerpo ($calculado); se recalcula"
    fi

    local -a nuevas=()
    local tiene_cl=0
    for line in "${HR_HEADERS[@]}"; do
        if printf '%s' "${line%%:*}" | grep -qi '^content-length$'; then
            nuevas+=("Content-Length: $calculado")
            tiene_cl=1
        else
            nuevas+=("$line")
        fi
    done
    if (( tiene_cl == 0 )) && [[ -n "$HR_BODY" ]]; then
        nuevas+=("Content-Length: $calculado")
    fi
    HR_HEADERS=("${nuevas[@]}")

    [[ -n "$aviso" ]] && echo "$aviso" >&2
    return 0
}

# ─── Esquema, puerto y URL ─────────────────────────────────

# hr_scheme <puerto> → http | https
hr_scheme() {
    case "$1" in
        443|8443) printf 'https\n' ;;
        *)        printf 'http\n' ;;
    esac
}

# hr_port <esquema> → puerto del Host: si lo trae; si no, el del esquema
hr_port() {
    local esquema="$1" puerto=""
    if [[ "$HR_HOST" =~ :([0-9]+)$ ]]; then
        puerto="${BASH_REMATCH[1]}"
    fi
    if [[ -z "$puerto" ]]; then
        [[ "$esquema" == "https" ]] && puerto=443 || puerto=80
    fi
    printf '%s\n' "$puerto"
}

# hr_url <objetivo> <esquema> → URL completa (omite el puerto por defecto)
hr_url() {
    local objetivo="$1" esquema="$2" puerto defecto ruta="$HR_TARGET"
    puerto=$(hr_port "$esquema")
    if [[ "$esquema" == "https" ]]; then defecto=443; else defecto=80; fi
    [[ "$ruta" == /* ]] || ruta="/$ruta"
    if [[ "$puerto" == "$defecto" ]]; then
        printf '%s://%s%s\n' "$esquema" "$objetivo" "$ruta"
    else
        printf '%s://%s:%s%s\n' "$esquema" "$objetivo" "$puerto" "$ruta"
    fi
}
