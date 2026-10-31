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

# ─── Parámetros ────────────────────────────────────────────

# _hr_pares <cadena> <ubicacion> → una línea "ubicacion|nombre|valor" por par
_hr_pares() {
    local cadena="$1" ubicacion="$2" par k v
    local -a pares=()
    IFS='&' read -r -a pares <<< "$cadena"
    for par in "${pares[@]}"; do
        [[ -z "$par" ]] && continue
        k="${par%%=*}"; v=""
        [[ "$par" == *=* ]] && v="${par#*=}"
        printf '%s|%s|%s\n' "$ubicacion" "$k" "$v"
    done
}

# _hr_pares_sustituidos <cadena> <nombre> <valor> → la misma cadena con un par cambiado
_hr_pares_sustituidos() {
    local cadena="$1" nombre="$2" valor="$3" par k out="" primero=1
    local -a pares=()
    IFS='&' read -r -a pares <<< "$cadena"
    for par in "${pares[@]}"; do
        [[ -z "$par" ]] && continue
        (( primero == 0 )) && out+="&"
        primero=0
        k="${par%%=*}"
        if [[ "$k" == "$nombre" ]]; then
            out+="$k=$valor"
        else
            out+="$par"
        fi
    done
    printf '%s' "$out"
}

# hr_params → "ubicacion|nombre|valor" por parámetro (query, form o json)
# 4 si el cuerpo es JSON y no hay python3 · 5 si el JSON no parsea
hr_params() {
    local consulta

    if [[ "$HR_CT" == application/x-www-form-urlencoded* && -n "$HR_BODY" ]]; then
        _hr_pares "$HR_BODY" form
    fi

    if [[ "$HR_CT" == application/json* ]]; then
        if ! command -v python3 >/dev/null 2>&1; then
            echo "El cuerpo es JSON y no hay python3: no se pueden listar sus parámetros" >&2
            return 4
        fi
        python3 - "$HR_BODY" <<'PY' || return 5
import json, sys

try:
    datos = json.loads(sys.argv[1])
except Exception:
    sys.exit(5)

def recorrer(valor, ruta):
    if isinstance(valor, dict):
        for clave, hijo in valor.items():
            recorrer(hijo, f"{ruta}.{clave}" if ruta else str(clave))
    elif isinstance(valor, list):
        for i, hijo in enumerate(valor):
            recorrer(hijo, f"{ruta}.{i}" if ruta else str(i))
    else:
        if isinstance(valor, bool):
            texto = "true" if valor else "false"
        elif valor is None:
            texto = "null"
        else:
            texto = str(valor)
        print(f"json|{ruta}|{texto}")

recorrer(datos, "")
PY
    fi

    consulta="${HR_TARGET#*\?}"
    [[ "$consulta" == "$HR_TARGET" ]] && consulta=""
    [[ -n "$consulta" ]] && _hr_pares "$consulta" query
    return 0
}

# hr_target_with <ubicacion> <nombre> <valor> → target con la query sustituida
hr_target_with() {
    local ubicacion="$1" nombre="$2" valor="$3" base consulta
    if [[ "$ubicacion" != "query" || "$HR_TARGET" != *\?* ]]; then
        printf '%s\n' "$HR_TARGET"
        return 0
    fi
    base="${HR_TARGET%%\?*}"
    consulta="${HR_TARGET#*\?}"
    printf '%s?%s\n' "$base" "$(_hr_pares_sustituidos "$consulta" "$nombre" "$valor")"
}

# hr_body_with <ubicacion> <nombre> <valor> → cuerpo con el parámetro sustituido
hr_body_with() {
    local ubicacion="$1" nombre="$2" valor="$3"
    case "$ubicacion" in
        query) printf '%s' "$HR_BODY" ;;
        form)  _hr_pares_sustituidos "$HR_BODY" "$nombre" "$valor" ;;
        json)
            python3 - "$HR_BODY" "$nombre" "$valor" <<'PY'
import json, sys

try:
    datos = json.loads(sys.argv[1])
except Exception:
    sys.exit(5)

ruta, valor = sys.argv[2], sys.argv[3]
claves = ruta.split(".")
actual = datos
for clave in claves[:-1]:
    actual = actual[int(clave)] if isinstance(actual, list) else actual[clave]
ultima = claves[-1]
if isinstance(actual, list):
    actual[int(ultima)] = valor
else:
    actual[ultima] = valor
print(json.dumps(datos, ensure_ascii=False))
PY
            ;;
        *) printf '%s' "$HR_BODY" ;;
    esac
}
