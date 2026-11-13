#!/bin/bash
# ============================================================
#  WEB TARGET - URL explícita para las hojas web de 05
#  Uso: source 00_Config/lib/web_target.bash
#
#  Las funciones imprimen SOLO el valor por stdout. No contactan nada.
#  Sirven para que `<TARGET> [PUERTO] [RUTA]` y `--url URL` acaben en el
#  mismo esquema, host, puerto y ruta, sin reinterpretar el uno con el otro.
# ============================================================

# webt_parse_url <url> → "esquema|host|puerto|ruta?query"
# Falla (1) si no es http/https o no trae host. El puerto por defecto lo pone
# el esquema; la query se conserva tal cual venía.
webt_parse_url() {
    python3 - "$1" <<'PY'
import sys
from urllib.parse import urlsplit

try:
    u = urlsplit(sys.argv[1])
    puerto = u.port
except ValueError:
    sys.exit(1)
if u.scheme not in ("http", "https") or not u.hostname:
    sys.exit(1)
if puerto is None:
    puerto = 443 if u.scheme == "https" else 80
ruta = u.path or "/"
if u.query:
    ruta = f"{ruta}?{u.query}"
print(f"{u.scheme}|{u.hostname}|{puerto}|{ruta}")
PY
}

# webt_encode <valor> → valor codificado para query (espacio → %20, etc.)
webt_encode() {
    python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"
}

# webt_url <esquema> <host> <puerto> <ruta> → URL (omite el puerto por defecto)
webt_url() {
    local esquema="$1" host="$2" puerto="$3" ruta="${4:-/}" defecto
    [[ "$ruta" == /* ]] || ruta="/$ruta"
    if [[ "$esquema" == "https" ]]; then defecto=443; else defecto=80; fi
    if [[ "$puerto" == "$defecto" ]]; then
        printf '%s://%s%s\n' "$esquema" "$host" "$ruta"
    else
        printf '%s://%s:%s%s\n' "$esquema" "$host" "$puerto" "$ruta"
    fi
}

# webt_con_param <url> <param> <valor_codificado> → URL con el parámetro
# añadido conservando la query existente (? si no hay, & si ya hay).
webt_con_param() {
    local url="$1" param="$2" valor="$3" sep='?'
    [[ "$url" == *"?"* ]] && sep='&'
    printf '%s%s%s=%s\n' "$url" "$sep" "$param" "$valor"
}

# webt_fuzz_url <url> → URL con /FUZZ antes de la query
webt_fuzz_url() {
    local url="$1" base="$1" query=""
    [[ "$url" == *"?"* ]] && { base="${url%%\?*}"; query="?${url#*\?}"; }
    printf '%s/FUZZ%s\n' "${base%/}" "$query"
}

# webt_reflejo <fichero_cuerpo> <payload> → literal | escapado | (nada)
# «literal» = el payload está tal cual; «escapado» = aparece solo tras
# deshacer las entidades HTML. No prueba ejecución en ningún caso.
webt_reflejo() {
    python3 - "$1" "$2" <<'PY'
import html, sys
try:
    with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
        cuerpo = f.read()
except OSError:
    sys.exit(0)
payload = sys.argv[2]
if payload in cuerpo:
    print("literal")
elif payload in html.unescape(cuerpo):
    print("escapado")
PY
}
