#!/bin/bash
# ============================================================
#  SCANS - Rutas, nombres y línea base de los resultados
#  Uso: source 00_Config/lib/scans.bash
#  Quien devuelve un valor imprime SOLO el valor por stdout.
# ============================================================

SCANS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SCANS_CONFIG_DIR="$(cd "$SCANS_LIB_DIR/.." && pwd)"
SCANS_FW_DIR="$(cd "$SCANS_CONFIG_DIR/.." && pwd)"
SCANS_REPO_DIR="$(cd "$SCANS_FW_DIR/.." && pwd)"

# ─── Rutas ─────────────────────────────────────────────────

# scans_root → <repo>/scans
scans_root() {
    printf '%s\n' "$SCANS_REPO_DIR/scans"
}

# scans_dir <tool> → <repo>/scans/<tool>, creado
scans_dir() {
    local tool="$1" dir
    [[ -z "$tool" ]] && return 1
    dir="$(scans_root)/$tool"
    mkdir -p "$dir" 2>/dev/null || return 1
    printf '%s\n' "$dir"
}

# ─── Nombres ───────────────────────────────────────────────

# scans_slug <objetivo> → objetivo con ':' y '/' sustituidos por '_'
scans_slug() {
    printf '%s\n' "${1//[:\/]/_}"
}

# ─── Línea base ────────────────────────────────────────────

# scans_signature <url> → "<código>:<tamaño>" de la respuesta
scans_signature() {
    curl -sk -o /dev/null -w '%{http_code}:%{size_download}' "$1" 2>/dev/null
}

# scans_baseline_size <url> → tamaño del relleno catch-all, o NADA (cadena
# vacía) si el servidor responde 404/5xx o no responde.
# Pide una ruta aleatoria que no debería existir: si el servidor contesta 2xx/3xx
# con contenido, está sirviendo lo mismo para todo (SPA, rewrite) y ese tamaño
# es el que hay que filtrar en el fuzzing. Un 403 también cuenta: un WAF que
# contesta lo mismo a cualquier ruta falsea el fuzzing igual que una SPA.
# La señal de "no hay catch-all" NO puede ser 0, porque 0 es un tamaño legítimo
# (un rewrite que solo redirige, sin cuerpo): por eso se devuelve vacío.
scans_baseline_size() {
    local url="${1%/}" sig code size
    sig=$(curl -sk -o /dev/null -w '%{http_code}:%{size_download}' \
        "${url}/scans_probe_${RANDOM}${RANDOM}" 2>/dev/null)
    code=${sig%%:*}
    size=${sig#*:}
    [[ "$code" =~ ^([23][0-9][0-9]|403)$ ]] || return 0
    [[ "$size" =~ ^[0-9]+$ ]] || size=0
    printf '%s\n' "$size"
}

# scans_ffuf_count <json> → número de hallazgos en la salida JSON de ffuf.
# Contar '"url"' no vale: la configuración de ffuf también trae su propia "url"
# con el marcador FUZZ, así que un run sin hallazgos se leía como uno solo.
scans_ffuf_count() {
    local file="$1" n
    [[ -f "$file" ]] || { printf '0\n'; return 0; }
    if command -v python3 >/dev/null 2>&1; then
        n=$(python3 -c '
import json, sys
try:
    print(len(json.load(open(sys.argv[1])).get("results") or []))
except Exception:
    print(0)
' "$file" 2>/dev/null)
        [[ "$n" =~ ^[0-9]+$ ]] && { printf '%s\n' "$n"; return 0; }
    fi
    # Sin python3: cada hallazgo lleva "position", que la configuración no tiene.
    n=$(grep -o '"position"' "$file" 2>/dev/null | wc -l | tr -d ' ')
    printf '%s\n' "${n:-0}"
}
