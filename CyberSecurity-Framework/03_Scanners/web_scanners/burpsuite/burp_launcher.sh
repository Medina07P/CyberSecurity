#!/bin/bash

# ─── BURP LAUNCHER - Arranca Burp y explica el flujo manual ────────────
# Burp Suite Community no se puede automatizar como escáner: no tiene
# Scanner ni API, y su proyecto vive en memoria (lo dice el propio Burp al
# arrancar). Lo que sí se puede automatizar es el arranque: este script lanza
# Burp con un config generado, comprueba en qué puerto escucha de verdad y
# deja impreso el comando exacto que hay que ejecutar después.
#
# Uso: ./burp_launcher.sh [puerto]
# Ejemplo: ./burp_launcher.sh 8080
#
#   [puerto]   puerto del proxy de Burp. Si no se indica, 8080 y luego
#              8080-8099; si el indicado está ocupado, error.
#
# En la línea de comandos, fuera de la línea Uso:
#   --estado   PID, puerto y si escucha
#   --parar    cierra solo el Burp que arrancó este script (por PID)
#
# Variable de entorno: BURP_LAUNCHER_ESPERA (segundos de espera al listener).
# ───────────────────────────────────────────────────────────────────────

FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "$FW_DIR/00_Config/lib/scans.bash"
source "$FW_DIR/00_Config/lib/session.bash"

DIR=$(scans_dir burp) || { echo "❌ No se pudo crear el directorio de resultados"; exit 1; }
TARGET=$(session_target)
SLUG=$(scans_slug "${TARGET:-sin_objetivo}")
CONFIG="$DIR/config_${SLUG}.json"
PIDFILE="$DIR/burp.pid"
LOG="$DIR/launcher.log"
ESPERA="${BURP_LAUNCHER_ESPERA:-60}"

# ─── Utilidades ────────────────────────────────────────────

puerto_libre() {
    local p="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$" && return 1
        return 0
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/${p}") 2>/dev/null; then
        exec 3>&- 2>/dev/null
        return 1
    fi
    return 0
}

puerto_del_config() {
    [[ -f "$CONFIG" ]] || return 0
    grep -o '"listener_port":[0-9]*' "$CONFIG" 2>/dev/null | cut -d: -f2
}

estado() {
    local pid="" puerto escucha="no"
    [[ -f "$PIDFILE" ]] && pid=$(head -1 "$PIDFILE" 2>/dev/null)
    puerto=$(puerto_del_config)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        :
    else
        pid=""
    fi
    [[ -n "$puerto" ]] && ! puerto_libre "$puerto" && escucha="sí"
    echo "PID: ${pid:-ninguno}"
    echo "Puerto: ${puerto:-desconocido}"
    echo "Escuchando: ${escucha}"
    echo "Config: ${CONFIG}"
    return 0
}

parar() {
    local pid i
    [[ -f "$PIDFILE" ]] || { echo "No hay ningún Burp arrancado por este script."; return 0; }
    pid=$(head -1 "$PIDFILE" 2>/dev/null)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        for i in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.2
        done
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
        echo "Burp parado (PID ${pid})."
    else
        echo "El PID guardado (${pid:-ninguno}) ya no existe."
    fi
    rm -f "$PIDFILE"
    return 0
}

elegir_puerto() {
    local pedido="$1" p
    if [[ -n "$pedido" ]]; then
        if puerto_libre "$pedido"; then
            printf '%s\n' "$pedido"
            return 0
        fi
        return 1
    fi
    for p in $(seq 8080 8099); do
        if puerto_libre "$p"; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 1
}

escribir_config() {
    local puerto="$1" cfg
    cfg=$(printf '{"proxy":{"request_listeners":[{"listener_port":%s,"listen_mode":"loopback_only","running":true}]}' "$puerto")
    if [[ -n "$TARGET" ]]; then
        cfg+=$(printf ',"target":{"scope":{"advanced_mode":true,"include":[{"enabled":true,"protocol":"any","host":"^%s$"}]}}' "$TARGET")
    fi
    cfg+='}'
    printf '%s\n' "$cfg" > "$CONFIG"
}

# ─── Subcomandos ───────────────────────────────────────────

case "${1:-}" in
    --estado) estado; exit 0 ;;
    --parar)  parar; exit 0 ;;
esac

PUERTO_PEDIDO="${1:-}"

if ! command -v burpsuite >/dev/null 2>&1; then
    echo "❌ No se encontró el wrapper 'burpsuite'."
    echo "   Instálalo con: sudo apt install burpsuite"
    exit 1
fi

if ! PUERTO=$(elegir_puerto "$PUERTO_PEDIDO"); then
    echo "❌ El puerto ${PUERTO_PEDIDO} está ocupado o no hay ninguno libre entre 8080 y 8099."
    echo "   Comprueba quién lo ocupa con: ss -ltnp | grep '${PUERTO_PEDIDO:-8080}'"
    exit 1
fi

escribir_config "$PUERTO"

# El wrapper /usr/bin/burpsuite pasa --suppress-jre-check y
# --disable-check-for-updates-dialog; llamar a `java -jar` deja un modal
# "JRE warning" que bloquea el arranque.
burpsuite --project-file="$DIR/burp_${SLUG}.burp" --config-file="$CONFIG" \
    >> "$LOG" 2>&1 &
PID=$!
printf '%s\n' "$PID" > "$PIDFILE"

echo "🚀 Burp arrancado (PID ${PID}) con config: ${CONFIG}"
echo "   Puerto pedido: ${PUERTO}"
echo "   Log: ${LOG}"
