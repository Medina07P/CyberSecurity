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

# ─── Espera al listener ────────────────────────────────────
# Community ignora el --project-file y puede ignorar el puerto del config:
# no se asume nada, se comprueba quién escucha de verdad.

esperar_listener() {
    local puerto="$1" i=0
    while (( i < ESPERA )); do
        puerto_libre "$puerto" || return 0
        sleep 2
        i=$((i + 2))
    done
    return 1
}

# Ofrece pulsar Start Burp si hay ventana. Solo con confirmación explícita:
# es una acción sobre la interfaz del operador.
pulsar_start_burp() {
    command -v xdotool >/dev/null 2>&1 || return 1
    local w geom x y ancho alto
    w=$(xdotool search --name 'Burp Suite Community' 2>/dev/null | head -1)
    [[ -z "$w" ]] && return 1
    echo ""
    echo "Hay una ventana de Burp esperando. ¿Pulso 'Start Burp' por ti? [s/N]"
    read -r respuesta
    case "$respuesta" in
        s|S|si|SI|sí|SÍ) ;;
        *) return 1 ;;
    esac
    geom=$(xwininfo -id "$w" 2>/dev/null)
    x=$(printf '%s' "$geom" | awk -F: '/Absolute upper-left X/{gsub(/ /,"",$2); print $2}')
    y=$(printf '%s' "$geom" | awk -F: '/Absolute upper-left Y/{gsub(/ /,"",$2); print $2}')
    ancho=$(printf '%s' "$geom" | awk -F: '/Width/{gsub(/ /,"",$2); print $2}')
    alto=$(printf '%s' "$geom" | awk -F: '/Height/{gsub(/ /,"",$2); print $2}')
    [[ -z "$x" || -z "$y" || -z "$ancho" || -z "$alto" ]] && return 1
    xdotool windowraise "$w" 2>/dev/null
    xdotool windowactivate --sync "$w" 2>/dev/null
    sleep 1
    xdotool mousemove $((x + ancho - 62)) $((y + alto - 33)) click 1 2>/dev/null
    return 0
}

if ! esperar_listener "$PUERTO"; then
    if pulsar_start_burp; then
        esperar_listener "$PUERTO" || true
    fi
fi

if puerto_libre "$PUERTO"; then
    echo ""
    echo "❌ Burp no está escuchando en ${PUERTO}."
    echo "   En Community, el puerto del config no siempre se aplica y el 8080"
    echo "   puede estar ocupado por otro proceso."
    echo "   Cámbialo en Settings → Proxy → Proxy settings, o libera el puerto."
    echo "   Vuelve a comprobar con: ./burp_launcher.sh --estado"
    exit 0
fi

echo "✅ Burp escucha en 127.0.0.1:${PUERTO}"

# Verificación de captura: una petición real a través del proxy. Se fuerza el
# proxy con --noproxy '' porque curl se salta localhost por defecto.
if [[ -n "$TARGET" ]]; then
    codigo=$(curl -sk --max-time 5 --noproxy '' -x "http://127.0.0.1:${PUERTO}" \
        -o /dev/null -w '%{http_code}' "http://${TARGET}/" 2>/dev/null)
    if [[ -n "$codigo" && "$codigo" != "000" ]]; then
        echo "✅ Proxy comprobado: una petición a ${TARGET} ha pasado por el puerto ${PUERTO} (HTTP ${codigo})."
    else
        echo "⚠️  No se pudo comprobar la captura: sin respuesta a través del proxy."
        echo "   El listener responde, pero puede faltar aceptar el CA o no ser HTTP."
    fi
fi

# ─── Flujo manual ──────────────────────────────────────────

echo ""
echo "── Qué hacer ahora (Burp no escanea; captura) ──────────────"
echo "1. Apunta el navegador al proxy 127.0.0.1:${PUERTO}."
echo "2. Abre https:// y acepta el CA de Burp (http://burp) si hace falta."
echo "3. Navega con la sesión iniciada, manda la petición interesante a Repeater."
echo "4. Guárdala como: ${DIR}/peticion_${SLUG}.txt"
echo "   (este script no crea ese fichero: lo guardas tú)"
echo "5. Prueba la inyección sobre ella:"
echo "   ./05_Exploitation/web/http_inject.sh ${DIR}/peticion_${SLUG}.txt ${TARGET:-<objetivo>}"
echo ""
echo "⚠️  Community no guarda proyectos en disco: al cerrar Burp se pierde el"
echo "   historial. Lo único que sobrevive es la petición que guardes en el paso 4."
echo ""
echo "   Para cerrar este Burp: ./burp_launcher.sh --parar"
