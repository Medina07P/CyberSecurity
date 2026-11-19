#!/bin/bash
# MASSCAN — requiere root, sin elevación automática.
# Uso: ./masscan_scan.sh <red> [PUERTOS] [TASA]
# Ejemplo: ./masscan_scan.sh 192.0.2.1 80,443 1000
#
# <red>     IPv4 o CIDR de una máquina REMOTA (no 127.0.0.1 ni una IP propia).
# PUERTOS   por defecto 1-65535.
# TASA      paquetes/s, 1-100000, por defecto 1000 (también MASSCAN_RATE).
#
# Masscan usa su propia pila TCP por la interfaz de red: no ve el loopback ni
# los servicios de esta misma máquina. Para eso usa «nmap -sT» (módulo 03, básico).
TARGET="${1:-}"
PORTS="${2:-1-65535}"
RATE="${3:-${MASSCAN_RATE:-1000}}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
[[ -n "$TARGET" ]] || { echo 'Uso: ./masscan_scan.sh <red> [PUERTOS] [TASA]'; exit 1; }
scanner_network "$TARGET" && scanner_ports "$PORTS" && scanner_require masscan || exit 1
if ! [[ "$RATE" =~ ^[0-9]+$ ]] || (( 10#$RATE < 1 || 10#$RATE > 100000 )); then
    echo "✖ Tasa no válida: '$RATE'. Usa un entero entre 1 y 100000 paquetes/s." >&2
    exit 1
fi
RATE=$((10#$RATE))

# Masscan no puede medir loopback ni direcciones de esta máquina: los SYN que
# inyecta no pasan por la pila del kernel y la respuesta nunca vuelve. Un «0
# puertos» ahí sería un falso negativo, así que se rechaza antes de ejecutar.
_masscan_local_overlap() {
    python3 - "$1" <<'PY'
import ipaddress, subprocess, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
if net.overlaps(ipaddress.ip_network('127.0.0.0/8')) or net.overlaps(ipaddress.ip_network('0.0.0.0/8')):
    print('loopback'); sys.exit(0)
try:
    out = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], capture_output=True, text=True, timeout=5).stdout
except Exception:
    sys.exit(1)
for line in out.splitlines():
    parts = line.split()
    if 'inet' in parts:
        addr = ipaddress.ip_interface(parts[parts.index('inet') + 1]).ip
        if addr in net:
            print(str(addr)); sys.exit(0)
sys.exit(1)
PY
}
if LOCAL=$(_masscan_local_overlap "$TARGET"); then
    echo "✖ Masscan no puede escanear $TARGET ($LOCAL): es esta misma máquina." >&2
    echo '   Sus paquetes no pasan por el kernel local y devolvería 0 puertos aunque haya servicios.' >&2
    echo '   Usa nmap con connect: nmap -sT -p <puertos> 127.0.0.1  (o el modo básico del módulo 03).' >&2
    exit 1
fi

[[ "$(id -u)" == 0 ]] || { echo '✖ Masscan necesita root (sockets raw). No se ha ejecutado.' >&2; exit 1; }
OUTPUT_DIR=$(scans_dir masscan) || exit 1
SLUG=$(scans_slug "$TARGET")
OUT="$OUTPUT_DIR/masscan_${SLUG}.json"

# La barra de progreso de masscan usa \r y se repetía cientos de veces en
# errores.log. Se descartan esas líneas y se conservan banner y errores reales.
masscan_filtrado() {
    local err rc
    err=$(mktemp "$OUTPUT_DIR/.masscan_err.XXXXXX") || return 1
    masscan "$@" 2>"$err"
    rc=$?
    tr '\r' '\n' <"$err" | grep -v -E '^[[:space:]]*(rate:.*)?$' >&2
    rm -f "$err"
    return $rc
}

echo "Masscan: $TARGET; puertos $PORTS; tasa $RATE paquetes/s"
# Masscan solo admite un formato por ejecución; JSON conserva campos estructurados.
scanner_run "$OUTPUT_DIR/errores.log" masscan_filtrado -p"$PORTS" --rate="$RATE" "$TARGET" \
    -oJ "$OUT" || exit 1

if [[ ! -e "$OUT" ]]; then
    echo "⚠  Masscan terminó sin crear $OUT. Resultado NO DETERMINADO." >&2
    exit 1
fi
N=$(grep -c '"port"' "$OUT")
if (( N == 0 )); then
    echo "● SIN PUERTOS ABIERTOS DETECTADOS: masscan terminó sin errores y 0 respuestas."
    echo "   Esto NO prueba que estén cerrados: con tasas altas o redes con pérdida se"
    echo "   pierden respuestas, y un firewall que descarta paquetes se ve igual."
    echo "   Confirma con: nmap -sT -p $PORTS <host>   (o repite con una tasa menor)."
else
    echo "● $N puerto(s) abierto(s) respondieron. Revisa $OUT"
fi
echo "✔ Escaneo completado. Resultados: $OUT"
