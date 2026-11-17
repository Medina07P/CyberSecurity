#!/bin/bash
# ZAP — spider y pasivo (nunca Active Scan/inyección). Puede tardar varios minutos.
# Uso: ./zap_scan.sh <URL>
# Ejemplo: ./zap_scan.sh https://example.com
URL="${1:-}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
[[ -n "$URL" ]] || { echo 'Uso: ./zap_scan.sh <URL>'; exit 1; }
scanner_url "$URL" && scanner_require zaproxy || exit 1
python3 -c 'import zapv2' >/dev/null 2>&1 || {
    echo '❌ Falta python3-zapv2 (paquete python-owasp-zap-v2.4).' >&2
    exit 1
}

PUERTO=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])') || exit 1
PERFIL=$(mktemp -d) || exit 1

zaproxy -daemon -host 127.0.0.1 -port "$PUERTO" -dir "$PERFIL" \
    -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
    >/dev/null 2>&1 &
ZAP_PID=$!

zap_cleanup() {
    curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$PUERTO/JSON/core/action/shutdown/" 2>/dev/null
    sleep 0.3
    kill -TERM "$ZAP_PID" 2>/dev/null
    sleep 0.3
    kill -KILL "$ZAP_PID" 2>/dev/null
    rm -rf "$PERFIL"
}
trap zap_cleanup EXIT INT TERM

LIMITE_ARRANQUE=$(( $(date +%s) + 30 ))
LISTO=0
while (( $(date +%s) < LIMITE_ARRANQUE )); do
    if curl -s --max-time 1 -fo /dev/null "http://127.0.0.1:$PUERTO/JSON/core/view/version/"; then
        LISTO=1
        break
    fi
    sleep 0.5
done
if (( LISTO == 0 )); then
    echo '❌ ZAP no respondió en 30s; abortando.' >&2
    exit 1
fi

OUTPUT_DIR=$(scans_dir zap) || exit 1
SLUG=$(scans_slug "$URL")
INFORME="$OUTPUT_DIR/zap_${SLUG}.txt"

ZAP_DRIVER_ARGS=(--host 127.0.0.1 --port "$PUERTO" --url "$URL" --salida "$INFORME")
[[ -n "${ZAP_MAX_SEG:-}" ]] && ZAP_DRIVER_ARGS+=(--max-seg "$ZAP_MAX_SEG")
echo "🔬 ZAP: $URL (spider + pasivo; puede tardar varios minutos)"
python3 "$SCANS_LIB/zap/zap_driver.py" "${ZAP_DRIVER_ARGS[@]}"
rc=$?
if (( rc != 0 )); then
    echo "❌ ZAP no completó la evaluación. NO DETERMINADO. Revisa: $INFORME" >&2
    exit 1
fi
echo "✅ Ejecución completada."
echo "📁 Resultados: $INFORME"
