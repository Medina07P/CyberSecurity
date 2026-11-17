#!/bin/bash
# Pruebas de ZAP — aisladas, nunca contra un daemon zaproxy real.
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAKE_API="$FW/tests/fixtures/zap_fake_api.py"
pasan=0; fallan=0
ok()  { echo "  ok   $1"; pasan=$((pasan+1)); }
ko()  { echo "  FALLO $1"; fallan=$((fallan+1)); }
eq()  { [[ "$2" == "$3" ]] && ok "$1" || ko "$1 (esperado '$3', obtenido '$2')"; }

echo "=== zap_fake_api.py ==="
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
READY="$TMPD/ready"
python3 "$FAKE_API" 0 "$READY" & FAKEPID=$!
for _ in $(seq 1 50); do [[ -s "$READY" ]] && break; sleep 0.05; done
read -r RPID RPORT < "$READY"
eq "fixture: version responde" \
    "$(curl -s "http://127.0.0.1:$RPORT/JSON/core/view/version/" | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])')" "fake"

eq "fixture: spider/status avanza y se queda en el último valor" \
    "$(for i in 1 2 3; do curl -s "http://127.0.0.1:$RPORT/JSON/spider/view/status/" | python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])'; done | tr '\n' ',')" \
    "100,100,100,"

READY2="$TMPD/ready2"
ZAP_FAKE_SPIDER_STATUSES=0,50,100 python3 "$FAKE_API" 0 "$READY2" & FAKEPID2=$!
for _ in $(seq 1 50); do [[ -s "$READY2" ]] && break; sleep 0.05; done
read -r RPID2 RPORT2 < "$READY2"
eq "fixture: spider/status sigue la secuencia configurada" \
    "$(for i in 1 2 3 4; do curl -s "http://127.0.0.1:$RPORT2/JSON/spider/view/status/" | python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])'; done | tr '\n' ',')" \
    "0,50,100,100,"
kill "$FAKEPID2" 2>/dev/null; wait "$FAKEPID2" 2>/dev/null

eq "fixture: pscan/recordsToScan sigue su propia secuencia por defecto" \
    "$(curl -s "http://127.0.0.1:$RPORT/JSON/pscan/view/recordsToScan/" | python3 -c 'import json,sys;print(json.load(sys.stdin)["recordsToScan"])')" "0"

eq "fixture: sin alertas configuradas, alerts/ está vacío" \
    "$(curl -s "http://127.0.0.1:$RPORT/JSON/core/view/alerts/" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["alerts"]))')" "0"

ALERTAS_JSON="$TMPD/alertas.json"
printf '[{"name":"X","risk":"Low","confidence":"Medium","url":"http://x/"}]' > "$ALERTAS_JSON"
READY3="$TMPD/ready3"
ZAP_FAKE_ALERTS_FILE="$ALERTAS_JSON" python3 "$FAKE_API" 0 "$READY3" & FAKEPID3=$!
for _ in $(seq 1 50); do [[ -s "$READY3" ]] && break; sleep 0.05; done
read -r RPID3 RPORT3 < "$READY3"
eq "fixture: alerts/ devuelve el fichero configurado" \
    "$(curl -s "http://127.0.0.1:$RPORT3/JSON/core/view/alerts/" | python3 -c 'import json,sys;print(json.load(sys.stdin)["alerts"][0]["name"])')" "X"
kill "$FAKEPID3" 2>/dev/null; wait "$FAKEPID3" 2>/dev/null

eq "fixture: ruta desconocida da 404" \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$RPORT/JSON/no/existe/")" "404"

curl -s "http://127.0.0.1:$RPORT/JSON/core/action/shutdown/" >/dev/null
sleep 0.2
curl -s --max-time 1 "http://127.0.0.1:$RPORT/JSON/core/view/version/" >/dev/null 2>&1
eq "fixture: tras shutdown deja de responder" "$?" "7"
wait "$FAKEPID" 2>/dev/null

READY4="$TMPD/ready4"
ZAP_FAKE_IGNORE_SHUTDOWN=1 python3 "$FAKE_API" 0 "$READY4" & FAKEPID4=$!
for _ in $(seq 1 50); do [[ -s "$READY4" ]] && break; sleep 0.05; done
read -r RPID4 RPORT4 < "$READY4"
curl -s "http://127.0.0.1:$RPORT4/JSON/core/action/shutdown/" >/dev/null
sleep 0.2
eq "fixture: con IGNORE_SHUTDOWN sigue respondiendo" \
    "$(curl -s --max-time 1 "http://127.0.0.1:$RPORT4/JSON/core/view/version/" | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])')" "fake"
kill "$FAKEPID4" 2>/dev/null; wait "$FAKEPID4" 2>/dev/null

echo ""; echo "Resultado: $pasan ok, $fallan fallos"
[[ $fallan -eq 0 ]]
