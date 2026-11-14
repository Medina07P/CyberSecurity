#!/bin/bash
# Solo para pruebas sintéticas. Invocar en el shell padre, nunca con $(...).

iniciar_servidor_http() {
    local i ready_pid ready_port extra
    [[ -z "${HTTP_SRV_PID:-}" ]] || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    HPORT=""
    HTTP_READY_DIR=$(mktemp -d) || return 1
    python3 "$FW/tests/fixtures/http_target.py" 0 "$HTTP_READY_DIR/ready" >/dev/null 2>&1 &
    HTTP_SRV_PID=$!
    HTTP_SRV_OWNER=$BASHPID
    for i in {1..20}; do
        kill -0 "$HTTP_SRV_PID" 2>/dev/null || break
        if [[ -f "$HTTP_READY_DIR/ready" ]] &&
           read -r ready_pid ready_port extra < "$HTTP_READY_DIR/ready" &&
           [[ "$ready_pid" == "$HTTP_SRV_PID" && "$ready_port" =~ ^[0-9]{1,5}$ && -z "$extra" ]] &&
           (( 10#$ready_port > 0 && 10#$ready_port <= 65535 )); then
            HPORT=$ready_port
            if curl --noproxy '*' --max-time 1 -fs -o /dev/null "http://127.0.0.1:$HPORT/safe"; then
                return 0
            fi
        fi
        sleep 0.05
    done
    detener_servidor_http
    return 1
}

detener_servidor_http() {
    if [[ -n "${HTTP_SRV_PID:-}" && "${HTTP_SRV_OWNER:-}" == "$BASHPID" ]]; then
        kill "$HTTP_SRV_PID" 2>/dev/null || :
        wait "$HTTP_SRV_PID" 2>/dev/null || :
        [[ -z "${HTTP_READY_DIR:-}" ]] || rm -rf -- "$HTTP_READY_DIR"
        HTTP_READY_DIR=""
        HTTP_SRV_PID=""
        HTTP_SRV_OWNER=""
    fi
}

limpiar_evidencia_http() {
    local base
    [[ -n "${HPORT:-}" ]] || return 0
    [[ "$HPORT" =~ ^[0-9]{1,5}$ ]] || return 1
    (( 10#$HPORT > 0 && 10#$HPORT <= 65535 )) || return 1
    base="$FW/../scans/web/http_inject_127.0.0.1_${HPORT}"
    rm -rf -- "$base"
    rm -f -- "$base.txt" "$base.tsv"
}
