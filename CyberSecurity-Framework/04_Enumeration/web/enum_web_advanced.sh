#!/bin/bash
# Web avanzada: siete puertos, cabeceras y siete archivos sensibles.
# Uso: ./enum_web_advanced.sh <IP>
# Ejemplo: ./enum_web_advanced.sh 192.0.2.1
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_web.bash"
TARGET="${1:-}"
scanner_host "$TARGET" && scanner_require nc || exit 1
FAILED=0
for port in 80 443 8080 8443 8000 8888 9000; do
    if nc -zv -w 3 "$TARGET" "$port" >/dev/null 2>&1; then
        enum_web_run advanced "$TARGET" "$port" || FAILED=$((FAILED + 1))
    else
        echo "Puerto $port: NO_DETERMINADO (sonda TCP fallida); no se afirma cerrado."
        enum_web_run invalidate "$TARGET" "$port" || :
        FAILED=$((FAILED + 1))
    fi
done
(( FAILED == 0 ))
