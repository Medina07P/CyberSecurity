#!/bin/bash
# Validación local y ejecución con estados explícitos. No realiza peticiones.
SCANNER_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "$SCANNER_LIB_DIR/scans.bash"

scanner_require() {
    command -v "$1" >/dev/null 2>&1 && return 0
    printf '❌ %s no instalado; instala la herramienta antes de continuar.\n' "$1" >&2
    return 1
}

# Python estándar evita aceptar octetos, CIDR o autoridades URL ambiguos.
_scanner_validate() {
    scanner_require python3 || return 1
    python3 - "$@" <<'PY'
import ipaddress
import re
import sys
from urllib.parse import urlsplit
kind, value = sys.argv[1:3]
def host(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        if re.fullmatch(r'[0-9.]+', v):
            return False
        return len(v) <= 253 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                     for label in v.rstrip('.').split('.'))
valid = bool(value) and not value.startswith('-') and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
try:
    if kind == 'host':
        # Los perfiles de red actuales y sus informes no implementan IPv6.
        # No aceptar un literal que Nmap trataría como objetivo IPv4 inválido.
        valid = valid and ':' not in value and host(value)
    elif kind == 'network':
        valid = valid and ipaddress.ip_network(value, strict=False).version == 4
    elif kind == 'url':
        u = urlsplit(value)
        valid = valid and u.scheme in ('http', 'https') and bool(u.hostname) and host(u.hostname) and u.username is None and u.password is None and not u.fragment and '\\' not in value
        valid = valid and (u.port is None or 1 <= u.port <= 65535)
    elif kind == 'ports':
        valid = valid and bool(re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*', value))
        if valid:
            for item in value.split(','):
                ports = [int(p) for p in item.split('-')]
                valid = valid and all(1 <= p <= 65535 for p in ports) and ports[0] <= ports[-1]
    elif kind == 'severity':
        valid = valid and all(s in ('info', 'low', 'medium', 'high', 'critical', 'unknown') for s in value.split(','))
    else:
        valid = False
except (ValueError, TypeError):
    valid = False
if not valid:
    print('❌ Entrada no válida para ' + kind + '.', file=sys.stderr)
sys.exit(0 if valid else 1)
PY
}
scanner_host() { _scanner_validate host "$1"; }
scanner_network() { _scanner_validate network "$1"; }
scanner_url() { _scanner_validate url "$1"; }
scanner_ports() { _scanner_validate ports "$1"; }
scanner_severity() { _scanner_validate severity "$1"; }

# Solo añade una sección al historial cuando esta orden emite stderr o falla.
# Un aviso en stderr no cambia el estado real de la herramienta.
scanner_run() {
    local log="$1" err rc
    shift
    err=$(mktemp "${log}.tmp.XXXXXX") || return 1
    "$@" 2>"$err"
    rc=$?
    if [[ -s "$err" || $rc -ne 0 ]]; then
        {
            printf '\n[%s] %s — código %s\n' "$(date -Is)" "$1" "$rc"
            cat "$err"
        } >>"$log"
        printf 'ℹ️ Diagnóstico de esta ejecución: %s\n' "$log" >&2
    fi
    rm -f "$err"
    if (( rc != 0 )); then
        printf '❌ Falló %s (código %s). Resultado NO DETERMINADO.\n' "$1" "$rc" >&2
        return 1
    fi
    return 0
}
