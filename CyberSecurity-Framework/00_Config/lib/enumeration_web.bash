#!/bin/bash
ENUM_WEB_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "$ENUM_WEB_LIB/scanner_runtime.bash"

enum_web_run() {
    local mode="$1" target="${2:-}" port="${3:-}" scheme="${4:-}" url output
    scanner_require python3 && scanner_require curl || return 1
    if [[ "$target" == --url ]]; then
        url="$port"
        scanner_url "$url" || return 1
    else
        scanner_host "$target" || return 1
        [[ -n "$port" ]] || { [[ "$mode" != api ]] && port=80 || port=8080; }
        scanner_ports "$port" && [[ "$port" =~ ^[0-9]+$ ]] || return 1
        if [[ -z "$scheme" ]]; then
            scheme=http; [[ "$port" != 443 && "$port" != 8443 ]] || scheme=https
            echo 'Esquema inferido por puerto: heurística; usa --url para indicarlo explícitamente.'
        fi
        [[ "$scheme" == http || "$scheme" == https ]] || return 1
        url="$scheme://$target:$port"
    fi
    local service=web
    [[ "$mode" != api ]] || service=api
    output=$(scans_dir "$service") || return 1
    python3 "$ENUM_WEB_LIB/enumeration_http.py" "$mode" --url "$url" --output "$output"
}
