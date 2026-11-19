#!/bin/bash

# ============================================================
# SETUP LAB - Configura laboratorio
# Uso:     ./setup_lab.sh <TIPO> <NOMBRE> [--root DIR]
# Ejemplo: ./setup_lab.sh htb "Blue"
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

TYPE="${1:-}"
if [[ -z "$TYPE" ]]; then
    echo "Uso: ./setup_lab.sh <TIPO> <NOMBRE>"
    echo "Tipos: htb, thm, ad, web, cloud"
    echo "Ejemplo: ./setup_lab.sh htb Blue"
    exit 1
fi
shift

case "$TYPE" in
    htb)
        exec "$SCRIPT_DIR/hackthebox/htb_setup.sh" "$@"
        ;;
    thm)
        exec "$SCRIPT_DIR/tryhackme/thm_setup.sh" "$@"
        ;;
    ad)
        exec "$SCRIPT_DIR/active_directory/ad_setup.sh" "$@"
        ;;
    web)
        exec "$SCRIPT_DIR/web_apps/web_setup.sh" "$@"
        ;;
    cloud)
        exec "$SCRIPT_DIR/cloud/cloud_setup.sh" "$@"
        ;;
    *)
        echo "✖ Tipo no válido: $TYPE"
        echo "Tipos: htb, thm, ad, web, cloud"
        exit 1
        ;;
esac
