#!/bin/bash

# ============================================================
# SETUP LAB - Configura laboratorio
# Uso:     ./setup_lab.sh <TIPO> <NOMBRE>
# Ejemplo: ./setup_lab.sh htb "Blue"
# ============================================================

TYPE="$1"
NAME="$2"

if [[ -z "$TYPE" || -z "$NAME" ]]; then
    echo "Uso: ./setup_lab.sh <TIPO> <NOMBRE>"
    echo "Tipos: htb, thm, ad, web, cloud"
    echo "Ejemplo: ./setup_lab.sh htb Blue"
    exit 1
fi

echo "════════════════════════════════════════════════════════"
echo " CONFIGURANDO LABORATORIO: ${TYPE} - ${NAME}"
echo "════════════════════════════════════════════════════════"

case "$TYPE" in
    htb)
        cd hackthebox && ./htb_setup.sh "$NAME"
        ;;
    thm)
        cd tryhackme && ./thm_setup.sh "$NAME"
        ;;
    ad)
        cd active_directory && ./ad_setup.sh "$NAME"
        ;;
    web)
        cd web_apps && ./web_setup.sh "$NAME"
        ;;
    cloud)
        cd cloud && ./cloud_setup.sh "$NAME"
        ;;
    *)
        echo "❌ Tipo no válido: $TYPE"
        echo "Tipos: htb, thm, ad, web, cloud"
        exit 1
        ;;
esac
