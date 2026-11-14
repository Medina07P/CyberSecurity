#!/bin/bash

# Burp Community: apertura GUI/manual; nunca tráfico al objetivo de sesión.
# Uso: ./burp_launcher.sh [puerto]
# Ejemplo: ./burp_launcher.sh 8080
# Consulta inerte: --help | --estado [--instance ID]
# GET explícito: --verificar URL --proxy-port N --execute --confirm-network
# Parada propia: --parar --instance ID --execute (pidfd, sin adoptar PIDlegacy)
FRAMEWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)" || exit 1
exec /usr/bin/python3 -I -B -X utf8 "$FRAMEWORK_DIR/00_Config/lib/consent/burp_cli.py" "$@"
