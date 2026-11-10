#!/bin/bash
# Web completa: headers, tecnologías, robots, sitemap y fuzzing.
# Uso: ./enum_web.sh <IP> [PUERTO] [esquema]
# Ejemplo: ./enum_web.sh 192.0.2.1 80 http
# Alternativa CLI: ./enum_web.sh --url https://example.com:9443/ruta
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_web.bash"
enum_web_run web "$@"
