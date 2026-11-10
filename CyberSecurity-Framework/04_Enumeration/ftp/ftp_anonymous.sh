#!/bin/bash
# FTP: pruebas anónimas en 21,2121,2221.
# Uso: ./ftp_anonymous.sh <IP>
# Ejemplo: ./ftp_anonymous.sh 192.0.2.1
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service ftp_anon "$@"
