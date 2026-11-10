#!/bin/bash
# FTP: banner, acceso anónimo/listado y TODOS los NSE ftp-* originales.
# Uso: ./enum_ftp.sh <IP> [PUERTO]
# Ejemplo: ./enum_ftp.sh 192.0.2.1 21
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service ftp "$@"
