#!/bin/bash
# MySQL: banner y prueba root SIN contraseña, sin credenciales heredadas.
# Uso: ./enum_mysql.sh <IP> [PUERTO]
# Ejemplo: ./enum_mysql.sh 192.0.2.1 3306
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service mysql "$@"
