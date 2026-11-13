#!/bin/bash
# PostgreSQL: banner, prueba postgres/postgres, versión y listado de bases.
# Uso: ./enum_postgres.sh <IP> [PUERTO]
# Ejemplo: ./enum_postgres.sh 192.0.2.1 5432
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service postgres "$@"
