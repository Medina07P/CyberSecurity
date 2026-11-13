#!/bin/bash
# Redis: INFO y KEYS * (operación potencialmente costosa).
# Uso: ./enum_redis.sh <IP> [PUERTO]
# Ejemplo: ./enum_redis.sh 192.0.2.1 6379
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service redis "$@"
