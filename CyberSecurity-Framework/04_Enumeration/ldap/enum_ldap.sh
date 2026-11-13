#!/bin/bash
# LDAP: RootDSE, namingContexts y usuarios (límite explícito 500,15s).
# Uso: ./enum_ldap.sh <IP> [PUERTO]
# Ejemplo: ./enum_ldap.sh 192.0.2.1 389
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service ldap "$@"
