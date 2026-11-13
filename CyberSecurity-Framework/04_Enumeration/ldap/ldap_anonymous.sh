#!/bin/bash
# LDAP/LDAPS: pruebas anónimas en 389,636,3268,3269.
# Uso: ./ldap_anonymous.sh <IP>
# Ejemplo: ./ldap_anonymous.sh 192.0.2.1
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service ldap_anon "$@"
