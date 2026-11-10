#!/bin/bash
# SSH: versión, autenticación, usuarios y algoritmos; sin fuerza bruta añadida.
# Uso: ./enum_ssh.sh <IP> [PUERTO]
# Ejemplo: ./enum_ssh.sh 192.0.2.1 22
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service ssh "$@"
