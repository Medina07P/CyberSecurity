#!/bin/bash
# SMB: null session, RPC, enum4linux, shares y NSE.
# Uso: ./enum_smb_advanced.sh <IP>
# Ejemplo: ./enum_smb_advanced.sh 192.0.2.1
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service smb "$@"
