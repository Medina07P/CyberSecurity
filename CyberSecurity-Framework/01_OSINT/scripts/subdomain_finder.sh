#!/bin/bash
# SUBDOMAIN FINDER - Descubrimiento pasivo y DNS activo opcional
# Uso: ./subdomain_finder.sh <dominio> [directorio_salida] [diccionario] [resolver]
# Ejemplo: ./subdomain_finder.sh example.com
# Con diccionario local: exige DNS_SI; máximo 1.000 nombres y 5 consultas/s.
# Sin diccionario: certificados públicos + resolución; nunca AXFR.
FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$FW_DIR/00_Config/lib${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m osint.cli subdomains "$@"
