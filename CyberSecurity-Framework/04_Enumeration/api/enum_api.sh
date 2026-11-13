#!/bin/bash
# API completa: endpoints, TODOS los métodos originales y Swagger/OpenAPI.
# Uso: ./enum_api.sh <IP> [PUERTO] [esquema]
# Ejemplo: ./enum_api.sh 192.0.2.1 8080 http
# Alternativa CLI: ./enum_api.sh --url https://example.com:9443/ruta
# AVISO: POST/PUT/DELETE/PATCH pueden modificar datos; requieren autorización.
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_web.bash"
enum_web_run api "$@"
