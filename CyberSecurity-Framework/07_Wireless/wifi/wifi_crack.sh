#!/bin/bash

# WIFI CRACK - Craqueo de handshake
# Uso: ./wifi_crack.sh <HANDSHAKE_FILE> [WORDLIST]
# Ejemplo: ./wifi_crack.sh handshake-01.cap

HANDSHAKE="$1"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"
OUTPUT_DIR="../captures/logs"

if [[ -z "$HANDSHAKE" ]]; then
    echo "Uso: ./wifi_crack.sh <HANDSHAKE_FILE> [WORDLIST]"
    echo "Ejemplo: ./wifi_crack.sh handshake-01.cap"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔓 Craqueando handshake..."
echo "────────────────────────────────────────"
echo " ARCHIVO: $HANDSHAKE"
echo " WORDLIST: $WORDLIST"
echo ""

# Verificar archivo
if [[ ! -f "$HANDSHAKE" ]]; then
    echo "❌ Archivo no encontrado: $HANDSHAKE"
    exit 1
fi

# Verificar wordlist
if [[ ! -f "$WORDLIST" ]]; then
    echo "❌ Wordlist no encontrada: $WORDLIST"
    echo " → Usando wordlist por defecto..."
    WORDLIST="/usr/share/wordlists/rockyou.txt"
fi

# Ejecutar aircrack
if command -v aircrack-ng &>/dev/null; then
    echo " → Ejecutando aircrack-ng..."
    aircrack-ng -w "$WORDLIST" -b "$HANDSHAKE" 2>/dev/null | tee "$OUTPUT_DIR/crack_$(date +%Y%m%d).txt"
else
    echo "❌ aircrack-ng no instalado"
    echo " Instalar con: sudo apt install aircrack-ng"
fi
