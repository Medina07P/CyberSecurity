#!/bin/bash

# CHANNEL HOPPER - Cambia canales automáticamente
# Uso: ./channel_hopper.sh <INTERFACE>
# Ejemplo: ./channel_hopper.sh wlan0mon

INTERFACE="$1"

if [[ -z "$INTERFACE" ]]; then
    echo "Uso: ./channel_hopper.sh <INTERFACE>"
    echo "Ejemplo: ./channel_hopper.sh wlan0mon"
    exit 1
fi

echo "📡 Cambiando canales en: $INTERFACE"
echo "────────────────────────────────────────"
echo " (presiona Ctrl+C para detener)"
echo ""

CHANNELS=(1 2 3 4 5 6 7 8 9 10 11)

while true; do
    for channel in "${CHANNELS[@]}"; do
        echo -ne " → Canal: $channel\r"
        sudo iw dev "$INTERFACE" set channel "$channel"
        sleep 1
    done
done
