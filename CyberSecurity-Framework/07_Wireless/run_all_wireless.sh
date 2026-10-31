#!/bin/bash

# RUN ALL WIRELESS - Ejecuta todas las herramientas wireless
# Uso: ./run_all_wireless.sh <INTERFACE>
# Ejemplo: ./run_all_wireless.sh wlan0

INTERFACE="$1"

if [[ -z "$INTERFACE" ]]; then
    echo "Uso: ./run_all_wireless.sh <INTERFACE>"
    echo "Ejemplo: ./run_all_wireless.sh wlan0"
    echo ""
    echo "Interfaces disponibles:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
    exit 1
fi

echo "════════════════════════════════════════════════════════"
echo " HERRAMIENTAS WIRELESS PARA: $INTERFACE"
echo "════════════════════════════════════════════════════════"

# 1. Escanear redes
echo ""
echo "📡 ESCANEO WIFI"
echo "────────────────────────────────────────"
./wifi/wifi_scan.sh "$INTERFACE"

# 2. Activar modo monitor
echo ""
echo "📡 MODO MONITOR"
echo "────────────────────────────────────────"
./scripts/interface_manager.sh monitor "$INTERFACE"

# 3. Escanear Bluetooth
echo ""
echo "📡 BLUETOOTH"
echo "────────────────────────────────────────"
./bluetooth/bt_scan.sh

echo ""
echo "════════════════════════════════════════════════════════"
echo " ✅ WIRELESS COMPLETADO"
echo "════════════════════════════════════════════════════════"
echo ""
echo "💡 Próximos pasos:"
echo " 1. Capturar handshake: ./wifi/wifi_handshake.sh ${INTERFACE}mon"
echo " 2. Atacar red: ./wifi/wifi_deauth.sh ${INTERFACE}mon <BSSID> <CHANNEL>"
echo " 3. Craquear: ./wifi/wifi_crack.sh handshake-01.cap"
