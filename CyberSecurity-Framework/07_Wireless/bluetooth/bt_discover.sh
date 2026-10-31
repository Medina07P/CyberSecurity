#!/bin/bash

# BT DISCOVER - Descubre información de dispositivos BT
# Uso: ./bt_discover.sh <MAC>
# Ejemplo: ./bt_discover.sh AA:BB:CC:DD:EE:FF

MAC="$1"
OUTPUT_DIR="../captures/logs"

if [[ -z "$MAC" ]]; then
    echo "Uso: ./bt_discover.sh <MAC>"
    echo "Ejemplo: ./bt_discover.sh AA:BB:CC:DD:EE:FF"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔍 Descubriendo dispositivo: $MAC"
echo "────────────────────────────────────────"

# 1. Información básica
echo " → Información del dispositivo:"
sudo hcitool info "$MAC" 2>/dev/null | tee "$OUTPUT_DIR/bt_info_${MAC}.txt"

# 2. Servicios
echo ""
echo " → Servicios disponibles:"
sudo sdptool browse "$MAC" 2>/dev/null | grep -E "Service Name|Protocol" | head -20

# 3. Características
echo ""
echo " → Características:"
sudo gatttool -b "$MAC" --characteristics 2>/dev/null | head -10

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR/bt_info_${MAC}.txt"
