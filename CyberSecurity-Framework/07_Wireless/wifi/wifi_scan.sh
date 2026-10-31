#!/bin/bash

# WIFI SCAN - Escanea redes WiFi cercanas
# Uso: ./wifi_scan.sh <INTERFACE>
# Ejemplo: ./wifi_scan.sh wlan0

INTERFACE="$1"
OUTPUT_DIR="../captures/logs"

if [[ -z "$INTERFACE" ]]; then
    echo "Uso: ./wifi_scan.sh <INTERFACE>"
    echo "Ejemplo: ./wifi_scan.sh wlan0"
    echo ""
    echo "Interfaces disponibles:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "📡 Escaneando redes WiFi en: $INTERFACE"
echo "────────────────────────────────────────"

# Poner interfaz en modo monitor
echo " → Activando modo monitor..."
sudo ip link set "$INTERFACE" down
sudo iw dev "$INTERFACE" set type monitor
sudo ip link set "$INTERFACE" up

# Escanear
echo " → Escaneando redes..."
sudo iw dev "$INTERFACE" scan 2>/dev/null | grep -E "SSID:|BSS|signal|channel" | tee "$OUTPUT_DIR/wifi_scan_$(date +%Y%m%d).txt"

# Mostrar resumen
echo ""
echo "📊 Resumen de redes encontradas:"
grep "SSID:" "$OUTPUT_DIR/wifi_scan_$(date +%Y%m%d).txt" | sort -u

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR/wifi_scan_$(date +%Y%m%d).txt"
