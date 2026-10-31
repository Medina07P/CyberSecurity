#!/bin/bash

# BT SCAN - Escanea dispositivos Bluetooth
# Uso: ./bt_scan.sh
# Ejemplo: ./bt_scan.sh

OUTPUT_DIR="../captures/logs"

mkdir -p "$OUTPUT_DIR"

echo "📡 Escaneando dispositivos Bluetooth..."
echo "────────────────────────────────────────"

# Verificar Bluetooth
if ! command -v hcitool &>/dev/null; then
    echo "❌ hcitool no instalado"
    echo " Instalar con: sudo apt install bluez-utils"
    exit 1
fi

# Escanear
echo " → Buscando dispositivos..."
sudo hcitool scan 2>/dev/null | tee "$OUTPUT_DIR/bt_scan_$(date +%Y%m%d).txt"

# Escanear con bluetoothctl
echo ""
echo " → Escaneo avanzado..."
sudo bluetoothctl scan on 2>/dev/null | head -20

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR/bt_scan_$(date +%Y%m%d).txt"
