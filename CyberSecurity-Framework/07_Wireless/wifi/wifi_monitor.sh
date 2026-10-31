#!/bin/bash

# WIFI MONITOR - Activa modo monitor en interfaz
# Uso: ./wifi_monitor.sh <INTERFACE>
# Ejemplo: ./wifi_monitor.sh wlan0

INTERFACE="$1"

if [[ -z "$INTERFACE" ]]; then
    echo "Uso: ./wifi_monitor.sh <INTERFACE>"
    echo "Ejemplo: ./wifi_monitor.sh wlan0"
    exit 1
fi

echo "📡 Activando modo monitor en: $INTERFACE"
echo "────────────────────────────────────────"

# Verificar interfaz
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "❌ Interfaz $INTERFACE no existe"
    exit 1
fi

# Activar modo monitor
sudo ip link set "$INTERFACE" down
sudo iw dev "$INTERFACE" set type monitor
sudo ip link set "$INTERFACE" up

# Verificar
if iw dev "$INTERFACE" info | grep -q "type monitor"; then
    echo "✅ Modo monitor activado en $INTERFACE"
    echo " → Usar: sudo airodump-ng $INTERFACE"
else
    echo "❌ Error al activar modo monitor"
fi
