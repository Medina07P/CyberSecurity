#!/bin/bash

# INTERFACE MANAGER - Gestiona interfaces wireless
# Uso: ./interface_manager.sh [ACCION]
# Ejemplo: ./interface_manager.sh list

ACTION="${1:-list}"

echo "📡 Gestión de interfaces wireless"
echo "────────────────────────────────────────"

case "$ACTION" in
    list)
        echo " → Interfaces disponibles:"
        ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
        echo ""
        echo " → Interfaces en modo monitor:"
        iw dev | grep -A 4 "type monitor" | grep Interface | awk '{print $2}'
        ;;
    monitor)
        INTERFACE="$2"
        if [[ -z "$INTERFACE" ]]; then
            echo " Uso: ./interface_manager.sh monitor <INTERFACE>"
            exit 1
        fi
        echo " → Activando modo monitor en $INTERFACE..."
        sudo ip link set "$INTERFACE" down
        sudo iw dev "$INTERFACE" set type monitor
        sudo ip link set "$INTERFACE" up
        echo " ✅ Modo monitor activado"
        ;;
    managed)
        INTERFACE="$2"
        if [[ -z "$INTERFACE" ]]; then
            echo " Uso: ./interface_manager.sh managed <INTERFACE>"
            exit 1
        fi
        echo " → Activando modo managed en $INTERFACE..."
        sudo ip link set "$INTERFACE" down
        sudo iw dev "$INTERFACE" set type managed
        sudo ip link set "$INTERFACE" up
        echo " ✅ Modo managed activado"
        ;;
    *)
        echo " Uso: ./interface_manager.sh [list|monitor|managed]"
        echo " list → Lista interfaces"
        echo " monitor <IFACE> → Activa modo monitor"
        echo " managed <IFACE> → Activa modo managed"
        ;;
esac
