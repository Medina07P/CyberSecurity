#!/bin/bash
# ============================================================
#  PING SWEEP - Descubrimiento de hosts en red
#  Uso: ./ping_sweep.sh <red> [rango]
#  Ejemplo: ./ping_sweep.sh 192.168.1 1-254
# ============================================================

NETWORK="$1"
RANGE="${2:-1-254}"

if [[ -z "$NETWORK" ]]; then
    echo "Uso: ./ping_sweep.sh <red> [rango]"
    echo "Ejemplo: ./ping_sweep.sh 192.168.1 1-254"
    exit 1
fi

START=$(echo "$RANGE" | cut -d'-' -f1)
END=$(echo "$RANGE" | cut -d'-' -f2)

echo "🔍 Escaneando red: $NETWORK.0/24 ($RANGE)"
echo "────────────────────────────────────────"

# Archivo de salida
OUTPUT="host_discovery/ping_sweep_$(date +%Y%m%d).txt"
mkdir -p host_discovery

for i in $(seq "$START" "$END"); do
    IP="$NETWORK.$i"
    if ping -c 1 -W 1 "$IP" &>/dev/null; then
        echo "  ✅ $IP - Activo"
        echo "$IP|$(date)|ping" >> "$OUTPUT"
        # Resolver hostname
        HOST=$(host "$IP" 2>/dev/null | head -1 | awk '{print $NF}')
        [[ -n "$HOST" ]] && echo "    ↳ $HOST"
    else
        echo "  ❌ $IP - Inactivo"
    fi
done

echo "────────────────────────────────────────"
TOTAL=$(grep -c "|" "$OUTPUT" 2>/dev/null)
echo "✅ $TOTAL hosts activos encontrados"
echo "📁 Resultados guardados en: $OUTPUT"
