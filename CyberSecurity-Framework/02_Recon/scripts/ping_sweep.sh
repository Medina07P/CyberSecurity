#!/bin/bash
# ============================================================
#  PING SWEEP - Descubrimiento de hosts en red
#  Uso: ./ping_sweep.sh <red> [rango]
#  Ejemplo: ./ping_sweep.sh 192.168.1 1-254
#  También acepta una IP suelta (192.168.1.10) o una red /24 (192.168.1.0/24)
# ============================================================

NETWORK="$1"
RANGE="${2:-1-254}"

if [[ -z "$NETWORK" ]]; then
    echo "Uso: ./ping_sweep.sh <red> [rango]"
    echo "Ejemplo: ./ping_sweep.sh 192.168.1 1-254"
    echo "También: ./ping_sweep.sh 192.168.1.10"
    echo "         ./ping_sweep.sh 192.168.1.0/24"
    exit 1
fi

# Resultados junto al módulo, no en el cwd desde el que se lance
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$MODULE_DIR/host_discovery"
OUTPUT="$OUTPUT_DIR/ping_sweep_$(date +%Y%m%d).txt"

IPS=()
if [[ "$NETWORK" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    # IP suelta: un solo host, sin inventar un /24
    IPS=("$NETWORK")
    echo "🔍 Comprobando host: $NETWORK"
elif [[ "$NETWORK" =~ ^([0-9]{1,3}\.){2}[0-9]{1,3}/24$ ]]; then
    BASE="${NETWORK%/24}"
    BASE="${BASE%.*}"
elif [[ "$NETWORK" =~ ^([0-9]{1,3}\.){2}[0-9]{1,3}$ ]]; then
    BASE="$NETWORK"
else
    echo "❌ Objetivo no válido: '$NETWORK'"
    echo "   Usa una IP (192.168.1.10), una red /24 (192.168.1.0/24) o un prefijo (192.168.1)"
    exit 1
fi

if [[ ${#IPS[@]} -eq 0 ]]; then
    START=$(echo "$RANGE" | cut -d'-' -f1)
    END=$(echo "$RANGE" | cut -d'-' -f2)
    if [[ ! "$START" =~ ^[0-9]+$ || ! "$END" =~ ^[0-9]+$ ]]; then
        echo "❌ Rango no válido: '$RANGE' (formato: 1-254)"
        exit 1
    fi
    echo "🔍 Escaneando red: ${BASE}.0/24 ($RANGE)"
    for i in $(seq "$START" "$END"); do
        IPS+=("${BASE}.${i}")
    done
fi

echo "────────────────────────────────────────"

mkdir -p "$OUTPUT_DIR"

FOUND=0
for IP in "${IPS[@]}"; do
    if ping -c 1 -W 1 "$IP" &>/dev/null; then
        echo "  ✅ $IP - Activo"
        echo "$IP|$(date)|ping" >> "$OUTPUT"
        FOUND=$((FOUND + 1))
        # Resolver hostname
        HOST=$(host "$IP" 2>/dev/null | head -1 | awk '{print $NF}')
        [[ -n "$HOST" ]] && echo "    ↳ $HOST"
    else
        echo "  ❌ $IP - Inactivo"
    fi
done

echo "────────────────────────────────────────"
if [[ "$FOUND" -gt 0 ]]; then
    echo "✅ $FOUND hosts activos encontrados"
    echo "📁 Resultados guardados en: $OUTPUT"
else
    echo "⚠️  No se encontraron hosts activos"
    echo "📁 Sin resultados que guardar en: $OUTPUT"
fi
