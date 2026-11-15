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
FRAMEWORK_DIR="$(cd "$MODULE_DIR/.." && pwd)"
LIB="$FRAMEWORK_DIR/00_Config/lib"
OUTPUT_DIR="$MODULE_DIR/host_discovery"
OUTPUT="$OUTPUT_DIR/ping_sweep_$(date +%Y%m%d).txt"

# Parseo previo: no crear salida si el objetivo/rango es inválido.
_RCFILE="$(mktemp)" || exit 1
mapfile -t IPS < <(python3 -I -B "$LIB/recon_targets.py" "$NETWORK" "$RANGE"; rc=$?; printf '%s\n' "$rc" > "$_RCFILE"; exit "$rc")
PARSE_RC="$(cat "$_RCFILE" 2>/dev/null)"
rm -f "$_RCFILE"
if [[ "$PARSE_RC" != "0" || ${#IPS[@]} -eq 0 ]]; then
    echo "❌ Objetivo o rango no válido: '$NETWORK' ${RANGE:+($RANGE)}"
    exit 1
fi

if ! command -v ping >/dev/null 2>&1; then
    echo "❌ 'ping' no está disponible en el sistema"
    exit 1
fi

DISPLAY_NETWORK="$NETWORK"
if [[ "$NETWORK" == */24 ]]; then
    DISPLAY_NETWORK="${NETWORK%.*}.0/24"
fi
echo "🔍 Escaneando: $DISPLAY_NETWORK ${RANGE:+($RANGE)}"
echo "────────────────────────────────────────"

if ! mkdir -p "$OUTPUT_DIR"; then
    echo "❌ No se pudo preparar el directorio de resultados" >&2
    exit 1
fi

FOUND=0
BACKEND_ERROR=0
for IP in "${IPS[@]}"; do
    ping -c 1 -W 1 "$IP" >/dev/null 2>&1
    PING_RC=$?
    if [[ "$PING_RC" -eq 0 ]]; then
        if ! printf '%s|%s|ping\n' "$IP" "$(date)" >> "$OUTPUT"; then
            echo "❌ No se pudo guardar el resultado de esta ejecución" >&2
            exit 1
        fi
        echo "  ✅ $IP - Activo"
        FOUND=$((FOUND + 1))
        # Resolver hostname
        HOST=$(host "$IP" 2>/dev/null | head -1 | awk '{print $NF}')
        [[ -n "$HOST" ]] && echo "    ↳ $HOST"
    elif [[ "$PING_RC" -ne 1 ]]; then
        echo "  ⚠️  $IP - Error de backend ping (rc=$PING_RC)"
        BACKEND_ERROR=1
    else
        echo "  ❌ $IP - Inactivo"
    fi
done

echo "────────────────────────────────────────"
if [[ "$BACKEND_ERROR" -ne 0 ]]; then
    echo "❌ Error de backend durante el barrido"
    exit 1
fi
if [[ "$FOUND" -gt 0 ]]; then
    echo "✅ $FOUND hosts activos encontrados en esta ejecución"
    echo "📁 Archivo diario acumulado (incluye históricos): $OUTPUT"
else
    echo "⚠️  No se encontraron hosts activos"
    echo "📁 Sin resultados que guardar en: $OUTPUT"
fi
