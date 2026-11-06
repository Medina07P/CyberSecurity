#!/bin/bash

# ============================================================
# AUTO CAPTURE - Captura automática de evidencias
# Uso: ./auto_capture.sh <TARGET>
# Ejemplo: ./auto_capture.sh 192.168.1.10
# ============================================================

TARGET="$1"
DATE=$(date +%Y%m%d_%H%M%S)

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./auto_capture.sh <TARGET>"
    echo "Ejemplo: ./auto_capture.sh 192.168.1.10"
    exit 1
fi

echo "📸 Capturando evidencias de: $TARGET"
echo "════════════════════════════════════════════════════════"

# Todo se guarda junto al módulo, no en el cwd desde el que se lance
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

# 1. Captura de pantalla web
echo "  → Capturando pantalla web..."
if command -v cutycapt &>/dev/null; then
    mkdir -p screenshots/web
    cutycapt --url="http://${TARGET}" --out="screenshots/web/${TARGET}_${DATE}.png" 2>/dev/null
    echo "  ✅ Screenshot web guardado"
else
    echo "  ⚠️  cutycapt no disponible, omitiendo screenshot web"
fi

# 2. Captura de tráfico
echo "  → Capturando tráfico de red..."
mkdir -p pcaps/traffic
timeout 10 tcpdump -c 100 -i any host "$TARGET" -w "pcaps/traffic/${TARGET}_${DATE}.pcap" 2>/dev/null
if [[ -f "pcaps/traffic/${TARGET}_${DATE}.pcap" ]]; then
    echo "  ✅ Captura de tráfico guardada"
else
    echo "  ⚠️  No se pudo capturar tráfico (requiere permisos de root)"
fi

# 3. Logs de escaneo
echo "  → Guardando logs de escaneo..."
mkdir -p logs/results
nmap -sV -p- --min-rate 1000 "$TARGET" -oN "logs/results/${TARGET}_${DATE}.txt" 2>/dev/null
echo "  ✅ Logs de escaneo guardados"

# 4. Información del sistema
echo "  → Guardando información del sistema..."
mkdir -p logs/audit
{
    echo "TARGET: $TARGET"
    echo "DATE: $(date)"
    echo "USER: $(whoami)"
    echo "HOSTNAME: $(hostname)"
    echo "OS: $(uname -a)"
} > "logs/audit/system_${DATE}.txt"
echo "  ✅ Información del sistema guardada"

echo ""
echo "✅ Captura completada"
echo "📁 Evidencias guardadas en: $(pwd)"
