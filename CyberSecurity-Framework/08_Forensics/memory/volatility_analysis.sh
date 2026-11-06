#!/bin/bash

# VOLATILITY ANALYSIS - Análisis de memoria con Volatility
# Uso: ./volatility_analysis.sh <MEMORY_FILE>
# Ejemplo: ./volatility_analysis.sh memory.raw

MEMORY_FILE="$1"
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$MODULE_DIR/analysis/memory"

if [[ -z "$MEMORY_FILE" ]]; then
    echo "Uso: ./volatility_analysis.sh <MEMORY_FILE>"
    echo "Ejemplo: ./volatility_analysis.sh memory.raw"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔬 Analizando memoria con Volatility..."
echo "────────────────────────────────────────"
echo " ARCHIVO: $MEMORY_FILE"

if ! command -v volatility &>/dev/null; then
    echo "❌ Volatility no instalado"
    echo " Instalar con: sudo apt install volatility"
    echo " O desde: https://github.com/volatilityfoundation/volatility"
    exit 1
fi

# 1. Identificar perfil
echo " → Identificando perfil..."
volatility -f "$MEMORY_FILE" imageinfo > "$OUTPUT_DIR/imageinfo.txt"
PROFILE=$(grep -m1 "Profile" "$OUTPUT_DIR/imageinfo.txt" | awk '{print $4}')
echo " ✅ Perfil: $PROFILE"

# 2. Procesos
echo " → Listando procesos..."
volatility -f "$MEMORY_FILE" --profile="$PROFILE" pslist > "$OUTPUT_DIR/pslist.txt"
volatility -f "$MEMORY_FILE" --profile="$PROFILE" pstree > "$OUTPUT_DIR/pstree.txt"

# 3. Conexiones de red
echo " → Conexiones de red..."
volatility -f "$MEMORY_FILE" --profile="$PROFILE" netscan > "$OUTPUT_DIR/netscan.txt"

# 4. DLLs
echo " → DLLs cargados..."
volatility -f "$MEMORY_FILE" --profile="$PROFILE" dlllist > "$OUTPUT_DIR/dlllist.txt"

# 5. Comandos ejecutados
echo " → Historial de comandos..."
volatility -f "$MEMORY_FILE" --profile="$PROFILE" cmdscan > "$OUTPUT_DIR/cmdscan.txt"
volatility -f "$MEMORY_FILE" --profile="$PROFILE" consoles > "$OUTPUT_DIR/consoles.txt"

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
