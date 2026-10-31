#!/bin/bash
# ============================================================
#  NMAP SMART SCAN - Escaneo inteligente
#  Uso: ./nmap_smart.sh <IP>
#  Ejemplo: ./nmap_smart.sh 192.168.1.10
# ============================================================

TARGET="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/nmap"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./nmap_smart.sh <IP>"
    echo "Ejemplo: ./nmap_smart.sh 192.168.1.10"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "📡 Escaneo inteligente de: $TARGET"

# Fase 1: Puertos abiertos (usando -Pn para evitar problemas de ping)
echo "  Fase 1: Descubriendo puertos..."
nmap -Pn -p- --min-rate 2000 -T4 "$TARGET" -oA "$OUTPUT_DIR/smart_ports" 2>/dev/null

# Extraer puertos
if [[ -f "$OUTPUT_DIR/smart_ports.nmap" ]]; then
    OPEN_PORTS=$(grep open "$OUTPUT_DIR/smart_ports.nmap" 2>/dev/null | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
else
    OPEN_PORTS=""
fi

if [[ -n "$OPEN_PORTS" ]]; then
    echo "  ✅ Puertos encontrados: $OPEN_PORTS"
    
    # Fase 2: Servicios y versiones
    echo "  Fase 2: Detectando servicios..."
    nmap -Pn -sV -sC -O -p "$OPEN_PORTS" "$TARGET" -oA "$OUTPUT_DIR/smart_services" 2>/dev/null
    
    # Fase 3: Scripts de vulnerabilidad
    echo "  Fase 3: Escaneando vulnerabilidades..."
    nmap --script vuln -p "$OPEN_PORTS" "$TARGET" -oA "$OUTPUT_DIR/smart_vuln" 2>/dev/null
    
    echo ""
    echo "✅ Escaneo completado"
    echo "📁 Resultados: $OUTPUT_DIR/smart_*"
else
    echo "  ⚠️ No se encontraron puertos abiertos"
    echo ""
    echo "  💡 Sugerencia: Si estás escaneando localhost,"
    echo "     asegúrate de tener servicios corriendo:"
    echo "     - sudo systemctl start ssh  (puerto 22)"
    echo "     - sudo systemctl start apache2 (puerto 80)"
fi
