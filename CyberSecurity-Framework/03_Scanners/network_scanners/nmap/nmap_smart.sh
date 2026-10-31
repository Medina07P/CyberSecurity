#!/bin/bash
# ============================================================
#  NMAP SMART SCAN - Escaneo inteligente
#  Uso: ./nmap_smart.sh <IP>
#  Ejemplo: ./nmap_smart.sh 192.168.1.10
# ============================================================

TARGET="$1"

SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scans.bash"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./nmap_smart.sh <IP>"
    echo "Ejemplo: ./nmap_smart.sh 192.168.1.10"
    exit 1
fi

OUTPUT_DIR=$(scans_dir nmap)
SLUG=$(scans_slug "$TARGET")

echo "📡 Escaneo inteligente de: $TARGET"

# Fase 1: Puertos abiertos (usando -Pn para evitar problemas de ping)
echo "  Fase 1: Descubriendo puertos..."
nmap -Pn -p- --min-rate 2000 -T4 "$TARGET" -oA "$OUTPUT_DIR/smart_ports_${SLUG}" 2>>"$OUTPUT_DIR/errores.log"

# Extraer puertos
if [[ -f "$OUTPUT_DIR/smart_ports_${SLUG}.nmap" ]]; then
    OPEN_PORTS=$(grep open "$OUTPUT_DIR/smart_ports_${SLUG}.nmap" 2>/dev/null | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
else
    OPEN_PORTS=""
fi

if [[ -n "$OPEN_PORTS" ]]; then
    echo "  ✅ Puertos encontrados: $OPEN_PORTS"
    
    # Fase 2: Servicios y versiones
    echo "  Fase 2: Detectando servicios..."
    nmap -Pn -sV -sC -O -p "$OPEN_PORTS" "$TARGET" -oA "$OUTPUT_DIR/smart_services_${SLUG}" 2>>"$OUTPUT_DIR/errores.log"
    
    # Fase 3: Scripts de vulnerabilidad
    echo "  Fase 3: Escaneando vulnerabilidades..."
    nmap --script vuln -p "$OPEN_PORTS" "$TARGET" -oA "$OUTPUT_DIR/smart_vuln_${SLUG}" 2>>"$OUTPUT_DIR/errores.log"
    
    echo ""
    echo "✅ Escaneo completado"
    echo "📁 Resultados: $OUTPUT_DIR/smart_*_${SLUG}"
else
    echo "  ⚠️ No se encontraron puertos abiertos"
    echo ""
    echo "  💡 Sugerencia: Si estás escaneando localhost,"
    echo "     asegúrate de tener servicios corriendo:"
    echo "     - sudo systemctl start ssh  (puerto 22)"
    echo "     - sudo systemctl start apache2 (puerto 80)"
fi

# El stderr de la herramienta no se descarta: un "0 hallazgos" no debe
# poder ser en realidad un fallo de ejecucion.
if [[ -s "$OUTPUT_DIR/errores.log" ]]; then
    echo "⚠️  Errores registrados en: $OUTPUT_DIR/errores.log"
fi
