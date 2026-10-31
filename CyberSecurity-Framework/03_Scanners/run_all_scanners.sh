#!/bin/bash
# ============================================================
#  RUN ALL SCANNERS - Ejecuta todos los escáneres
#  Uso: ./run_all_scanners.sh <TARGET>
#  Ejemplo: ./run_all_scanners.sh 192.168.1.10
# ============================================================

TARGET="$1"

# Los hijos se invocan con rutas relativas: ejecutar desde este directorio.
# Los resultados van siempre a <repo>/scans/, se lance desde donde se lance.
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scans"
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./run_all_scanners.sh <TARGET>"
    echo "Ejemplo: ./run_all_scanners.sh 192.168.1.10"
    exit 1
fi

echo "════════════════════════════════════════════════════════"
echo "  EJECUTANDO TODOS LOS ESCÁNERES PARA: $TARGET"
echo "════════════════════════════════════════════════════════"

# ─── Network Scanners ────────────────────────────────────
echo ""
echo "📡 NETWORK SCANNERS"
echo "────────────────────────────────────────"

# Nmap (usando ruta relativa correcta)
echo "  → Nmap Smart..."
if [[ -f "network_scanners/nmap/nmap_smart.sh" ]]; then
    ./network_scanners/nmap/nmap_smart.sh "$TARGET"
else
    echo "  ⚠️ nmap_smart.sh no encontrado, usando nmap básico..."
    mkdir -p "$SCANS_DIR/nmap"
    nmap -sV -sC -p- --min-rate 1000 "$TARGET" -oN "$SCANS_DIR/nmap/basic_${TARGET}.txt" 2>/dev/null
fi

# Masscan (solo si es IP)
if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "  → Masscan..."
    if [[ -f "network_scanners/masscan/masscan_scan.sh" ]]; then
        ./network_scanners/masscan/masscan_scan.sh "$TARGET" 1-65535
    else
        echo "  ⚠️ masscan_scan.sh no encontrado"
    fi
fi

# ─── Web Scanners ────────────────────────────────────────
echo ""
echo "🌐 WEB SCANNERS"
echo "────────────────────────────────────────"

# Verificar si hay puertos web abiertos
WEB_PORTS=$(nmap -p 80,443,8080,8443 "$TARGET" 2>/dev/null | grep -E "^[0-9]+/tcp.*open" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

if [[ -n "$WEB_PORTS" ]]; then
    echo "  → Puertos web abiertos: $WEB_PORTS"
    
    # Nikto
    echo "  → Nikto..."
    if [[ -f "web_scanners/nikto/nikto_scan.sh" ]]; then
        ./web_scanners/nikto/nikto_scan.sh "http://$TARGET"
    else
        echo "  ⚠️ nikto_scan.sh no encontrado"
    fi
    
    # Nuclei
    echo "  → Nuclei..."
    if [[ -f "web_scanners/nuclei/nuclei_scan.sh" ]]; then
        ./web_scanners/nuclei/nuclei_scan.sh "http://$TARGET"
    else
        echo "  ⚠️ nuclei_scan.sh no encontrado"
    fi
else
    echo "  ⚠️ No se encontraron puertos web abiertos"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ ESCANEOS COMPLETADOS"
echo "════════════════════════════════════════════════════════"
