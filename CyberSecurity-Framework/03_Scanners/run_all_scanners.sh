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

    # Un escaneo por puerto detectado, con el esquema correcto: nunca asumir el 80.
    for WEB_PORT in ${WEB_PORTS//,/ }; do
        WEB_SCHEME="http"
        [[ "$WEB_PORT" == "443" || "$WEB_PORT" == "8443" ]] && WEB_SCHEME="https"
        WEB_URL="${WEB_SCHEME}://${TARGET}:${WEB_PORT}"

        # Nikto
        echo "  → Nikto ($WEB_URL)..."
        if [[ -f "web_scanners/nikto/nikto_scan.sh" ]]; then
            ./web_scanners/nikto/nikto_scan.sh "$WEB_URL"
        else
            echo "  ⚠️ nikto_scan.sh no encontrado"
        fi

        # Nuclei
        echo "  → Nuclei ($WEB_URL)..."
        if [[ -f "web_scanners/nuclei/nuclei_scan.sh" ]]; then
            ./web_scanners/nuclei/nuclei_scan.sh "$WEB_URL"
        else
            echo "  ⚠️ nuclei_scan.sh no encontrado"
        fi
    done
else
    echo "  ⚠️ No se encontraron puertos web abiertos"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ ESCANEOS COMPLETADOS"
echo "════════════════════════════════════════════════════════"

# ─── Resumen de errores ──────────────────────────────────
# Un "0 hallazgos" puede ser en realidad un fallo de ejecución: cada escáner
# escribe su stderr en <scans>/<herramienta>/errores.log. Se listan aquí los
# que quedaron con contenido para no cerrar el run dando por buenos los vacíos.
LOGS_ERRORES=()
for log in "$SCANS_DIR"/*/errores.log "$SCANS_DIR"/*/*/errores.log; do
    [[ -s "$log" ]] || continue
    LOGS_ERRORES+=("$log")
done

if (( ${#LOGS_ERRORES[@]} )); then
    echo ""
    echo "📋 LOGS CON ERRORES"
    echo "────────────────────────────────────────"
    for log in "${LOGS_ERRORES[@]}"; do
        N=$(wc -l < "$log" 2>/dev/null | tr -d ' ')
        [[ "$N" == "1" ]] && UNIDAD="línea" || UNIDAD="líneas"
        echo "  ⚠️  $log ($N $UNIDAD)"
    done
    echo "  Revisa esos logs antes de dar por buenos los resultados vacíos."
fi
