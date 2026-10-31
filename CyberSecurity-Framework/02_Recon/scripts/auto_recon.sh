#!/bin/bash
# ============================================================
#  AUTO RECON - Reconocimiento completo automatizado
#  Uso: ./auto_recon.sh <IP/DOMINIO>
#  Ejemplo: ./auto_recon.sh 192.168.1.10
#  Ejemplo: ./auto_recon.sh example.com
# ============================================================

# ─── COLORES ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── VARIABLES ──────────────────────────────────────────────
TARGET="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${BASE_DIR}/recon_${TARGET}_${TIMESTAMP}"

# ─── FUNCIONES ──────────────────────────────────────────────
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_ok() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[!!]${NC} $1"
}

log_sep() {
    echo -e "${CYAN}──────────────────────────────────────────────────${NC}"
}

# ─── VALIDACIÓN ─────────────────────────────────────────────
if [[ -z "$TARGET" ]]; then
    echo "Uso: ./auto_recon.sh <IP/DOMINIO>"
    echo "Ejemplo: ./auto_recon.sh 192.168.1.10"
    echo "Ejemplo: ./auto_recon.sh example.com"
    exit 1
fi

# ─── CREAR DIRECTORIO DE SALIDA ─────────────────────────────
mkdir -p "$OUTPUT_DIR"/{host_discovery,dns,whois,screenshots,fingerprinting,scans}
cd "$OUTPUT_DIR" || exit 1

# ─── INICIO ──────────────────────────────────────────────────
clear
echo ""
echo "════════════════════════════════════════════════════════"
echo -e "${GREEN}  AUTO RECON - $TARGET${NC}"
echo "  Inicio: $(date)"
echo "  Directorio: $OUTPUT_DIR"
echo "════════════════════════════════════════════════════════"
echo ""

# ─── 1. DETECTAR TIPO DE OBJETIVO ──────────────────────────
log_info "Detectando tipo de objetivo..."

# Verificar si es IP o Dominio
if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IS_IP=true
    IS_DOMAIN=false
    log_ok "Objetivo identificado como IP: $TARGET"
    
    # Extraer red para ping sweep
    NETWORK=$(echo "$TARGET" | cut -d'.' -f1-3)
    log_info "Red detectada: ${NETWORK}.0/24"
    
else
    IS_IP=false
    IS_DOMAIN=true
    log_ok "Objetivo identificado como Dominio: $TARGET"
    
    # Resolver IP
    RESOLVED_IP=$(dig +short "$TARGET" 2>/dev/null | head -1)
    if [[ -n "$RESOLVED_IP" ]]; then
        log_ok "Resuelve a: $RESOLVED_IP"
    else
        log_warn "No se pudo resolver el dominio"
    fi
fi

echo ""

# ─── 2. PING SWEEP (si es IP) ─────────────────────────────
if [[ "$IS_IP" == true ]]; then
    log_sep
    log_info "📡 Ejecutando Ping Sweep en ${NETWORK}.0/24..."
    
    echo "  Escaneando hosts activos..."
    for i in {1..254}; do
        IP="${NETWORK}.$i"
        if ping -c 1 -W 1 "$IP" &>/dev/null; then
            echo -e "  ${GREEN}✅${NC} $IP - Activo"
            echo "$IP|$(date)|ping" >> "host_discovery/hosts_activos.txt"
        fi
    done
    
    if [[ -f "host_discovery/hosts_activos.txt" ]]; then
        TOTAL_HOSTS=$(wc -l < "host_discovery/hosts_activos.txt")
        log_ok "✅ $TOTAL_HOSTS hosts activos encontrados"
    fi
    echo ""
fi

# ─── 3. DNS ENUMERATION (si es dominio) ────────────────────
if [[ "$IS_DOMAIN" == true ]]; then
    log_sep
    log_info "🌐 Ejecutando DNS Enumeration para $TARGET..."
    
    # Registros básicos
    echo "  → Consultando registros DNS..."
    dig "$TARGET" ANY > "dns/dig_${TARGET}.txt"
    dig "$TARGET" A >> "dns/dig_${TARGET}.txt"
    dig "$TARGET" MX >> "dns/dig_${TARGET}.txt"
    dig "$TARGET" TXT >> "dns/dig_${TARGET}.txt"
    
    # Transferencia de zona
    echo "  → Intentando transferencia de zona..."
    for ns in $(dig +short NS "$TARGET" 2>/dev/null); do
        dig "@$ns" "$TARGET" AXFR 2>/dev/null > "dns/zone_transfer_${TARGET}.txt"
        if [[ -s "dns/zone_transfer_${TARGET}.txt" ]]; then
            log_warn "⚠️ Transferencia de zona POSIBLE desde $ns"
        fi
    done
    
    # Subdominios comunes
    echo "  → Buscando subdominios comunes..."
    SUBDOMAINS=("www" "mail" "ftp" "admin" "api" "dev" "test" "staging" "prod" "backup" "dns" "ns1" "ns2" "pop" "smtp" "imap" "webmail" "cpanel" "whm" "blog" "shop" "store" "app" "mobile" "remote" "vpn")
    for sub in "${SUBDOMAINS[@]}"; do
        if dig +short "$sub.$TARGET" 2>/dev/null | grep -qE '^[0-9]+'; then
            echo -e "    ${GREEN}✅${NC} $sub.$TARGET"
            echo "$sub.$TARGET|$(dig +short "$sub.$TARGET" 2>/dev/null)" >> "dns/subdominios_encontrados.txt"
        fi
    done
    
    log_ok "✅ DNS Enumeration completada"
    echo ""
fi

# ─── 4. FINGERPRINTING ─────────────────────────────────────
log_sep
log_info "🔍 Ejecutando Fingerprinting en $TARGET..."

# Escaneo de puertos y servicios
if [[ "$IS_IP" == true ]]; then
    TARGET_IP="$TARGET"
else
    TARGET_IP=$(dig +short "$TARGET" 2>/dev/null | head -1)
    if [[ -z "$TARGET_IP" ]]; then
        TARGET_IP="$TARGET"
    fi
fi

echo "  → Escaneo de puertos y servicios..."
nmap -sV -sC -O -p- --min-rate 1000 "$TARGET_IP" > "fingerprinting/nmap_${TARGET}.txt" 2>/dev/null

# Extraer información del escaneo
if [[ -f "fingerprinting/nmap_${TARGET}.txt" ]]; then
    # SO
    grep -i "OS details" "fingerprinting/nmap_${TARGET}.txt" > "fingerprinting/os_detection.txt"
    
    # Puertos abiertos
    grep "^[0-9]" "fingerprinting/nmap_${TARGET}.txt" | grep open > "fingerprinting/servicios.txt"
    
    # Puertos web abiertos para screenshots
    grep -E "^[0-9]+/tcp.*open.*http" "fingerprinting/nmap_${TARGET}.txt" | cut -d'/' -f1 > "fingerprinting/puertos_web.txt"
fi

log_ok "✅ Fingerprinting completado"
echo ""

# ─── 5. WEB SCREENSHOTS ────────────────────────────────────
log_sep
log_info "📸 Capturando screenshots web..."

if [[ -f "fingerprinting/puertos_web.txt" ]]; then
    while read -r port; do
        echo "  → Puerto $port"
        PROTO="http"
        [[ "$port" == "443" ]] && PROTO="https"
        URL="${PROTO}://${TARGET_IP}:${port}"
        
        # Intentar diferentes herramientas de captura
        if command -v cutycapt &>/dev/null; then
            cutycapt --url="$URL" --out="screenshots/${TARGET}_${port}.png" 2>/dev/null
            if [[ -f "screenshots/${TARGET}_${port}.png" ]]; then
                log_ok "    ✅ Screenshot guardado"
            fi
        elif command -v wkhtmltoimage &>/dev/null; then
            wkhtmltoimage "$URL" "screenshots/${TARGET}_${port}.png" 2>/dev/null
            if [[ -f "screenshots/${TARGET}_${port}.png" ]]; then
                log_ok "    ✅ Screenshot guardado"
            fi
        else
            log_warn "    ⚠️ No hay herramienta de captura (instalar cutycapt o wkhtmltopdf)"
        fi
    done < "fingerprinting/puertos_web.txt"
else
    log_warn "No se encontraron puertos web abiertos"
fi
echo ""

# ─── 6. SCAN DE VULNERABILIDADES (RÁPIDO) ──────────────────
log_sep
log_info "🔬 Escaneo rápido de vulnerabilidades..."

echo "  → Ejecutando scripts NSE de vulnerabilidades..."
if [[ -f "fingerprinting/puertos_web.txt" ]]; then
    PORTS=$(tr '\n' ',' < "fingerprinting/puertos_web.txt" | sed 's/,$//')
    nmap --script vuln -p "$PORTS" "$TARGET_IP" > "scans/vuln_scan.txt" 2>/dev/null
    
    # Extraer CVEs encontrados
    grep -E "CVE-[0-9]{4}-[0-9]{4,}" "scans/vuln_scan.txt" > "scans/cves_encontrados.txt"
    if [[ -s "scans/cves_encontrados.txt" ]]; then
        log_warn "⚠️ Se encontraron CVEs potenciales"
        cat "scans/cves_encontrados.txt"
    else
        log_ok "No se encontraron CVEs obvios"
    fi
fi
echo ""

# ─── 7. WHOIS (si es dominio) ─────────────────────────────
if [[ "$IS_DOMAIN" == true ]]; then
    log_sep
    log_info "📋 Consultando WHOIS para $TARGET..."
    whois "$TARGET" > "whois/whois_${TARGET}.txt" 2>/dev/null
    
    # Extraer información relevante
    grep -E "Registrar|Creation|Expir|Name Server|Registrant" "whois/whois_${TARGET}.txt" > "whois/whois_resumen_${TARGET}.txt" 2>/dev/null
    log_ok "✅ WHOIS consultado"
    echo ""
fi

# ─── 8. RESUMEN FINAL ──────────────────────────────────────
log_sep
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ AUTO RECON COMPLETADO${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo "📊 RESUMEN DE RESULTADOS:"
echo "  Objetivo: $TARGET"
echo "  IP: ${TARGET_IP:-N/A}"
echo "  Fecha: $(date)"
echo ""

# Mostrar estadísticas
if [[ -f "host_discovery/hosts_activos.txt" ]]; then
    echo "  📡 Hosts activos: $(wc -l < host_discovery/hosts_activos.txt)"
fi

if [[ -f "fingerprinting/servicios.txt" ]]; then
    echo "  🔌 Puertos abiertos: $(wc -l < fingerprinting/servicios.txt)"
fi

if [[ -f "fingerprinting/os_detection.txt" ]]; then
    echo "  💻 SO detectado: $(cat fingerprinting/os_detection.txt)"
fi

if [[ -f "scans/cves_encontrados.txt" ]]; then
    echo "  🚨 CVEs potenciales: $(wc -l < scans/cves_encontrados.txt)"
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
echo ""
echo "Para ver la estructura: tree -L 2 \"$OUTPUT_DIR\""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"