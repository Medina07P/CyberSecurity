#!/bin/bash
# NMAP SMART — puertos, servicios y NSE (perfil completo).
# Uso: ./nmap_smart.sh <IP> [perfil]
# Ejemplo: ./nmap_smart.sh 192.0.2.1 completo
# perfil: basico (100 puertos, sin NSE) o completo (por defecto).
TARGET="${1:-}"
PROFILE="${2:-completo}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
if [[ -z "$TARGET" ]]; then
    echo 'Uso: ./nmap_smart.sh <IP> [perfil]'
    exit 1
fi
case "$PROFILE" in basico|completo) ;; *) echo '❌ Perfil no válido: basico o completo.' >&2; exit 1 ;; esac
scanner_host "$TARGET" && scanner_require nmap || exit 1
OUTPUT_DIR=$(scans_dir nmap) || exit 1
SLUG=$(scans_slug "$TARGET")
LOG="$OUTPUT_DIR/errores.log"
if [[ "$PROFILE" == basico ]]; then
    echo "📡 Perfil básico: $TARGET; 100 puertos TCP, servicios ligeros; sin NSE."
    scanner_run "$LOG" nmap -Pn -sV --version-light --top-ports 100 "$TARGET" \
        -oA "$OUTPUT_DIR/basic_${SLUG}" || exit 1
    echo "✅ Ejecución completada. Resultados: $OUTPUT_DIR/basic_${SLUG}.*"
    exit 0
fi
echo "📡 Escaneo inteligente completo de: $TARGET (todos los puertos y NSE vuln)"
# Extraer solo resultados recién generados, nunca el archivo del run anterior.
WORK=$(mktemp -d "$OUTPUT_DIR/.smart.XXXXXX") || exit 1
trap 'rm -f "$WORK/ports.nmap" "$WORK/ports.gnmap" "$WORK/ports.xml"; rmdir "$WORK" 2>/dev/null' EXIT
scanner_run "$LOG" nmap -Pn -p- --min-rate 2000 -T4 "$TARGET" -oA "$WORK/ports" || exit 1
[[ -f "$WORK/ports.nmap" ]] || { echo '❌ Nmap no produjo salida nueva. NO DETERMINADO.' >&2; exit 1; }
OPEN_PORTS=$(awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {split($1,p,"/"); printf "%s%s",sep,p[1]; sep=","}' "$WORK/ports.nmap")
for ext in nmap gnmap xml; do
    [[ ! -f "$WORK/ports.$ext" ]] || mv "$WORK/ports.$ext" "$OUTPUT_DIR/smart_ports_${SLUG}.$ext" || exit 1
done
if [[ -z "$OPEN_PORTS" ]]; then
    echo 'No se encontraron puertos TCP abiertos en esta ejecución.'
    exit 0
fi
echo "Puertos abiertos: $OPEN_PORTS"
scanner_run "$LOG" nmap -Pn -sV -sC -O -p "$OPEN_PORTS" "$TARGET" -oA "$OUTPUT_DIR/smart_services_${SLUG}" || exit 1
scanner_run "$LOG" nmap -Pn --script vuln -p "$OPEN_PORTS" "$TARGET" -oA "$OUTPUT_DIR/smart_vuln_${SLUG}" || exit 1
echo "✅ Escaneo completado. Resultados: $OUTPUT_DIR/smart_*_${SLUG}"
