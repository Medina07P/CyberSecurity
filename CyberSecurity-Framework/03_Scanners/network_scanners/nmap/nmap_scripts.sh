#!/bin/bash
# NMAP SCRIPTS — NSE únicamente sobre los puertos elegidos.
# Uso: ./nmap_scripts.sh <IP> [PUERTOS]
# Ejemplo: ./nmap_scripts.sh 192.0.2.1 80,443
TARGET="${1:-}"
PORTS="${2:-80,443,445,3306,8080}"
SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scanner_runtime.bash"
[[ -n "$TARGET" ]] || { echo 'Uso: ./nmap_scripts.sh <IP> [PUERTOS]'; exit 1; }
scanner_host "$TARGET" && scanner_ports "$PORTS" && scanner_require nmap || exit 1
OUTPUT_DIR=$(scans_dir nmap/scripts) || exit 1
SLUG=$(scans_slug "$TARGET")
# Los patrones llevan comodín: smb-enum no es el nombre de un script NSE.
CATEGORIES=('vuln' 'smb-enum*' 'http-enum' 'ftp-anon' 'rdp-enum*')
NAMES=('vuln' 'smb-enum' 'http-enum' 'ftp-anon' 'rdp-enum')
for i in "${!CATEGORIES[@]}"; do
    scanner_run "$OUTPUT_DIR/errores.log" nmap -Pn --script "${CATEGORIES[$i]}" \
        -p "$PORTS" "$TARGET" -oN "$OUTPUT_DIR/${NAMES[$i]}_${SLUG}.txt" || exit 1
done
scanner_run "$OUTPUT_DIR/errores.log" nmap -Pn --script smb-os-discovery,smb-security-mode,smtp-commands \
    -p "$PORTS" "$TARGET" -oN "$OUTPUT_DIR/specific_${SLUG}.txt" || exit 1
echo "✅ Scripts ejecutados en puertos $PORTS. Resultados: $OUTPUT_DIR"
