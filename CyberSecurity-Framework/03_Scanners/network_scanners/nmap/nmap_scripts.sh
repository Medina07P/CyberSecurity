#!/bin/bash
# ============================================================
#  NMAP SCRIPTS - Ejecución de scripts NSE específicos
#  Uso: ./nmap_scripts.sh <IP> [PUERTOS]
#  Ejemplo: ./nmap_scripts.sh 192.168.1.10 80,443
# ============================================================

TARGET="$1"
PORTS="${2:-80,443,445,3306,8080}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/nmap/scripts"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./nmap_scripts.sh <IP> [PUERTOS]"
    echo "Ejemplo: ./nmap_scripts.sh 192.168.1.10 80,443"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# El log es de este run: sin truncar, el error de hace un mes sigue ahí y
# todas las ejecuciones posteriores avisan sin motivo real.
: > "$OUTPUT_DIR/errores.log"

echo "📜 Ejecutando scripts NSE en: $TARGET"

# Categorías de scripts
CATEGORIES=("vuln" "smb-enum" "http-enum" "ftp-anon" "rdp-enum")

for category in "${CATEGORIES[@]}"; do
    echo "  → Scripts: $category"
    nmap --script "$category" -p "$PORTS" "$TARGET" \
        -oN "$OUTPUT_DIR/${category}_${TARGET}.txt" 2>>"$OUTPUT_DIR/errores.log"
done

# Scripts específicos
echo "  → Scripts específicos..."
nmap --script smb-os-discovery,smb-security-mode,smtp-commands \
    -p 445,25 "$TARGET" \
    -oN "$OUTPUT_DIR/specific_${TARGET}.txt" 2>>"$OUTPUT_DIR/errores.log"

echo "✅ Scripts ejecutados"
echo "📁 Resultados: $OUTPUT_DIR"

# El stderr de la herramienta no se descarta: un "0 hallazgos" no debe
# poder ser en realidad un fallo de ejecucion.
if [[ -s "$OUTPUT_DIR/errores.log" ]]; then
    echo "⚠️  Errores registrados en: $OUTPUT_DIR/errores.log"
fi
