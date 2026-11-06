#!/bin/bash

# LOG ANALYZER - Analiza logs del sistema
# Uso: ./log_analyzer.sh <LOG_FILE>
# Ejemplo: ./log_analyzer.sh /var/log/syslog

LOG_FILE="$1"
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$MODULE_DIR/analysis/logs"

if [[ -z "$LOG_FILE" ]]; then
    echo "Uso: ./log_analyzer.sh <LOG_FILE>"
    echo "Ejemplo: ./log_analyzer.sh /var/log/syslog"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "📋 Analizando logs: $LOG_FILE"
echo "────────────────────────────────────────"

# 1. Estadísticas generales
echo " → Estadísticas:"
echo "Total líneas: $(wc -l < "$LOG_FILE")" > "$OUTPUT_DIR/stats.txt"

# 2. Niveles de log
echo " → Niveles de log:"
grep -E "ERROR|WARNING|INFO|DEBUG" "$LOG_FILE" > "$OUTPUT_DIR/levels.txt"

# 3. Errores
echo " → Errores:"
grep -i "error" "$LOG_FILE" > "$OUTPUT_DIR/errors.txt"
echo "Total errores: $(wc -l < "$OUTPUT_DIR/errors.txt")"

# 4. Eventos de autenticación
echo " → Autenticaciones:"
grep -E "authentication|login|auth|password" "$LOG_FILE" > "$OUTPUT_DIR/auth.txt"

# 5. Conexiones SSH
echo " → Conexiones SSH:"
grep -E "sshd|ssh" "$LOG_FILE" > "$OUTPUT_DIR/ssh.txt"

# 6. Patrones de IPs
echo " → IPs sospechosas:"
grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$LOG_FILE" > "$OUTPUT_DIR/ips.txt"

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
