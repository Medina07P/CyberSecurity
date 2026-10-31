#!/bin/bash

# TIMELINE CREATOR - Crea línea de tiempo de eventos
# Uso: ./timeline_creator.sh [OUTPUT_DIR]
# Ejemplo: ./timeline_creator.sh

OUTPUT_DIR="${1:-../analysis/timeline}"
DATE=$(date +%Y%m%d)

mkdir -p "$OUTPUT_DIR"

echo "📅 Creando línea de tiempo..."
echo "────────────────────────────────────────"

# 1. Eventos del sistema
echo " → Eventos del sistema..."
echo "=== SISTEMA ===" > "$OUTPUT_DIR/timeline_$DATE.txt"
journalctl --since "24 hours ago" 2>/dev/null | head -100 >> "$OUTPUT_DIR/timeline_$DATE.txt"

# 2. Eventos de autenticación
echo " → Autenticaciones..."
echo "=== AUTENTICACIONES ===" >> "$OUTPUT_DIR/timeline_$DATE.txt"
last -a | head -20 >> "$OUTPUT_DIR/timeline_$DATE.txt"

# 3. Conexiones SSH
echo " → Conexiones SSH..."
echo "=== SSH ===" >> "$OUTPUT_DIR/timeline_$DATE.txt"
grep "sshd" /var/log/auth.log 2>/dev/null | tail -20 >> "$OUTPUT_DIR/timeline_$DATE.txt"

# 4. Cambios en archivos
echo " → Archivos modificados..."
echo "=== ARCHIVOS MODIFICADOS ===" >> "$OUTPUT_DIR/timeline_$DATE.txt"
find / -type f -mtime -1 2>/dev/null | head -20 >> "$OUTPUT_DIR/timeline_$DATE.txt"

# 5. Instalaciones de paquetes
echo " → Paquetes instalados..."
echo "=== PAQUETES ===" >> "$OUTPUT_DIR/timeline_$DATE.txt"
grep "install" /var/log/dpkg.log 2>/dev/null | tail -10 >> "$OUTPUT_DIR/timeline_$DATE.txt"

echo ""
echo "📁 Línea de tiempo guardada en: $OUTPUT_DIR/timeline_$DATE.txt"
