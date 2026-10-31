#!/bin/bash

# DISK FORENSICS - Análisis de discos
# Uso: ./disk_forensics.sh <DISK_IMAGE>
# Ejemplo: ./disk_forensics.sh /dev/sda1

DISK="$1"
OUTPUT_DIR="../analysis/disk"

if [[ -z "$DISK" ]]; then
    echo "Uso: ./disk_forensics.sh <DISK_IMAGE>"
    echo "Ejemplo: ./disk_forensics.sh /dev/sda1"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "💾 Analizando disco: $DISK"
echo "────────────────────────────────────────"

# 1. Información del disco
echo " → Información del disco..."
if [[ -f "$DISK" ]] || [[ -b "$DISK" ]]; then
    file "$DISK" > "$OUTPUT_DIR/disk_info.txt"
fi
sudo fdisk -l "$DISK" 2>/dev/null >> "$OUTPUT_DIR/disk_info.txt"

# 2. Sistema de archivos
echo " → Sistema de archivos..."
sudo blkid "$DISK" | tee -a "$OUTPUT_DIR/disk_info.txt"

# 3. Estructura de directorios
if [[ -b "$DISK" ]]; then
    MOUNT_POINT="/mnt/forensics_$(date +%s)"
    mkdir -p "$MOUNT_POINT"
    sudo mount "$DISK" "$MOUNT_POINT" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo " → Listando archivos..."
        sudo ls -laR "$MOUNT_POINT" > "$OUTPUT_DIR/filelist.txt"
        echo " → Archivos sensibles..."
        sudo find "$MOUNT_POINT" -type f -name "*.key" -o -name "*.pem" -o -name "*.crt" -o -name "*.pfx" > "$OUTPUT_DIR/sensitive_files.txt"
        sudo umount "$MOUNT_POINT"
        sudo rm -rf "$MOUNT_POINT"
    else
        echo " ❌ No se pudo montar el disco"
    fi
fi

# 4. Análisis con autopsy (si está instalado)
if command -v autopsy &>/dev/null; then
    echo " → Abrir con autopsy:"
    echo " autopsy $DISK"
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
