#!/bin/bash

# ─── VALIDATE_CONFIG.SH ─────────────────────────────────────
# Valida que todos los archivos de configuración existan
# Ubicación: 00_Config/scripts/validate_config.sh

# Obtener la ruta del directorio del módulo (subir un nivel desde scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")"  # Esto da 00_Config/

echo "🔍 Validando configuración..."
echo "📂 Directorio base: $CONFIG_DIR"
echo ""

# Lista de archivos requeridos
REQUIRED_FILES=(
    "README.md"
    "scope.yaml"
    "targets.txt"
)

# Lista de directorios requeridos
REQUIRED_DIRS=(
    "wordlists"
    "credentials"
    "scripts"
)

# Archivos dentro de wordlists que debe tener
WORDLIST_FILES=(
    "custom.lst"
    "users.txt"
    "passwords.txt"
    "directories.txt"
)

# Variables para errores
ERROR_COUNT=0

# Verificar archivos en la raíz
echo "📁 Verificando archivos en la raíz..."
for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$CONFIG_DIR/$file" ]]; then
        echo "  ✅ $file encontrado"
    else
        echo "  ❌ $file NO encontrado"
        ((ERROR_COUNT++))
    fi
done

echo ""
echo "📁 Verificando directorios..."
for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ -d "$CONFIG_DIR/$dir" ]]; then
        echo "  ✅ $dir/ encontrado"
    else
        echo "  ❌ $dir/ NO encontrado"
        ((ERROR_COUNT++))
    fi
done

echo ""
echo "📁 Verificando archivos en wordlists/..."
for file in "${WORDLIST_FILES[@]}"; do
    if [[ -f "$CONFIG_DIR/wordlists/$file" ]]; then
        LINES=$(wc -l < "$CONFIG_DIR/wordlists/$file" 2>/dev/null || echo "0")
        echo "  ✅ wordlists/$file ($LINES líneas)"
    else
        echo "  ❌ wordlists/$file NO encontrado"
        ((ERROR_COUNT++))
    fi
done

echo ""
echo "📁 Verificando scripts..."
if [[ -d "$CONFIG_DIR/scripts" ]]; then
    for script in "$CONFIG_DIR/scripts"/*.sh "$CONFIG_DIR/scripts"/*.py; do
        if [[ -f "$script" ]]; then
            name=$(basename "$script")
            echo "  ✅ scripts/$name"
        fi
    done
fi

echo ""
echo "════════════════════════════════════════════════════════"
if [[ $ERROR_COUNT -eq 0 ]]; then
    echo "✅ Validación completada - TODO OK ($ERROR_COUNT errores)"
else
    echo "❌ Validación completada - $ERROR_COUNT ERRORES encontrados"
fi
echo "════════════════════════════════════════════════════════"
