#!/bin/bash
# ============================================================
#  VERIFY_00_CONFIG.sh - Verificación PORTABLE
#  Funciona desde cualquier ubicación
#  Uso: ./scripts/verify_00_config.sh
# ============================================================

# ─── OBTENER RUTA ABSOLUTA ─────────────────────────────────
# Obtiene la ruta REAL donde está este script
SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")"

echo "════════════════════════════════════════════════════════"
echo "  VERIFICANDO 00_CONFIG"
echo "  Ruta del script: $SCRIPT_DIR"
echo "  Ruta de CONFIG: $CONFIG_DIR"
echo "════════════════════════════════════════════════════════"

# ─── FUNCIÓN PARA VERIFICAR ARCHIVOS ──────────────────────
check_file() {
    if [[ -f "$CONFIG_DIR/$1" ]]; then
        echo "  ✅ OK: $1"
        return 0
    else
        echo "  ❌ FALTA: $1"
        return 1
    fi
}

check_file_in() {
    if [[ -f "$CONFIG_DIR/$1/$2" ]]; then
        echo "  ✅ OK: $1/$2"
        return 0
    else
        echo "  ❌ FALTA: $1/$2"
        return 1
    fi
}

# ─── EJECUTAR VERIFICACIONES ──────────────────────────────

echo ""
echo "📁 Archivos en raíz de 00_Config:"
check_file "README.md"
check_file "scope.yaml"
check_file "targets.txt"
check_file ".gitignore"

echo ""
echo "📁 wordlists/:"
check_file_in "wordlists" "custom.lst"
check_file_in "wordlists" "users.txt"
check_file_in "wordlists" "passwords.txt"
check_file_in "wordlists" "directories.txt"

echo ""
echo "📁 credentials/:"
check_file_in "credentials" "README.md"
check_file_in "credentials" ".gitkeep"

echo ""
echo "📁 scripts/:"
check_file_in "scripts" "validate_config.sh"
check_file_in "scripts" "parse_targets.py"
check_file_in "scripts" "verify_00_config.sh"

echo ""
echo "────────────────────────────────────────────────────────"

# ─── ESTADÍSTICAS ──────────────────────────────────────────

TOTAL_FILES=$(find "$CONFIG_DIR" -type f \( -name "*.txt" -o -name "*.yaml" -o -name "*.md" -o -name "*.sh" -o -name "*.py" -o -name ".gitignore" -o -name ".gitkeep" \) 2>/dev/null | wc -l)
echo "📊 Total archivos en 00_Config: $TOTAL_FILES"

echo ""
echo "📊 Estadísticas de wordlists:"
for f in custom.lst users.txt passwords.txt directories.txt; do
    if [[ -f "$CONFIG_DIR/wordlists/$f" ]]; then
        LINES=$(wc -l < "$CONFIG_DIR/wordlists/$f" 2>/dev/null)
        echo "  📄 $f: $LINES líneas"
    fi
done

echo ""
echo "✅ Verificación completada"

# ─── MOSTRAR RUTA COMPLETA ─────────────────────────────────
echo ""
echo "📂 Ruta completa: $CONFIG_DIR"
