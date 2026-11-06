#!/bin/bash

# ============================================================
# EVIDENCE MANAGER - Gestión de evidencias
# Uso: ./evidence_manager.sh [COMANDO] [OPCIONES]
# Ejemplo: ./evidence_manager.sh --add screenshot web_login.png
# ============================================================

EVIDENCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$EVIDENCE_DIR" || exit 1
DATE=$(date +%Y%m%d_%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

add_evidence() {
    local type="$1"
    local file="$2"
    local description="$3"

    if [[ -z "$type" || -z "$file" ]]; then
        echo "Uso: ./evidence_manager.sh --add <TIPO> <ARCHIVO> [DESCRIPCION]"
        echo "Tipos: screenshot, pcap, credential, finding, proof"
        return 1
    fi

    case "$type" in
        screenshot) dest="screenshots/web" ;;
        pcap)       dest="pcaps/traffic" ;;
        credential) dest="credentials/found" ;;
        finding)    dest="findings/vulnerabilities" ;;
        proof)      dest="proofs/access" ;;
        *)
            echo "❌ Tipo no válido: $type"
            return 1
            ;;
    esac

    mkdir -p "$dest"

    if [[ -f "$file" ]]; then
        local new_name="${DATE}_$(basename "$file")"
        cp "$file" "$dest/$new_name"
        echo "✅ Evidencia añadida: $dest/$new_name"

        cat > "$dest/${new_name}.meta" << EOF
TYPE: $type
DATE: $(date)
FILE: $new_name
DESCRIPTION: ${description:-Sin descripción}
HASH: $(md5sum "$dest/$new_name" | cut -d' ' -f1)
USER: $(whoami)
EOF
        echo "📝 Metadatos guardados: $dest/${new_name}.meta"
    else
        echo "❌ Archivo no encontrado: $file"
        return 1
    fi
}

verify_evidence() {
    echo "🔍 Verificando integridad de evidencias..."
    echo "════════════════════════════════════════════════════════"

    local errors=0

    find . -name "*.meta" | while read -r meta; do
        local dir
        dir=$(dirname "$meta")
        local file
        file=$(grep "FILE:" "$meta" | cut -d' ' -f2)
        local hash
        hash=$(grep "HASH:" "$meta" | cut -d' ' -f2)

        if [[ -f "$dir/$file" ]]; then
            local current_hash
            current_hash=$(md5sum "$dir/$file" | cut -d' ' -f1)
            if [[ "$current_hash" == "$hash" ]]; then
                echo "✅ $dir/$file - OK"
            else
                echo "❌ $dir/$file - HASH MODIFICADO"
                errors=$((errors + 1))
            fi
        else
            echo "❌ $dir/$file - NO ENCONTRADO"
            errors=$((errors + 1))
        fi
    done

    if [[ $errors -eq 0 ]]; then
        echo "✅ Todas las evidencias están íntegras"
    else
        echo "⚠️  Se encontraron $errors problemas"
    fi
}

list_evidence() {
    echo "📋 Listando evidencias..."
    echo "════════════════════════════════════════════════════════"

    for dir in screenshots pcaps credentials findings proofs logs; do
        if [[ -d "$dir" ]]; then
            echo ""
            echo "📁 $dir/"
            find "$dir" -type f ! -name "*.meta" | head -10 | sed 's/^/  /'
            local count
            count=$(find "$dir" -type f ! -name "*.meta" | wc -l)
            echo "  Total: $count archivos"
        fi
    done
}

package_evidence() {
    local name="${1:-$(date +%Y%m%d)_evidence}"
    local output="../11_Reports/evidence/${name}.tar.gz"

    mkdir -p "../11_Reports/evidence"

    echo "📦 Empaquetando evidencias..."
    echo "  → $output"

    cat > "manifest.txt" << EOF
EVIDENCE PACKAGE: $name
DATE: $(date)
USER: $(whoami)
TOTAL FILES: $(find . -type f ! -name "*.meta" | wc -l)
SIZE: $(du -sh . | cut -f1)

CONTENTS:
$(find . -type f ! -name "*.meta" | sed 's/^/  /')
EOF

    tar -czf "$output" --exclude="*.meta" . 2>/dev/null

    if [[ -f "$output" ]]; then
        echo "✅ Paquete creado: $output"
        echo "📏 Tamaño: $(du -h "$output" | cut -f1)"
        rm manifest.txt
    else
        echo "❌ Error al crear el paquete"
    fi
}

show_help() {
    echo "════════════════════════════════════════════════════════"
    echo "  EVIDENCE MANAGER"
    echo "════════════════════════════════════════════════════════"
    echo ""
    echo "  Uso: ./evidence_manager.sh [COMANDO] [OPCIONES]"
    echo ""
    echo "  Comandos:"
    echo "    --add <TIPO> <ARCHIVO> [DESC]  Añadir evidencia"
    echo "    --verify                        Verificar integridad"
    echo "    --list                          Listar evidencias"
    echo "    --package [NOMBRE]              Empaquetar evidencias"
    echo "    --help                          Mostrar esta ayuda"
    echo ""
    echo "  Tipos de evidencia:"
    echo "    screenshot  - Capturas de pantalla"
    echo "    pcap        - Capturas de red"
    echo "    credential  - Credenciales"
    echo "    finding     - Hallazgos"
    echo "    proof       - Pruebas"
    echo ""
    echo "  Ejemplos:"
    echo "    ./evidence_manager.sh --add screenshot web_login.png"
    echo "    ./evidence_manager.sh --add credential creds.txt"
    echo "    ./evidence_manager.sh --verify"
    echo "    ./evidence_manager.sh --package audit_2026"
}

case "$1" in
    --add)     add_evidence "$2" "$3" "$4" ;;
    --verify)  verify_evidence ;;
    --list)    list_evidence ;;
    --package) package_evidence "$2" ;;
    --help|-h) show_help ;;
    *)
        echo "❌ Comando no reconocido: $1"
        echo "Usa: ./evidence_manager.sh --help"
        exit 1
        ;;
esac
