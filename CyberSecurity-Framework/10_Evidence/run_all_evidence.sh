#!/bin/bash

# ============================================================
# RUN ALL EVIDENCE - Gestión completa de evidencias
# Uso: ./run_all_evidence.sh <TARGET>
# Ejemplo: ./run_all_evidence.sh 192.168.1.10
# ============================================================

TARGET="$1"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./run_all_evidence.sh <TARGET>"
    echo "Ejemplo: ./run_all_evidence.sh 192.168.1.10"
    exit 1
fi

echo "════════════════════════════════════════════════════════"
echo "  GESTIÓN DE EVIDENCIAS PARA: $TARGET"
echo "════════════════════════════════════════════════════════"

# Los hijos se invocan con rutas relativas: ejecutar desde este directorio.
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

echo ""
echo "📸 CAPTURA AUTOMÁTICA"
echo "────────────────────────────────────────"
./auto_capture.sh "$TARGET"

echo ""
echo "📋 LISTA DE EVIDENCIAS"
echo "────────────────────────────────────────"
./evidence_manager.sh --list

echo ""
echo "🔍 VERIFICACIÓN DE INTEGRIDAD"
echo "────────────────────────────────────────"
./evidence_manager.sh --verify

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ EVIDENCIAS COMPLETADAS"
echo "════════════════════════════════════════════════════════"
