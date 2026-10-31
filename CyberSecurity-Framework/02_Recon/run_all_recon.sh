#!/bin/bash
echo "════════════════════════════════════════════════════════"
echo "  EJECUTANDO RECONOCIMIENTO"
echo "════════════════════════════════════════════════════════"
TARGETS_FILE="../00_Config/targets.txt"
if [[ -f "$TARGETS_FILE" ]]; then
    TARGETS=$(grep -v "^#" "$TARGETS_FILE" | grep "|" | head -3 | cut -d'|' -f1 | tr -d ' ')
else
    TARGETS="127.0.0.1"
fi
echo "🎯 Objetivos: $TARGETS"
echo ""
for script in scripts/*.sh scripts/*.py; do
    if [[ -f "$script" && "$script" != "run_all"* ]]; then
        echo ""
        echo "▶️  Ejecutando: $script"
        echo "────────────────────────────────────────────────"
        for target in $TARGETS; do
            echo "  → Objetivo: $target"
            if [[ "$script" == *.py ]]; then
                python3 "$script" "$target" 2>/dev/null
            else
                bash "$script" "$target" 2>/dev/null
            fi
        done
    fi
done
echo ""
echo "✅ Reconocimiento completado"
