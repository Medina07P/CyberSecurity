#!/bin/bash
echo "════════════════════════════════════════════════════════"
echo "  EJECUTANDO OSINT"
echo "════════════════════════════════════════════════════════"
for script in scripts/*.sh scripts/*.py; do
    if [[ -f "$script" && "$script" != "run_all"* ]]; then
        echo ""
        echo "▶️  Ejecutando: $script"
        echo "────────────────────────────────────────────────"
        if [[ "$script" == *.py ]]; then
            python3 "$script" 2>/dev/null
        else
            bash "$script" 2>/dev/null
        fi
    fi
done
echo ""
echo "✅ OSINT completado"
