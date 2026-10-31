#!/bin/bash
echo "════════════════════════════════════════════════════════"
echo "  EJECUTANDO AUTOMATIZACIÓN"
echo "════════════════════════════════════════════════════════"
for script in bash/*.sh; do
    if [[ -f "$script" ]]; then
        echo ""
        echo "▶️  Ejecutando: $script"
        echo "────────────────────────────────────────────────"
        bash "$script" 2>/dev/null
    fi
done
for script in python/*.py; do
    if [[ -f "$script" ]]; then
        echo ""
        echo "▶️  Ejecutando: $script"
        echo "────────────────────────────────────────────────"
        python3 "$script" 2>/dev/null
    fi
done
for script in powershell/*.ps1; do
    if [[ -f "$script" ]]; then
        echo ""
        echo "▶️  Ejecutando: $script"
        echo "────────────────────────────────────────────────"
        pwsh "$script" 2>/dev/null || echo "  ⚠️  PowerShell no disponible"
    fi
done
echo ""
echo "✅ Automatización completada"
