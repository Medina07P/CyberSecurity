#!/bin/bash
echo "════════════════════════════════════════════════════════"
echo "  EJECUTANDO CONFIGURACIÓN"
echo "════════════════════════════════════════════════════════"
for script in scripts/*.sh scripts/*.py; do
    # run_all* se llaman entre sí y config_wizard.sh pide datos por teclado:
    # dentro del "run all" se quedaría esperando entrada.
    case "$(basename "$script")" in
        run_all*|config_wizard.sh) continue ;;
    esac
    if [[ -f "$script" ]]; then
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
echo "✅ Configuración completada"
