#!/bin/bash
# ============================================================
# REPORT GENERATOR - Envoltorio del motor de informes
# Uso: ./report_generator.sh [tipo]
# Ejemplo: ./report_generator.sh ambos
#
# Genera informes técnico y/o de cliente a partir de los
# resultados de escaneo. Llama a report_engine.py.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# ─── Ayuda ──────────────────────────────────────────────────
mostrar_ayuda() {
    echo "Uso: ./report_generator.sh [tipo] [opciones del motor]"
    echo ""
    echo "Tipos:"
    echo "  tecnico        Informe técnico detallado"
    echo "  cliente        Informe ejecutivo para el cliente"
    echo "  ambos          Los dos informes (por defecto)"
    echo ""
    echo "Alias aceptados:"
    echo "  --executive  → cliente"
    echo "  --technical  → tecnico"
    echo "  --full, --all → ambos"
    echo ""
    echo "Opciones del motor (se reenvían tal cual):"
    echo "  --scans <dir>       Directorio de resultados de escaneo"
    echo "  --salida <dir>      Raíz de historial; cada generación crea runs/<id>/"
    echo "  --objetivo <host>   Objetivo del informe"
    echo "  --cliente <nombre>  Nombre del cliente"
    echo "  --auditor <nombre>  Nombre del auditor"
    echo "  --help              Ayuda del motor"
}

# ─── Resolución del tipo ────────────────────────────────────
tipo="ambos"
# Solo el primer argumento es selector de tipo. Los valores de opciones
# posteriores pueden llamarse «cliente», «tecnico» o «ambos».
if [[ $# -gt 0 ]]; then
        case "$1" in
            --help|-h)
                mostrar_ayuda
                exit 0
                ;;
            --executive|--ejecutivo)
                tipo="cliente"
                shift
                ;;
            --technical|--tecnico)
                tipo="tecnico"
                shift
                ;;
            --full|--all|--ambos)
                tipo="ambos"
                shift
                ;;
            tecnico|cliente|ambos)
                tipo="$1"
                shift
                ;;
        esac
fi

# ─── Llamar al motor ────────────────────────────────────────
python3 "$SCRIPT_DIR/report_engine.py" --tipo "$tipo" "$@"
exit $?
