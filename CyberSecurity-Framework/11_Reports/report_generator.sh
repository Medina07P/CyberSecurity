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
    echo "  --salida <dir>      Directorio de salida"
    echo "  --objetivo <host>   Objetivo del informe"
    echo "  --cliente <nombre>  Nombre del cliente"
    echo "  --auditor <nombre>  Nombre del auditor"
    echo "  --help              Ayuda del motor"
}

# ─── Resolución del tipo ────────────────────────────────────
tipo=""
resto=()

for arg in "$@"; do
    if [[ -z "$tipo" ]]; then
        case "$arg" in
            --help|-h)
                mostrar_ayuda
                exit 0
                ;;
            --executive|--ejecutivo)
                tipo="cliente"
                continue
                ;;
            --technical|--tecnico)
                tipo="tecnico"
                continue
                ;;
            --full|--all|--ambos)
                tipo="ambos"
                continue
                ;;
            --*)
                # Primera bandera → no hay tipo positional; tratar como opción
                resto+=("$arg")
                continue
                ;;
            tecnico|cliente|ambos)
                tipo="$arg"
                continue
                ;;
            *)
                echo "❌ Tipo no reconocido: $arg" >&2
                echo "Usa: tecnico | cliente | ambos" >&2
                echo "   o: ./report_generator.sh --help" >&2
                exit 1
                ;;
        esac
    fi
    resto+=("$arg")
done

# Tipo por defecto
: "${tipo:=ambos}"

# ─── Llamar al motor ────────────────────────────────────────
python3 "$SCRIPT_DIR/report_engine.py" --tipo "$tipo" "${resto[@]}"
exit $?
