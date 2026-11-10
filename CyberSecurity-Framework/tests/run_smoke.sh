#!/bin/bash
# ============================================================
#  TESTS - Prueba de humo del gestor
#  Uso: ./run_smoke.sh
#  Entrada simulada por tubería: no hace falta terminal interactiva.
# ============================================================

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW="$(cd "$TESTS_DIR/.." && pwd)"
cd "$FW" || exit 1
export TERM=xterm

# Sesión aislada: no toca la configuración real
SESION_TMP="$(mktemp -d)"
export SESSION_FILE="$SESION_TMP/.session"
# HOME y registro de claves aislados: la opción K nunca lee ni escribe los reales
export HOME="$SESION_TMP/home"; mkdir -p "$HOME"
export KEYS_FILE="$SESION_TMP/keys.yaml"
export KEYS_HARVESTER_DIRS="$SESION_TMP/ht"
trap 'rm -rf "$SESION_TMP"' EXIT

fail=0

run() { # <nombre> <entrada> <patron-esperado>
    local nombre="$1" entrada="$2" patron="$3" out rc
    out=$(printf '%b' "$entrada" | timeout 20 bash ./cyber_framework.sh 2>&1)
    rc=$?
    out=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')
    if [[ $rc -eq 124 ]]; then
        echo "  COLGADO  $nombre"; fail=$((fail+1)); return
    fi
    if printf '%s' "$out" | grep -qF -- "$patron"; then
        echo "  OK       $nombre (rc=$rc)"
    else
        echo "  FALLO    $nombre (rc=$rc) — no apareció: $patron"
        printf '%s\n' "$out" | tail -15 | sed 's/^/            /'
        fail=$((fail+1))
    fi
}

echo "=== arranque y salida ==="
run "Q cierra el gestor"              'Q\n'                    "Hasta luego"

echo ""
echo "=== cabecera ==="
rm -f "$SESSION_FILE"
run "muestra el objetivo sin definir" 'Q\n'                    "sin definir"
printf '%s\n' "192.168.1.10" > "$SESSION_FILE"
run "muestra el objetivo guardado"    'Q\n'                    "192.168.1.10"
run "muestra el estado de fases"      'Q\n'                    "Fases:"
run "explica la leyenda de fases"     'Q\n'                    "hecha, . pendiente"
run "sin pendientes, no sugiere nada" 'Q\n'                    "Salir"
rm -f "$SESSION_FILE"

echo ""
echo "=== navegación ==="
run "acepta '0' como '00'"            '0\n0\nQ\n'              "MÓDULO 00_Configuración"
run "lista del módulo 00"             '00\n0\nQ\n'             "scripts disponibles"
run "no lista la librería"            '00\n0\nQ\n'             "run_all_config.sh"
out=$(printf '00\n0\nQ\n' | timeout 20 bash ./cyber_framework.sh 2>&1)
if printf '%s' "$out" | grep -q "lib/params"; then
    echo "  FALLO    la librería aparece como herramienta"; fail=$((fail+1))
else
    echo "  OK       la librería no aparece como herramienta"
fi

echo ""
echo "=== ayudas y errores ==="
run "?? muestra la ayuda"             '?\n\nQ\n'              "ORDEN RECOMENDADO"
run "opción inválida no cuelga"       'zz\n\nQ\n'             "Opción inválida"
run "99 sin objetivo avisa"           '99\n\nQ\n'             "No hay objetivo definido"

echo ""
echo "=== marcas en la lista de módulos ==="
out=$(printf '05\n13\n0\n0\nQ\n' | timeout 20 bash ./cyber_framework.sh 2>&1)
if printf '%s' "$out" | grep -qF "[intrusiva]"; then
    echo "  OK       [intrusiva] en 05_Exploitation"
else
    echo "  FALLO    sin [intrusiva] en 05_Exploitation"; fail=$((fail+1))
fi
out=$(printf '10\n0\nQ\n' | timeout 20 bash ./cyber_framework.sh 2>&1)
if printf '%s' "$out" | grep -qF "[manual]"; then
    echo "  OK       [manual] en 10_Evidence"
else
    echo "  FALLO    sin [manual] en 10_Evidence"; fail=$((fail+1))
fi
if printf '%s' "$out" | grep -qF "evidence_manager.sh"; then
    echo "  OK       lista evidence_manager.sh"
else
    echo "  FALLO    no lista evidence_manager.sh"; fail=$((fail+1))
fi

echo ""
echo "=== marcas en 06 ==="
# 01_OSINT ya no tiene generadores: osint_harvester.sh se reescribía a sí mismo
# y se materializó el 2026-10-31. Los generadores que quedan están en 06.
out=$(printf '06\n9\n0\n0\nQ\n' | timeout 20 bash ./cyber_framework.sh 2>&1)
printf '%s' "$out" | grep -qF "[generador]" && echo "  OK       aparece [generador] en 06" || { echo "  FALLO    sin [generador] en 06"; fail=$((fail+1)); }
printf '%s' "$out" | grep -qF "[intrusiva]" && echo "  OK       aparece [intrusiva] en 06" || { echo "  FALLO    sin [intrusiva] en 06"; fail=$((fail+1)); }

out=$(printf '00\n0\nQ\n' | timeout 20 bash ./cyber_framework.sh 2>&1)
printf '%s' "$out" | grep -qF "config_wizard.sh" \
    && echo "  OK       configuración lista config_wizard.sh" \
    || { echo "  FALLO    no lista config_wizard.sh"; fail=$((fail + 1)); }

echo ""
echo "=== informes: acción R ==="
# La acción R del menú principal muestra el submenu de informe rápido.
# La generación real se prueba en run_reports.sh con fixtures aislados.
run "R muestra el submenu de informes" 'R\n0\nQ\n' "Informe técnico"

echo ""
echo "=== claves de API: acción K ==="
run "menú: K aparece"                 'Q\n'            "Claves de API"
run "menú: K abre el submenú"         'K\n0\nQ\n'     "CLAVES DE API"
run "menú: K muestra el estado"       'K\n3\n0\nQ\n' "theHarvester"
[[ -e "$KEYS_FILE" ]] && { echo "  FALLO    K no debe crear el registro"; fail=$((fail+1)); } \
    || echo "  OK       K no crea el registro"

echo ""
echo "----------------------------------------"
echo "fallos: $fail"
