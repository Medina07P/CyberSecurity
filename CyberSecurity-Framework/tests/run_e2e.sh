#!/bin/bash
# ============================================================
#  TESTS - Extremo a extremo del gestor
#  Uso: ./run_e2e.sh
#
#  Comprueba lo que de verdad importa: que un script lanzado
#  desde el gestor recibe EXACTAMENTE el argumento tecleado,
#  en vez del texto del prompt (el bug original).
# ============================================================

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$TESTS_DIR/.." && pwd)"
BASE="$(mktemp -d)"
COPIA="$BASE/framework"
BIN="$BASE/bin"
REGISTRO="$BASE/args.txt"
mkdir -p "$BIN" "$REGISTRO"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FALLO %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "esperado [$3] / obtenido [$2]"; fi; }

# Copia del framework para no ensuciar el árbol real
cp -a "$SRC/." "$COPIA/"

# Stub de nmap: registra los argumentos recibidos
cat > "$BIN/nmap" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> "$REGISTRO/llamadas.txt"
exit 0
STUB
chmod +x "$BIN/nmap"
export PATH="$BIN:$PATH"
export TERM=xterm

cd "$COPIA" || exit 1
source "$COPIA/cyber_framework.sh"

# Sesión aislada
export SESSION_FILE="$BASE/.session"
source "$COPIA/00_Config/lib/session.bash"

limpiar() { : > "$REGISTRO/llamadas.txt"; }

printf '\n── El script recibe el valor tecleado, no el prompt\n'

limpiar
printf '192.168.1.50\n8080\n' | execute_script \
    "03_Scanners/network_scanners/nmap/nmap_scripts.sh" "03_Scanners" >/dev/null 2>&1

llamadas=$(cat "$REGISTRO/llamadas.txt" 2>/dev/null)
if [[ -z "$llamadas" ]]; then
    bad "nmap se ejecutó" "no hubo ninguna llamada"
else
    ok "nmap se ejecutó"
fi

# El objetivo debe aparecer como argumento suelto
if printf '%s' "$llamadas" | grep -qE '(^| )192\.168\.1\.50( |$)'; then
    ok "el objetivo llega limpio (192.168.1.50)"
else
    bad "el objetivo llega limpio" "llamadas: $llamadas"
fi

if printf '%s' "$llamadas" | grep -qE '(^| )8080( |$)'; then
    ok "el puerto llega limpio (8080)"
else
    bad "el puerto llega limpio" "llamadas: $llamadas"
fi

# Y no debe colarse nada del prompt
case "$llamadas" in
    *"necesita datos"*|*"Uso:"*|*"➜"*|*"Equipo o IP"*)
        bad "no se cuela el texto del prompt" "llamadas: $llamadas" ;;
    *) ok "no se cuela el texto del prompt" ;;
esac

# El número de argumentos tampoco debe dispararse
nargs=$(printf '%s\n' "$llamadas" | head -1 | wc -w | tr -d ' ')
eq "argumentos razonables en la llamada" "$nargs" "7"

printf '\n── El ejemplo se usa como defecto al pulsar Enter\n'

limpiar
printf '10.0.0.5\n\n' | execute_script \
    "03_Scanners/network_scanners/nmap/nmap_scripts.sh" "03_Scanners" >/dev/null 2>&1
llamadas=$(cat "$REGISTRO/llamadas.txt" 2>/dev/null)
if printf '%s' "$llamadas" | grep -qE '(^| )10\.0\.0\.5( |$)'; then
    ok "acepta el objetivo tecleado"
else
    bad "acepta el objetivo tecleado" "$llamadas"
fi
if printf '%s' "$llamadas" | grep -qF "80,443"; then
    ok "el puerto vacío usa el valor del Ejemplo (80,443)"
else
    bad "el puerto vacío usa el valor del Ejemplo" "$llamadas"
fi

printf '\n── El objetivo de sesión se propone como defecto\n'

session_set_target "10.9.9.9"
limpiar
printf '\n\n' | execute_script \
    "03_Scanners/network_scanners/nmap/nmap_scripts.sh" "03_Scanners" >/dev/null 2>&1
llamadas=$(cat "$REGISTRO/llamadas.txt" 2>/dev/null)
if printf '%s' "$llamadas" | grep -qE '(^| )10\.9\.9\.9( |$)'; then
    ok "usa el objetivo de la sesión"
else
    bad "usa el objetivo de la sesión" "$llamadas"
fi
session_clear

printf '\n── Una herramienta intrusiva pide confirmación\n'

limpiar
# "n" a la confirmación: no debe ejecutarse nada
printf 'n\n' | execute_script \
    "05_Exploitation/network/ssh_bruteforce.sh" "05_Exploitation" >/dev/null 2>&1
if [[ -s "$REGISTRO/llamadas.txt" ]]; then
    bad "cancelar no ejecuta el script" "hubo llamadas"
else
    ok "cancelar no ejecuta el script"
fi

printf '\n── Una entrada agotada no ejecuta nada\n'

limpiar
execute_script "03_Scanners/network_scanners/nmap/nmap_scripts.sh" "03_Scanners" </dev/null >/dev/null 2>&1
rc=$?
if [[ $rc -eq 0 && ! -s "$REGISTRO/llamadas.txt" ]]; then
    ok "EOF: sale limpio y sin ejecutar"
else
    bad "EOF: sale limpio y sin ejecutar" "rc=$rc, llamadas=$(cat "$REGISTRO/llamadas.txt" 2>/dev/null)"
fi

printf '\n── El gestor no arranca el menú al cargarse con source\n'
if [[ -z "${choice:-}" ]]; then
    ok "source no lanza main"
else
    bad "source no lanza main"
fi

rm -rf "$BASE"
printf '\n────────────────────────────────────────\n'
printf 'pasan: %s   fallan: %s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
