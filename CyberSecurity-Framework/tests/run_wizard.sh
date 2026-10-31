#!/bin/bash
# ============================================================
#  PRUEBAS DEL ASISTENTE DE OBJETIVOS (00_Config/scripts/config_wizard.sh)
#  Uso: bash tests/run_wizard.sh
# ============================================================

FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WZ="$FW_DIR/00_Config/scripts/config_wizard.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/wizard.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

pasan=0; fallan=0
ok()  { echo "  ok   $1"; pasan=$((pasan + 1)); }
ko()  { echo "  FALLO $1"; fallan=$((fallan + 1)); }

# Carga las funciones sin lanzar el main
# shellcheck source=/dev/null
source "$WZ"

echo ""
echo "=== validadores ==="
[[ "$(wz_default_protocol 22)" == "SSH" ]]   && ok "22 → SSH"   || ko "22 → SSH"
[[ "$(wz_default_protocol 443)" == "HTTPS" ]] && ok "443 → HTTPS" || ko "443 → HTTPS"
[[ -z "$(wz_default_protocol 9999)" ]]       && ok "puerto raro sin defecto" || ko "puerto raro sin defecto"

for p in 1 8080 65535; do
    wz_valid_port "$p" && ok "puerto válido $p" || ko "puerto válido $p"
done
for p in 0 65536 abc "" 8080x; do
    wz_valid_port "$p" && ko "puerto inválido '$p'" || ok "puerto inválido '$p'"
done

for pr in C A M B c a m b; do
    wz_valid_priority "$pr" && ok "prioridad válida $pr" || ko "prioridad válida $pr"
done
for pr in X "" CC 1; do
    wz_valid_priority "$pr" && ko "prioridad inválida '$pr'" || ok "prioridad inválida '$pr'"
done

wz_valid_text "Portal Web" && ok "texto normal" || ko "texto normal"
wz_valid_text "a|b" && ko "texto con |" || ok "texto con |"
wz_valid_text "" && ko "texto vacío" || ok "texto vacío"

echo ""
echo "=== captura y resumen (sin escribir) ==="
f="$FIXTURE/targets.txt"
cat > "$f" <<'EOF'
# cabecera
192.168.1.10|80|HTTP|Portal|C
EOF
antes=$(md5sum "$f" | cut -d' ' -f1)

# Flujo válido, respuesta "no" en la confirmación final: no debe escribir
out=$(printf '1\n10.9.9.9\n8080\n\nPrueba\n\ns\nn\nn\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qF '10.9.9.9|8080|HTTP|Prueba|M' \
    && ok "monta la línea con defectos (HTTP, M)" || ko "monta la línea con defectos (HTTP, M)"
[[ "$(md5sum "$f" | cut -d' ' -f1)" == "$antes" ]] \
    && ok "no escribe si se dice que no" || ko "no escribe si se dice que no"

# Puerto inválido y luego válido
out=$(printf '1\n10.9.9.9\n70000\n8080\n\n\n\ns\nn\nn\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qE '70000.*no válid|no válid.*70000|Puerto no válido' \
    && ok "avisa del puerto inválido" || ko "avisa del puerto inválido"
printf '%s' "$out" | grep -qF '10.9.9.9|8080|HTTP|HTTP|M' \
    && ok "acepta el puerto válido después" || ko "acepta el puerto válido después"

# Descripción con | se rechaza y se vuelve a pedir
out=$(printf '1\n10.9.9.9\n8080\n\nmal|aqui\nBuena\n\ns\nn\nn\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qF '10.9.9.9|8080|HTTP|Buena|M' \
    && ok "rechaza | en la descripción" || ko "rechaza | en la descripción"

# Muestra la lista actual antes de preguntar
out=$(printf '1\n\nn\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qF '192.168.1.10' \
    && ok "muestra los objetivos actuales" || ko "muestra los objetivos actuales"

# Duplicado: avisa y no lo añade si se dice que no
out=$(printf '1\n192.168.1.10\n80\n\n\n\nn\nn\nn\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qiE 'ya existe|duplicado' \
    && ok "detecta duplicado" || ko "detecta duplicado"
printf '%s' "$out" | grep -qF '192.168.1.10|80|HTTP|HTTP|M' \
    && ko "no añade el duplicado rechazado" || ok "no añade el duplicado rechazado"

# Host vacío al principio: nada que añadir
out=$(printf '1\n\nn\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qi 'nada' && ok "sin entradas avisa y sale" || ko "sin entradas avisa y sale"

# EOF a mitad: no escribe y no se cuelga
out=$(printf '1\n10.9.9.9\n' | SESSION_TARGETS_FILE="$f" timeout 10 bash "$WZ" 2>&1)
[[ "$(md5sum "$f" | cut -d' ' -f1)" == "$antes" ]] \
    && ok "EOF a mitad no escribe" || ko "EOF a mitad no escribe"

echo ""
echo "=== escritura ==="
# Añadir conservando lo anterior
f="$FIXTURE/targets.txt"
printf '%s\n' "# cabecera" "192.168.1.10|80|HTTP|Portal|C" > "$f"
out=$(printf '1\n10.9.9.9\n8080\n\nPrueba\n\ns\nn\ns\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
grep -qF '192.168.1.10|80|HTTP|Portal|C' "$f" && ok "añadir conserva lo previo" || ko "añadir conserva lo previo"
grep -qF '10.9.9.9|8080|HTTP|Prueba|M' "$f" && ok "añadir escribe la línea nueva" || ko "añadir escribe la línea nueva"
grep -qE '^# ─── AÑADIDOS POR config_wizard' "$f" && ok "añadir deja marca de fecha" || ko "añadir deja marca de fecha"
printf '%s' "$out" | grep -qF 'RESUMEN DE OBJETIVOS' && ok "cierra con el resumen del parser" || ko "cierra con el resumen del parser"

# Sin salto de línea final: la línea nueva no se pega
f="$FIXTURE/sin_salto.txt"
printf '%s' "192.168.1.10|80|HTTP|Portal|C" > "$f"
printf '1\n10.9.9.9\n22\n\n\n\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
grep -qE '^192\.168\.1\.10\|80\|HTTP\|Portal\|C$' "$f" && ok "no pega la línea al final sin \\n" || ko "no pega la línea al final sin \\n"
grep -qF '10.9.9.9|22|SSH|SSH|M' "$f" && ok "escribe aunque faltase el salto final" || ko "escribe aunque faltase el salto final"

# Lista nueva: .bak con lo anterior, fichero con cabecera y solo lo nuevo
f="$FIXTURE/nueva.txt"
printf '%s\n' "192.168.1.10|80|HTTP|Portal|C" "10.0.0.1|22|SSH|Viejo|A" > "$f"
printf '2\n10.9.9.9\n443\n\n\nA\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
grep -qF '10.0.0.1|22|SSH|Viejo|A' "$f.bak" && ok "lista nueva guarda .bak" || ko "lista nueva guarda .bak"
grep -qF '192.168.1.10|80|HTTP|Portal|C' "$f" && ko "lista nueva descarta lo viejo" || ok "lista nueva descarta lo viejo"
grep -qF '10.9.9.9|443|HTTPS|HTTPS|A' "$f" && ok "lista nueva escribe la entrada" || ko "lista nueva escribe la entrada"
head -1 "$f" | grep -q '^# =====' && ok "lista nueva lleva cabecera estándar" || ko "lista nueva lleva cabecera estándar"

# .bak previo se sobrescribe
f="$FIXTURE/rebak.txt"
printf '%s\n' "1.1.1.1|80|HTTP|X|B" > "$f"
printf '%s\n' "viejo backup" > "$f.bak"
printf '2\n10.9.9.9\n22\n\n\n\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
grep -qF 'viejo backup' "$f.bak" && ko ".bak previo se sobrescribe" || ok ".bak previo se sobrescribe"

# Fichero inexistente: se crea con cabecera
f="$FIXTURE/no_existe.txt"
printf '1\n10.9.9.9\n22\n\n\n\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
[[ -f "$f" ]] && grep -qF '10.9.9.9|22|SSH|SSH|M' "$f" && ok "crea el fichero si falta" || ko "crea el fichero si falta"

# Fichero vacío: no falla y escribe cabecera + entrada
f="$FIXTURE/vacio.txt"
: > "$f"
printf '1\n10.9.9.9\n22\n\n\n\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
grep -qF '10.9.9.9|22|SSH|SSH|M' "$f" && ok "escribe sobre fichero vacío" || ko "escribe sobre fichero vacío"

echo ""
echo "----------------------------------------"
echo "pasan: $pasan   fallan: $fallan"
[[ "$fallan" -eq 0 ]]
