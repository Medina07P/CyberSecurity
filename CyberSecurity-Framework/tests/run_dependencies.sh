#!/bin/bash
# Pruebas de 00_Config/lib/dependencies.bash — aisladas, sin red ni sudo/apt reales.
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$FW/00_Config/lib/dependencies.bash"
pasan=0; fallan=0
ok()  { echo "  ok   $1"; pasan=$((pasan+1)); }
ko()  { echo "  FALLO $1"; fallan=$((fallan+1)); }
eq()  { [[ "$2" == "$3" ]] && ok "$1" || ko "$1 (esperado '$3', obtenido '$2')"; }

echo "=== dependencies_binary_ok ==="
TMPBIN="$(mktemp -d)"; trap 'rm -rf "$TMPBIN"' EXIT
printf '#!/bin/sh\n' > "$TMPBIN/presente"; chmod +x "$TMPBIN/presente"
bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok presente"
eq "binario presente en PATH cerrado" "$?" "0"
bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok ausente-de-verdad"
eq "binario ausente en PATH cerrado" "$?" "1"
NMAP_VULNERS_PATH="$TMPBIN/nmap-vulners.nse" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok nmap-vulners"
eq "nmap-vulners ausente (archivo no existe)" "$?" "1"
touch "$TMPBIN/nmap-vulners.nse"
NMAP_VULNERS_PATH="$TMPBIN/nmap-vulners.nse" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok nmap-vulners"
eq "nmap-vulners presente (archivo existe)" "$?" "0"
grep -q '/usr/share/nmap/scripts/vulners.nse' "$FW/00_Config/lib/dependencies.bash"
eq "el código usa vulners.nse como ruta por defecto" "$?" "0"
grep -q 'nmap-vulners\.nse' "$FW/00_Config/lib/dependencies.bash"
eq "el código ya no menciona nmap-vulners.nse" "$?" "1"

echo "=== dependencies_status ==="
out=$(bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_status")
printf '%s\n' "$out" | grep -qF '03_Scanners:' && ok "incluye el grupo 03_Scanners" || ko "incluye el grupo 03_Scanners"
printf '%s\n' "$out" | grep -qF 'Dependencias adicionales:' && ok "incluye el grupo adicional" || ko "incluye el grupo adicional"
eq "nmap aparece una sola vez en el reporte" \
    "$(printf '%s\n' "$out" | grep -c -E '^  [✓✗] nmap$')" "1"
printf '%s\n' "$out" | grep -qF 'avml (binario de GitHub' && ok "avml muestra el motivo" || ko "avml muestra el motivo"
printf '%s\n' "$out" | grep -qF 'ollama' && ok "ollama aparece en el reporte de D" || ko "ollama aparece en el reporte de D"
printf '%s\n' "$out" | grep -qF 'ollama (se instala con' && ok "ollama muestra el motivo (no es apt)" || ko "ollama muestra el motivo (no es apt)"

echo "=== dependencies_missing_with_package ==="
out=$(bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_missing_with_package")
eq "avml nunca aparece (sin paquete apt)" "$(printf '%s\n' "$out" | grep -c -F avml)" "0"
eq "nmap-vulners nunca aparece (sin paquete apt)" "$(printf '%s\n' "$out" | grep -c -F nmap-vulners)" "0"
eq "ollama nunca aparece (sin paquete apt)" "$(printf '%s\n' "$out" | grep -c -F ollama)" "0"
eq "aircrack-ng aparece una sola vez aunque 3 binarios compartan el paquete" \
    "$(printf '%s\n' "$out" | grep -c -F aircrack-ng)" "1"
eq "nmap aparece (binario ausente en el PATH cerrado de prueba)" \
    "$(printf '%s\n' "$out" | grep -c -F nmap)" "1"

echo "=== dependencies_install ==="
STUBDIR="$(mktemp -d)"
cat > "$STUBDIR/sudo" <<'EOF'
#!/bin/sh
exec "$@"
EOF
chmod +x "$STUBDIR/sudo"
CALLS="$STUBDIR/calls.log"
cat > "$STUBDIR/apt-get" <<EOF
#!/bin/sh
echo "\$@" >> "$CALLS"
exit "\${APT_GET_RC:-0}"
EOF
chmod +x "$STUBDIR/apt-get"

printf 'no\n' | bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install paquete-x" >/dev/null 2>&1
eq "confirmación negada: rc 1" "$?" "1"
[[ -f "$CALLS" ]] && ko "confirmación negada: no debía llamar a apt-get" || ok "confirmación negada: no llamó a apt-get"

printf '' | bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install paquete-x" >/dev/null 2>&1
eq "EOF en la confirmación: rc 1" "$?" "1"
[[ -f "$CALLS" ]] && ko "EOF: no debía llamar a apt-get" || ok "EOF: no llamó a apt-get"

printf 'instalar\n' | APT_GET_RC=0 bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install aircrack-ng rustscan" >/dev/null 2>&1
eq "confirmado: rc del apt-get real (0)" "$?" "0"
eq "una sola llamada a apt-get" "$(wc -l < "$CALLS")" "1"
eq "argumentos exactos de la única llamada" "$(cat "$CALLS")" "install -y aircrack-ng rustscan"
rm -f "$CALLS"

printf 'instalar\n' | APT_GET_RC=42 bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install rustscan" >/dev/null 2>&1
eq "propaga el rc real de apt-get" "$?" "42"
rm -f "$CALLS"

bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install"
eq "sin paquetes: rc 0 sin preguntar" "$?" "0"
[[ -f "$CALLS" ]] && ko "sin paquetes: no debía llamar a apt-get" || ok "sin paquetes: no llamó a apt-get"
rm -rf "$STUBDIR"

echo "=== dependencies_resolve_selection ==="
FALTAN3=(paquete-a paquete-b paquete-c)
out=$(bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_resolve_selection todas '${FALTAN3[0]}' '${FALTAN3[1]}' '${FALTAN3[2]}'")
eq "'todas' imprime las 3 en orden" "$out" "$(printf '%s\n%s\n%s' "${FALTAN3[@]}")"

out=$(bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_resolve_selection 2 '${FALTAN3[0]}' '${FALTAN3[1]}' '${FALTAN3[2]}'")
eq "número único elige el paquete correcto" "$out" "paquete-b"

out=$(bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_resolve_selection '1 3' '${FALTAN3[0]}' '${FALTAN3[1]}' '${FALTAN3[2]}'")
eq "varios números en el orden tecleado" "$out" "$(printf '%s\n%s' paquete-a paquete-c)"

DRO_FUERA="$(mktemp)"; DRO_BASURA="$(mktemp)"; DRO_PARCIAL="$(mktemp)"
bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_resolve_selection 99 '${FALTAN3[0]}' '${FALTAN3[1]}' '${FALTAN3[2]}'" >"$DRO_FUERA" 2>&1
eq "fuera de rango: rc 1" "$?" "1"
eq "fuera de rango: no imprime nada" "$(cat "$DRO_FUERA")" ""

bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_resolve_selection abc '${FALTAN3[0]}'" >"$DRO_BASURA" 2>&1
eq "entrada no numérica: rc 1" "$?" "1"
eq "entrada no numérica: no imprime nada" "$(cat "$DRO_BASURA")" ""

bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_resolve_selection '1 99' '${FALTAN3[0]}' '${FALTAN3[1]}' '${FALTAN3[2]}'" >"$DRO_PARCIAL" 2>&1
eq "un token inválido cancela todo el lote (ni el 1 válido se imprime)" "$?-$(cat "$DRO_PARCIAL")" "1-"
rm -f "$DRO_FUERA" "$DRO_BASURA" "$DRO_PARCIAL"

out=$(bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_resolve_selection '1 1' '${FALTAN3[0]}' '${FALTAN3[1]}' '${FALTAN3[2]}'")
eq "número repetido no duplica el paquete" "$out" "paquete-a"

echo "=== dependencies_resumen_line ==="
out=$(bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_resumen_line")
N_FALTAN=$(bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_missing_with_package" | wc -l | tr -d ' ')
eq "resumen: cuenta paquetes instalables pendientes" "$out" "$N_FALTAN paquetes por apt"

TODO_INSTALADO="$(mktemp -d)"
bash -c "
source '$FW/00_Config/lib/dependencies.bash'
for b in \"\${!DEPENDENCIES_MAP[@]}\"; do touch '$TODO_INSTALADO/'\"\$b\"; chmod +x '$TODO_INSTALADO/'\"\$b\"; done
"
out=$(NMAP_VULNERS_PATH="$TODO_INSTALADO/nmap-vulners.nse" bash -c "export PATH='$TODO_INSTALADO'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_resumen_line")
eq "resumen: nada pendiente cuando todo está instalado" "$out" "nada pendiente por apt"
rm -rf "$TODO_INSTALADO"

echo ""; echo "Resultado: $pasan ok, $fallan fallos"
[[ $fallan -eq 0 ]]
