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

echo "=== dependencies_status ==="
out=$(bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_status")
printf '%s\n' "$out" | grep -qF '03_Scanners:' && ok "incluye el grupo 03_Scanners" || ko "incluye el grupo 03_Scanners"
printf '%s\n' "$out" | grep -qF 'Dependencias adicionales:' && ok "incluye el grupo adicional" || ko "incluye el grupo adicional"
eq "nmap aparece una sola vez en el reporte" \
    "$(printf '%s\n' "$out" | grep -c -E '^  [✓✗] nmap$')" "1"
printf '%s\n' "$out" | grep -qF 'avml (binario de GitHub' && ok "avml muestra el motivo" || ko "avml muestra el motivo"

echo "=== dependencies_missing_with_package ==="
out=$(bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_missing_with_package")
eq "avml nunca aparece (sin paquete apt)" "$(printf '%s\n' "$out" | grep -c -F avml)" "0"
eq "nmap-vulners nunca aparece (sin paquete apt)" "$(printf '%s\n' "$out" | grep -c -F nmap-vulners)" "0"
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

echo ""; echo "Resultado: $pasan ok, $fallan fallos"
[[ $fallan -eq 0 ]]
