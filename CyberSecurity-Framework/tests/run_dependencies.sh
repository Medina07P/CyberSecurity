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

echo ""; echo "Resultado: $pasan ok, $fallan fallos"
[[ $fallan -eq 0 ]]
