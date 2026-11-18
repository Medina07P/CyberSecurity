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

echo "=== dependencies_extra_missing ==="
# NMAP_VULNERS_PATH se fija siempre: la ruta por defecto puede existir de
# verdad en la máquina (nmap ya trae vulners.nse en algunos paquetes).
out=$(NMAP_VULNERS_PATH="$TMPBIN/no-existe.nse" bash -c "export PATH='$TMPBIN'; export NMAP_VULNERS_PATH='$TMPBIN/no-existe.nse'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_extra_missing")
eq "ollama aparece (ausente en el PATH cerrado)" "$(printf '%s\n' "$out" | grep -c -F ollama)" "1"
eq "avml aparece (ausente en el PATH cerrado)" "$(printf '%s\n' "$out" | grep -c -F avml)" "1"
eq "nmap-vulners aparece (ausente en el PATH cerrado)" "$(printf '%s\n' "$out" | grep -c -F nmap-vulners)" "1"
eq "exactamente 3 líneas" "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "3"
touch "$TMPBIN/ollama"; chmod +x "$TMPBIN/ollama"
out=$(NMAP_VULNERS_PATH="$TMPBIN/no-existe.nse" bash -c "export PATH='$TMPBIN'; export NMAP_VULNERS_PATH='$TMPBIN/no-existe.nse'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_extra_missing")
eq "ollama ya no aparece si está en PATH" "$(printf '%s\n' "$out" | grep -c -F ollama)" "0"
rm -f "$TMPBIN/ollama"

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

echo "=== dependencies_install_nmap_vulners ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
cat > "$STUBDIR/sudo" <<'EOF'
#!/bin/sh
exec "$@"
EOF
chmod +x "$STUBDIR/sudo"
cat > "$STUBDIR/git" <<EOF
#!/bin/sh
echo "git \$*" >> "$CALLS"
if [ "\$1" = "clone" ]; then
    last=""
    for a in "\$@"; do last="\$a"; done
    mkdir -p "\$last"
    printf 'contenido de prueba\n' > "\$last/vulners.nse"
fi
exit 0
EOF
chmod +x "$STUBDIR/git"
cat > "$STUBDIR/nmap" <<EOF
#!/bin/sh
echo "nmap \$@" >> "$CALLS"
exit 0
EOF
chmod +x "$STUBDIR/nmap"

NVP="$STUBDIR/scripts/vulners.nse"
printf 'no\n' | PATH="$STUBDIR:$PATH" NMAP_VULNERS_PATH="$NVP" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_nmap_vulners" >/dev/null 2>&1
eq "confirmación negada: rc 1" "$?" "1"
[[ -f "$NVP" ]] && ko "confirmación negada: no debía clonar nada" || ok "confirmación negada: no clonó nada"

printf 'NMAP_VULNERS_SI\n' | PATH="$STUBDIR:$PATH" NMAP_VULNERS_PATH="$NVP" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_nmap_vulners" >/dev/null 2>&1
eq "confirmado: instala y verifica, rc 0" "$?" "0"
grep -q -F 'clone' "$CALLS" && ok "invocó git clone" || ko "invocó git clone"
grep -q -F -- '--script-updatedb' "$CALLS" && ok "invocó nmap --script-updatedb" || ko "invocó nmap --script-updatedb"
[[ -f "$NVP" ]] && ok "copió vulners.nse al destino" || ko "copió vulners.nse al destino"

out=$(PATH="$STUBDIR:$PATH" NMAP_VULNERS_PATH="$NVP" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_nmap_vulners" 2>&1)
eq "ya presente: no vuelve a clonar" "$(printf '%s\n' "$out" | grep -c -F clone)" "0"
rm -rf "$STUBDIR"

echo "=== dependencies_github_token ==="
KEYSFILE="$(mktemp)"
out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
eq "sin registro: cadena vacía" "$out" ""
printf 'version: 1\ntheharvester:\n  github:\n    key: tok-de-prueba\n' > "$KEYSFILE"
out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
eq "registro con clave: la devuelve" "$out" "tok-de-prueba"
rm -f "$KEYSFILE"

echo "=== dependencies_offer_github_token ==="
KEYSDIR="$(mktemp -d)"
KEYSFILE="$KEYSDIR/registro.yaml"
printf '\n' | KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_offer_github_token"
out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
eq "Enter vacío: no guarda nada" "$out" ""
printf 'tok-nuevo\n' | KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_offer_github_token"
out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
eq "valor escrito: queda guardado" "$out" "tok-nuevo"
printf 'otro\n' | KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_offer_github_token"
out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
eq "ya había token: no vuelve a preguntar/sobrescribir" "$out" "tok-nuevo"
rm -rf "$KEYSDIR"

echo "=== dependencies_avml_release / dependencies_install_avml ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
export STUBDIR CALLS
cat > "$STUBDIR/sudo" <<'EOF'
#!/bin/sh
echo "sudo $*" >> "$CALLS"
if [ "$1" = "install" ]; then
    prev2=""; prev1=""
    for a in "$@"; do prev2="$prev1"; prev1="$a"; done
    if [ "$prev1" = "/usr/local/bin/avml" ]; then
        cp "$prev2" "$STUBDIR/avml" 2>/dev/null
        chmod +x "$STUBDIR/avml" 2>/dev/null
    fi
    exit 0
fi
exec "$@"
EOF
chmod +x "$STUBDIR/sudo"
cat > "$STUBDIR/curl" <<'EOF'
#!/bin/sh
echo "curl $*" >> "$CALLS"
out=""; prev=""
for a in "$@"; do
    [ "$prev" = "-o" ] && out="$a"
    prev="$a"
done
last=""
for a in "$@"; do last="$a"; done
case "$last" in
    *releases/latest*)
        cat "${CURL_JSON_FILE:-/dev/null}"
        exit 0
        ;;
esac
if [ -n "$out" ]; then
    cat > "$out" <<'INNER'
#!/bin/sh
case "$1" in
  --help) printf 'avml 0.0.0-test\nUSAGE:\n    avml <FILENAME>\n' ;;
esac
exit 0
INNER
    chmod +x "$out"
    exit 0
fi
exit 1
EOF
chmod +x "$STUBDIR/curl"

cat > "$STUBDIR/fixture.json" <<'JSON'
{"tag_name": "v0.99.0", "assets": [{"name": "avml", "browser_download_url": "https://example.invalid/avml"}]}
JSON
out=$(CURL_JSON_FILE="$STUBDIR/fixture.json" PATH="$STUBDIR:$PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_avml_release")
eq "tag y URL del asset avml" "$out" "v0.99.0|https://example.invalid/avml"

cat > "$STUBDIR/sin-asset.json" <<'JSON'
{"tag_name": "v0.99.0", "assets": [{"name": "avml-arm64", "browser_download_url": "https://example.invalid/arm"}]}
JSON
CURL_JSON_FILE="$STUBDIR/sin-asset.json" PATH="$STUBDIR:$PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_avml_release" >/dev/null 2>&1
eq "sin asset avml: rc 1" "$?" "1"

rm -f "$CALLS"
printf 'no\n' | CURL_JSON_FILE="$STUBDIR/fixture.json" PATH="$STUBDIR:$PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_avml" >/dev/null 2>&1
eq "confirmación negada: rc 1" "$?" "1"
[[ -s "$CALLS" ]] && ko "confirmación negada: no debía invocar curl/sudo" || ok "confirmación negada: no invocó nada"

printf 'AVML_SI\n\n' | CURL_JSON_FILE="$STUBDIR/fixture.json" PATH="$STUBDIR:$PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_avml" >/dev/null 2>&1
eq "confirmado: instala y verifica, rc 0" "$?" "0"
grep -q -F 'releases/latest' "$CALLS" && ok "consultó la API de releases" || ko "consultó la API de releases"
grep -q -F '/usr/local/bin/avml' "$CALLS" && ok "instaló en /usr/local/bin/avml" || ko "instaló en /usr/local/bin/avml"
rm -rf "$STUBDIR"
unset STUBDIR CALLS

echo "=== dependencies_install_ollama ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
cat > "$STUBDIR/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$CALLS"
printf 'touch "%s/ollama"; chmod +x "%s/ollama"\n' "$STUBDIR" "$STUBDIR"
EOF
chmod +x "$STUBDIR/curl"

printf 'no\n' | PATH="$STUBDIR:$PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_ollama" >/dev/null 2>&1
eq "confirmación negada: rc 1" "$?" "1"
[[ -x "$STUBDIR/ollama" ]] && ko "confirmación negada: no debía instalar ollama" || ok "confirmación negada: no instaló ollama"

printf 'OLLAMA_SI\n' | PATH="$STUBDIR:$PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_ollama" >/dev/null 2>&1
eq "confirmado: rc 0 y ollama queda en PATH" "$?" "0"
[[ -x "$STUBDIR/ollama" ]] && ok "ollama quedó instalado" || ko "ollama no quedó instalado"

out=$(PATH="$STUBDIR:$PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_ollama" 2>&1)
eq "ya presente: no vuelve a pedir confirmación ni a invocar curl" "$out" "ollama ya está instalado."
rm -rf "$STUBDIR"
unset STUBDIR CALLS

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
