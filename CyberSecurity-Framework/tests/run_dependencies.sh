#!/bin/bash
# Pruebas de 00_Config/lib/dependencies.bash y dependencies_models.bash —
# aisladas, sin red ni sudo/apt reales.
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$FW/00_Config/lib/dependencies.bash"
source "$FW/00_Config/lib/dependencies_models.bash"

# PATH cerrado para las pruebas que necesitan coreutils reales (mktemp,
# chmod, rm...) además del stub: si avml/ollama quedaron instalados de
# verdad en esta máquina (p.ej. tras usar la opción D), un PATH abierto los
# deja "ya instalados" según dependencies_binary_ok y las pruebas de
# confirmación negada / fallo del instalador dejan de ser deterministas.
# Se excluyen solo avml, ollama y llama-server en un directorio espejo cuando
# algún componente del PATH real los contiene (sin eliminar /usr/bin entero).
CLEAN_BIN="$(mktemp -d)"
CLEAN_PATH="$(python3 - "$CLEAN_BIN" "$PATH" <<'PY'
import os, sys
root, path_env = sys.argv[1], sys.argv[2]
hide = {"avml", "ollama", "llama-server"}
out = []
for idx, d in enumerate(path_env.split(":")):
    if not d or not os.path.isdir(d):
        continue
    if any(os.access(os.path.join(d, h), os.X_OK) for h in hide):
        mirror = os.path.join(root, f"m{idx}")
        os.mkdir(mirror, 0o700)
        for name in os.listdir(d):
            if name in hide:
                continue
            src = os.path.join(d, name)
            try:
                os.symlink(src, os.path.join(mirror, name))
            except OSError:
                pass
        out.append(mirror)
    else:
        out.append(d)
print(":".join(out), end="")
PY
)"

pasan=0; fallan=0
ok()  { echo "  ok   $1"; pasan=$((pasan+1)); }
ko()  { echo "  FALLO $1"; fallan=$((fallan+1)); }
eq()  { [[ "$2" == "$3" ]] && ok "$1" || ko "$1 (esperado '$3', obtenido '$2')"; }

echo "=== dependencies_binary_ok ==="
TMPBIN="$(mktemp -d)"; trap 'rm -rf "$TMPBIN" "$CLEAN_BIN"' EXIT
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

# Ollama: binario y runner. Un binario suelto no basta (HTTP 500 al generar).
touch "$TMPBIN/ollama"; chmod +x "$TMPBIN/ollama"
bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok ollama"
eq "ollama solo con binario: incompleto" "$?" "1"
touch "$TMPBIN/llama-server"; chmod +x "$TMPBIN/llama-server"
bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok ollama"
eq "ollama con binario y runner: completo" "$?" "0"
touch "$TMPBIN/runner-externo"; chmod +x "$TMPBIN/runner-externo"
OLLAMA_LLAMA_SERVER="$TMPBIN/runner-externo" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok ollama"
eq "OLLAMA_LLAMA_SERVER permite forzar la ruta del runner" "$?" "0"
rm -f "$TMPBIN/ollama" "$TMPBIN/llama-server" "$TMPBIN/runner-externo"

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
eq "ollama sigue apareciendo si solo está el binario (falta llama-server)" "$(printf '%s\n' "$out" | grep -c -F ollama)" "1"
touch "$TMPBIN/llama-server"; chmod +x "$TMPBIN/llama-server"
out=$(NMAP_VULNERS_PATH="$TMPBIN/no-existe.nse" bash -c "export PATH='$TMPBIN'; export NMAP_VULNERS_PATH='$TMPBIN/no-existe.nse'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_extra_missing")
eq "ollama ya no aparece con binario y runner llama-server" "$(printf '%s\n' "$out" | grep -c -F ollama)" "0"
rm -f "$TMPBIN/ollama" "$TMPBIN/llama-server"

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
printf 'no\n' | PATH="$STUBDIR:$CLEAN_PATH" NMAP_VULNERS_PATH="$NVP" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_nmap_vulners" >/dev/null 2>&1
eq "confirmación negada: rc 1" "$?" "1"
[[ -f "$NVP" ]] && ko "confirmación negada: no debía clonar nada" || ok "confirmación negada: no clonó nada"

printf 'NMAP_VULNERS_SI\n' | PATH="$STUBDIR:$CLEAN_PATH" NMAP_VULNERS_PATH="$NVP" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_nmap_vulners" >/dev/null 2>&1
eq "confirmado: instala y verifica, rc 0" "$?" "0"
grep -q -F 'clone' "$CALLS" && ok "invocó git clone" || ko "invocó git clone"
grep -q -F -- '--script-updatedb' "$CALLS" && ok "invocó nmap --script-updatedb" || ko "invocó nmap --script-updatedb"
[[ -f "$NVP" ]] && ok "copió vulners.nse al destino" || ko "copió vulners.nse al destino"

out=$(PATH="$STUBDIR:$CLEAN_PATH" NMAP_VULNERS_PATH="$NVP" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_nmap_vulners" 2>&1)
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
out=""; prev=""; read_cfg=0
for a in "$@"; do
    [ "$prev" = "-o" ] && out="$a"
    [ "$prev" = "-K" ] && [ "$a" = "-" ] && read_cfg=1
    prev="$a"
done
if [ "$read_cfg" = "1" ] && [ -n "${CURL_STDIN_LOG:-}" ]; then
    cat > "$CURL_STDIN_LOG"
fi
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
out=$(CURL_JSON_FILE="$STUBDIR/fixture.json" PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_avml_release")
eq "tag y URL del asset avml" "$out" "v0.99.0|https://example.invalid/avml"

KEYS_SEC="$STUBDIR/keys_sec.yaml"
STDIN_LOG="$STUBDIR/stdin.log"
printf 'version: 1\ntheharvester:\n  github:\n    key: tok-secreto-xyz\n' > "$KEYS_SEC"
: > "$CALLS"
out=$(KEYS_FILE="$KEYS_SEC" CURL_STDIN_LOG="$STDIN_LOG" CURL_JSON_FILE="$STUBDIR/fixture.json" PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_avml_release")
eq "avml release con token devuelve tag|url" "$out" "v0.99.0|https://example.invalid/avml"
eq "token no aparece en argv de curl" "$(grep -c -F 'tok-secreto-xyz' "$CALLS")" "0"
grep -q -F 'Authorization: Bearer tok-secreto-xyz' "$STDIN_LOG" && ok "token enviado por stdin (-K -)" || ko "token enviado por stdin (-K -)"
rm -f "$KEYS_SEC" "$STDIN_LOG"

cat > "$STUBDIR/sin-asset.json" <<'JSON'
{"tag_name": "v0.99.0", "assets": [{"name": "avml-arm64", "browser_download_url": "https://example.invalid/arm"}]}
JSON
CURL_JSON_FILE="$STUBDIR/sin-asset.json" PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_avml_release" >/dev/null 2>&1
eq "sin asset avml: rc 1" "$?" "1"

rm -f "$CALLS"
printf 'no\n' | CURL_JSON_FILE="$STUBDIR/fixture.json" PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_avml" >/dev/null 2>&1
eq "confirmación negada: rc 1" "$?" "1"
[[ -s "$CALLS" ]] && ko "confirmación negada: no debía invocar curl/sudo" || ok "confirmación negada: no invocó nada"

printf 'AVML_SI\n\n' | CURL_JSON_FILE="$STUBDIR/fixture.json" PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_avml" >/dev/null 2>&1
eq "confirmado: instala y verifica, rc 0" "$?" "0"
grep -q -F 'releases/latest' "$CALLS" && ok "consultó la API de releases" || ko "consultó la API de releases"
grep -q -F '/usr/local/bin/avml' "$CALLS" && ok "instaló en /usr/local/bin/avml" || ko "instaló en /usr/local/bin/avml"
rm -rf "$STUBDIR"
unset STUBDIR CALLS

echo "=== dependencies_install_avml: ya presente ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
export STUBDIR CALLS
cat > "$STUBDIR/sudo" <<'EOF'
#!/bin/sh
echo "sudo $*" >> "$CALLS"
exit 0
EOF
chmod +x "$STUBDIR/sudo"
cat > "$STUBDIR/curl" <<'EOF'
#!/bin/sh
echo "curl $*" >> "$CALLS"
exit 0
EOF
chmod +x "$STUBDIR/curl"
touch "$STUBDIR/avml"; chmod +x "$STUBDIR/avml"

out=$(printf '' | PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_avml" 2>&1)
eq "avml ya presente: rc 0 sin pedir confirmación" "$?" "0"
[[ -f "$CALLS" ]] && ko "avml ya presente: no debía invocar curl ni sudo" || ok "avml ya presente: no invocó curl ni sudo"
printf '%s\n' "$out" | grep -qF 'avml ya está instalado.' && ok "avml ya presente: lo dice" || ko "avml ya presente: lo dice"
rm -rf "$STUBDIR"
unset STUBDIR CALLS

echo "=== dependencies_descargar_archivo: paralelo por rangos ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
cat > "$STUBDIR/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$CALLS"
for a in "\$@"; do
    [ "\$a" = "-sIL" ] && { printf 'content-length: 8388608\r\n'; exit 0; }
done
out=""; rango=""; prev=""
for a in "\$@"; do
    [ "\$prev" = "-o" ] && out="\$a"
    [ "\$prev" = "-r" ] && rango="\$a"
    prev="\$a"
done
if [ -n "\$rango" ]; then
    ini=\${rango%-*}; fin=\${rango#*-}; n=\$((fin - ini + 1))
else
    n=8388608
fi
[ -n "\$out" ] && head -c "\$n" /dev/zero > "\$out"
echo "parte \$rango -> \$out (\$n)" >> "$CALLS"
exit 0
EOF
chmod +x "$STUBDIR/curl"

OLLAMA_DOWNLOAD_CONNECTIONS=4 PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_descargar_archivo 'http://ejemplo.invalid/paquete' '$STUBDIR/salida'" >/dev/null 2>&1
eq "descarga paralela: rc 0" "$?" "0"
eq "descarga paralela: tamaño total 8 MiB" "$(stat -c %s "$STUBDIR/salida")" "8388608"
eq "descarga paralela: cuatro rangos" "$(grep -c '^parte ' "$CALLS")" "4"
eq "descarga paralela: una sola cabecera HEAD" "$(grep -c -- '-sIL' "$CALLS")" "1"
rm -rf "$STUBDIR"
unset STUBDIR CALLS

echo "=== dependencies_install_ollama ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
cat > "$STUBDIR/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$CALLS"
printf 'touch "%s/ollama" "%s/llama-server"; chmod +x "%s/ollama" "%s/llama-server"\n' "$STUBDIR" "$STUBDIR" "$STUBDIR" "$STUBDIR"
EOF
chmod +x "$STUBDIR/curl"

printf 'no\n' | PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_ollama" >/dev/null 2>&1
eq "confirmación negada: rc 1" "$?" "1"
[[ -x "$STUBDIR/ollama" ]] && ko "confirmación negada: no debía instalar ollama" || ok "confirmación negada: no instaló ollama"

printf 'OLLAMA_SI\n0\n' | PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_install_ollama" >/dev/null 2>&1
eq "confirmado: rc 0 y ollama queda en PATH" "$?" "0"
[[ -x "$STUBDIR/ollama" ]] && ok "ollama quedó instalado" || ko "ollama no quedó instalado"
[[ -x "$STUBDIR/llama-server" ]] && ok "llama-server quedó instalado" || ko "llama-server no quedó instalado"

out=$(printf '0\n' | PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_install_ollama" 2>&1)
eq "ya presente: no vuelve a pedir confirmación ni a invocar curl" "$(printf '%s\n' "$out" | grep -c -F 'curl')" "0"
printf '%s\n' "$out" | grep -qF 'ollama ya está instalado.' && ok "ya presente: lo dice" || ko "ya presente: lo dice"
printf '%s\n' "$out" | grep -qF 'Catálogo de modelos para Ollama' && ok "ya presente: ofrece el catálogo" || ko "ya presente: ofrece el catálogo"
rm -rf "$STUBDIR"
unset STUBDIR CALLS

echo "=== dependencies_install_ollama: binario sin llama-server (el caso del HTTP 500) ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
mkdir -p "$STUBDIR/bin"
cat > "$STUBDIR/sudo" <<'EOF'
#!/bin/sh
exec "$@"
EOF
cat > "$STUBDIR/zstd" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$STUBDIR/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$CALLS"
out=""; prev=""
for a in "\$@"; do
    [ "\$prev" = "-o" ] && out="\$a"
    prev="\$a"
done
[ -n "\$out" ] && printf 'paquete falso\n' > "\$out"
exit 0
EOF
cat > "$STUBDIR/tar" <<EOF
#!/bin/sh
echo "tar \$*" >> "$CALLS"
dir=""; prev=""
for a in "\$@"; do
    [ "\$prev" = "-C" ] && dir="\$a"
    prev="\$a"
done
[ -n "\$dir" ] || exit 1
mkdir -p "\$dir/lib/ollama"
touch "\$dir/lib/ollama/llama-server"
chmod +x "\$dir/lib/ollama/llama-server"
exit 0
EOF
chmod +x "$STUBDIR/sudo" "$STUBDIR/zstd" "$STUBDIR/curl" "$STUBDIR/tar"
cat > "$STUBDIR/bin/ollama" <<'EOF'
#!/bin/sh
echo "ollama version is 0.40.16"
EOF
chmod +x "$STUBDIR/bin/ollama"

out=$(printf 'OLLAMA_SI\n0\n' | PATH="$STUBDIR/bin:$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_install_ollama" 2>&1)
eq "repara un Ollama incompleto: rc 0" "$?" "0"
printf '%s\n' "$out" | grep -qF 'le falta el runner' && ok "avisa de que falta llama-server" || ko "no avisa de que falta llama-server"
grep -q -F 'releases/download/v0.40.16/ollama-linux-amd64.tar.zst' "$CALLS" && ok "descarga la versión exacta del binario" || ko "no descarga la versión exacta del binario"
grep -q -F 'lib/ollama' "$CALLS" && ok "extrae solo lib/ollama" || ko "no extrae solo lib/ollama"
[[ -x "$STUBDIR/lib/ollama/llama-server" ]] && ok "tras reparar queda el runner" || ko "tras reparar falta el runner"
rm -rf "$STUBDIR"
unset STUBDIR CALLS

echo "=== dependencies_install_ollama: el paquete no deja llama-server ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
mkdir -p "$STUBDIR/bin"
cat > "$STUBDIR/sudo" <<'EOF'
#!/bin/sh
exec "$@"
EOF
cat > "$STUBDIR/zstd" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$STUBDIR/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$CALLS"
out=""; prev=""
for a in "\$@"; do
    [ "\$prev" = "-o" ] && out="\$a"
    prev="\$a"
done
[ -n "\$out" ] && printf 'paquete falso\n' > "\$out"
exit 0
EOF
cat > "$STUBDIR/tar" <<EOF
#!/bin/sh
echo "tar \$*" >> "$CALLS"
exit 0
EOF
chmod +x "$STUBDIR/sudo" "$STUBDIR/zstd" "$STUBDIR/curl" "$STUBDIR/tar"
touch "$STUBDIR/bin/ollama"; chmod +x "$STUBDIR/bin/ollama"

out=$(printf 'OLLAMA_SI\n' | PATH="$STUBDIR/bin:$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_install_ollama" 2>&1)
eq "sin runner tras reparar: rc 1" "$?" "1"
printf '%s\n' "$out" | grep -qF 'no se encontró «llama-server»' && ok "avisa de que no se encontró el runner" || ko "no avisa de que no se encontró el runner"
printf '%s\n' "$out" | grep -qF 'Catálogo de modelos para Ollama' && ko "sin runner: no debía ofrecer el catálogo" || ok "sin runner: no ofrece el catálogo"
rm -rf "$STUBDIR"
unset STUBDIR CALLS

echo "=== dependencies_install_ollama: el instalador termina con error ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
cat > "$STUBDIR/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$CALLS"
echo "exit 1"
EOF
chmod +x "$STUBDIR/curl"

out=$(printf 'OLLAMA_SI\n' | PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_install_ollama" 2>&1)
eq "instalador falla: rc 1" "$?" "1"
printf '%s\n' "$out" | grep -qF 'El instalador de Ollama terminó con error.' && ok "instalador falla: mensaje visible" || ko "instalador falla: mensaje visible"
printf '%s\n' "$out" | grep -qF 'Catálogo de modelos para Ollama' && ko "instalador falla: no debía ofrecer el catálogo" || ok "instalador falla: no ofrece el catálogo"
[[ -x "$STUBDIR/ollama" ]] && ko "instalador falla: no debía crear el binario" || ok "instalador falla: no creó el binario"
rm -rf "$STUBDIR"
unset STUBDIR CALLS

echo "=== dependencies_install_ollama: binario ausente tras instalar ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
cat > "$STUBDIR/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$CALLS"
echo "true"
EOF
chmod +x "$STUBDIR/curl"

out=$(printf 'OLLAMA_SI\n' | PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_install_ollama" 2>&1)
eq "binario ausente tras instalar: rc 1" "$?" "1"
printf '%s\n' "$out" | grep -qF 'no aparece en PATH.' && ok "binario ausente: mensaje visible" || ko "binario ausente: mensaje visible"
printf '%s\n' "$out" | grep -qF 'Catálogo de modelos para Ollama' && ko "binario ausente: no debía ofrecer el catálogo" || ok "binario ausente: no ofrece el catálogo"
rm -rf "$STUBDIR"
unset STUBDIR CALLS

echo "=== dependencies_models ==="
out=$(bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_model_rows")
eq "4 filas" "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "4"
printf '%s\n' "$out" | grep -q -F 'qwen|' && ok "incluye qwen" || ko "incluye qwen"
printf '%s\n' "$out" | grep -qi 'sin censura' && ok "DeepHat avisa sin censura" || ko "DeepHat avisa sin censura"
printf '%s\n' "$out" | grep -qi 'sin GPU.*más pequeño\|más pequeño.*sin GPU' && ok "general avisa de CPU sin GPU y modelo más pequeño" || ko "general avisa de CPU sin GPU y modelo más pequeño"

out=$(bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_model_sizes qwen")
eq "qwen tiene 6 tamaños" "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "6"

out=$(bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_model_lookup qwen 7b")
eq "lookup qwen:7b" "$out" "4.7|8|qwen2.5-coder:7b"

bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_model_lookup qwen 128b" >/dev/null 2>&1
eq "tamaño inexistente: rc 1" "$?" "1"

MEMINFO_FALSO="$(mktemp)"; printf 'MemAvailable:  3774320 kB\n' > "$MEMINFO_FALSO"
out=$(DEPENDENCIES_MEMINFO_PATH="$MEMINFO_FALSO" bash -c "export DEPENDENCIES_MEMINFO_PATH; source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_general_model_size")
eq "~3,6 GiB libres recomienda 3b" "$out" "3b"
out=$(DEPENDENCIES_MEMINFO_PATH="$MEMINFO_FALSO" bash -c "export DEPENDENCIES_MEMINFO_PATH; source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_mem_check 3")
eq "3,6 GiB libres sí alcanza para 3 GiB: rc 0" "$?" "0"
out=$(DEPENDENCIES_MEMINFO_PATH="$MEMINFO_FALSO" bash -c "export DEPENDENCIES_MEMINFO_PATH; source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_mem_check 14")
eq "3,6 GiB libres NO alcanza para 14 GiB: rc 1" "$?" "1"
rm -f "$MEMINFO_FALSO"

echo "=== dependencies_offer_model_catalog ==="
STUBDIR="$(mktemp -d)"
CALLS="$STUBDIR/calls.log"
cat > "$STUBDIR/ollama" <<EOF
#!/bin/sh
echo "ollama \$*" >> "$CALLS"
case "\$1" in
    pull)
        rc="\${OLLAMA_PULL_RC:-0}"
        if [ "\$rc" = "0" ]; then
            echo "\$2" >> "$STUBDIR/pulled.txt"
        fi
        exit "\$rc"
        ;;
    list)
        [ -f "$STUBDIR/pulled.txt" ] && cat "$STUBDIR/pulled.txt"
        exit 0
        ;;
esac
exit 0
EOF
chmod +x "$STUBDIR/ollama"

MEMINFO_BAJO="$(mktemp)"; printf 'MemAvailable:  3774320 kB\n' > "$MEMINFO_BAJO"  # ~3,6 GiB

# Declinar el catálogo: no es un fallo.
printf '0\n' | DEPENDENCIES_MEMINFO_PATH="$MEMINFO_BAJO" PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_offer_model_catalog" >/dev/null 2>&1
eq "declinar el catálogo: rc 0" "$?" "0"
[[ -f "$STUBDIR/pulled.txt" ]] && ko "declinar: no debía descargar nada" || ok "declinar: no descargó nada"

# Elegir qwen:14b con solo 3,6 GiB libres: el guardrail bloquea sin forzar.
printf '2\n14b\nno\n' | DEPENDENCIES_MEMINFO_PATH="$MEMINFO_BAJO" PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_offer_model_catalog" >/dev/null 2>&1
eq "guardrail sin forzar: rc 0 (cancela el pull, no la pieza)" "$?" "0"
[[ -f "$STUBDIR/pulled.txt" ]] && ko "guardrail sin forzar: no debía llegar a ollama pull" || ok "guardrail sin forzar: no llegó a ollama pull"

# Elegir qwen:3b (sí entra en 3,6 GiB): pull directo sin aviso de guardrail.
printf '2\n3b\n' | DEPENDENCIES_MEMINFO_PATH="$MEMINFO_BAJO" PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_offer_model_catalog" >/dev/null 2>&1
eq "entra en RAM libre: rc 0" "$?" "0"
grep -q -F 'qwen2.5-coder:3b' "$STUBDIR/pulled.txt" && ok "hizo ollama pull qwen2.5-coder:3b" || ko "hizo ollama pull qwen2.5-coder:3b"
rm -f "$STUBDIR/pulled.txt"; : > "$CALLS"

# Forzar qwen:14b con CONTINUAR_IGUAL: sí llega a ollama pull.
printf '2\n14b\nCONTINUAR_IGUAL\n' | DEPENDENCIES_MEMINFO_PATH="$MEMINFO_BAJO" PATH="$STUBDIR:$CLEAN_PATH" bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_offer_model_catalog" >/dev/null 2>&1
eq "forzado: rc 0" "$?" "0"
grep -q -F 'qwen2.5-coder:14b' "$STUBDIR/pulled.txt" && ok "forzado llega a ollama pull" || ko "forzado llega a ollama pull"
rm -f "$STUBDIR/pulled.txt" "$MEMINFO_BAJO"
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
