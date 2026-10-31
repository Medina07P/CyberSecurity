#!/bin/bash
# ============================================================
#  TESTS - Librería del gestor (00_Config/lib/)
#  Uso: ./run_tests.sh
#  No necesita terminal interactiva: alimenta stdin con printf.
# ============================================================

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW="$(cd "$TESTS_DIR/.." && pwd)"
cd "$FW" || exit 1

source "$FW/00_Config/lib/params.bash"
source "$FW/00_Config/lib/phase_status.bash"

# Sesión aislada: no toca la configuración real
TMPD="$(mktemp -d)"
export SESSION_FILE="$TMPD/.session"
export SESSION_TARGETS_FILE="$TMPD/targets.txt"
source "$FW/00_Config/lib/session.bash"
source "$FW/00_Config/lib/prompt.bash"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FALLO %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "esperado [$3] / obtenido [$2]"; fi; }

section() { printf '\n── %s\n' "$1"; }

# ──────────────────────────────────────────────────────────
section "Regresión: el prompt no se cuela en el valor"
# El bug original: el gestor capturaba el texto del prompt como parámetro.
S="$FW/04_Enumeration/web/enum_web.sh"
out=$(printf '192.168.1.50\n80\n' | prompt_for_slots "$S" "04_Enumeration/web/enum_web.sh" 2>/dev/null)
eq "stdout son solo los valores" "$out" "192.168.1.50
80"
case "$out" in
    *"➜"*|*"Uso:"*|*"necesita datos"*) bad "stdout no contiene interfaz" "obtenido: $out" ;;
    *) ok "stdout no contiene interfaz" ;;
esac
err=$(printf '192.168.1.50\n80\n' | prompt_for_slots "$S" "04_Enumeration/web/enum_web.sh" 2>&1 >/dev/null)
case "$err" in
    *"➜"*) ok "la interfaz sí va a stderr" ;;
    *) bad "la interfaz sí va a stderr" "stderr: $err" ;;
esac

# ──────────────────────────────────────────────────────────
section "Parser: recuentos sobre los .sh"
# Se excluye tests/ (este mismo fichero); la librería usa extensión .bash
total=$(find "$FW" -name '*.sh' -type f -not -path "$FW/tests/*" | wc -l | tr -d ' ')
eq "117 scripts .sh en el framework" "$total" "117"
eq "la librería no se cuenta como script" "$(find "$FW/00_Config/lib" -name '*.sh' | wc -l | tr -d ' ')" "0"

dos=0
oblig=0
for f in $(find "$FW" -name '*.sh' -type f -not -path "$FW/tests/*" | sort); do
    n=$(params_slot_count "$f")
    [ "$n" -ge 2 ] && dos=$((dos + 1))
    o=$(params_slots "$f" | awk -F'|' '$3=="obligatorio"' | wc -l | tr -d ' ')
    [ "$o" -ge 2 ] && oblig=$((oblig + 1))
done
eq "38 scripts con 2+ huecos" "$dos" "38"
eq "8 scripts con 2+ obligatorios" "$oblig" "8"

# ──────────────────────────────────────────────────────────
section "Parser: casos concretos"
eq "ps_exec.sh tiene 5 huecos" "$(params_slot_count 06_PostExploitation/lateral_movement/ps_exec.sh)" "5"
eq "enum_web.sh tiene 2 huecos" "$(params_slot_count 04_Enumeration/web/enum_web.sh)" "2"
eq "reverse_shell_php.sh tiene 2 obligatorios" \
   "$(params_slots 05_Exploitation/web/reverse_shell_php.sh | awk -F'|' '$3=="obligatorio"' | wc -l | tr -d ' ')" "2"
eq "ssh_backdoor.sh tiene 1 opcional" \
   "$(params_slots 06_PostExploitation/persistence/ssh_backdoor.sh | awk -F'|' '$3=="opcional"' | wc -l | tr -d ' ')" "1"
eq "enum_web.sh hueco 1 es IP" "$(params_slots 04_Enumeration/web/enum_web.sh | awk -F'|' 'NR==1{print $4}')" "IP"
eq "enum_web.sh hueco 2 es PUERTO" "$(params_slots 04_Enumeration/web/enum_web.sh | awk -F'|' 'NR==2{print $4}')" "PUERTO"
eq "PASS se trata como CONTRASENA" "$(params_slots 06_PostExploitation/lateral_movement/ps_exec.sh | awk -F'|' '$2=="PASS"{print $4}')" "CONTRASENA"

# ──────────────────────────────────────────────────────────
section "D2: huecos que no son una IP no se tratan como IP"
eq "masscan <IP/RANGO> es TEXTO" "$(params_slots 03_Scanners/network_scanners/masscan/masscan_scan.sh | awk -F'|' 'NR==1{print $4}')" "TEXTO"
eq "ping_sweep <red> es TEXTO" "$(params_slots 02_Recon/scripts/ping_sweep.sh | awk -F'|' 'NR==1{print $4}')" "TEXTO"

# ──────────────────────────────────────────────────────────
section "D1: scripts con banderas o subcomandos van en modo manual"
for f in 10_Evidence/evidence_manager.sh \
         11_Reports/report_generator.sh \
         09_Automation/python/report_generator.py \
         09_Automation/python/orchestrator.py \
         07_Wireless/scripts/interface_manager.sh \
         06_PostExploitation/persistence/cron_persistence.sh; do
    eq "manual: $f" "$(params_mode "$f")" "manual"
done
eq "masscan NO es manual" "$(params_mode 03_Scanners/network_scanners/masscan/masscan_scan.sh)" "slots"

# ──────────────────────────────────────────────────────────
section "D3: el ejemplo solo se usa si cuadra"
eq "search_kb.sh descarta su ejemplo" \
   "$(params_example_values 12_Knowledge_Base/search_kb.sh >/dev/null 2>&1; echo $?)" "1"
eq "enum_web.sh sí usa su ejemplo" \
   "$(params_example_values 04_Enumeration/web/enum_web.sh | tr '\n' ' ')" "192.168.1.10 80 "

# ──────────────────────────────────────────────────────────
section "Validación del objetivo"
for vale in 192.168.1.10 10.0.0.5 example.com sub.example.com; do
    if validate_target "$vale"; then ok "acepta $vale"; else bad "acepta $vale"; fi
done
for no in '' '1.2.3.4; rm -rf /' '1.2.3.4 5' 'con espacio' '999.1.1.1' 'http://x.com' 'a/b' '$HOME'; do
    if validate_target "$no"; then bad "rechaza [$no]"; else ok "rechaza [$no]"; fi
done

# ──────────────────────────────────────────────────────────
section "Sesión"
session_set_target "10.0.0.9" && ok "guarda el objetivo"
eq "lo devuelve" "$(session_target)" "10.0.0.9"
eq "sobrevive a otro proceso" "$(bash -c "SESSION_FILE='$SESSION_FILE' source '$FW/00_Config/lib/session.bash'; session_target")" "10.0.0.9"
session_set_target "malo con espacios" && bad "rechaza objetivo inválido" || ok "rechaza objetivo inválido"
session_clear
eq "tras limpiar está vacío" "$(session_target)" ""

# ──────────────────────────────────────────────────────────
section "Objetivos de targets.txt"
printf '%s\n' \
  '# comentario' \
  '192.168.1.10|22|SSH|Servidor Ubuntu|C' \
  '192.168.1.10|80|HTTP|Portal Web|C' \
  '192.168.1.1|—|—|Gateway|—(EXCLUIDO)' \
  'example.com|80|HTTP|Página|C' > "$SESSION_TARGETS_FILE"
lista=$(targets_from_config)
eq "quita duplicados" "$(printf '%s\n' "$lista" | wc -l | tr -d ' ')" "2"
eq "respeta los EXCLUIDO" "$(printf '%s\n' "$lista" | grep -c '^192\.168\.1\.1|' || true)" "0"
eq "conserva el huésped bueno" "$(printf '%s\n' "$lista" | cut -d'|' -f1 | tr '\n' ' ')" "192.168.1.10 example.com "

# ──────────────────────────────────────────────────────────
section "Estado de fases (fixture aislado)"
# Con un fixture propio, el test no depende de los escaneos locales
FIX="$TMPD/fixture"
mkdir -p "$FIX/fw/00_Config" "$FIX/scans/nmap" "$FIX/scans/web"
printf 'x|80|HTTP|desc|C\n' > "$FIX/fw/00_Config/targets.txt"
printf 'scope: x\n' > "$FIX/fw/00_Config/scope.yaml"
printf 'datos\n' > "$FIX/scans/nmap/algo.nmap"
PHASE_FW_DIR="$FIX/fw"
PHASE_SCANS_DIR="$FIX/scans"
source "$FW/00_Config/lib/phase_status.bash"

eq "00_Config hecha con alcance y objetivos" "$(phase_state 00_Config)" "done"
eq "03_Scanners hecha con resultados" "$(phase_state 03_Scanners)" "done"
eq "04_Enumeration pendiente sin datos" "$(phase_state 04_Enumeration)" "pending"
eq "02_Recon pendiente sin recon_*" "$(phase_state 02_Recon)" "pending"
eq "05_Exploitation no participa" "$(phase_state 05_Exploitation)" "na"
eq "sugiere la primera pendiente" "$(next_suggested_phase)" "02_Recon"

rm -rf "$FIX/scans/nmap" "$FIX/scans/web"
eq "sin datos, 03 vuelve a pendiente" "$(phase_state 03_Scanners)" "pending"

# ──────────────────────────────────────────────────────────
section "R2: la lista de peligrosas apunta a ficheros que existen"
faltan=0
while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    case "$rel" in \#*) continue ;; esac
    [ -f "$FW/$rel" ] || { bad "no existe $rel"; faltan=$((faltan + 1)); }
done < "$FW/00_Config/lib/dangerous.txt"
eq "todas las rutas de dangerous.txt existen" "$faltan" "0"
if params_is_dangerous "05_Exploitation/network/ssh_bruteforce.sh"; then ok "ssh_bruteforce es peligrosa"; else bad "ssh_bruteforce es peligrosa"; fi
if params_is_dangerous "04_Enumeration/web/enum_web.sh"; then bad "enum_web NO es peligrosa"; else ok "enum_web NO es peligrosa"; fi

# En una peligrosa no se propone el ejemplo como defecto
out=$(printf '\n\n' | prompt_for_slots "$FW/05_Exploitation/network/ssh_bruteforce.sh" "05_Exploitation/network/ssh_bruteforce.sh" 2>/dev/null)
eq "peligrosa: sin defecto del ejemplo, cancela sin valor" "$out" ""

# ──────────────────────────────────────────────────────────
section "split_args respeta comillas"
eq "comillas dobles" "$(split_args '--input "mi fichero.txt" --output x' | sed -n '2p')" "mi fichero.txt"
eq "comillas simples" "$(split_args "--add 'dos palabras' otra" | sed -n '1p')" "--add"
eq "sin comillas" "$(split_args 'a b c' | tr '\n' ',')" "a,b,c,"

# ──────────────────────────────────────────────────────────
section "D4: fin de entrada"
printf '' | prompt_for_slots "$FW/04_Enumeration/web/enum_web.sh" "04_Enumeration/web/enum_web.sh" >/dev/null 2>&1
eq "EOF devuelve 2" "$?" "2"

section "Cancelación tras 3 intentos"
printf 'x;y\nx;y\nx;y\n' | prompt_for_slots "$FW/03_Scanners/network_scanners/nmap/nmap_scripts.sh" "x" >/dev/null 2>&1
# nmap_scripts espera IP (no se valida como IP, pero 'x;y' pasa la regla universal)
# así que probamos con un puerto inválido
printf 'abc\nabc\nabc\n' | prompt_for_slots "$FW/06_PostExploitation/persistence/ssh_backdoor.sh" "x" >/dev/null 2>&1
eq "puerto inválido 3 veces devuelve 1" "$?" "1"

# ──────────────────────────────────────────────────────────
section "scans.bash: rutas, nombres y línea base"
source "$FW/00_Config/lib/scans.bash" 2>/dev/null

STUBD="$(mktemp -d)"
cat > "$STUBD/curl" <<'EOS'
#!/bin/bash
echo "${STUB_CODE:-200}:${STUB_SIZE:-433}"
EOS
chmod +x "$STUBD/curl"

eq "scans_root termina en /scans" "$(basename "$(scans_root)")" "scans"
eq "scans_slug limpia : y /"      "$(scans_slug 'https://a.b:443/x')" "https___a.b_443_x"
eq "scans_dir devuelve <scans>/pruebatool" "$(basename "$(scans_dir pruebatool)")" "pruebatool"
[ -d "$(scans_dir pruebatool)" ] && ok "scans_dir deja el directorio en disco" || bad "scans_dir no creó el directorio"

SCANS_PATH_BAK="$PATH"
PATH="$STUBD:$PATH"
export STUB_CODE=200 STUB_SIZE=433
eq "baseline con catch-all" "$(scans_baseline_size https://x/)" "433"
export STUB_CODE=404 STUB_SIZE=0
# Sin catch-all no hay nada que filtrar: la señal es la CADENA VACÍA, no "0",
# porque 0 es un tamaño legítimo (un rewrite que solo redirige).
eq "baseline sin catch-all" "$(scans_baseline_size https://x/)" ""
export STUB_CODE=403 STUB_SIZE=120
eq "baseline: WAF 403 con cuerpo también es catch-all" "$(scans_baseline_size https://x/)" "120"
export STUB_CODE=302 STUB_SIZE=0
eq "baseline: redirect sin cuerpo filtra tamaño 0" "$(scans_baseline_size https://x/)" "0"
export STUB_CODE=000 STUB_SIZE=0
eq "baseline: sin conexión no inventa catch-all" "$(scans_baseline_size https://x/)" ""
export STUB_CODE=200 STUB_SIZE=433
eq "signature devuelve código:tamaño" "$(scans_signature https://x/)" "200:433"

# El stub no debe sobrevivir a la sección: cualquier aserto posterior sobre
# curl mediría el falso.
PATH="$SCANS_PATH_BAK"
unset STUB_CODE STUB_SIZE SCANS_PATH_BAK

rm -rf "$STUBD" "$(scans_dir pruebatool)"

# ──────────────────────────────────────────────────────────
section "Librería: portable bajo zsh"
if command -v zsh >/dev/null 2>&1; then
    for par in "session:SESSION_LIB_DIR" "params:PARAMS_LIB_DIR" "phase_status:PHASE_LIB_DIR" "prompt:PROMPT_LIB_DIR" "scans:SCANS_LIB_DIR" "http_request:HR_LIB_DIR"; do
        libf="${par%%:*}"; var="${par##*:}"
        got=$(zsh -c "cd '$FW' && source '00_Config/lib/$libf.bash' >/dev/null 2>&1; printf '%s' \"\${$var}\"" 2>/dev/null)
        eq "zsh: $libf.bash resuelve bajo 00_Config/lib" "$got" "$FW/00_Config/lib"
    done
    # El .session real del operador no se toca: se aparta y se devuelve.
    SESS_REAL="$FW/00_Config/.session"
    SESS_BAK=""
    if [ -f "$SESS_REAL" ]; then SESS_BAK="$TMPD/session.bak"; cp "$SESS_REAL" "$SESS_BAK"; fi
    rm -f "$FW/../.session" "$SESS_REAL"
    zsh -c "cd '$FW'; unset SESSION_FILE SESSION_TARGETS_FILE; source '00_Config/lib/session.bash' >/dev/null 2>&1; session_set_target prueba.example >/dev/null 2>&1" 2>/dev/null
    [ -f "$FW/../.session" ] && bad "zsh: .session no debe acabar en la raíz del repo" || ok "zsh: .session no acaba en la raíz del repo"
    [ -f "$SESS_REAL" ] && ok "zsh: .session aterriza en 00_Config" || bad "zsh: .session no llegó a 00_Config"
    rm -f "$FW/../.session" "$SESS_REAL"
    [ -n "$SESS_BAK" ] && cp "$SESS_BAK" "$SESS_REAL"
else
    echo "  SKIP     zsh no instalado"
fi

# ──────────────────────────────────────────────────────────
section "run_all_recon acepta objetivo"
RMP="$TMPD/recon"
mkdir -p "$RMP/02_Recon/scripts" "$RMP/00_Config"
printf '192.168.1.10|22|SSH|fixture|C\n' > "$RMP/00_Config/targets.txt"
cat > "$RMP/02_Recon/scripts/fake.sh" <<'EOS'
#!/bin/bash
printf '%s\n' "$1" >> "$RMP_LOG"
EOS
cp "$FW/02_Recon/run_all_recon.sh" "$RMP/02_Recon/"
export RMP_LOG="$TMPD/recon_args"
: > "$RMP_LOG"
(cd "$RMP/02_Recon" && bash run_all_recon.sh 192.0.2.99 >/dev/null 2>&1)
eq "run_all_recon: usa el objetivo recibido"        "$(grep -c '192.0.2.99'   "$RMP_LOG")" "1"
eq "run_all_recon: con argumento no lee targets.txt" "$(grep -c '192.168.1.10' "$RMP_LOG")" "0"
eq "run_all_recon: declara su hueco en Uso:"         "$(params_mode "$FW/02_Recon/run_all_recon.sh")" "slots"

# Lanzado desde fuera de su directorio también debe encontrar sus hijos y
# targets.txt: los invoca con rutas relativas.
: > "$RMP_LOG"
(cd "$TMPD" && bash "$RMP/02_Recon/run_all_recon.sh" 192.0.2.97 >/dev/null 2>&1)
eq "run_all_recon: funciona desde cualquier cwd"      "$(grep -c '192.0.2.97' "$RMP_LOG")" "1"

# ──────────────────────────────────────────────────────────
section "enum_web: nombres con objetivo y línea base de ffuf"
WOUT="$FW/../scans/web"
mkdir -p "$WOUT"
rm -f "$WOUT"/headers_192.0.2.1_443.txt "$WOUT"/headers_192.0.2.2_443.txt "$WOUT"/headers_443.txt
WSTUB="$(mktemp -d)"
printf '#!/bin/bash\necho "200:433"\n' > "$WSTUB/curl"
printf '#!/bin/bash\necho "whatweb stub"\n' > "$WSTUB/whatweb"
cat > "$WSTUB/ffuf" <<'EOS'
#!/bin/bash
printf '%s\n' "$*" >> "$WSTUB_ARGS"
out=""; prev=""
for a in "$@"; do [[ "$prev" == "-o" ]] && out="$a"; prev="$a"; done
[[ -n "$out" ]] && printf '%s' '{"commandline":"x","results":[],"config":{"url":"http://x/FUZZ"}}' > "$out"
exit 0
EOS
chmod +x "$WSTUB/curl" "$WSTUB/whatweb" "$WSTUB/ffuf"
export WSTUB_ARGS="$WSTUB/ffuf_args"
: > "$WSTUB_ARGS"

PATH="$WSTUB:$PATH" bash "$FW/04_Enumeration/web/enum_web.sh" 192.0.2.1 443 >/dev/null 2>&1
PATH="$WSTUB:$PATH" bash "$FW/04_Enumeration/web/enum_web.sh" 192.0.2.2 443 >/dev/null 2>&1
WOUT_TXT=$(PATH="$WSTUB:$PATH" bash "$FW/04_Enumeration/web/enum_web.sh" 192.0.2.3 443 2>&1)

eq "enum_web: dos objetivos no se pisan"    "$(ls "$WOUT" | grep -c '^headers_192\.0\.2\.')" "3"
eq "enum_web: el nombre lleva el objetivo"  "$(ls "$WOUT" | grep -c '^headers_192\.0\.2\.1_443')" "1"
eq "enum_web: cada ejecución filtra por tamaño base"  "$(grep -c -- '-fs 433' "$WSTUB_ARGS")" "3"
# Un catch-all con results vacío debe decir 0, no 1 por la "url" de la config.
eq "enum_web: cero hallazgos se informa como cero" \
   "$(printf '%s' "$WOUT_TXT" | grep -c ' 0 directorios encontrados')" "1"

# Un catch-all contesta al robots.txt con el relleno de la app: 200 y cuerpo,
# así que "no vacío" no significa "existe".
eq "enum_web: no anuncia robots.txt cuando es el relleno" \
   "$(printf '%s' "$WOUT_TXT" | grep -c 'Robots.txt encontrado')" "0"

# Un objetivo inalcanzable no es un objetivo limpio: hay que decirlo.
cat > "$WSTUB/curl" <<'EOS'
#!/bin/bash
echo "000:0"
EOS
chmod +x "$WSTUB/curl"
: > "$WSTUB_ARGS"
WOUT_DOWN=$(PATH="$WSTUB:$PATH" bash "$FW/04_Enumeration/web/enum_web.sh" 192.0.2.8 443 2>&1)
eq "enum_web: sin conexión avisa"    "$(printf '%s' "$WOUT_DOWN" | grep -c 'No se pudo conectar')" "1"
eq "enum_web: sin conexión no fuzzea" "$(grep -c . "$WSTUB_ARGS")" "0"

rm -f "$WOUT"/*_192.0.2.*
rm -rf "$WSTUB"

# ──────────────────────────────────────────────────────────
section "Escáneres: nombres con objetivo"
NSTUB="$(mktemp -d)"
cat > "$NSTUB/nmap" <<'EOS'
#!/bin/bash
base=""
while [[ $# -gt 0 ]]; do [[ "$1" == "-oA" ]] && base="$2"; shift; done
[[ -n "$base" ]] && : > "${base}.nmap"
exit 0
EOS
cat > "$NSTUB/nuclei" <<'EOS'
#!/bin/bash
out=""
while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && out="$2"; shift; done
[[ -n "$out" ]] && echo "stub" > "$out"
exit 0
EOS
chmod +x "$NSTUB/nmap" "$NSTUB/nuclei"

rm -f "$FW/../scans/nmap/smart_ports_192.0.2.1".*
rm -f "$FW/../scans/nuclei/nuclei_https___192.0.2.1.txt"
PATH="$NSTUB:$PATH" bash "$FW/03_Scanners/network_scanners/nmap/nmap_smart.sh" 192.0.2.1 >/dev/null 2>&1
PATH="$NSTUB:$PATH" bash "$FW/03_Scanners/web_scanners/nuclei/nuclei_scan.sh" https://192.0.2.1 >/dev/null 2>&1

eq "nmap_smart: el nombre lleva el objetivo" "$(ls "$FW/../scans/nmap" | grep -c '^smart_ports_192\.0\.2\.1\.nmap')" "1"
eq "nuclei: el nombre no cambia"             "$(ls "$FW/../scans/nuclei" | grep -c '^nuclei_https___192\.0\.2\.1\.txt')" "1"

rm -f "$FW/../scans/nmap/smart_ports_192.0.2.1".* "$FW/../scans/nuclei/nuclei_https___192.0.2.1.txt"
rm -rf "$NSTUB"

# ──────────────────────────────────────────────────────────
section "sql_injection: línea base"
SQLI="$FW/05_Exploitation/web/sql_injection.sh"
WOUT_SQL="$FW/../scans/web"
QSTUB="$(mktemp -d)"
printf '#!/bin/bash\nexit 0\n' > "$QSTUB/sqlmap"
chmod +x "$QSTUB/sqlmap"

# Escenario 1: servidor catch-all, toda respuesta idéntica
printf '#!/bin/bash\necho "200:433"\n' > "$QSTUB/curl"
chmod +x "$QSTUB/curl"
rm -f "$WOUT_SQL"/sqli_findings_192.0.2.1.txt
PATH="$QSTUB:$PATH" bash "$SQLI" 192.0.2.1 443 / >/dev/null 2>&1
N1=$([ -f "$WOUT_SQL/sqli_findings_192.0.2.1.txt" ] && wc -l < "$WOUT_SQL/sqli_findings_192.0.2.1.txt" || echo 0)
eq "sqli: catch-all no genera hallazgos" "$N1" "0"

# Escenario 2: servidor normal que solo cambia con la carga de inyección
cat > "$QSTUB/curl" <<'EOS'
#!/bin/bash
url="${@: -1}"
case "$url" in
    *%27*) echo "200:999" ;;
    *)     echo "200:433" ;;
esac
EOS
chmod +x "$QSTUB/curl"
rm -f "$WOUT_SQL"/sqli_findings_192.0.2.*.txt
PATH="$QSTUB:$PATH" bash "$SQLI" 192.0.2.1 443 / >/dev/null 2>&1
N2=$([ -f "$WOUT_SQL/sqli_findings_192.0.2.1.txt" ] && wc -l < "$WOUT_SQL/sqli_findings_192.0.2.1.txt" || echo 0)
[ "$N2" -ge 1 ] && ok "sqli: detecta la diferencia real ($N2)" || bad "sqli: no detectó la diferencia real" "obtenido $N2"

# El fichero lleva el objetivo: lo de 192.0.2.1 no se le atribuye a 192.0.2.2
rm -f "$WOUT_SQL/sqli_findings_192.0.2.2.txt"
PATH="$QSTUB:$PATH" bash "$SQLI" 192.0.2.2 443 / >/dev/null 2>&1
eq "sqli: hallazgos por objetivo, sin arrastrar los ajenos" \
   "$([ -f "$WOUT_SQL/sqli_findings_192.0.2.2.txt" ] && wc -l < "$WOUT_SQL/sqli_findings_192.0.2.2.txt" || echo 0)" "90"

# Escenario 3: 8443 es TLS, no HTTP en claro
cat > "$QSTUB/curl" <<'EOS'
#!/bin/bash
printf '%s\n' "${@: -1}" >> "$QSTUB_URLS"
echo "200:433"
EOS
chmod +x "$QSTUB/curl"
export QSTUB_URLS="$QSTUB/urls"
: > "$QSTUB_URLS"
PATH="$QSTUB:$PATH" bash "$SQLI" 192.0.2.9 8443 / >/dev/null 2>&1
eq "sqli: 8443 se prueba por https" "$(grep -c '^http://' "$QSTUB_URLS")" "0"
eq "sqli: 8443 sí sondea"           "$([ -s "$QSTUB_URLS" ] && echo si)" "si"

# Escenario 4: servidor inalcanzable. NO puede decir "sin diferencias":
# eso sería presentar un fallo de conexión como un objetivo limpio.
cat > "$QSTUB/curl" <<'EOS'
#!/bin/bash
echo "000:0"
EOS
chmod +x "$QSTUB/curl"
QOUT=$(PATH="$QSTUB:$PATH" bash "$SQLI" 192.0.2.7 8443 / 2>&1); QRC=$?
eq "sqli: sin conexión no finge un objetivo limpio" "$(printf '%s' "$QOUT" | grep -c 'Sin diferencias')" "0"
eq "sqli: sin conexión avisa"                       "$(printf '%s' "$QOUT" | grep -c 'No se pudo conectar')" "1"
eq "sqli: sin conexión sale con error"              "$QRC" "1"

rm -f "$WOUT_SQL"/sqli_findings_192.0.2.*.txt
rm -rf "$QSTUB"
unset QSTUB_URLS

# ──────────────────────────────────────────────────────────
section "Escáneres: stderr a errores.log"
ESTUB="$(mktemp -d)"
cat > "$ESTUB/nmap" <<'EOS'
#!/bin/bash
echo "fallo simulado de nmap" >&2
exit 1
EOS
chmod +x "$ESTUB/nmap"
rm -f "$FW/../scans/nmap/errores.log"
PATH="$ESTUB:$PATH" bash "$FW/03_Scanners/network_scanners/nmap/nmap_smart.sh" 192.0.2.9 > "$TMPD/salida_scan" 2>&1
[ -s "$FW/../scans/nmap/errores.log" ] && ok "scanner: el error queda en el log" || bad "scanner: el error no quedó en el log"
grep -q "errores.log" "$TMPD/salida_scan" && ok "scanner: avisa de la ruta del log" || bad "scanner: no avisa de la ruta del log"
rm -f "$FW/../scans/nmap/errores.log"
rm -rf "$ESTUB"

# El log es de este run: uno heredado convierte cualquier ejecución futura en
# "⚠️ Errores registrados" permanente, y atribuye fallos viejos al objetivo actual.
TSTUB="$(mktemp -d)"
printf '#!/bin/bash\nexit 0\n' > "$TSTUB/nmap"
chmod +x "$TSTUB/nmap"
echo "error de una ejecución anterior" > "$FW/../scans/nmap/errores.log"
TOUT=$(PATH="$TSTUB:$PATH" bash "$FW/03_Scanners/network_scanners/nmap/nmap_smart.sh" 192.0.2.6 2>&1)
eq "scanner: el log se trunca en cada ejecución" "$([ -s "$FW/../scans/nmap/errores.log" ] && echo con-contenido || echo vacio)" "vacio"
eq "scanner: sin errores nuevos no avisa" "$(printf '%s' "$TOUT" | grep -c 'errores.log')" "0"
rm -f "$FW/../scans/nmap/errores.log"
rm -rf "$TSTUB"

# ──────────────────────────────────────────────────────────
section "run_all_scanners: resumen de logs con errores"
RSTUB="$(mktemp -d)"
for t in nmap masscan nikto nuclei rustscan whatweb ffuf; do
    printf '#!/bin/bash\nexit 0\n' > "$RSTUB/$t"
    chmod +x "$RSTUB/$t"
done
mkdir -p "$FW/../scans/nmap" "$FW/../scans/nikto" "$FW/../scans/masscan"
RBAK=""
for l in nmap nikto masscan; do
    if [[ -f "$FW/../scans/$l/errores.log" ]]; then
        mv "$FW/../scans/$l/errores.log" "$TMPD/$l.errores.bak"
        RBAK="$RBAK $l"
    fi
done
# Se siembra nikto (no se ejecuta con este stub: no hay puertos web) y masscan
# (solo corre con IP, y el objetivo es un dominio), así el run no los trunca.
echo "fallo simulado de nikto" > "$FW/../scans/nikto/errores.log"
: > "$FW/../scans/masscan/errores.log"

PATH="$RSTUB:$PATH" bash "$FW/03_Scanners/run_all_scanners.sh" prueba.example > "$TMPD/scan_all" 2>&1
# El hijo ya anuncia su propio log con "⚠️  Errores registrados en:", así que el
# aserto no puede ser "la ruta aparece": tiene que ser la línea del resumen.
eq "run_all_scanners: resume el log con contenido" "$(grep -cE '^  ⚠️  .*/scans/nikto/errores\.log \([0-9]+ líneas?\)' "$TMPD/scan_all")" "1"
eq "run_all_scanners: no resume un log vacío"     "$(grep -cE '/scans/masscan/errores\.log \(' "$TMPD/scan_all")" "0"

rm -f "$FW/../scans/nmap/errores.log" "$FW/../scans/nikto/errores.log" "$FW/../scans/masscan/errores.log"
for l in $RBAK; do mv "$TMPD/$l.errores.bak" "$FW/../scans/$l/errores.log"; done
rm -rf "$RSTUB"

# Si el descubrimiento de puertos falla, no se puede decir "no hay puertos web":
# son dos cosas distintas y la segunda cierra el run en verde sin haber mirado.
WSTUB2="$(mktemp -d)"
cat > "$WSTUB2/nmap" <<'EOS'
#!/bin/bash
case "$*" in
    *"-p 80,443,8080,8443"*|*"-p80,443,8080,8443"*) echo "nmap: host inalcanzable" >&2; exit 1 ;;
    *) exit 0 ;;
esac
EOS
chmod +x "$WSTUB2/nmap"
WOUT2=$(PATH="$WSTUB2:$PATH" bash "$FW/03_Scanners/run_all_scanners.sh" prueba.example 2>&1)
eq "run_all_scanners: distingue fallo de descubrimiento de 'sin puertos'" \
   "$(printf '%s' "$WOUT2" | grep -c 'No se pudo descubrir')" "1"
eq "run_all_scanners: no anuncia 'sin puertos web' cuando el sondeo falló" \
   "$(printf '%s' "$WOUT2" | grep -c 'No se encontraron puertos web abiertos')" "0"
rm -f "$FW/../scans/nmap/errores.log"
rm -rf "$WSTUB2"

# ──────────────────────────────────────────────────────────
section "ffuf: contar hallazgos, no la url de la configuración"
source "$FW/00_Config/lib/scans.bash" 2>/dev/null
FFJ="$TMPD/ffuf.json"
printf '%s' '{"commandline":"ffuf -u http://x/FUZZ","results":[],"config":{"url":"http://x/FUZZ"}}' > "$FFJ"
eq "ffuf: cero hallazgos es cero" "$(scans_ffuf_count "$FFJ")" "0"
printf '%s' '{"results":[{"position":10,"url":"http://x/a"},{"position":20,"url":"http://x/b"}],"config":{"url":"http://x/FUZZ"}}' > "$FFJ"
eq "ffuf: dos hallazgos son dos"  "$(scans_ffuf_count "$FFJ")" "2"
eq "ffuf: fichero ilegible es cero" "$(scans_ffuf_count "$TMPD/no-existe.json")" "0"

# ──────────────────────────────────────────────────────────
section "http_request: leer la petición capturada"
source "$FW/00_Config/lib/http_request.bash" 2>/dev/null

REQ="$TMPD/peticion_https.txt"
printf 'POST /api/login?next=%%2Fhome HTTP/1.1\r\nHost: app.example:8443\r\nCookie: sid=abc\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}' > "$REQ"
hr_load "$REQ"; eq "hr_load: acepta CRLF y CRLF final" "$?" "0"
eq "hr_load: método"        "$HR_METHOD" "POST"
eq "hr_load: target"        "$HR_TARGET" "/api/login?next=%2Fhome"
eq "hr_load: Host"          "$HR_HOST" "app.example:8443"
eq "hr_load: content-type"  "$HR_CT" "application/json"
eq "hr_load: cuerpo"        "$HR_BODY" "{}"
eq "hr_load: cabecera Cookie conservada" "$(printf '%s\n' "${HR_HEADERS[@]}" | grep -c '^Cookie: sid=abc')" "1"

eq "hr_scheme: 8443 es https"    "$(hr_scheme 8443)" "https"
eq "hr_scheme: 8080 es http"     "$(hr_scheme 8080)" "http"
eq "hr_port: del Host"           "$(hr_port https)" "8443"
eq "hr_url: host y puerto"       "$(hr_url app.example https)" "https://app.example:8443/api/login?next=%2Fhome"

REQ2="$TMPD/peticion_simple.txt"
printf 'GET /x HTTP/1.1\nHost: app.example\n\n' > "$REQ2"
hr_load "$REQ2"
eq "hr_port: sin puerto en Host y https" "$(hr_port https)" "443"
eq "hr_url: omite el puerto por defecto"  "$(hr_url app.example https)" "https://app.example/x"

REQ3="$TMPD/peticion_lc.txt"
printf 'POST /y HTTP/1.1\nHost: app.example\nContent-Length: 99\n\n{"a":1}' > "$REQ3"
hr_load "$REQ3" 2>"$TMPD/lc.err"
eq "hr_load: recalcula Content-Length" "$(printf '%s\n' "${HR_HEADERS[@]}" | grep -c '^Content-Length: 7$')" "1"
eq "hr_load: avisa del Content-Length mentiroso" "$(grep -c 'Content-Length' "$TMPD/lc.err")" "1"

printf 'POST /z HTTP/1.1\nHost: a\nTransfer-Encoding: chunked\n\n0\n' > "$TMPD/chunk.txt"
hr_load "$TMPD/chunk.txt" 2>/dev/null; eq "hr_load: rechaza chunked" "$?" "3"
printf 'POST /z HTTP/1.1\nHost: a\nContent-Type: multipart/form-data; boundary=x\n\n--x--' > "$TMPD/multi.txt"
hr_load "$TMPD/multi.txt" 2>/dev/null; eq "hr_load: rechaza multipart" "$?" "3"
printf 'no-es-una-peticion\n' > "$TMPD/malo.txt"
hr_load "$TMPD/malo.txt" 2>/dev/null; eq "hr_load: rechaza lo que no es petición" "$?" "2"

# ──────────────────────────────────────────────────────────
section "http_request: parámetros y sustitución"
REQF="$TMPD/form.txt"
printf 'POST /login HTTP/1.1\nHost: app.example\nContent-Type: application/x-www-form-urlencoded\n\nuser=ana&pass=x&remember=1' > "$REQF"
hr_load "$REQF"
eq "hr_params: formulario" "$(hr_params | tr '\n' ' ')" \
   "form|user|ana form|pass|x form|remember|1 "
eq "hr_body_with: sustituye un campo" "$(hr_body_with form pass PWNED)" "user=ana&pass=PWNED&remember=1"
eq "hr_target_with: sin query no cambia" "$(hr_target_with form pass PWNED)" "/login"

REQQ="$TMPD/query.txt"
printf 'GET /search?q=hola&page=2 HTTP/1.1\nHost: app.example\n\n' > "$REQQ"
hr_load "$REQQ"
eq "hr_params: query" "$(hr_params | tr '\n' ' ')" "query|q|hola query|page|2 "
eq "hr_target_with: sustituye en query" "$(hr_target_with query q hola2)" "/search?q=hola2&page=2"

if command -v python3 >/dev/null 2>&1; then
    REQJ="$TMPD/json.txt"
    printf 'POST /api HTTP/1.1\nHost: app.example\nContent-Type: application/json\n\n{"user":{"email":"a@b.c"},"n":7,"ok":true,"nulo":null}' > "$REQJ"
    hr_load "$REQJ"
    eq "hr_params: hojas JSON" "$(hr_params | tr '\n' ' ')" \
       "json|user.email|a@b.c json|n|7 json|ok|true json|nulo|null "
    eq "hr_body_with: sustituye hoja anidada" \
       "$(hr_body_with json user.email PWNED | python3 -c 'import json,sys; print(json.load(sys.stdin)["user"]["email"])')" "PWNED"
    eq "hr_body_with: número sustituido por cadena sigue siendo JSON válido" \
       "$(hr_body_with json n PWNED | python3 -c 'import json,sys; print(json.load(sys.stdin)["n"])')" "PWNED"

    REQM="$TMPD/jsonmalo.txt"
    printf 'POST /api HTTP/1.1\nHost: a\nContent-Type: application/json\n\n{"a":}' > "$REQM"
    hr_load "$REQM"; hr_params >/dev/null 2>&1
    eq "hr_params: JSON inválido no revienta" "$?" "5"
else
    echo "  SKIP     python3 no instalado: sin casos JSON"
fi

# ──────────────────────────────────────────────────────────
section "http_request: firma normalizada y señales"
printf '<html><input name="csrf" value="a1b2c3d4e5f6a7b8"><p>hola</p><span id="n">1717171717</span></html>' > "$TMPD/c1"
printf '<html><input name="csrf" value="9999888877776666"><p>hola</p><span id="n">1717179999</span></html>' > "$TMPD/c2"
eq "hr_signature: nonce y epoch no cambian la firma" \
   "$(hr_signature "$TMPD/c1" 200 96)" "$(hr_signature "$TMPD/c2" 200 96)"
sig=$(hr_signature "$TMPD/c1" 200 96)
eq "hr_signature: la firma no está vacía" "$([ -n "$sig" ] && echo si || echo no)" "si"
eq "hr_signature: formato codigo:tamano:md5" "$(printf '%s' "$sig" | cut -d: -f1-2)" "200:96"

printf '<p>tu busqueda: zq7xk1</p>' > "$TMPD/eco"
eq "hr_signature: el eco se neutraliza" \
   "$(hr_signature "$TMPD/eco" 200 22 zq7xk1)" "$(hr_signature "$TMPD/eco" 200 22 zq7xk1)"
printf '<p>tu busqueda: OTRO</p>' > "$TMPD/eco2"
eq "hr_signature: sin neutralizar, el eco difiere" \
   "$([ "$(hr_signature "$TMPD/eco" 200 22)" = "$(hr_signature "$TMPD/eco2" 200 22)" ] && echo igual || echo distinto)" "distinto"

printf '<div><script>alert(1)</script></div>' > "$TMPD/xss"
hr_unescaped "$TMPD/xss" '<script>alert(1)</script>'
eq "hr_unescaped: payload literal" "$?" "0"
printf '<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>' > "$TMPD/xss2"
hr_unescaped "$TMPD/xss2" '<script>alert(1)</script>'
eq "hr_unescaped: reflejo escapado no cuenta" "$?" "1"

printf 'You have an error in your SQL syntax near x' > "$TMPD/err"
eq "hr_db_error: detecta MySQL" "$(hr_db_error "$TMPD/err")" "MySQL"
printf '<p>todo bien</p>' > "$TMPD/ok"
hr_db_error "$TMPD/ok" >/dev/null; eq "hr_db_error: página normal no coincide" "$?" "1"

# ──────────────────────────────────────────────────────────
section "http_inject: arranque y guardas"
# Helper compartido por las secciones de las tareas 4-7
iniciar_servidor_http() {
    command -v python3 >/dev/null 2>&1 || return 1
    local p i
    p=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
    python3 "$FW/tests/fixtures/http_target.py" "$p" >/dev/null 2>&1 &
    HTTP_SRV_PID=$!
    for i in 1 2 3 4 5 6 7 8 9 10; do
        curl -s -o /dev/null "http://127.0.0.1:$p/safe" && break
        sleep 0.3
    done
    printf '%s\n' "$p"
}

if HPORT=$(iniciar_servidor_http); then
    export HTTP_INJECT_SI=1 HTTP_INJECT_UMBRAL=0.5

    # El directorio de configuración se puede aislar: sin esto, el aviso de
    # alcance dependería del scope.yaml real del operador.
    mkdir -p "$TMPD/conf"; printf 'scope:\n  allowed_hosts:\n    - 10.0.0.0/8\n' > "$TMPD/conf/scope.yaml"
    eq "session: SESSION_CONFIG_DIR se puede aislar" \
       "$(SESSION_CONFIG_DIR="$TMPD/conf" bash -c "source '$FW/00_Config/lib/session.bash'; printf '%s' \"\$SESSION_CONFIG_DIR\"")" "$TMPD/conf"

    printf 'GET /echo?q=hola HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_echo.txt"
    OUT=$(SESSION_CONFIG_DIR="$TMPD/conf" SESSION_FILE="$TMPD/.session" \
          bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_echo.txt" 127.0.0.1 2>&1)
    eq "http_inject: sale 0 con petición válida" "$?" "0"
    eq "http_inject: informa del objetivo" "$(printf '%s' "$OUT" | grep -q '127.0.0.1' && echo si || echo no)" "si"
    eq "http_inject: escribe el informe" "$(ls "$FW/../scans/web/"http_inject_127.0.0.1_"$HPORT".txt 2>/dev/null | wc -l | tr -d ' ')" "1"
    eq "http_inject: avisa si el objetivo está fuera de alcance" "$(printf '%s' "$OUT" | grep -ci 'alcance')" "1"

    printf 'GET /safe?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_safe.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_safe.txt" 127.0.0.1 2>&1)
    eq "http_inject: catch-all detectado" "$(printf '%s' "$OUT" | grep -ci 'catch-all')" "1"

    printf 'GET /echo HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_noparams.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_noparams.txt" 127.0.0.1 >/dev/null 2>&1
    eq "http_inject: sin parámetros sale 1" "$?" "1"

    printf 'POST /login HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"user":"ana"}' "$HPORT" > "$TMPD/req_post.txt"
    OUT=$(HTTP_INJECT_SI= bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_post.txt" 127.0.0.1 2>&1 <<< 'n')
    eq "http_inject: pide confirmación con POST" "$(printf '%s' "$OUT" | grep -c 'POST')" "1"
    eq "http_inject: si se niega, no envía nada" "$(printf '%s' "$OUT" | grep -ci 'cancelad\|no se ha enviado')" "1"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_post.txt" 127.0.0.1 2>&1)
    eq "http_inject: avisa de posible sesión caducada (401)" "$(printf '%s' "$OUT" | grep -ci 'sesi')" "1"

    printf 'GET /unstable?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_unstable.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_unstable.txt" 127.0.0.1 2>&1)
    eq "http_inject: avisa de línea base inestable" "$(printf '%s' "$OUT" | grep -ci 'inestable')" "1"

    eq "dangerous.txt incluye http_inject" "$(grep -cxF '05_Exploitation/web/http_inject.sh' "$FW/00_Config/lib/dangerous.txt")" "1"
    eq "http_inject se declara en modo slots" "$(bash -c "source '$FW/00_Config/lib/params.bash'; params_mode '$FW/05_Exploitation/web/http_inject.sh'")" "slots"
    kill "$HTTP_SRV_PID" 2>/dev/null
    rm -f "$FW/../scans/web/http_inject_127.0.0.1_"*.txt
else
    echo "  SKIP     python3 no instalado: sin servidor de prueba"
fi

# ──────────────────────────────────────────────────────────
section "http_inject: SQLi por niveles"
if HPORT=$(iniciar_servidor_http); then
    export HTTP_INJECT_SI=1 HTTP_INJECT_UMBRAL=0.5
    printf 'GET /sqli?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_sqli.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_sqli.txt" 127.0.0.1 >/dev/null 2>&1
    TSV="$FW/../scans/web/http_inject_127.0.0.1_"$HPORT".tsv"
    eq "sqli: par booleano es CONFIRMADO" "$(awk -F'\t' '$1=="CONFIRMADO" && $3=="sqli_bool"' "$TSV" | wc -l | tr -d ' ')" "1"
    eq "sqli: el par booleano va marcado como tal" "$(cut -f4 "$TSV" | grep -c "AND '1'='2")" "1"

    printf 'GET /err?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_err.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_err.txt" 127.0.0.1 >/dev/null 2>&1
    eq "sqli: error de BD es FUERTE, no CONFIRMADO" "$(awk -F'\t' '$1=="FUERTE" && $3=="sqli_error"' "$TSV" | wc -l | tr -d ' ')" "1"
    eq "sqli: el error no se declara confirmado" "$(awk -F'\t' '$1=="CONFIRMADO" && $3=="sqli_error"' "$TSV" | wc -l | tr -d ' ')" "0"

    printf 'GET /time?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_time.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_time.txt" 127.0.0.1 2>&1)
    eq "sqli: retardo confirmado en los dos payloads de sueño" "$(awk -F'\t' '$1=="CONFIRMADO" && $3=="sqli_time"' "$TSV" | wc -l | tr -d ' ')" "2"
    eq "sqli: resume confirmados en consola" "$(printf '%s' "$OUT" | grep -c '2 confirmados')" "1"

    # El falso positivo del 31: un parámetro que solo refleja no es SQLi.
    printf 'GET /echo?q=hola HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_echo3.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_echo3.txt" 127.0.0.1 >/dev/null 2>&1
    eq "sqli: un parámetro que solo refleja no da SQLi confirmada" \
       "$(awk -F'\t' '$1=="CONFIRMADO" && $3 ~ /^sqli/' "$TSV" | wc -l | tr -d ' ')" "0"
    rm -f "$FW/../scans/web/http_inject_127.0.0.1_"*
    kill "$HTTP_SRV_PID" 2>/dev/null
else
    echo "  SKIP     python3 no instalado"
fi

# ──────────────────────────────────────────────────────────
section "http_inject: XSS, comandos y SSTI"
if HPORT=$(iniciar_servidor_http); then
    export HTTP_INJECT_SI=1 HTTP_INJECT_UMBRAL=0.5
    TSV="$FW/../scans/web/http_inject_127.0.0.1_"$HPORT".tsv"
    printf 'GET /xss?q=hola HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_xss.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_xss.txt" 127.0.0.1 >/dev/null 2>&1
    eq "xss: los tres payloads reflejados sin escapar son CONFIRMADO" "$(awk -F'\t' '$1=="CONFIRMADO" && $3=="xss"' "$TSV" | wc -l | tr -d ' ')" "3"

    printf 'GET /esc?q=hola HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_esc.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_esc.txt" 127.0.0.1 >/dev/null 2>&1
    eq "xss: reflejo escapado se queda en FUERTE" "$(awk -F'\t' '$1=="FUERTE" && $3=="xss"' "$TSV" | wc -l | tr -d ' ')" "3"
    eq "xss: reflejo escapado no es CONFIRMADO" "$(awk -F'\t' '$1=="CONFIRMADO" && $3=="xss"' "$TSV" | wc -l | tr -d ' ')" "0"

    printf 'GET /echo?q=hola HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_echo2.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_echo2.txt" 127.0.0.1 >/dev/null 2>&1
    eq "cmd: sin retardo no hay hallazgo" "$(awk -F'\t' '$3=="cmd"' "$TSV" | wc -l | tr -d ' ')" "0"
    eq "ssti: sin 49 no hay hallazgo" "$(awk -F'\t' '$3=="ssti"' "$TSV" | wc -l | tr -d ' ')" "0"

    printf 'GET /cmd?c=hola HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_cmd.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_cmd.txt" 127.0.0.1 >/dev/null 2>&1
    eq "cmd: los cuatro payloads con retardo son CONFIRMADO" "$(awk -F'\t' '$1=="CONFIRMADO" && $3=="cmd"' "$TSV" | wc -l | tr -d ' ')" "4"

    printf 'GET /ssti?name=x HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_ssti.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_ssti.txt" 127.0.0.1 >/dev/null 2>&1
    eq "ssti: 49 es CONFIRMADO" "$(awk -F'\t' '$1=="CONFIRMADO" && $3=="ssti"' "$TSV" | wc -l | tr -d ' ')" "1"

    # Testigo de la tarea 4: con payloads reales, el catch-all sigue sin confirmar nada.
    printf 'GET /safe?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_safe3.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_safe3.txt" 127.0.0.1 >/dev/null 2>&1
    eq "catch-all: ningún hallazgo CONFIRMADO" "$(awk -F'\t' '$1=="CONFIRMADO"' "$TSV" | wc -l | tr -d ' ')" "0"
    rm -f "$FW/../scans/web/http_inject_127.0.0.1_"*
    kill "$HTTP_SRV_PID" 2>/dev/null
else
    echo "  SKIP     python3 no instalado"
fi

# ──────────────────────────────────────────────────────────
section "http_inject: evidencia y resumen"
if HPORT=$(iniciar_servidor_http); then
    export HTTP_INJECT_SI=1 HTTP_INJECT_UMBRAL=0.5
    printf 'GET /sqli?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_ev.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_ev.txt" 127.0.0.1 >/dev/null 2>&1
    EV="$FW/../scans/web/http_inject_127.0.0.1_"$HPORT
    eq "evidencia: hay pares .req" "$(ls "$EV"/*.req 2>/dev/null | wc -l | tr -d ' ' | awk '{print ($1>0)}')" "1"
    eq "evidencia: hay pares .resp" "$(ls "$EV"/*.resp 2>/dev/null | wc -l | tr -d ' ' | awk '{print ($1>0)}')" "1"
    eq "evidencia: el .req lleva la línea de petición" "$(head -1 "$(ls "$EV"/*.req | head -1)" | grep -c '^GET /sqli')" "1"
    eq "evidencia: el .resp no pasa de 64 KB" "$(find "$EV" -name '*.resp' -size +64k | wc -l | tr -d ' ')" "0"
    eq "contexto: el directorio de evidencia guarda el esquema" "$(grep -cx 'esquema=http' "$EV/contexto.txt" 2>/dev/null)" "1"
    eq "contexto: guarda el Host enviado" "$(grep -c '^host=127.0.0.1:' "$EV/contexto.txt" 2>/dev/null)" "1"
    eq "contexto: guarda el método" "$(grep -cx 'metodo=GET' "$EV/contexto.txt" 2>/dev/null)" "1"

    OUT=$(HTTP_INJECT_NIVEL=fuertes bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_ev.txt" 127.0.0.1 2>&1)
    eq "filtro fuertes: la consola omite los débiles" "$(printf '%s' "$OUT" | grep -c 'DEBIL')" "0"
    eq "filtro fuertes: la consola sigue mostrando lo confirmado" "$(printf '%s' "$OUT" | grep -c 'CONFIRMADO')" "1"
    TSV="$FW/../scans/web/http_inject_127.0.0.1_"$HPORT".tsv"
    eq "filtro fuertes: el fichero conserva lo confirmado" "$(awk -F'\t' '$1=="CONFIRMADO"' "$TSV" | wc -l | tr -d ' ' | awk '{print ($1>0)}')" "1"
    eq "resumen: cuenta por nivel" "$(printf '%s' "$OUT" | grep -cE '[0-9]+ confirmado')" "1"
    rm -rf "$FW/../scans/web/http_inject_127.0.0.1_"*
    kill "$HTTP_SRV_PID" 2>/dev/null
else
    echo "  SKIP     python3 no instalado"
fi

# ──────────────────────────────────────────────────────────
section "burp_launcher: puerto, config y PID"
BSTUB="$TMPD/bin"; mkdir -p "$BSTUB"
cat > "$BSTUB/burpsuite" <<'EOS'
#!/bin/bash
printf '%s\n' "$*" >> "${BSTUB_LOG:-/dev/null}"
if [ -n "${BSTUB_BIND:-}" ]; then
    exec python3 -c 'import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(5); time.sleep(30)' "$BSTUB_BIND"
fi
sleep 30
EOS
chmod +x "$BSTUB/burpsuite"
export BSTUB_LOG="$TMPD/burp_llamadas.txt" BSTUB_BIND=""
: > "$BSTUB_LOG"

export SESSION_FILE="$TMPD/.session"; printf '127.0.0.1\n' > "$SESSION_FILE"
OUT=$(PATH="$BSTUB:$PATH" BURP_LAUNCHER_ESPERA=2 bash "$FW/03_Scanners/web_scanners/burpsuite/burp_launcher.sh" 8099 2>&1)
sleep 0.5   # el stub corre en segundo plano
eq "launcher: llama al wrapper, no a java -jar" "$(grep -c . "$BSTUB_LOG")" "1"
eq "launcher: pasa --project-file" "$(grep -c -- '--project-file' "$BSTUB_LOG")" "1"
eq "launcher: escribe el config con el puerto" "$(grep -c '"listener_port":8099' "$FW/../scans/burp/config_127.0.0.1.json")" "1"
eq "launcher: guarda el PID" "$([ -s "$FW/../scans/burp/burp.pid" ] && echo 1)" "1"
eq "launcher: --estado informa del PID" "$(PATH="$BSTUB:$PATH" bash "$FW/03_Scanners/web_scanners/burpsuite/burp_launcher.sh" --estado 2>&1 | grep -c 'PID')" "1"
PATH="$BSTUB:$PATH" bash "$FW/03_Scanners/web_scanners/burpsuite/burp_launcher.sh" --parar >/dev/null 2>&1
eq "launcher: --parar borra el PID" "$([ -f "$FW/../scans/burp/burp.pid" ] && echo queda || echo borrado)" "borrado"

# Puerto ocupado: elige otro
python3 -c 'import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",8080));s.listen(1);time.sleep(8)' &
OCC=$!; sleep 1
: > "$BSTUB_LOG"
PATH="$BSTUB:$PATH" BURP_LAUNCHER_ESPERA=2 bash "$FW/03_Scanners/web_scanners/burpsuite/burp_launcher.sh" >/dev/null 2>&1
eq "launcher: con 8080 ocupado no usa 8080" "$(grep -c '"listener_port":8080' "$FW/../scans/burp/config_127.0.0.1.json")" "0"
kill $OCC 2>/dev/null
PATH="$BSTUB:$PATH" bash "$FW/03_Scanners/web_scanners/burpsuite/burp_launcher.sh" --parar >/dev/null 2>&1
rm -rf "$FW/../scans/burp" "$BSTUB"

# ──────────────────────────────────────────────────────────
section "burp_launcher: espera, captura y explicación"
BSTUB="$TMPD/bin"; mkdir -p "$BSTUB"
# burpsuite falso que SÍ abre el puerto indicado en el config
cat > "$BSTUB/burpsuite" <<'EOS'
#!/bin/bash
CFG=""; while [ $# -gt 0 ]; do
    case "$1" in
        --config-file=*) CFG="${1#*=}" ;;
        --config-file)   CFG="$2"; shift ;;
    esac
    shift
done
PORT=$(grep -o '"listener_port":[0-9]*' "$CFG" 2>/dev/null | cut -d: -f2)
exec python3 -c 'import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(5); time.sleep(20)' "$PORT"
EOS
chmod +x "$BSTUB/burpsuite"
export SESSION_FILE="$TMPD/.session"; printf '127.0.0.1\n' > "$SESSION_FILE"
OUT=$(PATH="$BSTUB:$PATH" BURP_LAUNCHER_ESPERA=10 bash "$FW/03_Scanners/web_scanners/burpsuite/burp_launcher.sh" 8090 2>&1)
eq "launcher: detecta el puerto cuando escucha" "$(printf '%s' "$OUT" | grep -c 'Burp escucha')" "1"
eq "launcher: explica el flujo manual" "$(printf '%s' "$OUT" | grep -ci 'Repeater')" "1"
eq "launcher: imprime el comando de http_inject" "$(printf '%s' "$OUT" | grep -c 'http_inject.sh')" "1"
eq "launcher: avisa de que Community no guarda el proyecto" "$(printf '%s' "$OUT" | grep -ci 'no guarda' )" "1"
PATH="$BSTUB:$PATH" bash "$FW/03_Scanners/web_scanners/burpsuite/burp_launcher.sh" --parar >/dev/null 2>&1

# El config se ignora y el puerto no escucha: no aborta, guía
cat > "$BSTUB/burpsuite" <<'EOS'
#!/bin/bash
sleep 5
EOS
chmod +x "$BSTUB/burpsuite"
OUT=$(PATH="$BSTUB:$PATH" BURP_LAUNCHER_ESPERA=2 bash "$FW/03_Scanners/web_scanners/burpsuite/burp_launcher.sh" 8091 2>&1)
eq "launcher: si no escucha, guía en vez de abortar" "$(printf '%s' "$OUT" | grep -ci 'Settings.*Proxy')" "1"
eq "launcher: si no escucha, no miente sobre la captura" "$(printf '%s' "$OUT" | grep -ci 'verificad')" "0"
PATH="$BSTUB:$PATH" bash "$FW/03_Scanners/web_scanners/burpsuite/burp_launcher.sh" --parar >/dev/null 2>&1
rm -rf "$FW/../scans/burp" "$BSTUB"

# ──────────────────────────────────────────────────────────
section "http_inject: guardas que pide la revisión"
if HPORT=$(iniciar_servidor_http); then
    export HTTP_INJECT_SI=1 HTTP_INJECT_UMBRAL=0.5
    TSV="$FW/../scans/web/http_inject_127.0.0.1_"$HPORT".tsv"

    printf 'GET /mostrar49?x=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req49.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req49.txt" 127.0.0.1 >/dev/null 2>&1
    eq "ssti: un 49 que ya estaba en la línea base no confirma" "$(awk -F'\t' '$1=="CONFIRMADO" && $3=="ssti"' "$TSV" | wc -l | tr -d ' ')" "0"

    printf 'GET /caduca?x=1 HTTP/1.1\nHost: 127.0.0.1:%s\nCookie: sid=ok\n\n' "$HPORT" > "$TMPD/reqcad.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/reqcad.txt" 127.0.0.1 2>&1)
    eq "sesión: avisa de que caducó a mitad" "$(printf '%s' "$OUT" | grep -ci 'caducada' )" "1"
    eq "sesión: no inventa hallazgos con 401" "$(awk -F'\t' '$1=="FUERTE" || $1=="CONFIRMADO"' "$TSV" | wc -l | tr -d ' ')" "0"

    printf 'GET /sqli?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/reqmax.txt"
    OUT=$(HTTP_INJECT_MAX=5 bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/reqmax.txt" 127.0.0.1 2>&1)
    eq "tope: avisa al alcanzarlo" "$(printf '%s' "$OUT" | grep -ci 'tope' )" "1"
    eq "tope: dice cuántos parámetros quedaron sin probar" "$(printf '%s' "$OUT" | grep -c '0 de 1' )" "1"
    eq "tope: no anuncia hallazgos" "$(awk -F'\t' '$1=="FUERTE" || $1=="CONFIRMADO"' "$TSV" | wc -l | tr -d ' ')" "0"

    printf 'GET /sqli?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\nCookie: a=b\n\n' "$HPORT" > "$TMPD/reqev2.txt"
    bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/reqev2.txt" 127.0.0.1 >/dev/null 2>&1
    EV="$FW/../scans/web/http_inject_127.0.0.1_"$HPORT
    eq "evidencia: una sola cabecera Host en el .req" "$(grep -c '^Host:' "$(ls "$EV"/*.req | head -1)")" "1"

    printf 'POST /pedido HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"qty":1,"sku":"A1"}' "$HPORT" > "$TMPD/reqjson.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/reqjson.txt" 127.0.0.1 2>&1)
    eq "catch-all: no se inventa en un POST JSON" "$(printf '%s' "$OUT" | grep -ci 'catch-all')" "0"

    printf 'GET /muere?x=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/reqmuere.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/reqmuere.txt" 127.0.0.1 2>&1)
    eq "red: avisa cuando el servidor deja de responder" "$(printf '%s' "$OUT" | grep -ci 'sin respuesta\|no responde' )" "1"
    eq "red: no puntúa una respuesta 000" "$(awk -F'\t' '$5=="000"' "$TSV" | wc -l | tr -d ' ')" "0"

    printf 'POST /pedido?debug=1 HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"qty":1}' "$HPORT" > "$TMPD/reqnopy.txt"
    OUT=$(HTTP_REQUEST_PYTHON=python-inexistente bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/reqnopy.txt" 127.0.0.1 2>&1)
    eq "sin python3: avisa de que el JSON se omite" "$(printf '%s' "$OUT" | grep -ci 'json' )" "1"
    eq "sin python3: sigue probando la query" "$(printf '%s' "$OUT" | grep -c 'debug (query)' )" "1"

    eq "hr_signature: neutraliza la comilla escapada &#x27;" \
       "$(printf '<p>a &#x27; b</p>' > "$TMPD/e1"; printf '<p>a &#39; b</p>' > "$TMPD/e2"; \
         [ "$(hr_signature "$TMPD/e1" 200 30 "'")" = "$(hr_signature "$TMPD/e2" 200 30 "'")" ] && echo igual || echo distinto)" "igual"

    rm -rf "$FW/../scans/web/http_inject_127.0.0.1_"*
    kill "$HTTP_SRV_PID" 2>/dev/null
else
    echo "  SKIP     python3 no instalado"
fi

# ──────────────────────────────────────────────────────────
section "http_inject: freno por 429/503"
if HPORT=$(iniciar_servidor_http); then
    export HTTP_INJECT_SI=1 HTTP_INJECT_UMBRAL=0.5 HTTP_INJECT_ESPERA=0
    TSV="$FW/../scans/web/http_inject_127.0.0.1_"$HPORT".tsv"

    printf 'GET /frena?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_frena.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_frena.txt" 127.0.0.1 2>&1); RC=$?
    eq "freno: un 429 se reintenta y la tanda termina" "$RC" "0"
    eq "freno: avisa de que reintenta" "$(printf '%s' "$OUT" | grep -ci 'reintent')" "1"
    eq "freno: el 429 no se puntúa" "$(awk -F'\t' '$5=="429"' "$TSV" | wc -l | tr -d ' ')" "0"

    printf 'GET /frena-fecha?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_frenaf.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_frenaf.txt" 127.0.0.1 2>&1); RC=$?
    eq "freno: Retry-After en fecha HTTP no rompe" "$RC" "0"
    eq "freno: fecha pasada no hace esperar" "$(printf '%s' "$OUT" | grep -ci 'reintent')" "1"

    printf 'GET /frena-largo?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_frenal.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_frenal.txt" 127.0.0.1 2>&1); RC=$?
    eq "freno: pide más del tope y se corta sin dormir" "$(printf '%s' "$OUT" | grep -ci 'no se reintenta\|supera' )" "1"
    eq "freno: por encima del tope sale 1" "$RC" "1"

    printf 'GET /frena-luego?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_frena2.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_frena2.txt" 127.0.0.1 2>&1); RC=$?
    eq "freno: si insiste, corta la tanda" "$RC" "1"
    eq "freno: el corte se anuncia" "$(printf '%s' "$OUT" | grep -ci 'frenando' )" "1"
    eq "freno: tras el corte no hay hallazgos" "$(awk -F'\t' '$1=="FUERTE" || $1=="CONFIRMADO"' "$TSV" | wc -l | tr -d ' ')" "0"

    printf 'GET /frena-base?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$HPORT" > "$TMPD/req_frenab.txt"
    OUT=$(bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_frenab.txt" 127.0.0.1 2>&1); RC=$?
    eq "freno: en la línea base lo dice" "$(printf '%s' "$OUT" | grep -ci 'antes de empezar' )" "1"
    eq "freno: línea base frenada sale 1" "$RC" "1"
    eq "freno: línea base frenada no puntúa" "$(awk -F'\t' '$1=="FUERTE" || $1=="CONFIRMADO"' "$TSV" | wc -l | tr -d ' ')" "0"

    rm -rf "$FW/../scans/web/http_inject_127.0.0.1_"*
    unset HTTP_INJECT_ESPERA
    kill "$HTTP_SRV_PID" 2>/dev/null
else
    echo "  SKIP     python3 no instalado"
fi

# ──────────────────────────────────────────────────────────
section "sqlmap_request: entrada, objetivo y permisos"
SSTUB="$(mktemp -d)"
cat > "$SSTUB/sqlmap" <<'EOS'
#!/bin/bash
printf '%s\n' "$*" >> "${SSTUB_LOG:-/dev/null}"
case " $* " in
    *" --dbs "*)      echo "[INFO] available databases [1]:"; echo "[*] clientes" ;;
    *" --tables "*)   echo "Database: clientes"; echo "[2 tables]"; echo "| clientes |"; echo "| pedidos |" ;;
    *" --dump "*)     echo "Table: clientes"; echo "| 1 | ana |"; echo "| 2 | luis |" ;;
    *)                echo "[INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable" ;;
esac
exit 0
EOS
chmod +x "$SSTUB/sqlmap"
export SSTUB_LOG="$TMPD/sqlmap_llamadas.txt"; : > "$SSTUB_LOG"
export SQLMAP_SI=1

printf 'GET /?id=1 HTTP/1.1\nHost: 127.0.0.1:18001\n\n' > "$TMPD/req_sm.req"
OUT=$(PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1)
eq "sqlmap_request: pasa --ignore-stdin" "$(grep -c -- '--ignore-stdin' "$SSTUB_LOG")" "1"
eq "sqlmap_request: exige --batch" "$(grep -c -- '--batch' "$SSTUB_LOG")" "1"
eq "sqlmap_request: technique B por defecto" "$(grep -c -- '--technique=B\b' "$SSTUB_LOG")" "1"
eq "sqlmap_request: escribe el resumen" "$(find "$FW/../scans/sqlmap" -name '*.txt' | wc -l | tr -d ' ')" "1"

# Sin sqlmap instalado: error explícito, no "no inyectable". Se le da un PATH
# mínimo (solo dirname, que es lo único que el script usa antes de comprobar
# la herramienta) porque con el PATH real sqlmap siempre aparece.
mkdir -p "$TMPD/minbin"
ln -sf "$(command -v dirname)" "$TMPD/minbin/dirname" 2>/dev/null
BASHBIN=$(command -v bash)
OUT=$(PATH="$TMPD/minbin" "$BASHBIN" "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1); RC=$?
eq "sqlmap_request: sin sqlmap lo dice" "$(printf '%s' "$OUT" | grep -ci 'no está instalado\|no se encuentra' )" "1"
eq "sqlmap_request: sin sqlmap sale 1" "$RC" "1"

# Entrada estándar: "-" lee la petición y la deja en un temporal
: > "$SSTUB_LOG"
printf 'GET /?id=1 HTTP/1.1\nHost: 127.0.0.1:18001\n\n' | PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" - >/dev/null 2>&1
eq "sqlmap_request: '-' lee de la entrada estándar" "$(grep -c -- '--batch' "$SSTUB_LOG")" "1"

# Directorio: un sqlmap por .req y ficheros que no se pisan
mkdir -p "$TMPD/ev"; cp "$TMPD/req_sm.req" "$TMPD/ev/001_id_sqli_bool.req"; cp "$TMPD/req_sm.req" "$TMPD/ev/002_q_xss.req"
: > "$SSTUB_LOG"
PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/ev" >/dev/null 2>&1
eq "sqlmap_request: directorio = un sqlmap por fichero" "$(grep -c -- '--batch' "$SSTUB_LOG")" "2"
eq "sqlmap_request: dos logs, uno por fichero" "$(find "$FW/../scans/sqlmap/127.0.0.1_18001" -name '*.log' | wc -l | tr -d ' ')" "2"
eq "sqlmap_request: un solo resumen para la tanda" "$(find "$FW/../scans/sqlmap" -name '*.txt' | wc -l | tr -d ' ')" "1"

# POST: pide confirmación y, si se niega, no llama a sqlmap
: > "$SSTUB_LOG"
printf 'POST /login HTTP/1.1\nHost: 127.0.0.1:18001\nContent-Type: application/json\n\n{"user":"ana"}' > "$TMPD/req_sm_post.req"
OUT=$(SQLMAP_SI= PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm_post.req" 2>&1 <<< 'n')
eq "sqlmap_request: POST pide confirmación" "$(printf '%s' "$OUT" | grep -ci 'repetir\|confirm' )" "1"
eq "sqlmap_request: si se niega, no ejecuta sqlmap" "$(wc -l < "$SSTUB_LOG" | tr -d ' ')" "0"

# Host reescrito: conserva el puerto del .req
printf 'GET /?id=1 HTTP/1.1\nHost: app.inventado.example:8443\n\n' > "$TMPD/req_sm_vhost.req"
PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm_vhost.req" 10.0.0.5 >/dev/null 2>&1
eq "sqlmap_request: el Host reescrito conserva el puerto" \
   "$(grep -ho 'Host: 10\.0\.0\.5:[0-9]*' "$FW/../scans/sqlmap/"*/copia_*.req 2>/dev/null | head -1 | grep -c ':8443')" "1"

unset SQLMAP_SI
rm -rf "$FW/../scans/sqlmap" "$SSTUB"

rm -rf "$TMPD"
printf '\n────────────────────────────────────────\n'
printf 'pasan: %s   fallan: %s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
