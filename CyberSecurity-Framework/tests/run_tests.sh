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
eq "114 scripts .sh en el framework" "$total" "114"
eq "la librería no se cuenta como script" "$(find "$FW/00_Config/lib" -name '*.sh' | wc -l | tr -d ' ')" "0"

dos=0
oblig=0
for f in $(find "$FW" -name '*.sh' -type f -not -path "$FW/tests/*" | sort); do
    n=$(params_slot_count "$f")
    [ "$n" -ge 2 ] && dos=$((dos + 1))
    o=$(params_slots "$f" | awk -F'|' '$3=="obligatorio"' | wc -l | tr -d ' ')
    [ "$o" -ge 2 ] && oblig=$((oblig + 1))
done
eq "36 scripts con 2+ huecos" "$dos" "36"
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

PATH="$STUBD:$PATH"
export STUB_CODE=200 STUB_SIZE=433
eq "baseline con catch-all" "$(scans_baseline_size https://x/)" "433"
export STUB_CODE=404 STUB_SIZE=0
eq "baseline sin catch-all" "$(scans_baseline_size https://x/)" "0"
export STUB_CODE=200 STUB_SIZE=433
eq "signature devuelve código:tamaño" "$(scans_signature https://x/)" "200:433"

rm -rf "$STUBD" "$(scans_dir pruebatool)"

# ──────────────────────────────────────────────────────────
section "Librería: portable bajo zsh"
if command -v zsh >/dev/null 2>&1; then
    for par in "session:SESSION_LIB_DIR" "params:PARAMS_LIB_DIR" "phase_status:PHASE_LIB_DIR" "prompt:PROMPT_LIB_DIR" "scans:SCANS_LIB_DIR"; do
        libf="${par%%:*}"; var="${par##*:}"
        got=$(zsh -c "cd '$FW' && source '00_Config/lib/$libf.bash' >/dev/null 2>&1; printf '%s' \"\${$var}\"" 2>/dev/null)
        eq "zsh: $libf.bash resuelve bajo 00_Config/lib" "$got" "$FW/00_Config/lib"
    done
    rm -f "$FW/../.session"
    zsh -c "cd '$FW'; unset SESSION_FILE SESSION_TARGETS_FILE; source '00_Config/lib/session.bash' >/dev/null 2>&1; session_set_target prueba.example >/dev/null 2>&1" 2>/dev/null
    [ -f "$FW/../.session" ] && bad "zsh: .session no debe acabar en la raíz del repo" || ok "zsh: .session no acaba en la raíz del repo"
    rm -f "$FW/../.session"
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

rm -f "$WOUT"/headers_192.0.2.1_443.txt "$WOUT"/headers_192.0.2.2_443.txt "$WOUT"/headers_192.0.2.3_443.txt
rm -f "$WOUT"/ffuf_192.0.2.*
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
SQLOUT="$FW/../scans/web/sqli_findings.txt"
QSTUB="$(mktemp -d)"
printf '#!/bin/bash\nexit 0\n' > "$QSTUB/sqlmap"
chmod +x "$QSTUB/sqlmap"

# Escenario 1: servidor catch-all, toda respuesta idéntica
printf '#!/bin/bash\necho "200:433"\n' > "$QSTUB/curl"
chmod +x "$QSTUB/curl"
rm -f "$SQLOUT"
PATH="$QSTUB:$PATH" bash "$SQLI" 192.0.2.1 443 / >/dev/null 2>&1
N1=$([ -f "$SQLOUT" ] && wc -l < "$SQLOUT" || echo 0)
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
rm -f "$SQLOUT"
PATH="$QSTUB:$PATH" bash "$SQLI" 192.0.2.1 443 / >/dev/null 2>&1
N2=$([ -f "$SQLOUT" ] && wc -l < "$SQLOUT" || echo 0)
if [ "$N2" -ge 1 ]; then ok "sqli: detecta la diferencia real ($N2)"; else bad "sqli: no detectó la diferencia real" "obtenido $N2"; fi

rm -f "$SQLOUT"
rm -rf "$QSTUB"

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

# ──────────────────────────────────────────────────────────
section "run_all_scanners: resumen de logs con errores"
RSTUB="$(mktemp -d)"
for t in nmap masscan nikto nuclei rustscan whatweb ffuf; do
    printf '#!/bin/bash\nexit 0\n' > "$RSTUB/$t"
    chmod +x "$RSTUB/$t"
done
mkdir -p "$FW/../scans/nmap" "$FW/../scans/nikto"
RBAK=""
for l in nmap nikto; do
    if [[ -f "$FW/../scans/$l/errores.log" ]]; then
        mv "$FW/../scans/$l/errores.log" "$TMPD/$l.errores.bak"
        RBAK="$RBAK $l"
    fi
done
echo "fallo simulado de nmap" > "$FW/../scans/nmap/errores.log"
: > "$FW/../scans/nikto/errores.log"

PATH="$RSTUB:$PATH" bash "$FW/03_Scanners/run_all_scanners.sh" prueba.example > "$TMPD/scan_all" 2>&1
# El hijo ya anuncia su propio log con "⚠️  Errores registrados en:", así que el
# aserto no puede ser "la ruta aparece": tiene que ser la línea del resumen.
eq "run_all_scanners: resume el log con contenido" "$(grep -cE '^  ⚠️  .*/scans/nmap/errores\.log \([0-9]+ líneas?\)' "$TMPD/scan_all")" "1"
eq "run_all_scanners: no resume un log vacío"     "$(grep -cE '/scans/nikto/errores\.log \(' "$TMPD/scan_all")" "0"

rm -f "$FW/../scans/nmap/errores.log" "$FW/../scans/nikto/errores.log"
for l in $RBAK; do mv "$TMPD/$l.errores.bak" "$FW/../scans/$l/errores.log"; done
rm -rf "$RSTUB"

# ──────────────────────────────────────────────────────────
section "ffuf: contar hallazgos, no la url de la configuración"
source "$FW/00_Config/lib/scans.bash" 2>/dev/null
FFJ="$TMPD/ffuf.json"
printf '%s' '{"commandline":"ffuf -u http://x/FUZZ","results":[],"config":{"url":"http://x/FUZZ"}}' > "$FFJ"
eq "ffuf: cero hallazgos es cero" "$(scans_ffuf_count "$FFJ")" "0"
printf '%s' '{"results":[{"position":10,"url":"http://x/a"},{"position":20,"url":"http://x/b"}],"config":{"url":"http://x/FUZZ"}}' > "$FFJ"
eq "ffuf: dos hallazgos son dos"  "$(scans_ffuf_count "$FFJ")" "2"
eq "ffuf: fichero ilegible es cero" "$(scans_ffuf_count "$TMPD/no-existe.json")" "0"

rm -rf "$TMPD"
printf '\n────────────────────────────────────────\n'
printf 'pasan: %s   fallan: %s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
