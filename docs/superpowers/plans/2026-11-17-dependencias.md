# Comprobación e instalación de dependencias (tecla `D`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `D` option to `cyber_framework.sh`'s main menu that shows, grouped by module, whether every binary the framework already checks (plus `rustscan`/`volatility3`/`foremost`/`nmap-vulners`/`zaproxy`) is installed, and lets the user pick which of the missing-with-apt-package ones to install with one confirmation and one `apt-get install`.

**Architecture:** A new sourced library `00_Config/lib/dependencies.bash` holds the binary→package/no-apt/group data and three pure functions (one check, one read-only status report, one read-only "what's missing and installable" list). `cyber_framework.sh` gets a `dependencies_menu()` function — same shape as the existing `keys_menu()` — that displays the status, numbers the installable-missing list, reads a selection, and calls a fourth library function that does the single confirmation + single `sudo apt-get install -y`.

**Tech Stack:** Bash only (no Python — see the spec's "Approaches" section for why). Tests use the same `ok`/`ko`/`eq` bash-assertion harness as `tests/run_keys.sh`, plus a closed-`PATH` stub sandbox (via `env PATH=... bash -c '...'`) for anything that would otherwise touch `sudo`/`apt-get`.

**Spec:** `docs/superpowers/specs/2026-11-17-dependencias-design.md` — read it in full before starting; this plan does not repeat its rationale, only the values and interfaces it pins.

## Global Constraints

- Only `apt`. Never `pip`, `cargo`, `go install`, Docker, or a GitHub binary — binaries with no apt package (`sdptool`, `gatttool`, `avml`, `lime`, `volatility` v2, and the non-binary `nmap-vulners`) are reported, never installed.
- No `set -e` anywhere; every install attempt propagates its own exit code and real `stderr` (never `2>/dev/null` on the install call itself).
- No coordination with `08_Forensics/requirements.sh --install` — known, accepted duplication (spec Non-goals). Do not modify `requirements.sh` or its tests.
- The `D` key must not collide with an existing one (confirmed free: `cyber_framework.sh` has no `D|d)` case arm today).
- Tests must run with no network access and without invoking the real `sudo`/`apt-get` — use a closed `PATH` (a temp dir containing only the stubs the test supplies), never a `PATH` prepend, for any assertion that exercises the install path.
- Visual style matches `keys_menu()`: `${CYAN}${BOLD}`/`${GREEN}`/`${DIM}`/`${RED}` from the colors already defined in `cyber_framework.sh`, `clear_screen`, `pause`, and `0` to go back.
- `zaproxy` is included in the data table now, per explicit user instruction, even though no scanner uses it yet (OWASP ZAP integration itself is out of scope for this plan).

## Review Focus

- **A binary checked by more than one existing module (e.g. `nmap`, `python3`, `curl`) must appear exactly once in the status report**, not once per module — the spec's anti-goal is a misleading aggregated view; a reasonable person expects a dependency list without duplicates. Covered in Task 2's status-report tests.
- **A binary with no apt package (`avml`, `lime`, `sdptool`, `gatttool`, `volatility`, `nmap-vulners`) must never appear in the numbered installable list**, even though it shows as `✗` in the status — a user picking "install everything shown as missing" by number must physically be unable to select one of these. Covered in Task 3's tests.
- **Selecting an out-of-range number, garbage input, or `0`/`!` on the install prompt must cancel without calling `apt-get`, not install everything or crash** — a reasonable person expects a typo to be safe, not destructive. Covered in Task 5's menu tests.
- **A declined confirmation (anything other than the literal word `instalar`) must never invoke `apt-get`, including on empty input / EOF** — the spec requires "una sola confirmación" to actually gate the install, mirroring `requirements.sh`'s own `test_install_denied_or_eof_has_no_effect`. Covered in Task 4's tests.
- **Two binaries that share one apt package (`airodump-ng`/`aireplay-ng`/`aircrack-ng` → `aircrack-ng`) must collapse to one numbered entry, and installing it must run `apt-get install` with that package name once, not three times** — a reasonable person who sees "3 missing" would be confused by `apt-get install -y aircrack-ng aircrack-ng aircrack-ng`. Covered in Task 3 (dedup) and Task 4 (install call shape) tests.

---

## File Structure

- **Create** `00_Config/lib/dependencies.bash` — data tables + the four library functions (check, status, list-missing, install). No UI beyond what `dependencies_status()` itself prints (it IS the display, like `keys_helper estado`).
- **Create** `tests/run_dependencies.sh` — isolated suite for the library, built up across Tasks 1–4 (same `ok`/`ko`/`eq` shape as `tests/run_keys.sh`).
- **Modify** `cyber_framework.sh` — source the new library, add `dependencies_menu()` (menu/selection UI only — no apt/package data of its own), add the `D|d)` dispatch arm, update the two menu-prompt strings and `show_help()`'s shortcut list.
- **Modify** `tests/run_smoke.sh` — three light navigation assertions for `D`, same shape as the existing `K` ones.
- **Create** `docs/DEPENDENCIAS-2026-11-17.md` — short user-facing doc, same role as `docs/API-KEYS-2026-11-06.md` for `K`.

---

### Task 1: Data tables + `dependencies_binary_ok`

**Files:**
- Create: `00_Config/lib/dependencies.bash`
- Test: `tests/run_dependencies.sh` (created here)

**Interfaces:**
- Produces: `DEPENDENCIES_MAP` (bash associative array, `binario` → `paquete apt`), `DEPENDENCIES_NO_APT` (associative array, `binario` → texto del motivo), `DEPENDENCIES_ORDER` (indexed array of `"grupo|binario"` strings, the fixed display/iteration order used by every later task), `dependencies_binary_ok(binario)` → return code 0/1.

- [ ] **Step 1: Write `00_Config/lib/dependencies.bash` with the two data tables and `DEPENDENCIES_ORDER`, exactly as follows**

```bash
#!/bin/bash
# Datos y comprobaciones de dependencias. Solo lo carga el gestor (tecla D).

declare -gA DEPENDENCIES_MAP=(
    [nmap]=nmap [masscan]=masscan [rustscan]=rustscan [nikto]=nikto
    [nuclei]=nuclei [burpsuite]=burpsuite [python3]=python3
    [hydra]=hydra [sqlmap]=sqlmap [curl]=curl [ffuf]=ffuf [nc]=netcat-traditional
    [iwlist]=wireless-tools [ip]=iproute2
    [ftp]=ftp [ldapsearch]=ldap-utils [rpcclient]=smbclient [smbclient]=smbclient
    [enum4linux]=enum4linux [mysql]=mariadb-client [psql]=postgresql-client
    [whatweb]=whatweb [timeout]=coreutils
    [sudo]=sudo [find]=findutils [ssh]=openssh-client [crontab]=cron
    [getcap]=libcap2-bin [scrot]=scrot [import]=imagemagick
    [gnome-screenshot]=gnome-screenshot [wget]=wget
    [iw]=iw [airodump-ng]=aircrack-ng [aireplay-ng]=aircrack-ng [aircrack-ng]=aircrack-ng
    [hcitool]=bluez [bluetoothctl]=bluez
    [cutycapt]=cutycapt [tcpdump]=tcpdump
    [autopsy]=autopsy [foremost]=foremost [scalpel]=scalpel [wireshark]=wireshark [dd]=coreutils
    [zaproxy]=zaproxy [volatility3]=volatility3
)

declare -gA DEPENDENCIES_NO_APT=(
    [sdptool]='sin paquete apt en este Kali'
    [gatttool]='sin paquete apt en este Kali'
    [avml]='binario de GitHub (Microsoft), no se instala aquí'
    [lime]='módulo de kernel que se compila, no se instala aquí'
    [volatility]='sin paquete apt en Kali (reemplazado por volatility3); solo se documenta'
    [nmap-vulners]='no es un binario: script NSE que se clona a mano a /usr/share/nmap/scripts/'
)

declare -ga DEPENDENCIES_ORDER=(
    '03_Scanners|nmap' '03_Scanners|masscan' '03_Scanners|rustscan' '03_Scanners|nikto'
    '03_Scanners|nuclei' '03_Scanners|burpsuite' '03_Scanners|python3'
    '05_Exploitation|hydra' '05_Exploitation|sqlmap' '05_Exploitation|curl' '05_Exploitation|ffuf'
    '05_Exploitation|nc' '05_Exploitation|iwlist' '05_Exploitation|ip'
    '04_Enumeration|ftp' '04_Enumeration|ldapsearch' '04_Enumeration|rpcclient'
    '04_Enumeration|smbclient' '04_Enumeration|enum4linux' '04_Enumeration|mysql'
    '04_Enumeration|psql' '04_Enumeration|whatweb' '04_Enumeration|timeout'
    '06_PostExploitation|sudo' '06_PostExploitation|find' '06_PostExploitation|ssh'
    '06_PostExploitation|crontab' '06_PostExploitation|getcap' '06_PostExploitation|scrot'
    '06_PostExploitation|import' '06_PostExploitation|gnome-screenshot' '06_PostExploitation|wget'
    '07_Wireless|iw' '07_Wireless|airodump-ng' '07_Wireless|aireplay-ng' '07_Wireless|aircrack-ng'
    '07_Wireless|hcitool' '07_Wireless|bluetoothctl' '07_Wireless|sdptool' '07_Wireless|gatttool'
    '10_Evidence|cutycapt' '10_Evidence|tcpdump'
    '08_Forensics|volatility' '08_Forensics|autopsy' '08_Forensics|foremost' '08_Forensics|scalpel'
    '08_Forensics|wireshark' '08_Forensics|avml' '08_Forensics|lime' '08_Forensics|dd'
    'Dependencias adicionales|zaproxy' 'Dependencias adicionales|volatility3'
    'Dependencias adicionales|nmap-vulners'
)
```

- [ ] **Step 2: Implement `dependencies_binary_ok(binario: str) -> rc`**

```bash
dependencies_binary_ok() {
    local binario="$1"
    if [[ "$binario" == 'nmap-vulners' ]]; then
        [[ -f "${NMAP_VULNERS_PATH:-/usr/share/nmap/scripts/nmap-vulners.nse}" ]]
        return $?
    fi
    command -v "$binario" >/dev/null 2>&1
}
```

- [ ] **Step 3: Write `tests/run_dependencies.sh`** (new file) with the harness header and the first assertions:

```bash
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
env PATH="$TMPBIN" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok presente"
eq "binario presente en PATH cerrado" "$?" "0"
env PATH="$TMPBIN" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok ausente-de-verdad"
eq "binario ausente en PATH cerrado" "$?" "1"
NMAP_VULNERS_PATH="$TMPBIN/nmap-vulners.nse" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok nmap-vulners"
eq "nmap-vulners ausente (archivo no existe)" "$?" "1"
touch "$TMPBIN/nmap-vulners.nse"
NMAP_VULNERS_PATH="$TMPBIN/nmap-vulners.nse" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_binary_ok nmap-vulners"
eq "nmap-vulners presente (archivo existe)" "$?" "0"

echo ""; echo "Resultado: $pasan ok, $fallan fallos"
[[ $fallan -eq 0 ]]
```

- [ ] **Step 4: Run it**

Run: `chmod +x tests/run_dependencies.sh && bash tests/run_dependencies.sh`
Expected: `Resultado: 4 ok, 0 fallos`, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add 00_Config/lib/dependencies.bash tests/run_dependencies.sh
git commit -m "feat(config): tabla de dependencias y comprobación por binario"
```

---

### Task 2: `dependencies_status()` — grouped read-only report

**Files:**
- Modify: `00_Config/lib/dependencies.bash`
- Test: `tests/run_dependencies.sh`

**Interfaces:**
- Consumes: `DEPENDENCIES_ORDER`, `DEPENDENCIES_NO_APT`, `dependencies_binary_ok()` from Task 1.
- Produces: `dependencies_status()` — prints the full grouped ✓/✗ report to stdout (this function IS the display; nothing captures its stdout as data, so UI text may be mixed in, same as `keys_helper estado`). One group header line per distinct group (in `DEPENDENCIES_ORDER`'s order, each appearing once, even though its binaries are scattered through the array only in the sense that all of one group's entries are contiguous by construction), then one line per binary: `  ✓ <binario>` or `  ✗ <binario>` for anything in `DEPENDENCIES_MAP`, and `  ✗ <binario> (<motivo>)` for anything in `DEPENDENCIES_NO_APT`.

- [ ] **Step 1: Add failing tests to `tests/run_dependencies.sh`**

```bash
echo "=== dependencies_status ==="
out=$(env PATH="$TMPBIN" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_status")
printf '%s\n' "$out" | grep -qF '03_Scanners:' && ok "incluye el grupo 03_Scanners" || ko "incluye el grupo 03_Scanners"
printf '%s\n' "$out" | grep -qF 'Dependencias adicionales:' && ok "incluye el grupo adicional" || ko "incluye el grupo adicional"
eq "nmap aparece una sola vez en el reporte" \
    "$(printf '%s\n' "$out" | grep -c -E '(^|[^a-z0-9_-])nmap([^a-z0-9_-]|$)')" "1"
printf '%s\n' "$out" | grep -qF 'avml (binario de GitHub' && ok "avml muestra el motivo" || ko "avml muestra el motivo"
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_dependencies.sh`
Expected: FAIL on all four new assertions (`dependencies_status: command not found`).

- [ ] **Step 3: Implement `dependencies_status()` in `00_Config/lib/dependencies.bash`**

Iterate `DEPENDENCIES_ORDER`; split each entry on `|` into `grupo`/`binario`; print `"$grupo:"` whenever `grupo` differs from the previous iteration's; for each binario call `dependencies_binary_ok`, and branch on membership in `DEPENDENCIES_NO_APT` (use `[[ -v DEPENDENCIES_NO_APT[$binario] ]]`) to decide whether to append `" (${DEPENDENCIES_NO_APT[$binario]})"`.

- [ ] **Step 4: Run to verify it passes**

Run: `bash tests/run_dependencies.sh`
Expected: all prior assertions plus these four pass, `0 fallos`.

- [ ] **Step 5: Commit**

```bash
git add 00_Config/lib/dependencies.bash tests/run_dependencies.sh
git commit -m "feat(config): reporte agrupado de dependencias"
```

---

### Task 3: `dependencies_missing_with_package()` — pure data for the install list

**Files:**
- Modify: `00_Config/lib/dependencies.bash`
- Test: `tests/run_dependencies.sh`

**Interfaces:**
- Consumes: `DEPENDENCIES_ORDER`, `DEPENDENCIES_MAP`, `dependencies_binary_ok()`.
- Produces: `dependencies_missing_with_package()` — prints **only** package names to stdout, one per line, no other text (pure data: the menu in Task 5 numbers these lines directly). Exactly one line per distinct apt package that (a) has at least one missing binario mapped to it in `DEPENDENCIES_MAP`, in the order that package's first-occurring binario appears in `DEPENDENCIES_ORDER`. A binario in `DEPENDENCIES_NO_APT` never contributes a line, regardless of its status.

- [ ] **Step 1: Add failing tests**

```bash
echo "=== dependencies_missing_with_package ==="
out=$(env PATH="$TMPBIN" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_missing_with_package")
eq "avml nunca aparece (sin paquete apt)" "$(printf '%s\n' "$out" | grep -c -F avml)" "0"
eq "nmap-vulners nunca aparece (sin paquete apt)" "$(printf '%s\n' "$out" | grep -c -F nmap-vulners)" "0"
eq "aircrack-ng aparece una sola vez aunque 3 binarios compartan el paquete" \
    "$(printf '%s\n' "$out" | grep -c -F aircrack-ng)" "1"
eq "nmap aparece (binario ausente en el PATH cerrado de prueba)" \
    "$(printf '%s\n' "$out" | grep -c -F nmap)" "1"
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_dependencies.sh`
Expected: FAIL (`dependencies_missing_with_package: command not found`).

- [ ] **Step 3: Implement `dependencies_missing_with_package()`**

Iterate `DEPENDENCIES_ORDER` in order; for each `binario` that is in `DEPENDENCIES_MAP`, not in `DEPENDENCIES_NO_APT`, and `! dependencies_binary_ok "$binario"`, print `"${DEPENDENCIES_MAP[$binario]}"` — but only the first time that package name is seen (track seen packages in a local associative array to dedupe).

- [ ] **Step 4: Run to verify it passes**

Run: `bash tests/run_dependencies.sh`
Expected: all pass, `0 fallos`.

- [ ] **Step 5: Commit**

```bash
git add 00_Config/lib/dependencies.bash tests/run_dependencies.sh
git commit -m "feat(config): lista deduplicada de paquetes instalables faltantes"
```

---

### Task 4: `dependencies_install()` — single confirmation, single `apt-get`

**Files:**
- Modify: `00_Config/lib/dependencies.bash`
- Test: `tests/run_dependencies.sh`

**Interfaces:**
- Consumes: nothing from this library (takes package names as its own arguments — the caller, Task 5's menu, is responsible for turning a number selection into package names via `dependencies_missing_with_package()`'s output).
- Produces: `dependencies_install(paquete1 [paquete2 ...]) -> rc`. Prints the exact list of packages and the confirmation prompt (`"Escribe 'instalar' para continuar (cualquier otra entrada cancela): "`) to **stderr**; reads one line from stdin. If it is not exactly `instalar`, prints a cancellation notice to stderr and returns `1` without running anything. If it is `instalar`, runs `sudo apt-get install -y "$@"` with real stdio (no `2>/dev/null`) and returns its exit code. If called with zero arguments, prints "nada que instalar" to stderr and returns `0` without prompting or running anything.

- [ ] **Step 1: Add failing tests** (closed-`PATH` stub sandbox — `sudo` execs straight into the stub `apt-get`, so the real `sudo`'s `secure_path` is never reached because the real `sudo` binary is never invoked at all):

```bash
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

printf 'no\n' | env PATH="$STUBDIR" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install paquete-x" >/dev/null 2>&1
eq "confirmación negada: rc 1" "$?" "1"
[[ -f "$CALLS" ]] && ko "confirmación negada: no debía llamar a apt-get" || ok "confirmación negada: no llamó a apt-get"

printf '' | env PATH="$STUBDIR" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install paquete-x" >/dev/null 2>&1
eq "EOF en la confirmación: rc 1" "$?" "1"
[[ -f "$CALLS" ]] && ko "EOF: no debía llamar a apt-get" || ok "EOF: no llamó a apt-get"

printf 'instalar\n' | env PATH="$STUBDIR" APT_GET_RC=0 bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install aircrack-ng rustscan" >/dev/null 2>&1
eq "confirmado: rc del apt-get real (0)" "$?" "0"
eq "una sola llamada a apt-get" "$(wc -l < "$CALLS")" "1"
eq "argumentos exactos de la única llamada" "$(cat "$CALLS")" "install -y aircrack-ng rustscan"
rm -f "$CALLS"

printf 'instalar\n' | env PATH="$STUBDIR" APT_GET_RC=42 bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install rustscan" >/dev/null 2>&1
eq "propaga el rc real de apt-get" "$?" "42"

env PATH="$STUBDIR" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_install"
eq "sin paquetes: rc 0 sin preguntar" "$?" "0"
[[ -f "$CALLS" ]] && ko "sin paquetes: no debía llamar a apt-get" || ok "sin paquetes: no llamó a apt-get"
rm -rf "$STUBDIR"
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash tests/run_dependencies.sh`
Expected: FAIL (`dependencies_install: command not found`).

- [ ] **Step 3: Implement `dependencies_install()`**

```bash
dependencies_install() {
    local respuesta
    if [[ $# -eq 0 ]]; then
        printf 'No hay nada que instalar.\n' >&2
        return 0
    fi
    printf 'Paquetes a instalar: %s\n' "$*" >&2
    printf "Escribe 'instalar' para continuar (cualquier otra entrada cancela): " >&2
    if ! IFS= read -r respuesta || [[ "$respuesta" != 'instalar' ]]; then
        printf 'Instalación cancelada.\n' >&2
        return 1
    fi
    sudo apt-get install -y "$@"
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `bash tests/run_dependencies.sh`
Expected: all pass, `0 fallos`.

- [ ] **Step 5: Commit**

```bash
git add 00_Config/lib/dependencies.bash tests/run_dependencies.sh
git commit -m "feat(config): instalación de dependencias con confirmación única"
```

---

### Task 5: Wire `D` into the manager

**Files:**
- Modify: `cyber_framework.sh`
- Modify: `tests/run_smoke.sh`

**Interfaces:**
- Consumes: `dependencies_status()`, `dependencies_missing_with_package()`, `dependencies_install()` from `00_Config/lib/dependencies.bash`.
- Produces: `dependencies_menu()` in `cyber_framework.sh` — no return value consumed by anyone, it is a terminal menu loop like `keys_menu()`.

- [ ] **Step 1: Source the library**

In `cyber_framework.sh`, add `source "$LIB_DIR/dependencies.bash"` to the existing block of `source "$LIB_DIR/...bash"` lines (after `source "$LIB_DIR/evidence_menu.bash"`).

- [ ] **Step 2: Write `dependencies_menu()`** (placed near `keys_menu()`, same file)

```bash
dependencies_menu() {
    local -a faltan
    local eleccion seleccion i idx
    local -a elegidos

    clear_screen
    echo -e "${CYAN}${BOLD}━━━ DEPENDENCIAS ━━━${NC}"
    echo ""
    dependencies_status
    echo ""
    mapfile -t faltan < <(dependencies_missing_with_package)
    if [[ ${#faltan[@]} -eq 0 ]]; then
        echo -e "  ${DIM}No falta nada instalable por apt.${NC}"
    else
        echo -e "${YELLOW}Paquetes que faltan e instalan por apt:${NC}"
        for i in "${!faltan[@]}"; do
            printf '  %d) %s\n' "$((i + 1))" "${faltan[$i]}"
        done
    fi
    echo ""
    echo -e "  ${GREEN}1${NC}) Instalar dependencias (elegir de la lista)"
    echo -e "  ${GREEN}0${NC}) Volver al menú principal"
    echo ""
    echo -ne "${BOLD}➜ Elige una opción [0-1]: ${NC}"
    if ! IFS= read -r eleccion; then
        return 0
    fi
    case "$eleccion" in
        0|'') return 0 ;;
        1)
            if [[ ${#faltan[@]} -eq 0 ]]; then
                echo -e "${DIM}Nada que instalar.${NC}"; pause; return 0
            fi
            echo -ne "${BOLD}➜ Números a instalar (espacio entre varios, 'todas', 0 o ! cancela): ${NC}"
            if ! IFS= read -r seleccion || [[ "$seleccion" == '0' || "$seleccion" == '!' || -z "$seleccion" ]]; then
                pause; return 0
            fi
            elegidos=()
            if [[ "$seleccion" == 'todas' ]]; then
                elegidos=("${faltan[@]}")
            else
                for idx in $seleccion; do
                    if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#faltan[@]} )); then
                        elegidos+=("${faltan[$((idx - 1))]}")
                    else
                        echo -e "${RED}Número inválido: $idx${NC}"; pause; return 0
                    fi
                done
            fi
            dependencies_install "${elegidos[@]}"
            ;;
        *) echo -e "${RED}❌ Opción inválida${NC}" ;;
    esac
    pause
}
```

- [ ] **Step 3: Dispatch and help text**

In `main()`'s `case "$choice" in`, add `D|d) dependencies_menu ;;` next to the `K|k) keys_menu ;;` line. Update the two literal prompt strings that list shortcuts (`main_menu`'s `➜ Selecciona un módulo [00-13, 99, R, T, K, ?, Q]:` and `main()`'s invalid-option message `Prueba con 00-13, 99, R, T, K, ? o Q.`) to insert `, D` after `K` in both. In `show_help()`, add one line under `⌨️  ATAJOS:` immediately after the `K` line: `echo -e "  ${GREEN}D${NC}   Dependencias (ver qué falta e instalarlo)"`.

- [ ] **Step 4: Add smoke tests to `tests/run_smoke.sh`**

Immediately after the existing `K`-key block (after the `K no crea el registro` check), add:

```bash
echo "=== dependencias: acción D ==="
run "menú: D aparece"            'Q\n'          "DEPENDENCIAS" || true
run "menú: D abre el submenú"    'D\n0\nQ\n'    "Paquetes que faltan"
run "menú: D 0 vuelve sin tocar nada" 'D\n0\nQ\n' "DEPENDENCIAS"
```

(Drop the first `run` call if, on inspection, `D` does not appear on the idle main-menu screen the way `K`'s label does — `K`'s equivalent line prints unconditionally in `main_menu`'s banner, which `D` is not specified to join; keep only the two that exercise the submenu itself if that's the case.)

- [ ] **Step 5: Run the full navigation check**

Run: `bash tests/run_smoke.sh 2>&1 | tail -20`
Expected: every `OK` line, including the three new ones, `0` failures reported at the end.

- [ ] **Step 6: Commit**

```bash
git add cyber_framework.sh tests/run_smoke.sh
git commit -m "feat(config): tecla D para ver e instalar dependencias"
```

---

### Task 6: Documentation and full regression

**Files:**
- Create: `docs/DEPENDENCIAS-2026-11-17.md`

- [ ] **Step 1: Write `docs/DEPENDENCIAS-2026-11-17.md`**

Short Spanish doc, same role as `docs/API-KEYS-2026-11-06.md`: what `D` shows, that it only uses `apt`, the explicit list of binaries with no apt package and why, the note that it does not coordinate with `08_Forensics/requirements.sh --install` (known, accepted duplication), and that `zaproxy` is listed even though no ZAP scanner exists yet. Link back to `docs/superpowers/specs/2026-11-17-dependencias-design.md`.

- [ ] **Step 2: Run every test suite touched or adjacent**

Run: `bash tests/run_dependencies.sh && bash tests/run_smoke.sh && bash tests/run_tests.sh 2>&1 | tail -5`
Expected: all three report zero failures. (`run_tests.sh` is the large pre-existing suite; it should be unaffected since no existing function or file it covers was modified beyond the two literal prompt strings and `show_help()` — if it has a pre-existing assertion on the exact text of either string that this plan's Task 5 Step 3 did not anticipate, fix that string match there rather than reverting the `D` addition.)

- [ ] **Step 3: `bash -n` on the one modified shell entrypoint**

Run: `bash -n cyber_framework.sh && bash -n 00_Config/lib/dependencies.bash`
Expected: no output, exit 0 (captures stderr too — a clean exit 0 is not sufficient on its own per the house convention for unterminated heredocs, but neither file here contains a heredoc).

- [ ] **Step 4: Commit**

```bash
git add docs/DEPENDENCIAS-2026-11-17.md
git commit -m "docs(config): documentar la tecla D de dependencias"
```

---

## Self-Review

**Spec coverage:** Goals (tecla `D`, status agrupado, instalación con una confirmación) → Tasks 1,2,3,4,5. Non-goals (solo apt, sin coordinarse con `requirements.sh`, sin versiones/`apt update`) → enforced by Task 1's data tables (nothing outside `DEPENDENCIES_MAP` is ever installed) and documented in Task 6. Anti-goals (nunca mezclar "falta y se instala" con "falta y no hay instalación automática") → Task 2's `dependencies_status()` always appends the reason text for `DEPENDENCIES_NO_APT` entries; Task 3 excludes them from the installable list entirely. Constraints (closed `PATH`, no `set -e`, free `D` key, style) → Tasks 1–5 each. The user's selection-by-number decision → Task 5's `dependencies_menu()`.

**Step scan:** every code step gives an exact signature or, where the spec pins exact values (the data tables), the exact value; every test step gives concrete assertions; no step says "handle edge cases" without naming the case.

**Type consistency:** `dependencies_binary_ok`, `dependencies_status`, `dependencies_missing_with_package`, `dependencies_install` are named and used identically across Tasks 1–5; `DEPENDENCIES_MAP`/`DEPENDENCIES_NO_APT`/`DEPENDENCIES_ORDER` likewise.

**Review Focus:** the five entries above are each pinned to the task whose tests exercise them (duplicate binary across modules → Task 2; no-apt binary leaking into the installable list → Task 3; invalid/out-of-range selection → Task 5; declined/EOF confirmation → Task 4; shared-package dedup end-to-end → Tasks 3 and 4 together).

**Proportion:** the plan is longer than the spec because it inlines the exact data tables (an explicit spec value, not a transcript of logic) and the exact test assertions; the functions themselves are each under 15 lines and only `dependencies_menu()` and the data block have bodies written out, because their exact shape (confirmation wording, selection parsing, the ~50-row table) is what the spec and the user's own instructions pinned — everything else is signature + test + a one-line approach note.
