# Herramientas adicionales interactivas en la tecla `D` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** La tecla `D` gana una segunda opción que instala/verifica `ollama`
(+ un catálogo de 4 modelos con guardrail de recursos), `avml` y
`nmap-vulners`, cada uno con su propia confirmación explícita; `lime` y
`volatility` (v2) no se tocan.

**Architecture:** Dos ficheros Bash nuevos/ampliados bajo `00_Config/lib/`:
`dependencies.bash` (ampliado: corrige el nombre de fichero de
`nmap-vulners`, añade los tres instaladores de herramienta y la lectura del
token de GitHub) y `dependencies_models.bash` (nuevo: catálogo de modelos,
guardrail de recursos, orquestación del `ollama pull`). `cyber_framework.sh`
fuente el fichero nuevo junto al existente y añade la opción `2` al menú de
`D`. Todo Python reutilizado (`hardware.py`, `osint/credentials.py`,
`api_keys.py`) se invoca vía `python3 -c`/subproceso, nunca se reimplementa.

**Tech Stack:** Bash (house style: sin `set -e`, autolocalización por
`BASH_SOURCE`, UI a stderr/valores a stdout), Python 3 stdlib (`json`) para
parsear la API de GitHub, `curl`/`git`/`sudo` reales fuera de los tests.

**Spec:** `docs/superpowers/specs/2026-11-17-dependencias-herramientas-design.md`

## Global Constraints

- Nunca ejecutar `curl`/`git`/`sudo`/`ollama`/red real desde los tests;
  todo doble en un `PATH` sintético, registrando su invocación exacta.
- Ningún paso ejecuta una acción real sin su propia confirmación explícita
  y literal por `stdin`; UI siempre a stderr, valores de retorno siempre
  solo en stdout (mismo contrato que `prompt.bash`).
- `lime` y `volatility` (v2) no se tocan: siguen solo en
  `DEPENDENCIES_NO_APT`, sin entrada en el submenú nuevo.
- No se reimplementa `hardware.py` (modelo general) ni
  `osint/credentials.py` (lectura de claves): se invocan, no se duplican.
- Ruta de `avml`: `/usr/local/bin/avml` (único sitio que `memory_dump.sh`
  mira, solo por `PATH`). Ruta de `nmap-vulners`: fichero `vulners.nse`
  (nombre real del proyecto, no `nmap-vulners.nse`) en
  `/usr/share/nmap/scripts/`.
- Autolocalización: todo fichero nuevo resuelve su propio directorio con
  `${BASH_SOURCE[0]:-$0}` (zsh-safe), nunca una ruta absoluta del usuario.
- Token de GitHub: nunca se imprime su valor; se persiste con
  `api_keys.py poner theharvester github.key --stdin` (el campo real es
  `github.key` bajo la herramienta `theharvester` — confirmado en
  `00_Config/scripts/api_keys.py`, no `poner github GITHUB_API` como decía
  una redacción anterior del diseño).
- Mensajes de usuario en español, sin jerga, como el resto del módulo `D`.

## Review Focus

1. Elegir una fila/tamaño del catálogo que no entra en la RAM libre y
   escribir cualquier cosa que no sea `CONTINUAR_IGUAL` no debe lanzar
   `ollama pull`: debe cancelar ese intento concreto y dejar elegir otro
   tamaño → Task 7.
2. Una API de GitHub que responde JSON sin el asset `avml` (artefacto
   renombrado, repo caído) no debe hacer que el instalador de avml
   descargue un binario equivocado ni se cuelgue: debe fallar con un
   mensaje claro y sin tocar `/usr/local/bin` → Task 4.
3. Confirmar la instalación de una herramienta que ya está presente no
   debe reinstalarla (la primera comprobación de cada instalador es
   `dependencies_binary_ok`) → Task 3/4/5.
4. Que `nmap-vulners` esté detectado en `dependencies_binary_ok` tiene que
   seguir funcionando con `NMAP_VULNERS_PATH` sobrescrito (como ya hace el
   test existente), no solo con la ruta por defecto nueva → Task 1.
5. Si falla la instalación de `ollama` (paso 1), no debe ofrecerse el
   catálogo de modelos ni preguntarse nada más: la pieza debe detenerse
   ahí con el error visible → Task 6.

---

### Task 1: Corregir el nombre de fichero de `nmap-vulners`

**Files:**
- Modify: `00_Config/lib/dependencies.bash` (función `dependencies_binary_ok`)
- Test: `tests/run_dependencies.sh` (sección `=== dependencies_binary_ok ===`)

**Interfaces:**
- Produces: `dependencies_binary_ok nmap-vulners` sigue comprobando
  `${NMAP_VULNERS_PATH:-<ruta-por-defecto>}`, con la ruta por defecto ahora
  `/usr/share/nmap/scripts/vulners.nse` (antes `nmap-vulners.nse`).

- [ ] **Step 1: Actualizar la prueba existente** en
  `tests/run_dependencies.sh`: los dos `touch`/comprobación de
  `nmap-vulners` ya usan `NMAP_VULNERS_PATH="$TMPBIN/nmap-vulners.nse"`
  (variable de entorno, nombre de fichero arbitrario de prueba — no
  depende del valor por defecto). Añadir un tercer caso nuevo que SÍ
  ejercita el valor por defecto real:
  ```bash
  rm -f /tmp/nmap-vulners-default-check
  mkdir -p "$TMPBIN/usr/share/nmap/scripts"
  touch "$TMPBIN/usr/share/nmap/scripts/vulners.nse"
  bash -c "source '$FW/00_Config/lib/dependencies.bash'; [[ \"\${NMAP_VULNERS_PATH:-/usr/share/nmap/scripts/vulners.nse}\" == */vulners.nse ]]"
  eq "la ruta por defecto termina en vulners.nse, no nmap-vulners.nse" "$?" "0"
  ```
- [ ] **Step 2: Ejecutar** `bash tests/run_dependencies.sh 2>&1 | tail -20`
  → el caso nuevo pasa ya (es una aserción sobre el string, no sobre el
  código); confirmar que el resto sigue en verde (los dos casos existentes
  seguían pasando antes del cambio real porque usan `NMAP_VULNERS_PATH`
  explícito, así que esta prueba por sí sola no fallaba — por eso Step 1 la
  amplía antes de tocar el código).
- [ ] **Step 3: Implementar.** En `dependencies_binary_ok`, cambiar
  `nmap-vulners.nse` por `vulners.nse` en la ruta por defecto (única línea
  de la función).
- [ ] **Step 4: Ejecutar** `bash tests/run_dependencies.sh 2>&1 | tail -5`
  → `Resultado: N ok, 0 fallos`.
- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/dependencies.bash CyberSecurity-Framework/tests/run_dependencies.sh
git commit -m "fix(config): la ruta por defecto de nmap-vulners no coincidía con el nombre real del proyecto"
```

### Task 2: Lista de las tres herramientas adicionales y autolocalización

**Files:**
- Modify: `00_Config/lib/dependencies.bash`
- Test: `tests/run_dependencies.sh`

**Interfaces:**
- Produces: `DEPENDENCIES_LIB_DIR` (variable global, directorio de
  `00_Config/lib/` resuelto por `BASH_SOURCE`); `DEPENDENCIES_EXTRA_ORDER`
  (array `(ollama avml nmap-vulners)`); `dependencies_extra_missing() ->`
  imprime a stdout, una por línea, las de `DEPENDENCIES_EXTRA_ORDER` para
  las que `dependencies_binary_ok` es falso.

- [ ] **Step 1: Write the failing test** en `tests/run_dependencies.sh`,
  nueva sección `=== dependencies_extra_missing ===`:
  ```bash
  out=$(bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_extra_missing")
  eq "ollama aparece (ausente en el PATH cerrado)" "$(printf '%s\n' "$out" | grep -c -F ollama)" "1"
  eq "avml aparece (ausente en el PATH cerrado)" "$(printf '%s\n' "$out" | grep -c -F avml)" "1"
  eq "nmap-vulners aparece (ausente en el PATH cerrado)" "$(printf '%s\n' "$out" | grep -c -F nmap-vulners)" "1"
  eq "exactamente 3 líneas" "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "3"
  touch "$TMPBIN/ollama"; chmod +x "$TMPBIN/ollama"
  out=$(bash -c "export PATH='$TMPBIN'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_extra_missing")
  eq "ollama ya no aparece si está en PATH" "$(printf '%s\n' "$out" | grep -c -F ollama)" "0"
  rm -f "$TMPBIN/ollama"
  ```
- [ ] **Step 2: Run** `bash tests/run_dependencies.sh 2>&1 | tail -20` →
  FALLA (función no existe).
- [ ] **Step 3: Implement.** Al principio de `dependencies.bash`, tras el
  comentario de cabecera:
  ```bash
  DEPENDENCIES_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
  declare -ga DEPENDENCIES_EXTRA_ORDER=(ollama avml nmap-vulners)
  ```
  y la función:
  ```bash
  dependencies_extra_missing() {
      local binario
      for binario in "${DEPENDENCIES_EXTRA_ORDER[@]}"; do
          dependencies_binary_ok "$binario" || printf '%s\n' "$binario"
      done
  }
  ```
- [ ] **Step 4: Run** → `Resultado: N ok, 0 fallos`.
- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/dependencies.bash CyberSecurity-Framework/tests/run_dependencies.sh
git commit -m "feat(config): listar qué herramientas adicionales faltan (ollama, avml, nmap-vulners)"
```

### Task 3: Instalador de `nmap-vulners`

**Files:**
- Modify: `00_Config/lib/dependencies.bash`
- Test: `tests/run_dependencies.sh`

**Interfaces:**
- Consumes: `dependencies_binary_ok` (existente).
- Produces: `dependencies_install_nmap_vulners() ->` rc 0 si ya estaba
  presente o si la instalación y verificación tuvieron éxito; rc 1 si la
  confirmación se niega, `git`/`sudo` fallan, o la verificación posterior
  falla. Toda la UI por stderr.

- [ ] **Step 1: Write the failing test**, nueva sección
  `=== dependencies_install_nmap_vulners ===`. Doble de `git` y `sudo` en
  un `STUBDIR` nuevo: `sudo` reexpone (`exec "$@"`, como ya hace el doble
  de `apt-get`); `git` registra su invocación completa en `CALLS` y, si el
  subcomando es `clone`, crea en el último argumento (el directorio
  destino) un fichero `vulners.nse` con contenido de prueba — simula el
  clon sin red. `nmap` se dobla solo para registrar que se llamó con
  `--script-updatedb`.
  ```bash
  printf 'no\n' | bash -c "export PATH='$STUBDIR'; export NMAP_VULNERS_PATH='$STUBDIR/scripts/vulners.nse'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_nmap_vulners" >/dev/null 2>&1
  eq "confirmación negada: rc 1" "$?" "1"
  [[ -f "$STUBDIR/scripts/vulners.nse" ]] && ko "confirmación negada: no debía clonar nada" || ok "confirmación negada: no clonó nada"

  printf 'NMAP_VULNERS_SI\n' | bash -c "export PATH='$STUBDIR'; export NMAP_VULNERS_PATH='$STUBDIR/scripts/vulners.nse'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_nmap_vulners" >/dev/null 2>&1
  eq "confirmado: instala y verifica, rc 0" "$?" "0"
  grep -q -F 'clone' "$CALLS" && ok "invocó git clone" || ko "invocó git clone"
  grep -q -F -- '--script-updatedb' "$CALLS" && ok "invocó nmap --script-updatedb" || ko "invocó nmap --script-updatedb"

  out=$(bash -c "export PATH='$STUBDIR'; export NMAP_VULNERS_PATH='$STUBDIR/scripts/vulners.nse'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_nmap_vulners" 2>&1)
  eq "ya presente: no vuelve a clonar" "$(printf '%s\n' "$out" | grep -c -F clone)" "0"
  ```
  (el literal exacto de confirmación es `NMAP_VULNERS_SI`; el `CALLS` se
  limpia entre bloques con `rm -f`).
- [ ] **Step 2: Run** → FALLA (función no existe).
- [ ] **Step 3: Implement.**
  ```bash
  dependencies_install_nmap_vulners() {
      dependencies_binary_ok nmap-vulners && { printf 'nmap-vulners ya está instalado.\n' >&2; return 0; }
      printf 'Clona vulnersCom/nmap-vulners de GitHub y copia vulners.nse a /usr/share/nmap/scripts/ con sudo; ejecuta "nmap --script-updatedb" al final.\nEscribe NMAP_VULNERS_SI para continuar (cualquier otra entrada cancela): ' >&2
      local respuesta; IFS= read -r respuesta
      [[ "$respuesta" == 'NMAP_VULNERS_SI' ]] || { printf 'Instalación de nmap-vulners cancelada.\n' >&2; return 1; }
      local tmp; tmp=$(mktemp -d)
      if ! git clone --depth 1 https://github.com/vulnersCom/nmap-vulners.git "$tmp/nmap-vulners" 2>&2; then
          printf 'No se pudo clonar nmap-vulners.\n' >&2; rm -rf "$tmp"; return 1
      fi
      local destino="${NMAP_VULNERS_PATH:-/usr/share/nmap/scripts/vulners.nse}"
      if ! sudo install -m 644 "$tmp/nmap-vulners/vulners.nse" "$destino"; then
          printf 'No se pudo copiar vulners.nse a su destino.\n' >&2; rm -rf "$tmp"; return 1
      fi
      [[ -f "$tmp/nmap-vulners/http-vulners-regex.nse" ]] && sudo install -m 644 "$tmp/nmap-vulners/http-vulners-regex.nse" "$(dirname "$destino")" 2>/dev/null
      rm -rf "$tmp"
      sudo nmap --script-updatedb >/dev/null 2>&1
      dependencies_binary_ok nmap-vulners && { printf 'nmap-vulners instalado y verificado.\n' >&2; return 0; }
      printf 'nmap-vulners se copió pero no se detecta en su ruta.\n' >&2
      return 1
  }
  ```
  Nota: el destino usa `${NMAP_VULNERS_PATH:-...}` para que la prueba, con
  la variable apuntando a `$STUBDIR/scripts/vulners.nse`, instale ahí en
  vez de en `/usr/share/nmap/scripts/` real.
- [ ] **Step 4: Run** `bash tests/run_dependencies.sh 2>&1 | tail -20` →
  `Resultado: N ok, 0 fallos`.
- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/dependencies.bash CyberSecurity-Framework/tests/run_dependencies.sh
git commit -m "feat(config): instalador interactivo de nmap-vulners desde la tecla D"
```

### Task 4: Token de GitHub (opcional) e instalador de `avml`

**Files:**
- Modify: `00_Config/lib/dependencies.bash`
- Test: `tests/run_dependencies.sh`

**Interfaces:**
- Consumes: `osint/credentials.load_credentials(registry, harvester_dirs)`
  (existente, solo lectura); `api_keys.py poner theharvester github.key
  --stdin` (existente, CLI).
- Produces: `dependencies_github_token() ->` imprime a stdout el valor
  guardado (`""` si no hay ninguno; nunca falla, nunca imprime nada más).
  `dependencies_offer_github_token() ->` si ya hay token, no hace nada y
  retorna 0; si no, pregunta una vez (opcional) y, si se escribe algo, lo
  persiste con `--stdin`. `dependencies_avml_release() ->` imprime
  `"<tag>|<url>"` a stdout y retorna 0, o retorna 1 con un mensaje por
  stderr si la API falla o no publica un asset llamado exactamente `avml`.
  `dependencies_install_avml() ->` mismo contrato de rc que
  `dependencies_install_nmap_vulners`.

- [ ] **Step 1: Write the failing test**, tres secciones nuevas.

  `=== dependencies_github_token ===` (usa `KEYS_FILE` apuntando a un
  registro temporal, como ya hacen otras suites aisladas del proyecto):
  ```bash
  KEYSFILE="$(mktemp)"
  out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
  eq "sin registro: cadena vacía" "$out" ""
  printf 'version: 1\ntheharvester:\n  github:\n    key: tok-de-prueba\n' > "$KEYSFILE"
  out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
  eq "registro con clave: la devuelve" "$out" "tok-de-prueba"
  rm -f "$KEYSFILE"
  ```

  `=== dependencies_offer_github_token ===`:
  ```bash
  KEYSFILE="$(mktemp)"
  printf '\n' | KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_offer_github_token"
  out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
  eq "Enter vacío: no guarda nada" "$out" ""
  printf 'tok-nuevo\n' | KEYS_FILE="$KEYSFILE" bash -c "export PATH='$PATH'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_offer_github_token"
  out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
  eq "valor escrito: queda guardado" "$out" "tok-nuevo"
  printf 'otro\n' | KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_offer_github_token"
  out=$(KEYS_FILE="$KEYSFILE" bash -c "source '$FW/00_Config/lib/dependencies.bash'; dependencies_github_token")
  eq "ya había token: no vuelve a preguntar/sobrescribir" "$out" "tok-nuevo"
  rm -f "$KEYSFILE"
  ```
  (la tercera aserción prueba que, al no leer stdin porque ya hay token,
  `printf 'otro\n'` queda sin consumir — el proceso no debe bloquear ni
  cambiar nada).

  `=== dependencies_avml_release / dependencies_install_avml ===`. Doble
  de `curl`: un script en `STUBDIR` que, según la URL en `$*`, responde
  JSON fijo para `api.github.com/repos/microsoft/avml/releases/latest`
  (controlado por `CURL_JSON_FILE`, un fichero de fixture con el JSON de
  prueba) o escribe un binario de prueba al `-o` indicado para la URL de
  descarga; registra toda invocación en `CALLS`. `sudo` reexpone. El
  binario de prueba que "descarga" es un script que imprime
  `avml 0.0.0-test\nUSAGE:\n    avml <FILENAME>\n` ante `--help`, para que
  la verificación lo reconozca.
  ```bash
  cat > "$STUBDIR/fixture.json" <<'JSON'
  {"tag_name": "v0.99.0", "assets": [{"name": "avml", "browser_download_url": "https://example.invalid/avml"}]}
  JSON
  out=$(CURL_JSON_FILE="$STUBDIR/fixture.json" bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_avml_release")
  eq "tag y URL del asset avml" "$out" "v0.99.0|https://example.invalid/avml"

  cat > "$STUBDIR/sin-asset.json" <<'JSON'
  {"tag_name": "v0.99.0", "assets": [{"name": "avml-arm64", "browser_download_url": "https://example.invalid/arm"}]}
  JSON
  CURL_JSON_FILE="$STUBDIR/sin-asset.json" bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_avml_release" >/dev/null 2>&1
  eq "sin asset avml: rc 1" "$?" "1"

  printf 'no\n' | CURL_JSON_FILE="$STUBDIR/fixture.json" bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_avml" >/dev/null 2>&1
  eq "confirmación negada: rc 1" "$?" "1"
  [[ -f "$CALLS" ]] && ko "confirmación negada: no debía invocar curl/sudo" || ok "confirmación negada: no invocó nada"

  printf 'AVML_SI\n\n' | CURL_JSON_FILE="$STUBDIR/fixture.json" bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_avml" >/dev/null 2>&1
  eq "confirmado: instala y verifica, rc 0" "$?" "0"
  grep -q -F 'releases/latest' "$CALLS" && ok "consultó la API de releases" || ko "consultó la API de releases"
  grep -q -F '/usr/local/bin/avml' "$CALLS" && ok "instaló en /usr/local/bin/avml" || ko "instaló en /usr/local/bin/avml"
  ```
  (el segundo `\n` tras `AVML_SI` responde vacío a la pregunta opcional
  del token, para no bloquearse esperando entrada).
- [ ] **Step 2: Run** → FALLA (funciones no existen).
- [ ] **Step 3: Implement.**
  ```bash
  dependencies_github_token() {
      python3 -c '
  import sys, os
  sys.path.insert(0, "'"$DEPENDENCIES_LIB_DIR"'")
  from pathlib import Path
  from osint.credentials import load_credentials
  fw = Path("'"$DEPENDENCIES_LIB_DIR"'").resolve().parents[1]
  registry = Path(os.environ.get("KEYS_FILE", fw / "00_Config/credentials/api-keys.yaml"))
  try:
      print(load_credentials(registry, []).get("github", ""), end="")
  except Exception:
      pass
  '
  }

  dependencies_offer_github_token() {
      [[ -n "$(dependencies_github_token)" ]] && return 0
      printf 'No hay un token de GitHub guardado; uno evita el límite de 60 peticiones/hora sin autenticar.\nToken de GitHub (opcional, Enter para omitir; nunca se imprime): ' >&2
      local respuesta; IFS= read -r respuesta
      [[ -n "$respuesta" ]] || return 0
      printf '%s' "$respuesta" | python3 "$DEPENDENCIES_LIB_DIR/../scripts/api_keys.py" poner theharvester github.key --stdin >/dev/null 2>&1
  }

  dependencies_avml_release() {
      local token json
      token=$(dependencies_github_token)
      if [[ -n "$token" ]]; then
          json=$(curl -fsSL -H "Authorization: Bearer $token" https://api.github.com/repos/microsoft/avml/releases/latest)
      else
          json=$(curl -fsSL https://api.github.com/repos/microsoft/avml/releases/latest)
      fi
      [[ -n "$json" ]] || { printf 'No se pudo consultar la API de releases de GitHub.\n' >&2; return 1; }
      python3 -c '
  import json, sys
  data = json.loads(sys.stdin.read())
  tag = data.get("tag_name", "")
  url = next((a.get("browser_download_url", "") for a in data.get("assets", [])
              if a.get("name") == "avml"), "")
  if not tag or not url:
      sys.exit(1)
  print(tag + "|" + url)
  ' <<<"$json"
  }

  DEPENDENCIES_AVML_MAX_BYTES=20971520

  dependencies_verify_avml() {
      command -v avml >/dev/null 2>&1 || { printf 'avml no aparece en PATH tras instalarlo.\n' >&2; return 1; }
      local ayuda; ayuda=$(timeout 10 avml --help 2>&1)
      if [[ "${ayuda,,}" == *avml* && "${ayuda,,}" == *usage:* \
            && ( "$ayuda" == *'<FILENAME>'* || "$ayuda" == *'<OUTPUT>'* ) ]]; then
          printf 'avml instalado y verificado.\n' >&2; return 0
      fi
      printf 'avml se instaló pero no respondió como se esperaba a --help.\n' >&2
      return 1
  }

  dependencies_install_avml() {
      dependencies_binary_ok avml && { printf 'avml ya está instalado.\n' >&2; return 0; }
      printf 'Descarga el binario de avml desde las releases de GitHub (microsoft/avml) a /usr/local/bin/avml con sudo. No hay suma de verificación oficial publicada: la integridad depende de HTTPS y del dominio de GitHub, no de una firma.\nEscribe AVML_SI para continuar (cualquier otra entrada cancela): ' >&2
      local respuesta; IFS= read -r respuesta
      [[ "$respuesta" == 'AVML_SI' ]] || { printf 'Instalación de avml cancelada.\n' >&2; return 1; }
      dependencies_offer_github_token
      local release; release=$(dependencies_avml_release) || { printf 'No se pudo resolver la última versión de avml.\n' >&2; return 1; }
      local tag="${release%%|*}" url="${release#*|}" tmp; tmp=$(mktemp)
      printf 'Descargando avml %s...\n' "$tag" >&2
      if ! curl -fsSL --max-filesize "$DEPENDENCIES_AVML_MAX_BYTES" -o "$tmp" "$url"; then
          printf 'La descarga de avml falló.\n' >&2; rm -f "$tmp"; return 1
      fi
      chmod +x "$tmp"
      if ! sudo install -m 755 "$tmp" /usr/local/bin/avml; then
          printf 'No se pudo instalar avml en /usr/local/bin.\n' >&2; rm -f "$tmp"; return 1
      fi
      rm -f "$tmp"
      dependencies_verify_avml
  }
  ```
  El doble de `curl` de los tests lee `CURL_JSON_FILE` para decidir qué
  JSON devolver cuando la URL contiene `releases/latest`, y para la URL de
  descarga escribe en el destino `-o` un script ejecutable que imprime la
  salida de `--help` esperada.
- [ ] **Step 4: Run** `bash tests/run_dependencies.sh 2>&1 | tail -30` →
  `Resultado: N ok, 0 fallos`.
- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/dependencies.bash CyberSecurity-Framework/tests/run_dependencies.sh
git commit -m "feat(config): instalador interactivo de avml con token de GitHub opcional"
```

### Task 5: Instalador de `ollama` (binario, sin modelo todavía)

**Files:**
- Modify: `00_Config/lib/dependencies.bash`
- Test: `tests/run_dependencies.sh`

**Interfaces:**
- Produces: `dependencies_install_ollama() ->` mismo contrato de rc que
  las dos anteriores. Ejecuta el instalador oficial vía
  `curl -fsSL https://ollama.com/install.sh | sh`.

- [ ] **Step 1: Write the failing test**, sección
  `=== dependencies_install_ollama ===`. El doble de `curl`, para la URL
  `ollama.com/install.sh`, imprime a stdout un script de una línea que
  crea `"$STUBDIR/ollama"` ejecutable (simula lo que haría el instalador
  real) — así `curl ... | sh` deja `ollama` en el `PATH` de prueba.
  ```bash
  printf 'no\n' | bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_ollama" >/dev/null 2>&1
  eq "confirmación negada: rc 1" "$?" "1"
  [[ -x "$STUBDIR/ollama" ]] && ko "confirmación negada: no debía instalar ollama" || ok "confirmación negada: no instaló ollama"

  printf 'OLLAMA_SI\n' | bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_ollama" >/dev/null 2>&1
  eq "confirmado: rc 0 y ollama queda en PATH" "$?" "0"
  [[ -x "$STUBDIR/ollama" ]] && ok "ollama quedó instalado" || ko "ollama no quedó instalado"

  out=$(bash -c "export PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; dependencies_install_ollama" 2>&1)
  eq "ya presente: no vuelve a pedir confirmación ni a invocar curl" "$out" "ollama ya está instalado."
  rm -f "$STUBDIR/ollama"
  ```
- [ ] **Step 2: Run** → FALLA (función no existe).
- [ ] **Step 3: Implement.**
  ```bash
  dependencies_install_ollama() {
      dependencies_binary_ok ollama && { printf 'ollama ya está instalado.\n' >&2; return 0; }
      printf 'Ejecuta el instalador oficial de Ollama (curl -fsSL https://ollama.com/install.sh | sh); puede pedir la contraseña de sudo por su cuenta e instala un servicio en segundo plano.\nEscribe OLLAMA_SI para continuar (cualquier otra entrada cancela): ' >&2
      local respuesta; IFS= read -r respuesta
      [[ "$respuesta" == 'OLLAMA_SI' ]] || { printf 'Instalación de Ollama cancelada.\n' >&2; return 1; }
      if ! curl -fsSL https://ollama.com/install.sh | sh; then
          printf 'El instalador de Ollama terminó con error.\n' >&2; return 1
      fi
      if ! dependencies_binary_ok ollama; then
          printf 'El instalador terminó pero «ollama» no aparece en PATH.\n' >&2; return 1
      fi
      printf 'ollama instalado correctamente.\n' >&2
  }
  ```
- [ ] **Step 4: Run** → `Resultado: N ok, 0 fallos`.
- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/dependencies.bash CyberSecurity-Framework/tests/run_dependencies.sh
git commit -m "feat(config): instalador interactivo del binario de Ollama"
```

### Task 6: Catálogo de modelos y guardrail de recursos (funciones puras)

**Files:**
- Create: `00_Config/lib/dependencies_models.bash`
- Test: `tests/run_dependencies.sh` (nueva sección)

**Interfaces:**
- Consumes: `00_Config/lib/ai/hardware.py` (`read_mem_available_gib`,
  `has_nvidia_gpu`, `recommend_model`, `MODEL_1B`/`MODEL_3B`/`MODEL_7B`/
  `MODEL_14B`), `DEPENDENCIES_LIB_DIR` (Task 2).
- Produces: `DEPENDENCIES_MODEL_CATALOG` (array asociativo, claves
  `fila:tamaño`, valores `"GB_descarga|RAM_GiB|pull_id"`, ver tabla
  abajo); `dependencies_model_rows() ->` imprime a stdout 4 líneas,
  `clave|Etiqueta|Descripción` (una por fila del catálogo);
  `dependencies_model_sizes(fila) ->` imprime a stdout los sufijos de
  tamaño de esa fila, uno por línea, en el orden de la tabla;
  `dependencies_model_lookup(fila, tamaño) ->` imprime
  `"GB|RAM|pull_id"` a stdout, rc 1 si la combinación no existe;
  `dependencies_general_model_size() ->` imprime a stdout el sufijo
  (`1b`/`3b`/`7b`/`14b`) que `hardware.recommend_model()` elegiría para
  esta máquina ahora mismo; `dependencies_mem_check(ram_necesaria_gib) ->`
  imprime a stdout la RAM libre real con un decimal, rc 0 si
  `disponible >= necesaria`, rc 1 si no.

  Tabla fija (orden de magnitud del diseño; valores de GGUF Q4_K_M
  conocidos, no medidos contra la red):

  | Clave | GB descarga | RAM GiB | pull_id |
  |---|---|---|---|
  | `general:1b` | 0.7 | 2 | `llama3.2:1b` |
  | `general:3b` | 1.9 | 3 | `qwen2.5:3b` |
  | `general:7b` | 4.7 | 8 | `qwen2.5:7b` |
  | `general:14b` | 9.0 | 14 | `qwen2.5:14b` |
  | `qwen:0.5b` | 0.4 | 1 | `qwen2.5-coder:0.5b` |
  | `qwen:1.5b` | 1.0 | 2 | `qwen2.5-coder:1.5b` |
  | `qwen:3b` | 1.9 | 3 | `qwen2.5-coder:3b` |
  | `qwen:7b` | 4.7 | 8 | `qwen2.5-coder:7b` |
  | `qwen:14b` | 9.0 | 14 | `qwen2.5-coder:14b` |
  | `qwen:32b` | 20 | 24 | `qwen2.5-coder:32b` |
  | `foundation:8b` | 5 | 8 | `hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` |
  | `deephat:7b` | 4.7 | 8 | `hf.co/liodon-ai/DeepHat-V1-7B-imatrix-GGUF:Q4_K_M` |

  **Nota de alcance:** la investigación del diseño mencionaba DeepHat en
  "7B o 32B", pero no se encontró una conversión GGUF verificable de la
  variante 32B (solo la V1-7B tiene GGUF publicado por un conversor
  conocido). Se fija solo `deephat:7b`; no se inventa un identificador de
  modelo para un artefacto no verificado. Si en el futuro aparece un GGUF
  real de la 32B, se añade como `deephat:32b` sin tocar el resto.

- [ ] **Step 1: Write the failing test**, nueva sección en
  `tests/run_dependencies.sh`, `=== dependencies_models ===` (fuente
  ambos ficheros: añadir `source "$FW/00_Config/lib/dependencies_models.bash"`
  justo después del `source` de `dependencies.bash` al principio del
  script):
  ```bash
  out=$(bash -c "source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_model_rows")
  eq "4 filas" "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "4"
  printf '%s\n' "$out" | grep -q -F 'qwen|' && ok "incluye qwen" || ko "incluye qwen"
  printf '%s\n' "$out" | grep -qi 'sin censura' && ok "DeepHat avisa sin censura" || ko "DeepHat avisa sin censura"

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
  ```
- [ ] **Step 2: Run** `bash tests/run_dependencies.sh 2>&1 | tail -30` →
  FALLA (fichero/funciones no existen). Antes de este paso, añadir el
  `source` nuevo al principio de `tests/run_dependencies.sh` (línea 4,
  junto al `source` existente).
- [ ] **Step 3: Implement** `00_Config/lib/dependencies_models.bash`.
  `read_mem_available_gib`/`recommend_model`/`has_nvidia_gpu` no aceptan
  hoy una ruta de `/proc/meminfo` desde fuera salvo por el parámetro
  posicional de `read_mem_available_gib(meminfo_path=...)`; para que el
  test controle la RAM "libre" sin tocar `/proc/meminfo` real, el
  `python3 -c` pasa `os.environ.get("DEPENDENCIES_MEMINFO_PATH", "/proc/meminfo")`
  como argumento posicional — no se modifica `hardware.py`.
  ```bash
  DEPENDENCIES_MODELS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

  declare -gA DEPENDENCIES_MODEL_CATALOG=(
      [general:1b]='0.7|2|llama3.2:1b'
      [general:3b]='1.9|3|qwen2.5:3b'
      [general:7b]='4.7|8|qwen2.5:7b'
      [general:14b]='9.0|14|qwen2.5:14b'
      [qwen:0.5b]='0.4|1|qwen2.5-coder:0.5b'
      [qwen:1.5b]='1.0|2|qwen2.5-coder:1.5b'
      [qwen:3b]='1.9|3|qwen2.5-coder:3b'
      [qwen:7b]='4.7|8|qwen2.5-coder:7b'
      [qwen:14b]='9.0|14|qwen2.5-coder:14b'
      [qwen:32b]='20|24|qwen2.5-coder:32b'
      [foundation:8b]='5|8|hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M'
      [deephat:7b]='4.7|8|hf.co/liodon-ai/DeepHat-V1-7B-imatrix-GGUF:Q4_K_M'
  )
  declare -ga DEPENDENCIES_MODEL_ROW_ORDER=(general qwen foundation deephat)

  dependencies_model_rows() {
      printf 'general|General (según esta máquina)|Modelo generalista recomendado por el asistente de IA según RAM/GPU; sin entrenamiento específico de seguridad.\n'
      printf 'qwen|Qwen2.5-Coder (oficial, recomendado)|Modelo de código de Alibaba, librería oficial de Ollama; benchmarks de seguridad ofensiva lo señalan por encima de los modelos etiquetados de seguridad. Apache-2.0 salvo el tamaño 3B.\n'
      printf 'foundation|Foundation-Sec-8B-Instruct (Cisco)|Especialista real en ciberseguridad: preentrenado con datos de seguridad por Cisco Foundation AI, Apache-2.0. Tamaño fijo ~8B.\n'
      printf 'deephat|DeepHat / WhiteRabbitNeo (comunidad)|Proyecto de investigación en seguridad presentado sin censura a propósito (barreras de seguridad quitadas deliberadamente); no es una subida oficial de una empresa.\n'
  }

  dependencies_model_sizes() {
      local fila="$1" clave
      for clave in "${!DEPENDENCIES_MODEL_CATALOG[@]}"; do
          [[ "$clave" == "$fila:"* ]] && printf '%s\n' "${clave#*:}"
      done | sort -V
  }

  dependencies_model_lookup() {
      local clave="$1:$2"
      [[ -v DEPENDENCIES_MODEL_CATALOG[$clave] ]] || return 1
      printf '%s\n' "${DEPENDENCIES_MODEL_CATALOG[$clave]}"
  }

  dependencies_general_model_size() {
      python3 -c '
  import os, sys
  sys.path.insert(0, "'"$DEPENDENCIES_LIB_DIR"'")
  from ai.hardware import read_mem_available_gib, has_nvidia_gpu, recommend_model, MODEL_1B, MODEL_3B, MODEL_7B, MODEL_14B
  mem = read_mem_available_gib(os.environ.get("DEPENDENCIES_MEMINFO_PATH", "/proc/meminfo"))
  rec = recommend_model(mem, has_nvidia_gpu())
  print({MODEL_1B: "1b", MODEL_3B: "3b", MODEL_7B: "7b", MODEL_14B: "14b"}.get(rec.model, "3b"))
  '
  }

  dependencies_mem_check() {
      python3 -c '
  import os, sys
  sys.path.insert(0, "'"$DEPENDENCIES_LIB_DIR"'")
  from ai.hardware import read_mem_available_gib
  necesaria = float(sys.argv[1])
  disponible = read_mem_available_gib(os.environ.get("DEPENDENCIES_MEMINFO_PATH", "/proc/meminfo"))
  print(f"{disponible:.1f}")
  sys.exit(0 if disponible >= necesaria else 1)
  ' "$1"
  }
  ```
  `sort -V` (orden de versión) ordena `0.5b 1.5b 3b 7b 14b 32b`
  correctamente; si no está disponible en algún entorno de prueba, el
  fallback es un `sort` lexicográfico — se verifica en Step 4 que el test
  de "6 tamaños" (que solo cuenta líneas, no el orden) sigue pasando igual.
- [ ] **Step 4: Run** `bash tests/run_dependencies.sh 2>&1 | tail -30` →
  `Resultado: N ok, 0 fallos`.
- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/dependencies_models.bash CyberSecurity-Framework/tests/run_dependencies.sh
git commit -m "feat(config): catálogo de modelos de Ollama y guardrail de recursos (funciones puras)"
```

### Task 7: Orquestación del catálogo — elegir, avisar recursos, forzar o cancelar, `ollama pull`

**Files:**
- Modify: `00_Config/lib/dependencies_models.bash`
- Modify: `00_Config/lib/dependencies.bash` (`dependencies_install_ollama`
  llama al final a `dependencies_offer_model_catalog` si la instalación
  tuvo éxito o si `ollama` ya estaba presente)
- Test: `tests/run_dependencies.sh`

**Interfaces:**
- Consumes: todo lo de Task 6; `dependencies_binary_ok` (Task existente).
- Produces: `dependencies_offer_model_catalog() ->` rc 0 siempre que no
  haya un fallo de `ollama pull` (declinar el catálogo, o no superar el
  guardrail sin forzar, no son errores de la pieza — ver Review Focus 1);
  `dependencies_pull_model(pull_id) ->` ejecuta `ollama pull "$pull_id"`
  y, si tuvo éxito, comprueba con `ollama list` que aparece; rc refleja el
  resultado real.

- [ ] **Step 1: Write the failing test**, nueva sección
  `=== dependencies_offer_model_catalog ===`. Doble de `ollama` en
  `STUBDIR`: `pull <id>` registra en `CALLS` y, si `OLLAMA_PULL_RC` no
  está puesto o es `0`, anota el modelo en `$STUBDIR/pulled.txt`; `list`
  imprime el contenido de `pulled.txt` (o nada si no existe).
  ```bash
  MEMINFO_BAJO="$(mktemp)"; printf 'MemAvailable:  3774320 kB\n' > "$MEMINFO_BAJO"  # ~3,6 GiB

  # Declinar el catálogo tras instalar/ver ollama: no es un fallo.
  printf '0\n' | DEPENDENCIES_MEMINFO_PATH="$MEMINFO_BAJO" bash -c "export DEPENDENCIES_MEMINFO_PATH PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_offer_model_catalog" >/dev/null 2>&1
  eq "declinar el catálogo: rc 0" "$?" "0"
  [[ -f "$STUBDIR/pulled.txt" ]] && ko "declinar: no debía descargar nada" || ok "declinar: no descargó nada"

  # Elegir qwen:14b con solo 3,6 GiB libres: el guardrail bloquea sin forzar.
  printf '2\n14b\nno\n' | DEPENDENCIES_MEMINFO_PATH="$MEMINFO_BAJO" bash -c "export DEPENDENCIES_MEMINFO_PATH PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_offer_model_catalog" >/dev/null 2>&1
  eq "guardrail sin forzar: rc 0 (cancela el pull, no la pieza)" "$?" "0"
  [[ -f "$STUBDIR/pulled.txt" ]] && ko "guardrail sin forzar: no debía llegar a ollama pull" || ok "guardrail sin forzar: no llegó a ollama pull"

  # Elegir qwen:3b (sí entra en 3,6 GiB): pull directo sin aviso de guardrail.
  printf '2\n3b\n' | DEPENDENCIES_MEMINFO_PATH="$MEMINFO_BAJO" bash -c "export DEPENDENCIES_MEMINFO_PATH PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_offer_model_catalog" >/dev/null 2>&1
  eq "entra en RAM libre: rc 0" "$?" "0"
  grep -q -F 'qwen2.5-coder:3b' "$STUBDIR/pulled.txt" && ok "hizo ollama pull qwen2.5-coder:3b" || ko "hizo ollama pull qwen2.5-coder:3b"
  rm -f "$STUBDIR/pulled.txt"; : > "$CALLS"

  # Forzar qwen:14b con CONTINUAR_IGUAL: sí llega a ollama pull.
  printf '2\n14b\nCONTINUAR_IGUAL\n' | DEPENDENCIES_MEMINFO_PATH="$MEMINFO_BAJO" bash -c "export DEPENDENCIES_MEMINFO_PATH PATH='$STUBDIR'; source '$FW/00_Config/lib/dependencies.bash'; source '$FW/00_Config/lib/dependencies_models.bash'; dependencies_offer_model_catalog" >/dev/null 2>&1
  eq "forzado: rc 0" "$?" "0"
  grep -q -F 'qwen2.5-coder:14b' "$STUBDIR/pulled.txt" && ok "forzado llega a ollama pull" || ko "forzado llega a ollama pull"
  rm -f "$STUBDIR/pulled.txt" "$MEMINFO_BAJO"
  ```
- [ ] **Step 2: Run** → FALLA (función no existe).
- [ ] **Step 3: Implement.**
  ```bash
  dependencies_pull_model() {
      local pull_id="$1"
      printf 'Descargando %s con Ollama...\n' "$pull_id" >&2
      if ! ollama pull "$pull_id"; then
          printf 'La descarga del modelo falló.\n' >&2; return 1
      fi
      if ! ollama list 2>/dev/null | grep -qF "$pull_id"; then
          printf 'El modelo se descargó pero no aparece en «ollama list».\n' >&2; return 1
      fi
      printf 'Modelo %s disponible.\n' "$pull_id" >&2
  }

  dependencies_offer_model_catalog() {
      printf 'Catálogo de modelos para Ollama:\n' >&2
      local fila etiqueta descripcion i=0
      local -a filas=()
      while IFS='|' read -r fila etiqueta descripcion; do
          i=$((i + 1)); filas+=("$fila")
          printf '  %d) %s — %s\n' "$i" "$etiqueta" "$descripcion" >&2
      done < <(dependencies_model_rows)
      printf '  0) No descargar ningún modelo ahora\n' >&2
      printf 'Elige una opción [0-%d]: ' "$i" >&2
      local eleccion; IFS= read -r eleccion
      [[ "$eleccion" =~ ^[0-9]+$ ]] && (( eleccion >= 1 && eleccion <= i )) || return 0
      fila="${filas[$((eleccion - 1))]}"

      local tamaño
      if [[ "$fila" == 'general' ]]; then
          tamaño=$(dependencies_general_model_size)
      else
          local -a tamaños; mapfile -t tamaños < <(dependencies_model_sizes "$fila")
          if [[ ${#tamaños[@]} -eq 1 ]]; then
              tamaño="${tamaños[0]}"
          else
              local j=0
              for j in "${!tamaños[@]}"; do printf '  %s\n' "${tamaños[$j]}" >&2; done
              printf 'Tamaño (de los listados arriba): ' >&2
              IFS= read -r tamaño
          fi
      fi
      local datos; datos=$(dependencies_model_lookup "$fila" "$tamaño") || {
          printf 'Combinación de modelo/tamaño no reconocida.\n' >&2; return 0
      }
      local gb="${datos%%|*}" resto="${datos#*|}" ram="${resto%%|*}" pull_id="${resto#*|}"

      local disponible; disponible=$(dependencies_mem_check "$ram")
      if [[ $? -ne 0 ]]; then
          printf 'Este modelo (%s GB, necesita ~%s GiB libres) no entra en la RAM libre de esta máquina (~%s GiB).\n' "$gb" "$ram" "$disponible" >&2
          printf 'Escribe CONTINUAR_IGUAL para forzarlo a sabiendas (puede ir muy lento o colgarse); cualquier otra entrada cancela solo esta descarga: ' >&2
          local forzar; IFS= read -r forzar
          [[ "$forzar" == 'CONTINUAR_IGUAL' ]] || { printf 'Descarga de modelo cancelada; puedes elegir otro tamaño.\n' >&2; return 0; }
      fi
      dependencies_pull_model "$pull_id"
  }
  ```
  Y en `dependencies.bash`, al final de `dependencies_install_ollama`
  (tanto en el camino "ya estaba instalado" como en el de instalación
  recién hecha con éxito) se añade la llamada:
  `dependencies_offer_model_catalog`.
- [ ] **Step 4: Run** `bash tests/run_dependencies.sh 2>&1 | tail -40` →
  `Resultado: N ok, 0 fallos`. Además, volver a correr las pruebas de
  Task 5 (`dependencies_install_ollama`) para confirmar que, con el doble
  de `ollama` también sirviendo `pull`/`list`, sigue en verde con la nueva
  llamada final.
- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/dependencies_models.bash CyberSecurity-Framework/00_Config/lib/dependencies.bash CyberSecurity-Framework/tests/run_dependencies.sh
git commit -m "feat(config): ofrecer el catálogo de modelos tras instalar/ver Ollama, con guardrail de recursos"
```

### Task 8: Integración en el menú de la tecla `D`

**Files:**
- Modify: `cyber_framework.sh` (`dependencies_menu`, ~línea 1084; `source`
  de `dependencies_models.bash` junto al de `dependencies.bash`)
- Modify: `tests/run_smoke.sh`

**Interfaces:**
- Produces: dentro de `dependencies_menu`, una opción `2` nueva que: lista
  (`dependencies_extra_missing`) lo que falta de las tres herramientas con
  su descripción (reutilizando `DEPENDENCIES_NO_APT[...]`, ya impresa en
  `dependencies_status`); pide selección numerada + `todas`/`0`/cancela
  (reutilizando `dependencies_resolve_selection`); instala cada elegida
  llamando a su `dependencies_install_<herramienta>` (con `-` por `-` en
  el nombre de función, p. ej. `nmap-vulners` → `dependencies_install_nmap_vulners`);
  al terminar, vuelve a imprimir `dependencies_status` filtrado a esas
  tres líneas (o simplemente relanza `dependencies_status` completo, más
  simple y consistente con lo que ya hace el menú al principio).

- [ ] **Step 1: Write the failing test** en `tests/run_smoke.sh`, sección
  `=== dependencias: acción D ===` (ya existe; añadir casos):
  `menú: D opción 2 aparece` (entrada `'D\n'` → la salida contiene
  "herramientas adicionales"); `menú: D 2 con PATH cerrado sin red lista
  las tres` (entrada `'D\n2\n0\n0\n'`, con `PATH` ya cerrado por la
  propia suite — nunca real — → la salida contiene `ollama`, `avml` y
  `nmap-vulners`, y el proceso vuelve limpio al menú principal sin
  intentar ninguna instalación real porque la segunda entrada es `0`
  dentro del submenú de selección).
- [ ] **Step 2: Run** `bash tests/run_smoke.sh 2>&1 | tail -20` → FALLA
  (la opción `2` no existe todavía).
- [ ] **Step 3: Implement.** Cerca de la línea donde se fuente
  `dependencies.bash` (según el diseño, ~línea 32), añadir el `source` de
  `dependencies_models.bash`. En `dependencies_menu`, tras la rama
  `1) ... ;;` existente, añadir:
  ```bash
  2)
      local -a extra; mapfile -t extra < <(dependencies_extra_missing)
      if [[ ${#extra[@]} -eq 0 ]]; then
          echo -e "${DIM}No falta ninguna herramienta adicional.${NC}"; pause; return 0
      fi
      echo -e "${YELLOW}Herramientas adicionales que faltan:${NC}"
      for i in "${!extra[@]}"; do
          printf '  %d) %s (%s)\n' "$((i + 1))" "${extra[$i]}" "${DEPENDENCIES_NO_APT[${extra[$i]}]}"
      done
      echo -ne "${BOLD}➜ Números a instalar (espacio entre varios, 'todas', 0 o ! cancela): ${NC}"
      if ! IFS= read -r seleccion || [[ "$seleccion" == '0' || "$seleccion" == '!' || -z "$seleccion" ]]; then
          pause; return 0
      fi
      local resuelto rc_resuelto
      resuelto=$(dependencies_resolve_selection "$seleccion" "${extra[@]}")
      rc_resuelto=$?
      if [[ $rc_resuelto -ne 0 ]]; then
          echo -e "${RED}Selección inválida.${NC}"; pause; return 0
      fi
      local -a elegidas; mapfile -t elegidas <<< "$resuelto"
      local herramienta funcion
      for herramienta in "${elegidas[@]}"; do
          funcion="dependencies_install_${herramienta//-/_}"
          "$funcion"
      done
      echo ""; dependencies_status
      ;;
  ```
  y actualizar el prompt/leyenda ("Elige una opción [0-2]") y la línea del
  menú ("2) Instalar/verificar herramientas adicionales (Ollama, avml,
  nmap-vulners)").
- [ ] **Step 4: Run** `bash tests/run_smoke.sh 2>&1 | tail -20` → todos
  `OK`; `bash -n cyber_framework.sh` con stderr capturado, vacío.
- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/cyber_framework.sh CyberSecurity-Framework/tests/run_smoke.sh
git commit -m "feat(config): tecla D ofrece instalar/verificar Ollama, avml y nmap-vulners"
```

### Task 9: Documentación y verificación final

**Files:**
- Modify: `docs/MANUAL-GESTOR.md` (sección de la tecla `D`)
- Modify: `AGENTS.md` (bloque de estado breve y fecha, como ya hacen las
  piezas anteriores)
- Modify: `00_Config/lib/dependencies.bash` / `dependencies_models.bash`
  solo si la verificación final encuentra algo (no se espera código
  nuevo en esta tarea)

**Interfaces:** ninguna nueva; esta tarea es documentación + verificación.

- [ ] **Step 1: Escribir la documentación.** En `docs/MANUAL-GESTOR.md`,
  ampliar la sección de la tecla `D` explicando la opción `2`: qué hace
  cada una de las tres herramientas, que `lime`/`volatility` siguen solo
  informativos y por qué, el catálogo de 4 modelos con su descripción
  honesta (incluido el aviso de censura de DeepHat y la falta de checksum
  oficial de avml), y el guardrail de recursos con el literal exacto
  `CONTINUAR_IGUAL`.
- [ ] **Step 2: Actualizar `AGENTS.md`** con un bloque fechado 2026-11-17
  resumiendo: qué se automatizó (ollama+catálogo, avml, nmap-vulners),
  qué se corrigió de paso (nombre de fichero de nmap-vulners), qué queda
  igual (`lime`/`volatility`), y que no se ejecutó ninguna instalación
  real durante el desarrollo (todo contra dobles).
- [ ] **Step 3: Verificación final.**
  ```bash
  bash -n CyberSecurity-Framework/00_Config/lib/dependencies.bash
  bash -n CyberSecurity-Framework/00_Config/lib/dependencies_models.bash
  bash -n CyberSecurity-Framework/cyber_framework.sh
  bash CyberSecurity-Framework/tests/run_dependencies.sh 2>&1 | tail -5
  bash CyberSecurity-Framework/tests/run_smoke.sh 2>&1 | tail -10
  ```
  Todos los `bash -n` capturan stderr y deben quedar vacíos; las dos
  suites deben terminar en `0 fallos`.
- [ ] **Step 4: Confirmar que nada de esto tocó `scope.yaml`/`targets.txt`
  reales ni ejecutó `curl`/`git`/`sudo`/`ollama` fuera de los tests**
  (revisión manual del `git diff` de esta tarea: solo documentación).
- [ ] **Step 5: Commit**

```bash
git add docs/MANUAL-GESTOR.md AGENTS.md
git commit -m "docs(config): documentar las herramientas adicionales interactivas de la tecla D"
```
