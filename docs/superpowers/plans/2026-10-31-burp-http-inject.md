# Fase Burp: petición capturada, inyección y validación — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir al framework una pieza que inyecte sobre una petición HTTP capturada en Burp (query, formulario y JSON, con sesión) y clasifique cada diferencia por evidencia, más un lanzador de Burp desde el gestor que explique el flujo manual.

**Architecture:** La lógica reutilizable va en una librería nueva, `00_Config/lib/http_request.bash` (lectura de la petición, sustitución de parámetros, firma normalizada y detección de señales), porque es lo único que el gestor ya sabe probar con asertos unitarios. `05_Exploitation/web/http_inject.sh` la orquesta y escribe en `scans/web/`. `03_Scanners/web_scanners/burpsuite/burp_launcher.sh` arranca Burp, comprueba el puerto real y explica el flujo. Los tests viven en `tests/run_tests.sh` (sección nueva por tarea), con un servidor de prueba en `tests/fixtures/http_target.py` y un `burpsuite` falso en `PATH`.

**Tech Stack:** Bash sin `set -e`, `curl`, `md5sum`, `python3` (solo para JSON y para el servidor de prueba), `ss`, `xdotool` (opcional), librerías de `00_Config/lib/`.

**Spec:** `docs/superpowers/specs/2026-10-31-burp-http-inject-design.md`

## Global Constraints

- Sin `set -e`. Mensajes de usuario en español. Ficheros LF.
- Autolocalización: ninguna ruta depende del `cwd`. La librería resuelve con `${BASH_SOURCE[0]:-$0}`; los scripts con `dirname "${BASH_SOURCE[0]}"`.
- `Uso:` y `Ejemplo:` funcionales, en la cabecera, con huecos `<...>`/`[...]` y **sin `|`** dentro de los huecos.
- Quien devuelve un valor imprime **solo** el valor por stdout; la interfaz va a stderr.
- Convención de salidas: librería `scans.bash` (`scans_dir`, `scans_slug`); nada de rutas construidas a mano.
- `stderr` de las herramientas a `errores.log`, nunca descartado en silencio.
- Los tests corren sin terminal interactiva y en Git Bash; lo que dependa de `python3`, `zsh`, `ss` o `xdotool` se salta con aviso explícito.
- Niveles exactos, en mayúsculas y sin tildes en el fichero de máquina: `CONFIRMADO`, `FUERTE`, `DEBIL`.
- Códigos de salida de `http_inject.sh`: `0` ejecutado (haya o no hallazgos), `1` error de uso, parseo, red o petición sin parámetros.
- Umbrales del spec: 3 líneas base por parámetro, 2 repeticiones, retardo de 5 s con umbral de 4 s, tope de 400 peticiones, evidencia truncada a 64 KB.

## Review Focus

1. **Petición con CRLF o `Content-Length` que no cuadra con el cuerpo**: debe aceptarse el CRLF y recalcular el tamaño sin corromper el cuerpo (Task 1).
2. **JSON anidado con números, booleanos y `null`**: se inyecta en las hojas, el JSON sigue siendo válido y un número sustituido por cadena no rompe el resto (Task 2).
3. **Respuesta con nonce/CSRF distinto en cada petición**: no puede generar DÉBILES en masa; la firma se normaliza antes de comparar (Task 3).
4. **Parámetro que solo refleja el valor**: es el falso positivo del 31; nunca puede salir CONFIRMADO (Tasks 4 y 6).
5. **Sesión que caduca a mitad de la tanda**: debe avisarse y no reportar esa tanda como limpia (Task 4).

---

### Task 1: Librería `http_request.bash` — lectura de la petición y URL

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/http_request.bash`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva al final, antes de `rm -rf "$TMPD"`)

**Interfaces:**
- Consumes: nada (librería independiente; no usa `scans.bash`).
- Produces:
  - `hr_load <fichero>` → `0` ok; `1` no legible; `2` petición mal formada; `3` cuerpo no soportado. Deja las globales `HR_METHOD`, `HR_TARGET`, `HR_VERSION`, `HR_HOST`, `HR_HEADERS[]`, `HR_BODY`, `HR_CT`, y `HR_CONFIG_DIR`.
  - `hr_scheme <puerto>` → `http` o `https` (443 y 8443 → `https`; vacío → `http`).
  - `hr_port <esquema>` → puerto del `Host:` si lo trae, si no 443/80.
  - `hr_url <objetivo> <esquema>` → URL completa; omite el puerto si es el del esquema.

- [ ] **Step 1: Escribir los tests que fallan**

Añadir al final de `tests/run_tests.sh`:

```bash
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
```

- [ ] **Step 2: Ejecutar y ver fallar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: la sección nueva falla (`hr_load: command not found`, `esperado [0] / obtenido [127]`).

- [ ] **Step 3: Implementar la librería**

En `00_Config/lib/http_request.bash`: cabecera con el contrato (stdout = valor, interfaz por stderr), resolución de ruta con `${BASH_SOURCE[0]:-$0}`, y las cuatro funciones. `hr_load` lee el fichero entero, quita `\r` finales de cada línea, separa cabeceras del cuerpo por la primera línea vacía, valida que la primera línea tenga tres campos y guarda todo en las globales. `Content-Length` se recalcula con `LC_ALL=C printf '%s' "$HR_BODY" | wc -c` y, si el valor original difería, se avisa por stderr. `HR_CT` es el `Content-Type` en minúsculas y sin parámetros. La detección de `Transfer-Encoding` y `multipart/form-data` se hace por cabecera, antes de leer el cuerpo.

- [ ] **Step 4: Ejecutar y ver pasar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: todos los asertos nuevos en `ok`, `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/http_request.bash CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(lib): leer una peticion HTTP cruda y construir su URL"
```

---

### Task 2: Librería — parámetros y sustitución (query, formulario, JSON)

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/lib/http_request.bash`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva)

**Interfaces:**
- Consumes: `hr_load` (globales `HR_TARGET`, `HR_BODY`, `HR_CT`).
- Produces:
  - `hr_params` → una línea por parámetro `ubicacion|nombre|valor`, con `ubicacion` en `query|form|json`; en JSON, `nombre` es la ruta con puntos (`user.email`). Código `4` si el cuerpo es JSON y no hay `python3`.
  - `hr_target_with <ubicacion> <nombre> <valor>` → `HR_TARGET` con la query sustituida (o el mismo target si la ubicación no es `query`).
  - `hr_body_with <ubicacion> <nombre> <valor>` → cuerpo resultante (o `HR_BODY` si la ubicación es `query`).
- Nota: la sustitución **no** aplica codificación; el llamante decide si codifica (query y form sí, JSON no).

- [ ] **Step 1: Escribir los tests que fallan**

```bash
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
```

- [ ] **Step 2: Ejecutar y ver fallar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `hr_params: command not found`.

- [ ] **Step 3: Implementar**

`hr_params` despacha por `HR_CT`: `application/x-www-form-urlencoded` recorre el cuerpo partiendo por `&` y `=`; `application/json` llama a `python3` con un script que recorre el árbol y emite solo hojas (cadenas, números, booleanos, `null`) con la ruta punteada, devolviendo `5` si el JSON no parsea; el resto de tipos solo mira la query. La query se recorre igual desde `HR_TARGET`. La sustitución se hace con un `awk`/bucle que reconstruye respetando el orden; en JSON, el script de `python3` recibe la ruta y el valor por argumentos (nunca interpolados en el código).

- [ ] **Step 4: Ejecutar y ver pasar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `fallan: 0` (o `SKIP` de la parte JSON si no hay `python3`).

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/http_request.bash CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(lib): listar y sustituir parametros de query, formulario y JSON"
```

---

### Task 3: Librería — firma normalizada, reflejo sin escapar y errores de BD

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/lib/http_request.bash`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva)

**Interfaces:**
- Consumes: nada nuevo.
- Produces:
  - `hr_signature <fichero_cuerpo> <codigo> <tamano> [cadena...]` → `codigo:tamano:<md5>` donde el md5 es del cuerpo **normalizado**.
  - `hr_unescaped <fichero_cuerpo> <payload>` → `0` si el payload aparece literal.
  - `hr_db_error <fichero_cuerpo>` → `0` si hay firma de error de BD; imprime la firma encontrada por stdout.

- [ ] **Step 1: Escribir los tests que fallan**

```bash
# ──────────────────────────────────────────────────────────
section "http_request: firma normalizada y señales"
printf '<html><input name="csrf" value="a1b2c3d4e5f6a7b8"><p>hola</p><span id="n">1717171717</span></html>' > "$TMPD/c1"
printf '<html><input name="csrf" value="9999888877776666"><p>hola</p><span id="n">1717179999</span></html>' > "$TMPD/c2"
eq "hr_signature: nonce y epoch no cambian la firma" \
   "$(hr_signature "$TMPD/c1" 200 96)" "$(hr_signature "$TMPD/c2" 200 96)"
sig=$(hr_signature "$TMPD/c1" 200 96)
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
```

- [ ] **Step 2: Ejecutar y ver fallar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `hr_signature: command not found`.

- [ ] **Step 3: Implementar**

`hr_signature` recibe las cadenas a neutralizar (payload, token y sus variantes URL/HTML) y las sustituye por `~~`; después normaliza patrones volátiles con `sed -E`: valores de `csrf`, tokens hexadecimales de 16+ caracteres, cadenas base64 de 24+ caracteres, fechas ISO-8601 y epoch de 10–13 dígitos. El md5 se calcula con `md5sum` sobre el resultado. `hr_unescaped` busca el literal con `grep -qF`. `hr_db_error` recorre una tabla de firmas (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) y devuelve la primera que case.

- [ ] **Step 4: Ejecutar y ver pasar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/http_request.bash CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(lib): firma normalizada, reflejo sin escapar y errores de BD"
```

---

### Task 4: `http_inject.sh` — arranque, guardas y línea base

**Files:**
- Create: `CyberSecurity-Framework/05_Exploitation/web/http_inject.sh`
- Create: `CyberSecurity-Framework/tests/fixtures/http_target.py`
- Modify: `CyberSecurity-Framework/00_Config/lib/dangerous.txt` (añadir `05_Exploitation/web/http_inject.sh`)
- Modify: `CyberSecurity-Framework/00_Config/lib/session.bash:8` (permitir aislar el directorio en tests)
- Modify: `CyberSecurity-Framework/tests/run_tests.sh:51` (recuento 114 → 115)
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva)

**Interfaces:**
- Consumes:
  - `00_Config/lib/http_request.bash`: `hr_load`, `hr_scheme`, `hr_port`, `hr_url`, `hr_params`, `hr_target_with`, `hr_body_with`, `hr_signature`, `hr_unescaped`, `hr_db_error`.
  - `00_Config/lib/scans.bash`: `scans_dir web`, `scans_slug`.
  - `00_Config/lib/session.bash`: `scope_allows <objetivo>` → `0` permitido, `1` no, `2` no interpretable.
- Produces: `http_inject.sh`, cuyas constantes y ficheros usan las tareas 5–7, y el helper `iniciar_servidor_http` en `tests/run_tests.sh` (imprime el puerto y deja `HTTP_SRV_PID`), que consumen las tareas 5–7.

- [ ] **Step 1: Crear el servidor de prueba**

`tests/fixtures/http_target.py`: servidor `http.server` en `127.0.0.1` con puerto tomado de `argv[1]`, endpoints listos para las tareas 4–6:

| Ruta | Comportamiento |
|---|---|
| `/echo?q=` | refleja `q` sin escapar en HTML |
| `/esc?q=` | refleja `q` escapado |
| `/safe?id=` | siempre el mismo HTML, ignore el valor (catch-all) |
| `/sqli?id=` | `1' AND '1'='1` → página normal; `1' AND '1'='2` → página distinta; el resto normal |
| `/err?id=` | 500 con `You have an error in your SQL syntax` si el valor trae `'` |
| `/time?id=` | duerme 1 s si el valor contiene `sleep` |
| `/xss?q=` | igual que `/echo` |
| `/ssti?name=` | si el valor trae `{{7*7}}` responde `49` |
| `/unstable` | tamaño aleatorio en cada respuesta |
| `/login` (POST JSON) | 401 si falta `Cookie: sid=ok`; 200 y refleja `user` si la trae |

- [ ] **Step 2: Escribir los tests que fallan**

```bash
# ──────────────────────────────────────────────────────────
section "http_inject: arranque y guardas"
# Helper compartido por las secciones de las tareas 4-7
iniciar_servidor_http() {
    command -v python3 >/dev/null 2>&1 || return 1
    local p
    p=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
    python3 "$FW/tests/fixtures/http_target.py" "$p" >/dev/null 2>&1 &
    HTTP_SRV_PID=$!
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        curl -s -o /dev/null "http://127.0.0.1:$p/safe" && break
        sleep 0.3
    done
    printf '%s\n' "$p"
}

if HPORT=$(iniciar_servidor_http); then
    _limpiar_http() { kill "$HTTP_SRV_PID" 2>/dev/null; }
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
    eq "http_inject: informa del objetivo" "$(printf '%s' "$OUT" | grep -c '127.0.0.1')" "1"
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
    _limpiar_http
    rm -f "$FW/../scans/web/http_inject_127.0.0.1_"*.txt
else
    echo "  SKIP     python3 no instalado: sin servidor de prueba"
fi
```

- [ ] **Step 3: Ejecutar y ver fallar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `http_inject.sh: No such file or directory`.

- [ ] **Step 4: Implementar**

Cabecera con `Uso: ./http_inject.sh <fichero> [objetivo]` y `Ejemplo: ./http_inject.sh /ruta/peticion.txt 10.10.10.5`, y comentario con las variables de entorno (`HTTP_INJECT_NIVEL`, `HTTP_INJECT_PARAM`, `HTTP_INJECT_RETARDO`, `HTTP_INJECT_ESQUEMA`, `HTTP_INJECT_PROXY`, `HTTP_INJECT_SI`, `HTTP_INJECT_MAX`=400, `HTTP_INJECT_SLEEP`=5, `HTTP_INJECT_UMBRAL`=4). Flujo: leer argumentos (`-` → fichero temporal), `hr_load`, calcular esquema/puerto/URL, avisar por `scope_allows` (código 1 o 2 → aviso, nunca bloqueo), listar `hr_params` (vacío → mensaje y `exit 1`), imprimir método y endpoint, y si el método no es `GET`/`HEAD` sin `HTTP_INJECT_SI=1` pedir confirmación por stdin (no → mensaje de cancelación y `exit 0`). Medir línea base por parámetro con token aleatorio ×3 y comparar con `hr_signature`; inestable → marca el parámetro. Sonda de catch-all: parámetro inexistente con token; si su firma coincide con la base, avisar. Si la línea base es 401/403, avisar de posible sesión caducada. De momento escribe el informe `.txt` con las secciones de nivel vacías y el recuento. Nada de payloads todavía. Los ficheros de salida se nombran con `scans_slug "<objetivo>_<puerto>"`.

Además, en `00_Config/lib/session.bash:8` cambiar `SESSION_CONFIG_DIR="$(cd …)"` por `SESSION_CONFIG_DIR="${SESSION_CONFIG_DIR:-$(cd …)}"`, igual que ya hace `SESSION_FILE`, para que los tests puedan aislar el `scope.yaml` sin tocar el del operador.

- [ ] **Step 5: Ejecutar y ver pasar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `fallan: 0` y `115 scripts .sh en el framework`.

- [ ] **Step 6: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/http_inject.sh CyberSecurity-Framework/tests/fixtures/http_target.py CyberSecurity-Framework/00_Config/lib/dangerous.txt CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(exploit): http_inject lee una peticion capturada, mide linea base y avisa de catch-all"
```

---

### Task 5: `http_inject.sh` — SQLi con niveles

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/http_inject.sh`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva, reutiliza el servidor de la Task 4)

**Interfaces:**
- Consumes: las guardas de la Task 4 y las funciones de la librería.
- Produces: la función interna `probar_sqli <ubicacion> <nombre>` y la emisión de líneas `CONFIRMADO|FUERTE|DEBIL` en el informe.

- [ ] **Step 1: Escribir los tests que fallan**

```bash
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
    eq "sqli: resume confirmados en consola" "$(printf '%s' "$OUT" | grep -c 'confirmado')" "1"

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
```

- [ ] **Step 2: Ejecutar y ver fallar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `sqli: par booleano es CONFIRMADO` → obtenido `0`.

- [ ] **Step 3: Implementar**

Tres rutas dentro de `probar_sqli`, una por clase:

1. **Booleana**: para cada par (`x' AND '1'='1` / `x' AND '1'='2`, y el numérico `1 AND 1=1` / `1 AND 1=2`), comparar con la línea base usando `hr_signature` neutralizando el payload y el token. Repetir 2 veces. Ambas verdaderas → `CONFIRMADO`; falsa distinta pero verdadera también distinta → `FUERTE`.
2. **Error**: enviar `'`, `"`, `')`, `';--`; si `hr_db_error` casa con el payload y no con el token → `FUERTE` (nunca `CONFIRMADO`: no demuestra impacto).
3. **Tiempo**: enviar los tres payloads de retardo, medir con `curl -w '%{time_total}'` y comparar con el mínimo de la base; ≥ base + `HTTP_INJECT_UMBRAL` dos veces → `CONFIRMADO`, una → `FUERTE`.

Cada envío pasa por un contador común que respeta `HTTP_INJECT_MAX` y por `HTTP_INJECT_RETARDO` (0,2 s por defecto). El `.tsv` se trunca al principio de cada ejecución (los hallazgos son de este objetivo y de este run). Toda petición usa `curl -sk` con las cabeceras del fichero (salvo `Host`, `Content-Length`, `Transfer-Encoding` y `Expect`), `--resolve` cuando el objetivo difiere del `Host:`, y `HTTP_INJECT_PROXY`/`http_proxy` si están definidos (la cabecera lo anuncia).

- [ ] **Step 4: Ejecutar y ver pasar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/http_inject.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(exploit): SQLi booleana, por error y por tiempo con niveles de evidencia"
```

---

### Task 6: `http_inject.sh` — XSS, comandos y SSTI

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/http_inject.sh`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva)

**Interfaces:**
- Consumes: `probar_sqli` como patrón; `hr_unescaped`, `hr_signature`.
- Produces: funciones internas `probar_xss`, `probar_cmd`, `probar_ssti` con las mismas firmas `<ubicacion> <nombre>`.

- [ ] **Step 1: Escribir los tests que fallan**

```bash
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
```

- [ ] **Step 2: Ejecutar y ver fallar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `xss: reflejo sin escapar es CONFIRMADO` → obtenido `0`.

- [ ] **Step 3: Implementar**

- **XSS**: payloads `<script>alert(1)</script>`, `"><svg onload=alert(1)>`, `'><img src=x onerror=alert(1)>`. `CONFIRMADO` si `hr_unescaped` casa y el `Content-Type` de la respuesta es HTML/JS; si el reflejo está escapado → `FUERTE`; si el `Content-Type` es JSON → `FUERTE` como máximo.
- **Comandos**: `; sleep N`, `| sleep N`, `$(sleep N)`, `` `sleep N` `` con `N=HTTP_INJECT_SLEEP`; mismas reglas de tiempo que la SQLi (2/2 → `CONFIRMADO`, 1 → `FUERTE`). Ningún payload de lectura ni escritura.
- **SSTI**: `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`; `CONFIRMADO` si aparece `49` y no aparece el literal `7*7`, 2 de 2; 1 de 2 → `FUERTE`.
- Cualquier otra diferencia de firma no explicada por las clases anteriores → `DEBIL` con el motivo.

- [ ] **Step 4: Ejecutar y ver pasar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/http_inject.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(exploit): XSS, inyeccion de comandos y SSTI con niveles de evidencia"
```

---

### Task 7: `http_inject.sh` — evidencia, resumen y filtro por nivel

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/http_inject.sh`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva)

**Interfaces:**
- Consumes: todo lo anterior.
- Produces: ficheros de evidencia en `scans/web/http_inject_<slug>/`, resumen en consola y filtro `HTTP_INJECT_NIVEL=fuertes`.

- [ ] **Step 1: Escribir los tests que fallan**

```bash
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

    OUT=$(HTTP_INJECT_NIVEL=fuertes bash "$FW/05_Exploitation/web/http_inject.sh" "$TMPD/req_ev.txt" 127.0.0.1 2>&1)
    eq "filtro fuertes: la consola no lista confirmados" "$(printf '%s' "$OUT" | grep -c 'CONFIRMADO')" "0"
    TSV="$FW/../scans/web/http_inject_127.0.0.1_"$HPORT".tsv"
    eq "filtro fuertes: el fichero conserva lo confirmado" "$(awk -F'\t' '$1=="CONFIRMADO"' "$TSV" | wc -l | tr -d ' ' | awk '{print ($1>0)}')" "1"
    eq "resumen: cuenta por nivel" "$(printf '%s' "$OUT" | grep -cE '[0-9]+ confirmado')" "1"
    rm -rf "$FW/../scans/web/http_inject_127.0.0.1_"*
    kill "$HTTP_SRV_PID" 2>/dev/null
else
    echo "  SKIP     python3 no instalado"
fi
```

- [ ] **Step 2: Ejecutar y ver fallar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `evidencia: hay pares .req` → obtenido `0`.

- [ ] **Step 3: Implementar**

Para cada `CONFIRMADO` y `FUERTE`, guardar la petición enviada (`%03d_<param>_<clase>.req`, con la línea de petición y cabeceras resueltas) y el cuerpo de la respuesta truncado con `head -c 65536`. El `.tsv` se escribe siempre completo; el `.txt` y la consola respetan `HTTP_INJECT_NIVEL=fuertes`. En consola, el nombre del nivel va en mayúsculas (`CONFIRMADO`), igual que en el `.tsv`. La consola termina con `N confirmados, M fuertes, K débiles → ruta` y, si hubo avisos (catch-all, línea base inestable, alcance, sesión), los repite al final.

- [ ] **Step 4: Ejecutar y ver pasar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/http_inject.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(exploit): evidencia reproducible, resumen por nivel y filtro de lectura"
```

---

### Task 8: `burp_launcher.sh` — puerto, config, arranque y PID

**Files:**
- Create: `CyberSecurity-Framework/03_Scanners/web_scanners/burpsuite/burp_launcher.sh`
- Modify: `CyberSecurity-Framework/tests/run_tests.sh:51` (recuento 115 → 116)
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva, con `burpsuite` falso en `PATH`)

**Interfaces:**
- Consumes: `00_Config/lib/scans.bash` (`scans_dir burp`, `scans_slug`) y `00_Config/lib/session.bash` (`session_target`).
- Produces: `scans/burp/config_<slug>.json`, `scans/burp/burp.pid`, `scans/burp/launcher.log`; subcomandos `--estado` y `--parar`; variable `BURP_LAUNCHER_ESPERA` (segundos, por defecto 60).

- [ ] **Step 1: Escribir los tests que fallan**

```bash
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
eq "launcher: llama al wrapper, no a java -jar" "$(grep -c 'burpsuite' "$BSTUB_LOG")" "1"
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
```

- [ ] **Step 2: Ejecutar y ver fallar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `burp_launcher.sh: No such file or directory`.

- [ ] **Step 3: Implementar**

`Uso: ./burp_launcher.sh [puerto]` / `Ejemplo: ./burp_launcher.sh 8080`. Elige puerto con `ss -ltn` (si el pedido está ocupado, error; si no se pide, 8080 y luego 8080-8099). Escribe `config_<slug>.json` con el listener y el `scope` del objetivo de sesión (config a la mejor de nuestras posibilidades; el script no deduce nada de su contenido), **en una sola línea y sin espacios** (`{"proxy":{"request_listeners":[{"listener_port":8099,...}]}}`) para que sea inspeccionable con `grep`. Lanza `burpsuite --project-file=... --config-file=... >> launcher.log 2>&1 &`, guarda `$!` en `burp.pid`. `--parar` mata solo ese PID y borra el fichero; `--estado` informa de PID y puerto.

- [ ] **Step 4: Ejecutar y ver pasar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `fallan: 0` y `116 scripts .sh en el framework`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/03_Scanners/web_scanners/burpsuite/burp_launcher.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(burp): lanzador con puerto libre, config y control por PID"
```

---

### Task 9: `burp_launcher.sh` — espera, Start Burp, captura y explicación

**Files:**
- Modify: `CyberSecurity-Framework/03_Scanners/web_scanners/burpsuite/burp_launcher.sh`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva)

**Interfaces:**
- Consumes: la Task 8 (`BURP_LAUNCHER_ESPERA`, PID, puerto).
- Produces: la explicación del flujo manual y la verificación de captura; nada que consuman otras tareas.

- [ ] **Step 1: Escribir los tests que fallan**

```bash
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
eq "launcher: detecta el puerto cuando escucha" "$(printf '%s' "$OUT" | grep -c '8090')" "1"
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
```

- [ ] **Step 2: Ejecutar y ver fallar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `launcher: detecta el puerto cuando escucha` → obtenido `0`.

- [ ] **Step 3: Implementar**

Espera activa hasta `BURP_LAUNCHER_ESPERA` comprobando `ss -ltn` cada 2 s. Si no aparece y `xdotool` existe con ventana `Burp Suite Community`, pedir confirmación y pulsar el botón calculando el centro con la geometría de `xwininfo` (`x + ancho - 62`, `y + alto - 33`); si no hay `xdotool` o se niega, explicar. Si sigue sin escuchar: mensaje con *Settings → Proxy → Proxy settings* y oferta de `--estado`, sin abortar. Si escucha: verificar captura con `curl --noproxy '' -x http://127.0.0.1:<puerto>` contra el objetivo y anunciar el código obtenido (o que no hubo respuesta). Imprimir la explicación: proxy del navegador, CA, Repeater, guardar como `scans/burp/peticion_<slug>.txt` (el lanzador no lo crea), comando `./http_inject.sh <ruta> <objetivo>`, y el aviso de que Community no guarda proyectos.

- [ ] **Step 4: Ejecutar y ver pasar**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/03_Scanners/web_scanners/burpsuite/burp_launcher.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(burp): espera al listener, verifica captura y explica el flujo manual"
```

---

### Task 10: Documentación y verificación final

**Files:**
- Create: `docs/BURP-HTTP-INJECT-2026-10-31.md`
- Modify: `AGENTS.md` (sección «Current state» y la de convenciones)
- Modify: `CyberSecurity-Framework/03_Scanners/README.md` (fila de `burpsuite/`)

**Interfaces:**
- Consumes: todo lo anterior.
- Produces: nada ejecutable.

- [ ] **Step 1: Documentar**

`docs/BURP-HTTP-INJECT-2026-10-31.md` con: qué se construyó, los hechos comprobados de Burp Community (tabla del spec), cómo se usa el par de scripts, qué significa cada nivel y qué no significa `CONFIRMADO`, y la evidencia de verificación (salidas de las suites). En `AGENTS.md`: párrafo en «Current state» con las dos piezas nuevas y su límite (Community no escanea ni guarda proyectos).

- [ ] **Step 2: Pasar todas las suites**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh && bash CyberSecurity-Framework/tests/run_e2e.sh && bash CyberSecurity-Framework/tests/run_smoke.sh && bash CyberSecurity-Framework/tests/run_wizard.sh`
Expected: `fallan: 0` en las cuatro (o `SKIP` declarado donde falte herramienta), sin cuelgues.

- [ ] **Step 3: Comprobar sintaxis**

Run: `: > /tmp/syntax.err; find CyberSecurity-Framework \( -name '*.sh' -o -name '*.bash' \) -print0 | while IFS= read -r -d '' f; do bash -n "$f" 2>>/tmp/syntax.err; done; test -s /tmp/syntax.err && cat /tmp/syntax.err || echo "sintaxis limpia"`
Expected: `sintaxis limpia` (recordar que `bash -n` devuelve 0 ante un heredoc sin cerrar: hay que mirar el fichero de errores).

- [ ] **Step 4: Prueba real con servidor propio**

Run: servidor de prueba en un puerto libre; petición `GET` con parámetro vulnerable → 1 `CONFIRMADO` con su par `.req`/`.resp`; la misma petición contra el endpoint catch-all → 0 confirmados y aviso de ruido.
Expected: lo descrito, y el informe en `scans/web/`.

- [ ] **Step 5: Commit**

```bash
git add docs/BURP-HTTP-INJECT-2026-10-31.md AGENTS.md CyberSecurity-Framework/03_Scanners/README.md
git commit -m "docs: fase Burp, niveles de evidencia y limites de Community"
```
