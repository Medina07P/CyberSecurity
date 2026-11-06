# Freno por 429/503 y `sqlmap -r` — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que un 429/503 nunca se puntúe como hallazgo en `http_inject.sh`, y que exista `sqlmap_request.sh` que consuma el `.req` ya validado hasta demostrar que se lee una tabla, con tres permisos separados.

**Architecture:** Dos piezas sobre la biblioteca que ya existe. La primera es un reintento con corte dentro de `peticion()` de `http_inject.sh`, más el esquema guardado en `contexto.txt` para que la segunda sepa si hablar TLS. La segunda es un script nuevo que reutiliza `http_request.bash` para leer el `.req`, ejecuta sqlmap en tres fases (`--dbs`, `--tables`, `--dump`) y traduce su salida a tres veredictos, sin heredar de sqlmap ni su silencio ni su optimismo.

**Tech Stack:** Bash (sin `set -e`), curl 8.x, sqlmap 1.10.6, Python 3 solo en los fixtures de prueba.

**Spec:** `docs/superpowers/specs/2026-10-31-freno-y-sqlmap-design.md`

## Global Constraints

- Todo el texto de cara al usuario va en español; comentarios y nombres de variables, también.
- Cada script: `#!/bin/bash`, cabecera con `Uso:` y `Ejemplo:`, validación de argumentos con bloque de uso y `exit 1`.
- Ninguna función que devuelva un valor imprime nada más que el valor por stdout; los avisos van por stderr.
- Prohibido `2>/dev/null` salvo en sondas (`command -v`, `grep` sobre un fichero que puede no existir). El `stderr` de las herramientas va a `errores.log` del directorio de salida.
- Prohibido cualquier ruta absoluta a un home. Rutas por `${BASH_SOURCE[0]:-$0}` y `scans_dir` / `scans_slug` de `00_Config/lib/scans.bash`.
- Salidas bajo `<repo>/scans/`, nombres con el objetivo: `scans/web/http_inject_<slug>.*` y `scans/sqlmap/<slug>/`.
- `sqlmap` **siempre** con `--batch --ignore-stdin --threads=1 --retries=1`, nivel 1 y riesgo 1 fijos (no configurables).
- Líneas LF. `bash -n` con `stderr` capturado para cada `.sh` tocado.
- Las suites son `tests/run_tests.sh`, `run_e2e.sh`, `run_smoke.sh`, `run_wizard.sh`; las cuatro tienen que seguir en 0 fallos al final.
- Lo que necesita `sqlmap` o `python3` se salta con un `SKIP` visible si la herramienta no está, nunca se da por bueno.

## Review Focus

Entradas y condiciones que el diseño implica y que nadie pediría probar, de más a menos probable que muerdan:

1. **`Retry-After` como fecha HTTP** en vez de segundos: un servidor real manda fecha; parsearla mal es dormir 0 o reventar. Test en Tarea 1 (endpoint `/frena-fecha`).
2. **`sqlmap` no instalado**: el script tiene que decirlo y salir 1, no informar «no inyectable». Test en Tarea 3.
3. **`.req` cuyo `Host:` no resuelve**: sqlmap da `CRITICAL ... does not exist`; es NO DETERMINADO, no «no inyectable». Test en Tarea 4.
4. **Directorio con varios `.req`**: los ficheros de salida no pueden pisarse. Test en Tarea 3.
5. **Volcado cortado por el tope de reloj**: «cortada por tiempo», nunca «volcada». Test en Tarea 6.

---

### Task 1: El freno 429/503 en `http_inject.sh`

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/http_inject.sh:179-242` (`peticion()`), `:102-113` (estado), `:573-611` (bucle), `:659-665` (salida)
- Modify: `CyberSecurity-Framework/tests/fixtures/http_target.py` (endpoints nuevos)
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva al final, antes de `rm -rf "$TMPD"`)

**Interfaces:**
- Consumes: nada nuevo de otras tareas.
- Produces: variables de entorno `HTTP_INJECT_FRENO` (`"429 503"`), `HTTP_INJECT_ESPERA` (10), `HTTP_INJECT_ESPERA_MAX` (60); global interno `FRENADO` (0/1). Los tests de la Tarea 2 dependen de que una tanda normal siga saliendo 0.

- [ ] **Step 1: Añadir los cinco endpoints al fixture**

En `tests/fixtures/http_target.py`, contadores globales `_FRENO_UNA`, `_FRENA_LUEGO`, y en `do_GET`:

| Ruta | Respuesta |
|---|---|
| `/frena` | la **primera** vez 429 con `Retry-After: 0`; después 200 `<html><body>libre</body></html>` |
| `/frena-fecha` | la **primera** vez 429 con `Retry-After: Sun, 06 Nov 1994 08:49:37 GMT`; después 200 `<html><body>libre</body></html>` |
| `/frena-largo` | siempre 429 con `Retry-After: 3600` |
| `/frena-luego` | las **tres primeras** veces 200 `<html><body>libre</body></html>`; después siempre 429 con `Retry-After: 0` |
| `/frena-base` | siempre 429 con `Retry-After: 0` |

Los tres primeros ya existen como patrón (`_CADUCA`, `_MUERE`). El 429 se envía con `send_response(429)`, `Retry-After`, `Content-Length: 0`.

- [ ] **Step 2: Escribir la prueba que falla**

```bash
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
    eq "freno: el corte se anuncia" "$(printf '%s' "$OUT" | grep -ci 'fren' )" "1"
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
```

- [ ] **Step 3: Ejecutar y ver que falla**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | tail -30`
Expected: los siete asertos nuevos fallan (`429` puntuado, exit 0 donde se espera 1). Ninguno pasa por casualidad.

- [ ] **Step 4: Implementar el reintento**

En el bloque de estado: `FRENADO=0`, `FRENO_CODIGOS="${HTTP_INJECT_FRENO:-429 503}"`, `ESPERA="${HTTP_INJECT_ESPERA:-10}"`, `ESPERA_MAX="${HTTP_INJECT_ESPERA_MAX:-60}"`, y `HDR_FILE=$(mktemp)` añadido al `trap` de limpieza.

Dos funciones nuevas antes de `peticion()`:

- `espera_pedida()` → imprime **solo** los segundos a esperar; lee `Retry-After` de `$HDR_FILE` con `awk -F': *' 'tolower($1)=="retry-after"{print $2}' | tr -d '\r'`. Si es entero, imprime ese entero. Si no, `date -d "$valor" +%s` menos `date +%s`, con suelo 0. Si no parsea, imprime `$ESPERA`.
- `es_freno()` → 0 si `$RESP_CODE` está en `$FRENO_CODIGOS`.

En `peticion()`, tras fijar `RESP_CODE`/`RESP_SIZE`/`RESP_TIME`/`RESP_CT` y **antes** de la comprobación de `000`, un bucle de como mucho dos intentos alrededor de la invocación de curl:

1. Llamar a curl con `-D "$HDR_FILE"` añadido a `args`.
2. Si `es_freno`, calcular `espera_pedida`. Si `espera > ESPERA_MAX`: `FRENADO=1`, `avisar "El servidor pide ${espera}s (por encima de ${ESPERA_MAX}s): no se reintenta y se corta la tanda"`, `return 1`. Si no: `avisar "HTTP ${RESP_CODE}: se reintenta en ${espera}s"`, `sleep "$espera"`, `N_ENVIOS=$((N_ENVIOS+1))`, y repetir una sola vez.
3. Si el segundo intento también es freno: `FRENADO=1`, `avisar "Sigue frenando (HTTP ${RESP_CODE}) tras el reintento: se corta la tanda y no se puntúa nada"`, `return 1`.

`N_ENVIOS` se incrementa una vez por invocación real de curl, también en el reintento (y el tope `MAX` se comprueba en cada vuelta). Añadir `(( FRENADO == 1 )) && return 1` junto a la guarda de `SESION_CAIDA`.

- [ ] **Step 5: Cortar en el bucle y en la línea base**

- Sustituir las cuatro apariciones de `(( SESION_CAIDA == 1 || AGOTADO == 1 )) && break` por `(( SESION_CAIDA == 1 || AGOTADO == 1 || FRENADO == 1 )) && break`, y la comprobación del principio del bucle para incluir `FRENADO` (sin aviso nuevo: ya se avisó).
- Junto a la comprobación de `BASE_CODE == "000"`, añadir:

```bash
if (( FRENADO == 1 )); then
    echo "❌ Te están frenando antes de empezar (HTTP ${RESP_CODE} en la línea base): no se ha probado nada."
    echo "   Baja el ritmo (HTTP_INJECT_RETARDO), espera o pide exclusión al WAF. El error queda en: ${LOG}"
    exit 1
fi
```

- En la salida final: `(( AGOTADO == 1 || SESION_CAIDA == 1 || FRENADO == 1 )) && exit 1`.
- Documentar las tres variables nuevas en la cabecera, dentro del bloque de opciones por entorno.

- [ ] **Step 6: Ejecutar y ver que pasa**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | tail -20`
Expected: `pasan: <nuevo total>   fallan: 0`.

- [ ] **Step 7: Comprobar que no se rompió nada más**

Run: `bash -n CyberSecurity-Framework/05_Exploitation/web/http_inject.sh 2>&1; python3 -m py_compile CyberSecurity-Framework/tests/fixtures/http_target.py`
Expected: sin salida en ambos.

- [ ] **Step 8: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/http_inject.sh CyberSecurity-Framework/tests/fixtures/http_target.py CyberSecurity-Framework/tests/run_tests.sh
git commit -m "fix(web): no puntuar un 429/503, reintentar con Retry-After y cortar la tanda"
```

---

### Task 2: `contexto.txt` en el directorio de evidencia

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/http_inject.sh` (`guardar_evidencia()`, ~línea 462)
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección «http_inject: evidencia y resumen»)

**Interfaces:**
- Produces: `<EVIDENCIA_DIR>/contexto.txt` con tres líneas `clave=valor`: `esquema`, `host`, `metodo`. La Tarea 4 lo lee como primera fuente del esquema. Claves y formato exactos:

```
esquema=https
host=app.example:8443
metodo=GET
```

- [ ] **Step 1: Escribir la prueba que falla**

En la sección «http_inject: evidencia y resumen», tras los asertos del `.req`:

```bash
eq "contexto: el directorio de evidencia guarda el esquema" "$(grep -cx 'esquema=http' "$EV/contexto.txt" 2>/dev/null)" "1"
eq "contexto: guarda el Host enviado" "$(grep -c '^host=127.0.0.1:' "$EV/contexto.txt" 2>/dev/null)" "1"
eq "contexto: guarda el método" "$(grep -cx 'metodo=GET' "$EV/contexto.txt" 2>/dev/null)" "1"
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep contexto`
Expected: tres `FALLO` (fichero inexistente), el resto en verde.

- [ ] **Step 3: Implementar**

En `guardar_evidencia()`, tras el `mkdir -p` y **solo cuando `N_EVID` pasa a 1** (el directorio se crea aquí, no antes):

```bash
printf 'esquema=%s\nhost=%s\nmetodo=%s\n' "$ESQUEMA" "$HR_HOST" "$HR_METHOD" > "$EVIDENCIA_DIR/contexto.txt"
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | tail -5`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/http_inject.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(web): dejar el esquema junto a la evidencia para que sqlmap no adivine"
```

---

### Task 3: `sqlmap_request.sh` — arranque, entrada y objetivo

**Files:**
- Create: `CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh`
- Create: `CyberSecurity-Framework/tests/fixtures/sql_target.py`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva antes de `rm -rf "$TMPD"`)

**Interfaces:**
- Consumes: `contexto.txt` (Tarea 2), `00_Config/lib/http_request.bash`, `00_Config/lib/scans.bash`, `00_Config/lib/session.bash`.
- Produces (funciones internas, usadas por las tareas 4-6):
  - `sm_esquema <directorio_req|""> <puerto>` → imprime `http` o `https`.
  - `sm_host_para <objetivo> <puerto_req>` → imprime el valor de `Host:` a escribir (`objetivo:puerto`), o vacío si no hay reescritura.
  - `sm_preparar <req> <destino>` → copia el `.req` a `destino` reescribiendo `Host:` si toca; deja `SM_HOST_ENVIADO`.
  - `sm_lista_reqs <ruta>` → imprime una ruta `.req` por línea, ordenadas. Acepta un `.req`, un directorio de evidencia, o `-` (lee la petición de la entrada estándar y la deja en un temporal).
  - `sm_slug` → imprime el slug del objetivo (del `contexto.txt` o del primer `.req`).
  - Variables de entorno: `SQLMAP_SI`, `SQLMAP_ESQUEMA`, `SQLMAP_TECNICA`, `SQLMAP_DELAY`, `SQLMAP_MAX_SEG`.

- [ ] **Step 1: Crear el fixture con una SQLi de verdad**

`tests/fixtures/sql_target.py`: servidor en `127.0.0.1:<puerto>` con sqlite en memoria, tabla `clientes(id INTEGER, nombre TEXT)` con `(1,'ana')` y `(2,'luis')`. `GET /?id=<valor>` ejecuta `SELECT id, nombre FROM clientes WHERE id = ` + valor sin escapar; con filas responde 200 con un cuerpo largo, sin filas un cuerpo corto (`sin resultados`), y con error 500 `error de SQL`. `do_POST` delega en `do_GET`. Es el mismo que se usó para medir el coste (51 peticiones con `--technique=B`).

- [ ] **Step 2: Escribir las pruebas que fallan**

```bash
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
export SSTUB_LOG="$TMPD/sqlmap_llamadas.txt"
export SQLMAP_SI=1

printf 'GET /?id=1 HTTP/1.1\nHost: 127.0.0.1:18001\n\n' > "$TMPD/req_sm.req"
OUT=$(PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1)
eq "sqlmap_request: pasa --ignore-stdin" "$(grep -c -- '--ignore-stdin' "$SSTUB_LOG")" "1"
eq "sqlmap_request: exige --batch" "$(grep -c -- '--batch' "$SSTUB_LOG")" "1"
eq "sqlmap_request: technique B por defecto" "$(grep -c -- '--technique=B\b' "$SSTUB_LOG")" "1"
eq "sqlmap_request: escribe el resumen" "$(ls "$FW/../scans/sqlmap/"*.txt 2>/dev/null | wc -l | tr -d ' ')" "1"

# Sin sqlmap instalado: error explícito, no "no inyectable"
mkdir -p "$TMPD/vacio"
OUT=$(PATH="$TMPD/vacio" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1); RC=$?
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
eq "sqlmap_request: dos logs, uno por fichero" "$(find "$FW/../scans/sqlmap" -name '*.log' | wc -l | tr -d ' ')" "2"
eq "sqlmap_request: un solo resumen para la tanda" "$(find "$FW/../scans/sqlmap" -name '*.txt' | wc -l | tr -d ' ')" "1"

# POST: pide confirmación y, si se niega, no llama a sqlmap
: > "$SSTUB_LOG"
printf 'POST /login HTTP/1.1\nHost: 127.0.0.1:18001\nContent-Type: application/json\n\n{"user":"ana"}' > "$TMPD/req_sm_post.req"
OUT=$(SQLMAP_SI= PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm_post.req" 2>&1 <<< 'n')
eq "sqlmap_request: POST pide confirmación" "$(printf '%s' "$OUT" | grep -ci 'repetir\|confirm' )" "1"
eq "sqlmap_request: si se niega, no ejecuta sqlmap" "$(grep -c . "$SSTUB_LOG" || echo 0)" "0"

# Host reescrito: conserva el puerto del .req
printf 'GET /?id=1 HTTP/1.1\nHost: app.inventado.example:8443\n\n' > "$TMPD/req_sm_vhost.req"
PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm_vhost.req" 10.0.0.5 >/dev/null 2>&1
eq "sqlmap_request: el Host reescrito conserva el puerto" \
   "$(grep -o 'Host: 10\.0\.0\.5:[0-9]*' "$FW/../scans/sqlmap/"*/copia_*.req 2>/dev/null | head -1 | grep -c ':8443')" "1"

unset SQLMAP_SI
rm -rf "$FW/../scans/sqlmap" "$SSTUB"
```

- [ ] **Step 3: Ejecutar y ver que falla**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep sqlmap_request`
Expected: todos fallan con `No such file or directory` del script.

- [ ] **Step 4: Implementar el arranque**

Cabecera con `Uso: ./sqlmap_request.sh <fichero> [objetivo]`, `Ejemplo: ./sqlmap_request.sh ../scans/web/http_inject_10.0.0.5_443/001_id_sqli_bool.req`, y el bloque de opciones por entorno, explicando que los tres permisos son distintos:

| Variable | Efecto |
|---|---|
| `SQLMAP_SI=1` | no pide confirmación para repetir la petición (método no `GET`/`HEAD`) |
| `SQLMAP_ENUMERAR=1` | autoriza `--dbs` y `--tables` sin preguntar |
| `SQLMAP_DB=<base>` | base para `--tables` / `--dump` |
| `SQLMAP_TABLA=<base.tabla>` | autoriza y elige el volcado |
| `SQLMAP_TECNICA=B\|BT` | técnica (por defecto `B`) |
| `SQLMAP_ESQUEMA=http\|https` | fuerza el esquema |
| `SQLMAP_DELAY=<s>` | pausa entre peticiones de sqlmap (0) |
| `SQLMAP_MAX_SEG=<s>` | tope de reloj por fase (900) |
| `SQLMAP_FILAS=<n>` | filas del volcado (50; 0 = sin tope) |

Flujo: validar argumentos y `command -v sqlmap` (mensaje «sqlmap no está instalado: `apt install sqlmap`» y `exit 1`); expandir la ruta con `sm_lista_reqs` (un `.req` o un directorio, ordenado, como mínimo 1 o sale 1); validar cada `.req` con `hr_load` y salir 1 si devuelve 2 o 3; `sm_esquema` (contexto.txt → `SQLMAP_ESQUEMA` → 443/8443 → http); `sm_slug`; crear `OUT_DIR=$(scans_dir sqlmap)/<slug>`; `scope_allows` con aviso si no es 0.

`sm_preparar` copia el `.req` a `$OUT_DIR/copia_<n>_<param>.req` y, si hay objetivo que no coincide en **host**, reescribe la línea `Host:` con `sm_host_para` (siempre con puerto) y avisa: «Reescribo Host: … → … (cambia el vhost; sqlmap con -r conecta al Host del fichero)».

La confirmación de método: si `$HR_METHOD` no es `GET`/`HEAD` y `SQLMAP_SI` no es 1, mostrar el comando, el fichero y el aviso de que sqlmap repetirá la petición muchas veces y que no existe tope de peticiones; leer sí/no; si se niega, «Cancelado: no se ha ejecutado sqlmap.» y `exit 0`.

- [ ] **Step 5: Ejecutar y ver que pasa**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep -A2 "sqlmap_request:"`
Expected: los asertos de esta tarea en verde; los de las tareas 4-6 todavía no existen.

- [ ] **Step 6: `bash -n` y commit**

```bash
bash -n CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh 2>&1
git add CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh CyberSecurity-Framework/tests/fixtures/sql_target.py CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(web): sqlmap_request.sh lee el .req, respeta el vhost y pide permiso"
```

---

### Task 4: Fase 1 — detección y tres veredictos

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección «sqlmap_request: veredictos»)

**Interfaces:**
- Consumes: `sm_*` de la Tarea 3.
- Produces:
  - `sm_ejecutar <fase> <log> [args...]` → ejecuta sqlmap con `--batch --ignore-stdin --threads=1 --retries=1 --delay=$SQLMAP_DELAY --level=1 --risk=1 --time-sec=<n>` (+ `--force-ssl` si https), `timeout "$SQLMAP_MAX_SEG"`, `stdout` y `stderr` al `log`; imprime el código de salida.
  - `sm_veredicto <log>` → imprime `INYECTABLE`, `NO_INYECTABLE` o `NO_DETERMINADO`.

- [ ] **Step 1: Escribir las pruebas que fallan**

```bash
section "sqlmap_request: veredictos"
SSTUB="$(mktemp -d)"
export SSTUB_LOG="$TMPD/sqlmap_veredicto.txt" SQLMAP_SI=1

escribir_stub() {  # <cuerpo de salida>
    cat > "$SSTUB/sqlmap" <<EOS
#!/bin/bash
printf '%s\n' "\$*" >> "\$SSTUB_LOG"
cat <<'FIN'
$1
FIN
exit ${2:-0}
EOS
    chmod +x "$SSTUB/sqlmap"
}

escribir_stub "[INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable"
OUT=$(PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1); RC=$?
eq "veredicto: inyectable sale 0" "$RC" "0"
eq "veredicto: inyectable se anuncia" "$(printf '%s' "$OUT" | grep -ci 'INYECTABLE' )" "1"
eq "veredicto: http normal no fuerza TLS" "$(grep -c -- '--force-ssl' "$SSTUB_LOG")" "0"

# https en 443: el .req no lo dice, el puerto sí
: > "$SSTUB_LOG"
printf 'GET /?id=1 HTTP/1.1\nHost: app.inventado.example:443\n\n' > "$TMPD/req_sm_443.req"
PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm_443.req" >/dev/null 2>&1
eq "veredicto: https en 443 pasa --force-ssl" "$(grep -c -- '--force-ssl' "$SSTUB_LOG")" "1"
: > "$SSTUB_LOG"
PATH="$SSTUB:$PATH" SQLMAP_ESQUEMA=https bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" >/dev/null 2>&1
eq "veredicto: SQLMAP_ESQUEMA=https fuerza TLS" "$(grep -c -- '--force-ssl' "$SSTUB_LOG")" "1"
: > "$SSTUB_LOG"
PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" >/dev/null 2>&1
eq "veredicto: http en 18001 no pasa --force-ssl" "$(grep -c -- '--force-ssl' "$SSTUB_LOG")" "0"

escribir_stub "[CRITICAL] all tested parameters do not appear to be injectable"
OUT=$(PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1); RC=$?
eq "veredicto: no inyectable sale 0" "$RC" "0"
eq "veredicto: se cualifica con la técnica" "$(printf '%s' "$OUT" | grep -ci 'con --technique=B' )" "1"

escribir_stub "[CRITICAL] host 'app.inventado.example' does not exist"
OUT=$(PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1); RC=$?
eq "veredicto: fallo de red es NO DETERMINADO" "$(printf '%s' "$OUT" | grep -ci 'NO DETERMINADO' )" "1"
eq "veredicto: fallo de red sale 1" "$RC" "1"
eq "veredicto: un fallo no se lee como no inyectable" "$(printf '%s' "$OUT" | grep -ci 'NO INYECTABLE' )" "0"

escribir_stub "[INFO] all tested parameters do not appear to be injectable
[WARNING] HTTP error codes detected during run:
429 (Too Many Requests) - 12 times"
OUT=$(PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1); RC=$?
eq "veredicto: 429 en el log de sqlmap es NO DETERMINADO" "$(printf '%s' "$OUT" | grep -ci 'NO DETERMINADO' )" "1"
eq "veredicto: 429 no se hereda como no inyectable" "$(printf '%s' "$OUT" | grep -ci 'NO INYECTABLE' )" "0"
eq "veredicto: 429 sale 1" "$RC" "1"

rm -rf "$FW/../scans/sqlmap" "$SSTUB"; unset SQLMAP_SI SSTUB_LOG
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep -A1 "veredicto:"`
Expected: fallan; el script corre sqlmap pero no imprime veredicto.

- [ ] **Step 3: Implementar**

`sm_ejecutar` compone el array de argumentos comunes y lanza `timeout "$SQLMAP_MAX_SEG" sqlmap -r "$copia" "${comunes[@]}" "$@" >> "$log" 2>&1`; imprime el rc (`124` = tope de reloj).

La fase 1 llama a `sm_ejecutar deteccion "$log" --technique="$SQLMAP_TECNICA"` y luego a `sm_veredicto`, que mira el log **en este orden** (el orden importa: un 429 gana a un «no inyectable»):

1. `grep -q 'HTTP error codes detected during run'` y dentro de las tres líneas siguientes un `429` o `503` → `NO_DETERMINADO`.
2. `grep -q 'appears to be .*injectable'` → `INYECTABLE`.
3. `grep -q 'does not appear to be injectable'` → `NO_INYECTABLE`.
4. cualquier otra cosa (`CRITICAL`, log vacío, rc 124) → `NO_DETERMINADO`.

Imprimir en consola y en el resumen: para `INYECTABLE`, la línea del parámetro y el payload (`grep` de `Parameter:`/`Type:`/`Payload:`); para `NO_INYECTABLE`, la frase «No inyectable con `--technique=${SQLMAP_TECNICA} --level=1` (no se probaron técnicas fuera de esa combinación)»; para `NO_DETERMINADO`, que la tanda no concluyó y dónde está el log.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep -c "veredicto:.*FALLO"`
Expected: `0`.

- [ ] **Step 5: Añadir la prueba con sqlmap real***

Al final de la sección, guardada por `command -v sqlmap`:

```bash
if command -v sqlmap >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    SP=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
    python3 "$FW/tests/fixtures/sql_target.py" "$SP" >/dev/null 2>&1 &
    SPID=$!
    for i in 1 2 3 4 5 6 7 8 9 10; do curl -s -o /dev/null "http://127.0.0.1:$SP/?id=1" && break; sleep 0.3; done
    printf 'GET /?id=1 HTTP/1.1\nHost: 127.0.0.1:%s\n\n' "$SP" > "$TMPD/req_real.req"
    OUT=$(SQLMAP_SI=1 SQLMAP_TECNICA=B bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_real.req" 2>&1); RC=$?
    eq "real: sqlmap confirma la inyección del fixture" "$(printf '%s' "$OUT" | grep -ci 'INYECTABLE' )" "1"
    eq "real: sale 0" "$RC" "0"
    kill "$SPID" 2>/dev/null
    rm -rf "$FW/../scans/sqlmap"
else
    echo "  SKIP     sqlmap o python3 no instalados"
fi
```

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep -E "real:|pasan:"`
Expected: los dos asertos `real:` en verde y `fallan: 0`.

- [ ] **Step 6: Commit**

```bash
bash -n CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh 2>&1
git add CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(web): veredicto de sqlmap en tres estados, sin heredar su no inyectable"
```

---

### Task 5: Fase 2 — enumerar con permiso propio

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección «sqlmap_request: enumeración»)

**Interfaces:**
- Produces: `sm_enumerar <base|"">` → deja `SM_BASES` y `SM_TABLAS` (una por línea) y la ruta del log de cada fase en `SM_LOG_DBS` y `SM_LOG_TABLAS`.

- [ ] **Step 1: Escribir las pruebas que fallan**

```bash
section "sqlmap_request: enumeración"
SSTUB="$(mktemp -d)"
cat > "$SSTUB/sqlmap" <<'EOS'
#!/bin/bash
printf '%s\n' "$*" >> "${SSTUB_LOG:-/dev/null}"
case " $* " in
    *" --dbs "*)    echo "[INFO] available databases [1]:"; echo "[*] clientes" ;;
    *" --tables "*) echo "Database: clientes"; echo "[2 tables]"; echo "| clientes |"; echo "| pedidos |" ;;
    *)              echo "[INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable" ;;
esac
exit 0
EOS
chmod +x "$SSTUB/sqlmap"
export SSTUB_LOG="$TMPD/sqlmap_enum.txt"; : > "$SSTUB_LOG"

# Sin permiso: no enumera, y el resumen lo dice
OUT=$(SQLMAP_SI=1 PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1)
RESUMEN=$(ls "$FW/../scans/sqlmap/"*.txt | head -1)
eq "enumeración: sin SQLMAP_ENUMERAR no se ejecuta --dbs" "$(grep -c -- '--dbs' "$SSTUB_LOG")" "0"
eq "enumeración: sin permiso el resumen lo dice" "$(grep -ci 'no se enumeró' "$RESUMEN")" "1"

# Con permiso: --dbs y --tables con la base elegida
: > "$SSTUB_LOG"
OUT=$(SQLMAP_ENUMERAR=1 PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1 <<< '')
RESUMEN=$(ls "$FW/../scans/sqlmap/"*.txt | head -1)
eq "enumeración: con SQLMAP_ENUMERAR sí hay --dbs" "$(grep -c -- '--dbs' "$SSTUB_LOG")" "1"
eq "enumeración: la base aparece en el resumen" "$(grep -ci 'clientes' "$RESUMEN")" "1"
eq "enumeración: --tables usa la base elegida" "$(grep -c -- '-D clientes' "$SSTUB_LOG")" "1"

# Con terminal simulada y respuesta negativa: se queda en el veredicto
: > "$SSTUB_LOG"
printf 'n\n' | SQLMAP_SI=1 PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" >/dev/null 2>&1
eq "enumeración: si se niega, no se ejecuta --dbs" "$(grep -c -- '--dbs' "$SSTUB_LOG")" "0"

rm -rf "$FW/../scans/sqlmap" "$SSTUB"; unset SSTUB_LOG
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep "enumeración:"`
Expected: fallan.

- [ ] **Step 3: Implementar**

Solo si el veredicto de la fase 1 es `INYECTABLE` (cualquier otro: se salta y el resumen lo dice):

- Si `SQLMAP_ENUMERAR` no es `1`: si hay terminal (`[[ -t 0 ]]`), preguntar «¿Seguir a enumeración? Se repetirá la petición muchas veces y sqlmap no tiene tope de peticiones. [s/N]»; si no hay terminal o se niega, se para aquí y el resumen escribe «No se enumeró: sin permiso (`SQLMAP_ENUMERAR=1`)».
- `sm_ejecutar dbs "$SM_LOG_DBS" --dbs`, veredicto propio: `OK` si se ven líneas `[*]`, `NO DETERMINADO` si rc 124 o `CRITICAL`. Guardar las líneas `[*]` en `SM_BASES`.
- Base a usar: `SQLMAP_DB` o, si solo hay una, esa; si hay varias y hay terminal, menú numerado; si no hay terminal, parar tras `--dbs`.
- `sm_ejecutar tablas "$SM_LOG_TABLAS" -D "$base" --tables`, mismas tres salidas. Extraer las tablas de las líneas entre `|`.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep -c "enumeración:.*FALLO"`
Expected: `0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(web): enumerar bases y tablas solo con SQLMAP_ENUMERAR"
```

---

### Task 6: Fase 3 — volcar una tabla, acotado

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección «sqlmap_request: volcado»)

**Interfaces:**
- Produces: `sm_volcar <base> <tabla>` → deja `SM_FILAS` (entero), `SM_VOLCADO` en `completa|muestra|cortada|fallo` y el log en `SM_LOG_DUMP`.

- [ ] **Step 1: Escribir las pruebas que fallan**

```bash
section "sqlmap_request: volcado"
SSTUB="$(mktemp -d)"
cat > "$SSTUB/sqlmap" <<'EOS'
#!/bin/bash
printf '%s\n' "$*" >> "${SSTUB_LOG:-/dev/null}"
case " $* " in
    *" --dbs "*)    echo "[INFO] available databases [1]:"; echo "[*] clientes" ;;
    *" --tables "*) echo "Database: clientes"; echo "[2 tables]"; echo "| clientes |"; echo "| pedidos |" ;;
    *" --dump "*)   echo "Table: clientes"; echo "| id | nombre |"; echo "| 1 | ana |"; echo "| 2 | luis |" ;;
    *)              echo "[INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable" ;;
esac
exit 0
EOS
chmod +x "$SSTUB/sqlmap"
export SSTUB_LOG="$TMPD/sqlmap_dump.txt"; : > "$SSTUB_LOG"

# Sin SQLMAP_TABLA: no se vuelca nada
OUT=$(SQLMAP_SI=1 SQLMAP_ENUMERAR=1 SQLMAP_DB=clientes PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1)
RESUMEN=$(ls "$FW/../scans/sqlmap/"*.txt | head -1)
eq "volcado: sin SQLMAP_TABLA no se vuelca nada" "$(grep -c -- '--dump' "$SSTUB_LOG")" "0"
eq "volcado: el resumen dice que no se volcó" "$(grep -ci 'no se volcó' "$RESUMEN")" "1"

# Con tabla: --dump acotado y con su -D/-T
: > "$SSTUB_LOG"
OUT=$(SQLMAP_SI=1 SQLMAP_ENUMERAR=1 SQLMAP_DB=clientes SQLMAP_TABLA=clientes.clientes PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1)
RESUMEN=$(ls "$FW/../scans/sqlmap/"*.txt | head -1)
eq "volcado: con tabla sí hay --dump" "$(grep -c -- '--dump' "$SSTUB_LOG")" "1"
eq "volcado: lleva el tope de filas" "$(grep -c -- '--stop=50' "$SSTUB_LOG")" "1"
eq "volcado: usa -D y -T" "$(grep -c -- '-D clientes -T clientes' "$SSTUB_LOG")" "1"
eq "volcado: cuenta las filas" "$(grep -ci '2 filas' "$RESUMEN")" "1"

# SQLMAP_FILAS=0: sin tope
: > "$SSTUB_LOG"
SQLMAP_FILAS=0 SQLMAP_SI=1 SQLMAP_ENUMERAR=1 SQLMAP_DB=clientes SQLMAP_TABLA=clientes.clientes \
    PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" >/dev/null 2>&1
eq "volcado: SQLMAP_FILAS=0 quita el tope" "$(grep -c -- '--stop=' "$SSTUB_LOG")" "0"

# Tope de reloj: el volcado se corta y NO se dice "volcada"
cat > "$SSTUB/sqlmap" <<'EOS'
#!/bin/bash
printf '%s\n' "$*" >> "${SSTUB_LOG:-/dev/null}"
case " $* " in *" --dump "*) sleep 5 ;; esac
echo "[INFO] GET parameter 'id' appears to be injectable"
EOS
chmod +x "$SSTUB/sqlmap"
OUT=$(SQLMAP_MAX_SEG=1 SQLMAP_SI=1 SQLMAP_ENUMERAR=1 SQLMAP_DB=clientes SQLMAP_TABLA=clientes.clientes \
      PATH="$SSTUB:$PATH" bash "$FW/05_Exploitation/web/sqlmap_request.sh" "$TMPD/req_sm.req" 2>&1); RC=$?
RESUMEN=$(ls "$FW/../scans/sqlmap/"*.txt | head -1)
eq "volcado: cortado por tiempo se marca como cortado" "$(printf '%s' "$OUT" | grep -ci 'cortad' )" "1"
eq "volcado: cortado no se anuncia como completo" "$(grep -ci 'volcada completa' "$RESUMEN")" "0"
eq "volcado: cortado sale 1" "$RC" "1"

rm -rf "$FW/../scans/sqlmap" "$SSTUB"; unset SSTUB_LOG
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep "volcado:"`
Expected: fallan.

- [ ] **Step 3: Implementar**

`sm_volcar` ejecuta `sm_ejecutar dump "$SM_LOG_DUMP" -D "$base" -T "$tabla" --dump [--stop=$SQLMAP_FILAS]` (`--stop` solo si `SQLMAP_FILAS` es > 0). Después:

- rc 124 → `cortada`, aviso «El volcado se cortó por el tope de ${SQLMAP_MAX_SEG}s: lo que hay en el fichero es parcial».
- `CRITICAL`/error → `fallo`.
- si no, contar filas con `grep -c '^|' "$SM_LOG_DUMP"` (menos la cabecera) → `SM_FILAS`; `muestra` si se usó `--stop` y hay exactamente `SQLMAP_FILAS` filas, `completa` en el resto.

Al resumen: `Volcado: <tabla> — <n> filas (<muestra de 50|completa|cortada por tiempo|falló>)`. Si no hay tabla elegida: `No se volcó ninguna tabla (falta SQLMAP_TABLA)`.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep -c "volcado:.*FALLO"`
Expected: `0`. Un volcado `cortada` o `fallo` cuenta como fase fallida: exit 1.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/sqlmap_request.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(web): volcar solo la tabla elegida y decir si la muestra está cortada"
```

---

### Task 7: Registro en el gestor, documentación y suites completas

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/lib/dangerous.txt` (una línea nueva)
- Modify: `AGENTS.md` (párrafo de estado y una línea donde toque)
- Create: `docs/SQLMAP-Y-FRENOS-2026-10-31.md`
- Test: las cuatro suites

**Interfaces:**
- Consumes: todo lo anterior.

- [ ] **Step 1: Registrar el script**

Añadir `05_Exploitation/web/sqlmap_request.sh` a `00_Config/lib/dangerous.txt` (una ruta por línea, orden alfabético respecto a las vecinas). Aserto nuevo en `tests/run_tests.sh`, junto al de `http_inject`:

```bash
eq "dangerous.txt incluye sqlmap_request" "$(grep -cxF '05_Exploitation/web/sqlmap_request.sh' "$FW/00_Config/lib/dangerous.txt")" "1"
eq "sqlmap_request se declara en modo slots" "$(bash -c "source '$FW/00_Config/lib/params.bash'; params_mode '$FW/05_Exploitation/web/sqlmap_request.sh'")" "slots"
```

- [ ] **Step 2: Documentar la sesión**

`docs/SQLMAP-Y-FRENOS-2026-10-31.md`, con la misma forma que `docs/BURP-HTTP-INJECT-2026-10-31.md`: qué se construyó y por qué, la tabla de lo comprobado (los cinco hechos del spec, con su evidencia: `sqlmap -r` sin `--ignore-stdin` = exit 0 y 0 peticiones; `-r` conecta al `Host:`; `443`→https y el resto→http; 51 peticiones con `B` y 58 con `BT`; `Retry-After` leído con `-D`), uso con los tres permisos, qué significa cada veredicto y qué **no** significa, salidas, verificación (números reales de las cuatro suites) y límites conocidos (incluido el 403-a-todo, que sigue sin tratarse).

- [ ] **Step 3: Actualizar `AGENTS.md`**

En «Current state», un párrafo de cuatro líneas con lo nuevo y su documento; en «Writing new scripts», una línea sobre `contexto.txt` y los tres permisos de `sqlmap_request.sh`; corregir el recuento de scripts `.sh` si cambia.

- [ ] **Step 4: Pasar las cuatro suites y la sintaxis**

```bash
bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | tail -3
bash CyberSecurity-Framework/tests/run_e2e.sh  2>&1 | tail -3
bash CyberSecurity-Framework/tests/run_smoke.sh 2>&1 | tail -3
bash CyberSecurity-Framework/tests/run_wizard.sh 2>&1 | tail -3
for f in $(git diff --name-only HEAD~6 -- '*.sh'); do bash -n "$f" 2>&1; done
```

Expected: `fallan: 0` en las cuatro; `bash -n` sin salida (capturando `stderr`: un heredoc sin cerrar solo avisa por ahí).

- [ ] **Step 5: Commit**

```bash
git add AGENTS.md docs/SQLMAP-Y-FRENOS-2026-10-31.md CyberSecurity-Framework/00_Config/lib/dangerous.txt CyberSecurity-Framework/tests/run_tests.sh
git commit -m "docs: frenos 429/503 y sqlmap sobre la petición capturada"
```
