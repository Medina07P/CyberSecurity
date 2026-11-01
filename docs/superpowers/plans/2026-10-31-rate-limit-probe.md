# Prueba de rate limit sobre el login capturado — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el framework pueda demostrar, de forma acotada y con evidencia por intento, si un endpoint de login capturado aplica o no rate limiting.

**Architecture:** Un script de hoja nuevo en `05_Exploitation/web/` que reutiliza `http_request.bash` para leer el `.req`, repite la petición N veces variando solo la contraseña, y traduce códigos, latencias y `Retry-After` a tres veredictos. No hay diccionario ni búsqueda de credenciales: los valores son `wrong-1…wrong-N`.

**Tech Stack:** Bash (sin `set -e`), curl, Python 3 solo en el fixture de pruebas.

**Spec:** `docs/superpowers/specs/2026-10-31-rate-limit-probe-design.md`

## Global Constraints

- Todo el texto de cara al usuario en español; comentarios y nombres de variables, también.
- Cada script: `#!/bin/bash`, cabecera con `Uso:` y `Ejemplo:`, validación con bloque de uso y `exit 1`.
- Ninguna función que devuelva un valor imprime nada más que el valor por stdout; los avisos van por stderr.
- Prohibido `2>/dev/null` salvo en sondas (`command -v`, `grep` sobre un fichero que puede no existir). El `stderr` de curl va a `errores.log` del directorio de salida.
- Rutas por `${BASH_SOURCE[0]:-$0}` y `scans_dir` / `scans_slug` de `00_Config/lib/scans.bash`; nunca un home absoluto.
- Salidas bajo `<repo>/scans/web/`: `rate_limit_<slug>.txt`, `.tsv` y el directorio `rate_limit_<slug>/`.
- Retardo por defecto **0** (`RATE_LIMIT_RETARDO`); tope duro de intentos **200**; 20 por defecto.
- Se corta en el primer freno: no se envía el intento siguiente.
- Líneas LF; `bash -n` con `stderr` capturado para cada `.sh` tocado.
- Las cuatro suites (`run_tests`, `run_e2e`, `run_smoke`, `run_wizard`) tienen que seguir en 0 fallos.

## Review Focus

Entradas y condiciones que el diseño implica y que nadie pediría probar, de más a menos probable que muerdan:

1. **Dos campos que parecen contraseña** (`password` y `password2`): se varía el primero y se avisa; el servidor puede seguir rechazando por el segundo, y el veredicto no debe prometer más de lo medido. Test en Tarea 1.
2. **El código de respuesta cambia a mitad sin ser freno** (un `403` de WAF): `NO DETERMINADO`, nunca `FRENADO`. Test en Tarea 3 (`/login-cambia`).
3. **Ya está frenado en el primer intento** (otra tanda dejó el contador lleno): `FRENADO` con `n=1`, sin una sola petición más. Test en Tarea 3 (`/login-freno-siempre`).
4. **La conexión muere** (`000`): se corta y sale 1, no `SIN FRENO`. Test en Tarea 3 (`/login-caido`).
5. **`Retry-After` en fecha HTTP**: se reporta literal en el resumen; el script no duerme ni lo interpreta. Test en Tarea 3 (`/login-freno-fecha`).

---

### Task 1: El script lee la petición, elige el campo y pide permiso

**Files:**
- Create: `CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh`
- Modify: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva «rate_limit_probe: arranque», antes del `rm -rf "$TMPD"` final)

**Interfaces:**
- Produces: `rl_campo <params>` → `ubicacion|nombre` del campo elegido, o vacío si no hay ninguno. Globales `RL_UBIC`, `RL_NOMBRE`.

- [ ] **Step 1: Escribir las pruebas que fallan**

```bash
section "rate_limit_probe: arranque"
RLREQ="$TMPD/req_rl.req"
printf 'POST /login-sin-freno HTTP/1.1\nHost: 127.0.0.1:18001\nContent-Type: application/json\n\n{"email":"ana@example.com","password":"x"}' > "$RLREQ"
printf 'POST /login-sin-freno HTTP/1.1\nHost: 127.0.0.1:18001\nContent-Type: application/json\n\n{"email":"ana@example.com"}' > "$TMPD/req_rl_sin_campo.req"
printf 'POST /login-sin-freno HTTP/1.1\nContent-Type: application/json\n\n{"email":"ana@example.com","password":"x"}' > "$TMPD/req_rl_sin_host.req"

OUT=$(bash "$FW/05_Exploitation/web/rate_limit_probe.sh" 2>&1); RC=$?
eq "rate_limit: sin argumentos da uso" "$(printf '%s' "$OUT" | grep -c 'Uso:')" "1"
eq "rate_limit: sin argumentos sale 1" "$RC" "1"

OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/no-existe.req" 2>&1); RC=$?
eq "rate_limit: petición ilegible sale 1" "$RC" "1"

OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_sin_campo.req" 2>&1); RC=$?
eq "rate_limit: sin campo de contraseña no adivina" "$(printf '%s' "$OUT" | grep -ci 'no se encontró.*contraseña\|campo de contraseña')" "1"
eq "rate_limit: sin campo sale 1" "$RC" "1"

OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_sin_host.req" 2>&1); RC=$?
eq "rate_limit: sin Host y sin objetivo sale 1" "$RC" "1"

# Dos campos que parecen contraseña: elige el primero y avisa del segundo
printf 'POST /login-sin-freno HTTP/1.1\nHost: 127.0.0.1:18001\nContent-Type: application/json\n\n{"email":"a@b.c","password":"x","password2":"y"}' > "$TMPD/req_rl_dos.req"
OUT=$(RATE_LIMIT_SI=1 RATE_LIMIT_INTENTOS=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_dos.req" 2>&1)
eq "rate_limit: avisa de un segundo campo de contraseña" "$(printf '%s' "$OUT" | grep -ci 'password2\|segundo campo')" "1"

eq "rate_limit: se declara en modo slots" "$(bash -c "source '$FW/00_Config/lib/params.bash'; params_mode '$FW/05_Exploitation/web/rate_limit_probe.sh'")" "slots"
eq "rate_limit: el ejemplo no estorba al parser" "$(bash -c "source '$FW/00_Config/lib/params.bash'; params_slots '$FW/05_Exploitation/web/rate_limit_probe.sh' | grep -c '|'")" "2"
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep "rate_limit:"`
Expected: todos fallan (el script no existe).

- [ ] **Step 3: Implementar el arranque**

Cabecera con:

```
Uso: ./rate_limit_probe.sh <fichero> [intentos]
Ejemplo: ./rate_limit_probe.sh ../scans/web/login.req 20
```

Variables: `RATE_LIMIT_INTENTOS` (20), `RATE_LIMIT_RETARDO` (0), `RATE_LIMIT_CAMPO`, `RATE_LIMIT_SI`, `RATE_LIMIT_MAX_SEG` (30), `RATE_LIMIT_ESQUEMA` (decisión del constructor, hermana de `HTTP_INJECT_ESQUEMA`).

Detección (case-insensitive) sobre `hr_params`: primer `ubicacion|nombre|valor` cuyo nombre case con `pass|clave|secret|contras`. Si no hay, mensaje `❌ No se encontró un campo de contraseña (pass/clave/secret/contras): indícalo con RATE_LIMIT_CAMPO` y `exit 1`. Si `hr_params` devuelve 4 o 5, el mensaje dice que no se pudo leer el cuerpo. Si hay un segundo candidato, `avisar` con su nombre.

Confirmación (salvo `RATE_LIMIT_SI=1`): `¿N intentos contra <url>? Puede bloquear la cuenta. [s/N]`; sin `s`, `exit 0`.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep -c "rate_limit:.*FALLO"`
Expected: `0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(web): rate_limit_probe lee el login y elige la contraseña sin adivinar"
```

---

### Task 2: La sonda, la evidencia por intento y el veredicto `SIN FRENO`

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh`
- Modify: `CyberSecurity-Framework/tests/fixtures/http_target.py` (endpoint `/login-sin-freno` en `do_POST`)
- Modify: `CyberSecurity-Framework/tests/run_tests.sh` (sección «rate_limit_probe: sonda»)

**Interfaces:**
- Produces: `rl_peticion <target> <cuerpo>` → deja `RESP_CODE`, `RESP_SIZE`, `RESP_TIME` y el cuerpo en `$RESP_FILE`; cuenta `N_ENVIOS`. Globales `PRIMER_CODIGO`, `SENAL`.

- [ ] **Step 1: Añadir el endpoint al fixture y escribir las pruebas que fallan**

En `http_target.py`, dentro de `do_POST`, antes del `else`:

```python
        elif ruta == "/login-sin-freno":
            self._responder(401, '{"error":"Credenciales incorrectas"}',
                            "application/json")
```

Pruebas:

```bash
section "rate_limit_probe: sonda"
# Arranca el fixture sin el defecto de `iniciar_servidor_http`: aquí el PID se
# guarda en el shell padre (nada de $(...)), para que el kill funcione.
rl_servidor() {
    RLPORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
    python3 "$FW/tests/fixtures/http_target.py" "$RLPORT" >/dev/null 2>&1 &
    RL_SRV=$!
    for i in 1 2 3 4 5 6 7 8 9 10; do
        curl -s -o /dev/null "http://127.0.0.1:$RLPORT/safe" && break
        sleep 0.3
    done
}
if command -v python3 >/dev/null 2>&1; then
    rl_servidor
    printf 'POST /login-sin-freno HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"email":"ana@example.com","password":"x"}' "$RLPORT" > "$TMPD/req_rl_sinfreno.req"

    OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_sinfreno.req" 20 2>&1); RC=$?
    RLTSV=$(find "$FW/../scans/web" -name "rate_limit_127.0.0.1_$RLPORT.tsv" | head -1)
    RLTXT=$(find "$FW/../scans/web" -name "rate_limit_127.0.0.1_$RLPORT.txt" | head -1)
    eq "sonda: 20 intentos se registran" "$(($(wc -l < "$RLTSV") - 1))" "20"
    eq "sonda: veredicto SIN FRENO" "$(grep -c 'Veredicto: SIN FRENO' "$RLTXT")" "1"
    eq "sonda: sale 0" "$RC" "0"
    eq "sonda: cada intento con su código" "$(awk -F'\t' 'NR>1 && $2==401' "$RLTSV" | wc -l | tr -d ' ')" "20"
    eq "sonda: guarda la respuesta del primer intento" "$(find "$FW/../scans/web/rate_limit_127.0.0.1_$RLPORT" -name '*_001.resp' | wc -l | tr -d ' ')" "1"
    eq "sonda: no hay diccionario, los valores son wrong-N" "$(grep -c 'wrong-' "$RLTXT")" "1"

    rm -rf "$FW/../scans/web/rate_limit_127.0.0.1_$RLPORT"*; kill "$RL_SRV" 2>/dev/null
else
    echo "  SKIP     python3 no instalado"
fi
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep "sonda:"`
Expected: fallan.

- [ ] **Step 3: Implementar la sonda**

`rl_peticion` replica `peticion()` de `http_inject.sh`: `curl -sk --max-time "$MAX_SEG"`, reenvía las cabeceras de `HR_HEADERS` (salvo `host`, `content-length`, `transfer-encoding`, `expect`, `connection`), añade `Host:` y `Accept-Encoding: identity`, `-o "$RESP_FILE" -D "$HDR_FILE" -w '%{http_code}:%{size_download}:%{time_total}'` y `2>>"$LOG"`. Código `000` si la salida viene vacía.

Escribe `rate_limit_<slug>.tsv` con cabecera `n\tcodigo\tms\ttamano\tretry_after\tseñal`, una fila por intento, y guarda `rate_limit_<slug>/<nnn>_intento.resp` (solo el primero en esta tarea). El `.txt` lleva cabecera (fecha, objetivo, endpoint, intentos, campo variado, retardo), la línea `- Veredicto: ...` y la tabla de intentos.

En esta tarea el veredicto solo distingue `SIN FRENO` (todos los intentos rechazados con el mismo código) de `NO DETERMINADO` (red); el freno llega en la Tarea 3.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep -c "sonda:.*FALLO"`
Expected: `0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh CyberSecurity-Framework/tests/fixtures/http_target.py CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(web): sonda de rate limit con una fila de evidencia por intento"
```

---

### Task 3: Freno explícito, freno por retardo y corte

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh`
- Modify: `CyberSecurity-Framework/tests/fixtures/http_target.py` (`/login-freno`, `/login-lento`, `/login-caido`)
- Modify: `CyberSecurity-Framework/tests/run_tests.sh` (sección «rate_limit_probe: freno»)

**Interfaces:**
- Produces: `rl_veredicto` → `FRENADO|SIN_FRENO|NO_DETERMINADO`; globales `FRENO_EN`, `FRENO_CODIGO`, `FRENO_ESPERA`.

- [ ] **Step 1: Añadir los endpoints y escribir las pruebas que fallan**

```python
        elif ruta == "/login-freno":
            global _RL_FRENO
            _RL_FRENO += 1
            if _RL_FRENO >= 4:
                self._frenar("7")
            else:
                self._responder(401, '{"error":"Credenciales incorrectas"}',
                                "application/json")
        elif ruta == "/login-freno-siempre":
            self._frenar("3")
        elif ruta == "/login-freno-fecha":
            global _RL_FECHA
            _RL_FECHA += 1
            if _RL_FECHA >= 2:
                self._frenar("Sun, 06 Nov 1994 08:49:37 GMT")
            else:
                self._responder(401, '{"error":"Credenciales incorrectas"}',
                                "application/json")
        elif ruta == "/login-cambia":
            global _RL_CAMBIA
            _RL_CAMBIA += 1
            if _RL_CAMBIA >= 3:
                self._responder(403, '{"error":"bloqueado"}', "application/json")
            else:
                self._responder(401, '{"error":"Credenciales incorrectas"}',
                                "application/json")
        elif ruta == "/login-lento":
            global _RL_LENTO
            _RL_LENTO += 1
            time.sleep(0.05 * _RL_LENTO)
            self._responder(401, '{"error":"Credenciales incorrectas"}',
                            "application/json")
        elif ruta == "/login-caido":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
```

con `_RL_FRENO = 0`, `_RL_FECHA = 0`, `_RL_CAMBIA = 0` y `_RL_LENTO = 0` entre los contadores globales.

Pruebas:

```bash
section "rate_limit_probe: freno"
if command -v python3 >/dev/null 2>&1; then
    rl_servidor
    printf 'POST /login-freno HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"email":"ana@example.com","password":"x"}' "$RLPORT" > "$TMPD/req_rl_freno.req"
    OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_freno.req" 20 2>&1); RC=$?
    RLTSV=$(find "$FW/../scans/web" -name "rate_limit_127.0.0.1_$RLPORT.tsv" | head -1)
    RLTXT=$(find "$FW/../scans/web" -name "rate_limit_127.0.0.1_$RLPORT.txt" | head -1)
    eq "freno: veredicto FRENADO" "$(grep -c 'Veredicto: FRENADO' "$RLTXT")" "1"
    eq "freno: se para en el intento 4" "$(awk -F'\t' 'NR>1' "$RLTSV" | wc -l | tr -d ' ')" "4"
    eq "freno: no hay intento 5" "$(awk -F'\t' '$1==5' "$RLTSV" | wc -l | tr -d ' ')" "0"
    eq "freno: el resumen dice que pidió 7s" "$(grep -c 'Retry-After: 7' "$RLTXT")" "1"
    eq "freno: sale 0 (veredicto obtenido)" "$RC" "0"

    # Ya frenado desde el primer intento: no se manda el segundo
    printf 'POST /login-freno-siempre HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"email":"ana@example.com","password":"x"}' "$RLPORT" > "$TMPD/req_rl_siempre.req"
    OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_siempre.req" 20 2>&1)
    RLTSV=$(find "$FW/../scans/web" -name "rate_limit_127.0.0.1_$RLPORT.tsv" | head -1)
    eq "freno: si ya frena, se para en el 1" "$(awk -F'\t' 'NR>1' "$RLTSV" | wc -l | tr -d ' ')" "1"

    # Retry-After en fecha: se reporta literal, sin interpretarlo
    printf 'POST /login-freno-fecha HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"email":"ana@example.com","password":"x"}' "$RLPORT" > "$TMPD/req_rl_fecha.req"
    OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_fecha.req" 20 2>&1)
    RLTXT=$(find "$FW/../scans/web" -name "rate_limit_127.0.0.1_$RLPORT.txt" | head -1)
    eq "freno: la fecha de Retry-After se copia tal cual" "$(grep -c '06 Nov 1994 08:49:37' "$RLTXT")" "1"

    # Código distinto del de rechazo sin ser freno: no se llama FRENADO
    printf 'POST /login-cambia HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"email":"ana@example.com","password":"x"}' "$RLPORT" > "$TMPD/req_rl_cambia.req"
    OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_cambia.req" 20 2>&1); RC=$?
    eq "freno: un 403 a mitad es NO DETERMINADO, no FRENADO" "$(printf '%s' "$OUT" | grep -c 'NO DETERMINADO')" "1"
    eq "freno: el cambio de código sale 1" "$RC" "1"

    printf 'POST /login-lento HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"email":"ana@example.com","password":"x"}' "$RLPORT" > "$TMPD/req_rl_lento.req"
    OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_lento.req" 12 2>&1)
    RLTXT=$(find "$FW/../scans/web" -name "rate_limit_127.0.0.1_$RLPORT.txt" | head -1)
    eq "freno: el retardo creciente cuenta como FRENADO" "$(grep -c 'Veredicto: FRENADO (por retardo)' "$RLTXT")" "1"

    printf 'POST /login-caido HTTP/1.1\nHost: 127.0.0.1:%s\nContent-Type: application/json\n\n{"email":"ana@example.com","password":"x"}' "$RLPORT" > "$TMPD/req_rl_caido.req"
    OUT=$(RATE_LIMIT_SI=1 bash "$FW/05_Exploitation/web/rate_limit_probe.sh" "$TMPD/req_rl_caido.req" 20 2>&1); RC=$?
    eq "freno: conexión caída es NO DETERMINADO" "$(printf '%s' "$OUT" | grep -ci 'NO DETERMINADO')" "1"
    eq "freno: conexión caída sale 1" "$RC" "1"

    rm -rf "$FW/../scans/web/rate_limit_127.0.0.1_$RLPORT"*; kill "$RL_SRV" 2>/dev/null
else
    echo "  SKIP     python3 no instalado"
fi
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep "freno:"`
Expected: fallan.

- [ ] **Step 3: Implementar**

Detección por intento: `429`/`503`, o cabecera `Retry-After`, o `X-RateLimit-Remaining: 0` → freno; se guarda el número, el código y la espera, se copia la respuesta a `rate_limit_<slug>/<nnn>_freno.resp` y **se corta**. `000` → `NO DETERMINADO` y corte. Código distinto del primero sin ser freno → `NO DETERMINADO` (cambio a revisar) y corte.

Al terminar: `FRENADO` si hubo freno; si no, `FRENADO (por retardo)` cuando la mediana de los últimos 5 intentos supera 2× la de los primeros 5 **y** la diferencia es mayor que 0,1 s; si no, `SIN FRENO`.

El resumen lleva la línea `- Veredicto: ...`, el intento donde frenó, y una nota de qué **no** significa: una IP, una cuenta, y que un `403` de WAF no es rate limiting.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | grep -c "freno:.*FALLO"`
Expected: `0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh CyberSecurity-Framework/tests/fixtures/http_target.py CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(web): veredicto de rate limit con corte en el primer freno"
```

---

### Task 4: Registro, documentación y suites completas

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/lib/dangerous.txt` (una línea)
- Create: `docs/RATE-LIMIT-2026-10-31.md`
- Modify: `AGENTS.md` (párrafo de estado y una línea en «Writing new scripts»)
- Test: las cuatro suites

**Interfaces:**
- Consumes: todo lo anterior.

- [ ] **Step 1: Registrar el script y sus asertos**

Añadir `05_Exploitation/web/rate_limit_probe.sh` a `dangerous.txt` entre `http_inject.sh` y `sql_injection.sh`, y dos asertos en la sección de arranque:

```bash
eq "dangerous.txt incluye rate_limit_probe" "$(grep -cxF '05_Exploitation/web/rate_limit_probe.sh' "$FW/00_Config/lib/dangerous.txt")" "1"
eq "rate_limit: el gestor lo marca como intrusivo" "$(bash -c "source '$FW/00_Config/lib/params.bash'; params_is_dangerous '05_Exploitation/web/rate_limit_probe.sh' && echo si")" "si"
```

- [ ] **Step 2: Documentar**

`docs/RATE-LIMIT-2026-10-31.md`, con la forma de `docs/BURP-HTTP-INJECT-2026-10-31.md`: qué se construyó y por qué (el hallazgo ALTO del informe y su medición manual), los cuatro endpoints del fixture, uso y variables, la tabla de veredictos y qué **no** significa cada uno, salidas, verificación con los números reales de las cuatro suites, y límites (una IP, una cuenta, 403-a-todo).

- [ ] **Step 3: Actualizar `AGENTS.md`**

Un párrafo de cuatro líneas en «Current state» con lo nuevo y su documento; en «Writing new scripts», una línea sobre variar solo el campo de contraseña y no usar diccionario; corregir el recuento de `.sh` (118 fuera de `tests/`, 122 con las suites).

- [ ] **Step 4: Pasar las cuatro suites y la sintaxis**

```bash
bash CyberSecurity-Framework/tests/run_tests.sh 2>&1 | tail -3
bash CyberSecurity-Framework/tests/run_e2e.sh  2>&1 | tail -3
bash CyberSecurity-Framework/tests/run_smoke.sh 2>&1 | tail -3
bash CyberSecurity-Framework/tests/run_wizard.sh 2>&1 | tail -3
for f in $(git diff --name-only HEAD~4 -- '*.sh'); do bash -n "$f" 2>&1; done
```

Expected: `fallan: 0` en las cuatro; `bash -n` sin salida (capturando `stderr`).

- [ ] **Step 5: Commit**

```bash
git add AGENTS.md docs/RATE-LIMIT-2026-10-31.md CyberSecurity-Framework/00_Config/lib/dangerous.txt CyberSecurity-Framework/tests/run_tests.sh
git commit -m "docs: prueba de rate limit sobre el login capturado"
```
