# Fase rate limit: ¿el login frena los intentos?

- **Fecha:** 2026-10-31
- **Diseño:** `docs/superpowers/specs/2026-10-31-rate-limit-probe-design.md`
- **Plan:** `docs/superpowers/plans/2026-10-31-rate-limit-probe.md`
- **Origen:** hallazgo ALTO de la prueba real de esta jornada, en
  `CyberSecurity-Framework/11_Reports/final_report/` (git-ignored: aquí no se repite el objetivo)

## Qué se construyó y por qué

El informe de la prueba real (una SPA de cobros recurrentes, autorizada por su titular)
cerró su hallazgo más grave midiendo a mano: **20 intentos consecutivos contra
`/api/auth/login` → 20 × `401`, cero `429`, latencia constante (~0,58 s), sin bloqueo de
cuenta ni backoff**. Es el hallazgo ALTO del informe, y hasta hoy vivía solo en el texto: si el
cliente pregunta cómo se midió, o quiere comprobar el arreglo dentro de un mes, hay que
recordarlo y repetirlo a pulso.

El framework sabía hacer lo contrario —tratar un `429`/`503` como corte, ya en
`http_inject.sh` y en `sqlmap_request.sh`— pero no tenía ninguna prueba cuyo objetivo fuera
**detectar si el freno existe**. Eso es lo que añade esta pieza:

| Pieza | Dónde | Qué hace |
|---|---|---|
| `rate_limit_probe.sh` | `05_Exploitation/web/` | Repite el login capturado N veces variando solo la contraseña, deja una fila de evidencia por intento y emite veredicto cortando en el primer freno |

Se apoya en lo que ya existía: `00_Config/lib/http_request.bash` (lectura de la petición cruda y
sustitución de un parámetro en query, formulario o JSON), el mismo que usan `http_inject.sh` y
`sqlmap_request.sh`, y `00_Config/lib/scans.bash` para las rutas y el nombre de las salidas.

No es fuerza bruta de credenciales y no lo parece: los valores son `wrong-1`, `wrong-2`, …
hasta `wrong-N`. No hay diccionario, no se buscan accesos válidos y el objetivo no es acertar
una contraseña, sino contar cuántos fallos acepta el servidor seguidos. Aun así el script está
en `00_Config/lib/dangerous.txt`: pide confirmación con el número de intentos y el aviso de que
la cuenta puede quedar bloqueada, y no acepta el valor del ejemplo como atajo.

## El fixture: ocho endpoints, no cuatro

El diseño hablaba de cuatro endpoints de prueba; al implementarlos hicieron falta ocho para
cubrir cada veredicto sin trampas. Están en `tests/fixtures/http_target.py`, y las suites los
levantan en un puerto efímero:

| Endpoint | Qué hace | Veredicto que produce |
|---|---|---|
| `/login-sin-freno` | `401` siempre, latencia constante | `SIN FRENO`, 20 filas, sale 0 |
| `/login-freno` | `401` hasta el 3.º; desde el 4.º `429` + `Retry-After: 7` | `FRENADO` en el intento 4, no hay intento 5, sale 0 |
| `/login-freno-siempre` | `429` + `Retry-After: 3` desde el primer intento | `FRENADO` y se para en el intento 1 |
| `/login-freno-fecha` | `401` y luego `429` con `Retry-After` en fecha HTTP | `FRENADO`; la fecha se copia literal, sin interpretarla |
| `/login-cambia` | `401` dos veces y después `403` | `NO DETERMINADO` (cambio de código, no freno), sale 1 |
| `/login-acepta` | `200` con la contraseña falsa | `NO DETERMINADO`, un solo intento, sale 1 |
| `/login-lento` | `401` con latencia creciente (`0,05 s × n`) | `FRENADO (por retardo)` con 12 intentos |
| `/login-caido` | Cierra la conexión sin responder | `NO DETERMINADO` (`000`), sale 1 |

Los tres últimos existen justo por los anti-objetivos del diseño: un `403` de WAF no es rate
limiting, un `200` a credenciales falsas es otro hallazgo, y un `000` es red. Los tres se
reportan sin llamarlos `FRENADO` ni `SIN FRENO`.

## Uso

```bash
# 1. Captura el login en Burp (Repeater → Copy to file / guardar como texto):
#    scans/web/login.req   — línea de petición, cabeceras, línea en blanco y cuerpo

# 2. Repite el intento variando solo la contraseña (20 por defecto)
cd CyberSecurity-Framework
./05_Exploitation/web/rate_limit_probe.sh ../scans/web/login.req

# 3. O con otro número de intentos (tope duro 200)
./05_Exploitation/web/rate_limit_probe.sh ../scans/web/login.req 50
```

El objetivo —host, puerto y ruta— sale de la propia petición (`Host:` y línea de petición): no
se le pasa por argumento ni se adivina. Una petición sin `Host:` se rechaza. El campo de
contraseña se detecta por nombre (`pass`, `clave`, `secret`, `contras`, sin distinguir
mayúsculas) entre los parámetros de query, de formulario o de JSON; si no hay ninguno el script
se para, y si hay dos avisa de cuál usa y de cuál ha descartado.

### Opciones por entorno

| Variable | Defecto | Qué hace |
|---|---|---|
| `RATE_LIMIT_INTENTOS` | `20` | Intentos cuando no se pasa `[intentos]`; mismo tope duro de 200 |
| `RATE_LIMIT_RETARDO` | `0` | Segundos entre peticiones (0 = tan rápido como responda el servidor) |
| `RATE_LIMIT_CAMPO` | autodetectado | Campo a variar cuando la detección por nombre no sirve |
| `RATE_LIMIT_SI=1` | — | No pide confirmación (suites y automatización) |
| `RATE_LIMIT_MAX_SEG` | `30` | Tope de reloj de **cada** petición |
| `RATE_LIMIT_ESQUEMA` | deducido del puerto | `http` o `https`, para cuando el puerto engaña |

Los valores de `RETARDO` y `MAX_SEG` se validan antes de enviar nada: un valor con unidad
(`5s`) haría fallar la tanda a mitad dejando media evidencia. El tope de 200 se rechaza en voz
alta en vez de recortarse en silencio: quien pide 500 tiene que saber que no se enviaron 500.

## Qué significa cada veredicto

| Veredicto | Regla | Qué NO significa |
|---|---|---|
| `FRENADO` | Una respuesta frenó: `429`/`503`, o cabecera `Retry-After`, o `X-RateLimit-Remaining: 0`. Se corta ahí y no se envía el intento siguiente | No dice si el freno es por IP, por cuenta o global, ni cuánto dura: `Retry-After` se copia tal cual, no se duerme ni se interpreta. Un `503` en una ruta puede ser sobrecarga, no un límite |
| `FRENADO (por retardo)` | Mismo código en todos los intentos, pero la mediana de los 5 últimos supera 2× la de los 5 primeros y hay más de 100 ms de diferencia (exige ≥10 intentos) | Puede ser carga del servidor, no un backoff: se midió una vez. Hay que repetir la tanda para descartarlo antes de darlo por defensa |
| `SIN FRENO` | Todos los intentos con el mismo código no-2xx y sin ralentizarse | No dice que el login no tenga límite: dice que en N intentos seguidos no apareció. Puede llegar más tarde, por IP o por cuenta, y N puede ser pequeño para ese servidor |
| `NO DETERMINADO` | No hay veredicto: `000` (sin respuesta), un código distinto que no es freno (`403` de WAF, sesión que caduca) o un `2xx`/`3xx` con la contraseña falsa aceptada | No es «limpio» ni «vulnerable»: es «no se pudo medir». Los tres casos cortan la tanda, y el `2xx` es además otro hallazgo (login que no valida, o catch-all) |

Códigos de salida: `0` cuando hay veredicto (`FRENADO`, `FRENADO (por retardo)`, `SIN FRENO`) o
el operador cancela; `1` cuando no lo hay (`NO DETERMINADO`) o por error de uso, de lectura o de
campo. Así una cadena de pruebas distingue «no frenó» de «no se pudo medir» sin leer el informe.

## Salidas

En `scans/web/` (git-ignored), con el objetivo y el puerto en el nombre:

- `rate_limit_<host>_<puerto>.txt` — resumen: objetivo, petición, campo variado, intentos
  enviados, códigos vistos, avisos, veredicto, motivo, alcance y la tabla de intentos.
- `rate_limit_<host>_<puerto>.tsv` — máquina: `n codigo ms tamano retry_after señal`, una fila
  por intento. La contraseña no se guarda en ninguna columna.
- `rate_limit_<host>_<puerto>/intento_001.resp` — cuerpo de la respuesta del primer intento, que
  es la línea base que se compara con el resto.
- `rate_limit_<host>_<puerto>/freno_<nnn>.resp` — cuerpo de la respuesta que frenó, con el
  número del intento delante para que la evidencia se ordene por nombre.

Solo se guarda el cuerpo del primer intento y el del freno: veinte cuerpos idénticos no añaden
nada y el `.tsv` ya cuenta qué pasó en cada uno.

## Verificación

- `tests/run_tests.sh` → **311 asserts, 0 fallos**, de los que **37** son de esta pieza:
  arranque (13, incluidos `dangerous.txt` y el modo slots del gestor), sonda contra
  `/login-sin-freno` (6) y frenos (18, un aserto por cada caso del fixture).
- `tests/run_e2e.sh` → 11/0 · `tests/run_smoke.sh` → 0 fallos · `tests/run_wizard.sh` → 58/0.
- `bash -n` con `stderr` capturado sobre los `.sh` que toca el plan
  (`05_Exploitation/web/rate_limit_probe.sh`, `tests/run_tests.sh`): sin salida.
- Contra el servidor de prueba se comprobó lo que el veredicto promete: `FRENADO` para en el
  intento 4 y no manda el 5; `FRENADO (por retardo)` sale con 12 filas y ningún `ms` a cero;
  `NO DETERMINADO` sale 1 en los tres casos (cambio, aceptación y conexión caída).

## Límites conocidos

- **Una IP y una cuenta.** La prueba se hace desde donde corre el script y contra la sesión
  capturada. No distingue un límite por IP de uno por cuenta ni de uno global, y el informe lo
  dice en «Alcance» en vez de insinuarlo.
- **Un `403` a todo no se llama freno.** Un WAF que contesta `403` a cualquier cosa, o una
  sesión que caduca a mitad, producen `NO DETERMINADO` (cambio de código), no `FRENADO`. Es el
  mismo hueco anotado desde la fase Burp: se confirma con las cabeceras y repitiendo desde otra
  IP.
- **El criterio de retardo es sensible a la carga.** «Mediana de los últimos 5 > 2× la de los
  primeros 5 y >100 ms» describe un backoff, pero un servidor ocupado se parece. Con menos de
  10 intentos no se evalúa, y una sola tanda no basta para acusar: hay que repetirla.
- **El retardo entre peticiones anula la prueba.** Con `RATE_LIMIT_RETARDO` alto (minutos) lo
  que se mide ya no es el límite del servidor, y el resumen recuerda el retardo usado para que
  nadie lea `SIN FRENO` donde solo hubo silencio.
- **La cuenta se puede bloquear de verdad.** Es el motivo del tope de 200, de la confirmación
  explícita y de la entrada en `dangerous.txt`. El operador elige el `.req` y, con él, la cuenta
  que se arriesga.
- **Cuerpos no soportados.** `multipart/form-data` y `Transfer-Encoding: chunked` se rechazan
  con mensaje; un cuerpo JSON exige `python3` (la misma dependencia que `http_inject.sh`).
