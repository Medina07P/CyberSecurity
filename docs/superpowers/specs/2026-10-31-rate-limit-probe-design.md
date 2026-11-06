# Diseño — Prueba de rate limit sobre el login capturado

- **Fecha:** 2026-10-31
- **Estado:** pendiente de aprobación
- **Origen:** hallazgo ALTO del informe del engagement (`11_Reports/final_report/`, fuera de git) («20 intentos consecutivos contra `/api/auth/login` → 20 × `401`, cero `429`, latencia constante, sin bloqueo ni backoff»), hoy medido a mano y no reproducible por el framework.

## Intención y por qué

El framework ya probó inyección sobre la petición capturada (`http_inject.sh`) y ya distingue el
freno 429/503 como **corte** (`sqlmap_request.sh`). Falta lo contrario: una prueba cuyo objetivo
sea **detectar si el freno existe**. Sin ella, el hallazgo depende de que alguien recuerde cómo
lo midió, y no se puede repetir ni comparar tras el arreglo del cliente.

No es fuerza bruta de credenciales: no se usa diccionario de contraseñas plausibles ni se buscan
accesos válidos. Es una **demostración acotada** de que el servidor acepta N intentos fallidos
sin frenar.

## Objetivos

- Repetir la petición de login capturada N veces (20 por defecto) con una contraseña distinta
  cada vez, y dejar **una fila de evidencia por intento**: código, latencia, tamaño y
  `Retry-After`.
- Emitir un veredicto de tres estados: `FRENADO`, `SIN FRENO`, `NO DETERMINADO`.
- Parar en cuanto aparezca el freno: no se sigue machacando lo que ya está protegido.
- Que el tope de intentos sea explícito y configurable, y que el script lo diga antes de empezar.

## No-objetivos

- Adivinar contraseñas (no hay diccionario; los valores son `wrong-1`, `wrong-2`, …).
- Probar bloqueo por cuenta de un usuario real ajeno: el operador elige el `.req`, y por tanto la
  cuenta; el script avisa de que si hay bloqueo por cuenta, esa cuenta se bloquea.
- Medir límites por IP frente a por cuenta: una sola IP, una sola cuenta; se documenta como límite.

## Anti-objetivos (cómo se vería un éxito falso)

1. Decir `SIN FRENO` porque se hicieron 20 intentos espaciados 60 s: eso no prueba nada. El
   retardo por defecto es **0** y se documenta.
2. Decir `FRENADO` por un 403 de WAF que contesta a todo, no por rate limiting. Por eso se
   reporta el código y el cuerpo, y un código distinto del de rechazo esperado se marca como
   cambio a revisar, no como freno.
3. Decir `NO DETERMINADO` ante un `429`: el `429` **es** el freno, es el resultado bueno.
4. Confundir un fallo de red (`000`) con ausencia de freno: corta y sale 1.

## Cómo se mide

Cada intento es una petición idéntica a la capturada (mismas cabeceras, `Host:`, cuerpo y
sesión) salvo **el campo de contraseña**, que se sustituye por un valor único. El campo se elige
por nombre (`password`, `pass`, `clave`, `secret`, sin distinguir mayúsculas) entre los
parámetros de formulario o JSON; si no hay ninguno, el script se para con mensaje: no adivina
qué campo es.

| Señal | Cómo se detecta | Peso |
|---|---|---|
| Freno explícito | código `429` o `503`, o cabecera `Retry-After`, o `X-RateLimit-Remaining: 0` | `FRENADO` |
| Freno por retardo | la mediana de los últimos 5 intentos supera 2× la de los 5 primeros | `FRENADO` (con nota) |
| Rechazo estable | todos los intentos con el mismo código no-2xx que el primero (p. ej. `401`) | `SIN FRENO` |
| Cambio de código | un código distinto del primero, sin ser freno (p. ej. `403`, `500`) | `NO DETERMINADO` + se reporta |
| Red | `000` | `NO DETERMINADO` y corte inmediato |

`FRENADO` se anuncia con el número de intento en que apareció, el código y lo que pidió el
servidor (`Retry-After`), que es lo que hace falta para el informe y para comparar tras el
arreglo.

## Salidas

En `scans/web/` (git-ignored), con el objetivo en el nombre:

| Fichero | Contenido |
|---|---|
| `rate_limit_<slug>.tsv` | `n codigo ms tamano retry_after señal` — una fila por intento |
| `rate_limit_<slug>.txt` | resumen: objetivo, endpoint, intentos, campo variado, veredicto, tabla de evidencia, avisos y «qué no significa» |
| `rate_limit_<slug>/*.resp` | cuerpo del primer intento y del intento donde frenó (o del último), para el informe |

## Uso

```bash
cd CyberSecurity-Framework
./05_Exploitation/web/rate_limit_probe.sh ../scans/web/login.req          # 20 intentos
./05_Exploitation/web/rate_limit_probe.sh ../scans/web/login.req 50      # 50
```

| Variable | Defecto | Qué hace |
|---|---|---|
| `RATE_LIMIT_INTENTOS` | `20` | Intentos si no se pasa el argumento; tope duro 200 |
| `RATE_LIMIT_RETARDO` | `0` | Segundos entre intentos (0 = tan rápido como responda) |
| `RATE_LIMIT_CAMPO` | autodetectado | Campo a variar |
| `RATE_LIMIT_ESQUEMA` | deducido del puerto | `http` o `https`, hermana de `HTTP_INJECT_ESQUEMA` |
| `RATE_LIMIT_SI=1` | — | No pide confirmación (para la suite y para automatizar) |
| `RATE_LIMIT_MAX_SEG` | `30` | Tiempo máximo por intento |

Se añade a `00_Config/lib/dangerous.txt` y pide confirmación con el número de intentos y el
aviso de posible bloqueo de la cuenta, salvo `RATE_LIMIT_SI=1`.

Códigos de salida: `0` veredicto obtenido (`FRENADO` o `SIN FRENO`) · `1` uso incorrecto,
`NO DETERMINADO` o fallo de red.

## Pruebas

Se añaden cuatro endpoints al fixture `tests/fixtures/http_target.py`:

| Endpoint | Comportamiento | Aserto |
|---|---|---|
| `/login-sin-freno` | `401` siempre, latencia constante | veredicto `SIN FRENO`, N filas en el `.tsv`, exit 0 |
| `/login-freno` | `429` + `Retry-After: 7` a partir del intento 4 | veredicto `FRENADO`, se para en el 4, no hay intento 5, exit 0 |
| `/login-lento` | `401`, latencia creciente por intento | veredicto `FRENADO` por retardo |
| `/login-caido` | sin respuesta | `NO DETERMINADO`, exit 1 |

Además: sin campo de contraseña el script no adivina; `dangerous.txt` lo incluye; el gestor lo
ve en modo slots (`Uso: <fichero> [intentos]`).

## Límites conocidos

- Una IP y una cuenta: no distingue límite por IP de límite por cuenta.
- Un WAF que contesta `403` a todo se reporta como cambio a revisar, no como freno; es el mismo
  hueco anotado desde la fase Burp.
- Con `RATE_LIMIT_RETARDO` alto la prueba deja de ser una prueba de rate limit; el resumen lo
  recuerda con el retardo usado.

## Decisiones tomadas aquí (no del partner)

- Tres veredictos, no cuatro: el freno por retardo se reporta como `FRENADO (por retardo)`,
  porque para el cliente es una defensa igual.
- Los valores de prueba son `wrong-1…wrong-N`, no un diccionario: es una demostración, no un
  ataque de credenciales.
- Se corta en el primer freno en vez de completar la tanda: machacar después de que el servidor
  pida parar es exactamente lo que el framework no hace.
