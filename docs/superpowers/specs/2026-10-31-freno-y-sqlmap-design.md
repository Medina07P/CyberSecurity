# Diseño — Freno por 429/503 y `sqlmap -r` sobre la petición capturada

- **Fecha:** 2026-10-31
- **Estado:** pendiente de aprobación
- **Origen:** cierra los dos pendientes de `docs/BURP-HTTP-INJECT-2026-10-31.md` («Rate limit: hay un hueco real» y «Consultar tablas no es cosa de este tool, es de sqlmap»).

## Intención y por qué

`http_inject.sh` ya prueba la petición real que el operador capturó en Burp y clasifica cada
diferencia por evidencia. Le faltan dos cosas, y las dos son de la misma familia: **que el
resultado no diga más de lo que se probó**.

1. Un WAF que estrangule a mitad de tanda devuelve **429** (o 503). Hoy solo 401/403/419 cuentan
   como «la tanda se rompió»; un 429 entra por el camino normal y, al no parecerse a la línea
   base, se registra como `FUERTE` —o peor, `CONFIRMADO` en un par booleano— sin decir que lo
   único que pasó es que nos frenaron. Es el error de ayer en la dirección contraria: primero
   confundimos el eco con un hallazgo; ahora confundiríamos el freno con un hallazgo.
2. Detectar que hay diferencial no demuestra impacto. Lo que demuestra impacto es **leer una
   tabla**, y eso es `sqlmap`, que ya está instalado. Lo que falta no es otro motor: es darle a
   sqlmap **la misma petición** que ya validamos, con su sesión y su cuerpo, y hacerlo sin
   heredar la parte imprudente de sqlmap.

## Lo que se comprobó antes de diseñar (Kali, 2026-10-31)

Todo con sqlmap **1.10.6#stable** y curl **8.20.0**, contra servidores locales propios.

| Hecho | Evidencia |
|---|---|
| `sqlmap -r` **con la entrada estándar en tubería no prueba nada y sale con código 0** | log: `using 'STDIN' for parsing targets list`, después `ending`; cuenta de peticiones del servidor: 0; `exit=0`. Con `--ignore-stdin` sí ataca |
| `_setStdinPipeTargets()` **sobrescribe** la lista de objetivos cuando `conf.url` está vacío, y `-r` no rellena `conf.url` | `/usr/share/sqlmap/lib/core/option.py:424-450` y `lib/parse/cmdline.py:1122-1127` |
| `-r` **conecta al host del `Host:` del fichero**; `--host` no lo redirige (probado: la cabecera enviada siguió siendo la del fichero) y `-r` es **incompatible con `-u`** | tres ejecuciones con `-v 4`: `[CRITICAL] host 'app.inventado.example' does not exist`, `option '-r' is incompatible with option '-u'` |
| Coste real de una tanda: `--technique=B --level=1 --risk=1` → **~51 peticiones** por parámetro inyectable; `BT` → **~58 en 4 s** contra un blanco booleano (un time-based real suma `--time-sec` por prueba) | contador del servidor sqlite de pruebas |
| sqlmap **no tiene tope de peticiones** (`--stop-*` no existe; solo técnica, nivel, riesgo, hilos, `--delay` y `--time-sec`) | `sqlmap -hh` |
| Un 429 local con `Retry-After: 7` se lee con `-D` (o `%header{retry-after}`) | curl 8.20 contra un 429 propio |

## Objetivos

- Que un 429/503 **nunca** se puntúe, ni en la línea base ni durante el sondeo.
- Que la tanda se **reintente una vez** respetando `Retry-After`, y se corte si insiste, avisando
  con el código y lo que pidió el servidor.
- Que exista un camino desde «hay diferencial» a «esto es lo que hay en la tabla», con la misma
  petición y el mismo alcance.
- Que cada fase pida su propio consentimiento y que el informe diga **qué se probó y qué no**.

## No objetivos

- Convertir `http_inject.sh` en un escáner de sqlmap. Sigue sin enumerar ni volcar nada.
- Reescribir `sql_injection.sh`. Su contrato `<IP> [PUERTO] [RUTA]` es lo que el gestor parsea.
- Automatizar el volcado de todo el esquema. El operador elige tabla; el script no decide por él.
- Tocar los niveles de evidencia de `http_inject.sh` (`CONFIRMADO`/`FUERTE`/`DEBIL`).

## Anti-objetivos (fracaso aunque funcione)

- Un informe que diga «0 hallazgos» cuando en realidad el WAF cortó la tanda.
- Un wrapper que herede de sqlmap la callada por respuesta: `--batch` sin `--ignore-stdin` sale
  con 0 y sin haber tocado el objetivo; leer ese 0 como «no inyectable» sería mentir.
- Un volcado que se dispare solo porque la fase 1 dijo «inyectable».

## Enfoques considerados

| Enfoque | Qué aporta | Qué cuesta |
|---|---|---|
| **A. Script nuevo `05_Exploitation/web/sqlmap_request.sh`** *(elegido)* | `Uso: <fichero.req\|directorio> [objetivo]`, modo slots, el gestor lo descubre solo, presupuesto de peticiones propio y separado del de `http_inject.sh` | Un comando más en el flujo |
| B. Interruptor `HTTP_INJECT_SQLMAP=1` en `http_inject.sh` | Un solo comando | Mezcla dos presupuestos de peticiones distintos y hace que el informe de inyección dependa de sqlmap |
| C. Extender `sql_injection.sh` con `-r` | Nombre ya conocido | Rompe el `Uso:` que el gestor parsea: `<IP> [PUERTO] [RUTA]` deja de ser cierto |

## Pieza 1 — freno por 429/503 en `http_inject.sh`

**Detección.** Código `429` o `503` en cualquier respuesta, con la línea base ya medida o sin
ella. La lista vive en `HTTP_INJECT_FRENO` (por defecto `429 503`).

**Reintento.** Uno solo por petición, tras esperar lo que pida el servidor:

| Caso | Espera |
|---|---|
| `Retry-After: <segundos>` ≤ `HTTP_INJECT_ESPERA_MAX` (60) | esos segundos |
| `Retry-After: <fecha HTTP>` | hasta esa fecha, con el mismo tope |
| `Retry-After` > tope | **no se reintenta**: se corta y se explica que el servidor pide más de lo que vamos a esperar |
| sin `Retry-After` | `HTTP_INJECT_ESPERA` (10 s) |

El reintento **cuenta** en `N_ENVIOS` (es una petición real) y respeta `HTTP_INJECT_MAX`.

**Corte.** Si el reintento vuelve a dar 429/503: `FRENADO=1`, aviso con código y espera pedida,
y se corta la tanda igual que con la sesión caducada. `peticion()` devuelve 1 **antes** de
cualquier `registrar`, y los llamadores ya hacen `|| return`: nada se puntúa.

**Línea base.** Si la base sale 429/503 el mensaje es propio («te están frenando antes de
empezar»), no se escribe informe de hallazgos y se sale con 1.

**Resumen.** El aviso entra en `== Avisos ==` del informe y la consola dice cuántas veces frenó.
Código de salida 1 si la tanda se cortó, junto a los casos de sesión y de tope.

**Contexto para la pieza 2.** `http_inject.sh` es el único que sabe con qué esquema habló
(`https` no se deduce del `.req`, que solo lleva `Host:`). Al guardar la primera evidencia escribe
`contexto.txt` en el directorio de evidencia, con `esquema=`, `host=` y `metodo=`. Sin ese fichero
—un `.req` de Repeater— la pieza 2 aplica su propia heurística.

**Pruebas.** Tres endpoints nuevos en `tests/fixtures/http_target.py`:

| Endpoint | Comportamiento | Aserto |
|---|---|---|
| `/frena` | 429 con `Retry-After: 0` las 2 primeras veces del parámetro, luego normal | se reintenta y la tanda termina; 0 hallazgos puntuados por el freno |
| `/frena-siempre` | 429 siempre | aviso de freno, corte, exit 1, **ningún** `FUERTE`/`CONFIRMADO` |
| `/frena-base` | 429 desde la primera petición | mensaje propio de línea base y exit 1 |

Las pruebas fijan `HTTP_INJECT_ESPERA=0` para no dormir.

## Pieza 2 — `sqlmap_request.sh`

**Entrada.** Un `.req` crudo —el que guarda `http_inject.sh` en `scans/web/http_inject_<objetivo>_<puerto>/`,
uno de Repeater, o `-` para la entrada estándar— o **el directorio** de evidencia. Con un
directorio se ejecuta un sqlmap por `.req` y el consentimiento muestra el recuento («3 ficheros
→ ~150 peticiones»). Se lee con `http_request.bash`, como `http_inject.sh`: mismo parseo, mismas
guardas de `chunked`/`multipart`/JSON.

**Objetivo distinto del `Host:`.** Si se pasa `[objetivo]` y su **host** no coincide con el del
`Host:`, se reescribe `Host:` en una **copia temporal** —es la única forma: con `-r`, sqlmap
conecta al host del fichero— y se avisa de que **cambia el vhost**. Reglas:

| Caso | Qué se escribe |
|---|---|
| `[objetivo]` sin puerto | `Host: <objetivo>:<puerto del .req>` — el puerto **nunca** se pierde: sqlmap lo toma del `Host:` y sin él caería a 80 |
| `[objetivo]` con `:puerto` | `Host: <objetivo>:<puerto indicado>` |
| sin `[objetivo]` | el fichero va intacto; si el nombre no resuelve, sqlmap falla y se reporta como fallo, nunca como «no inyectable» |

En modo directorio cada `.req` conserva su puerto; un `[objetivo]` con puerto se aplica a todos.

**Esquema y TLS.** Con `-r` y una línea de petición relativa, sqlmap deduce el esquema del puerto:
`443` → `https`, **todo lo demás → `http`** (`lib/core/common.py:5472-5474`). Por eso un `.req` de
8443 se probaría en claro y moriría con `connection reset`. El wrapper decide el esquema así, en
este orden: `contexto.txt` del directorio de evidencia → `SQLMAP_ESQUEMA` → puerto 443/8443 →
`http`; y cuando sale `https` pasa **`--force-ssl`**. Misma heurística que `http_inject.sh`, misma
variable de escape.

**Fase 1 — detección.**

```
sqlmap -r <copia> --batch --ignore-stdin --threads=1 --retries=1 --delay=<n> \
       --technique=<B|BT> --level=1 --risk=1 --time-sec=<n> [--force-ssl] \
       --output-dir=<scans/sqlmap/<slug>/>
```

`--ignore-stdin` **no es opcional**: sin él sqlmap sale con 0 sin probar nada. `B` por defecto y
no `BT` (decisión mía): el objetivo de la fase es «¿hay inyección?», y las pruebas de tiempo son
las que más peticiones y segundos gastan; `SQLMAP_TECNICA=BT` lo activa.

**Veredicto de la fase 1.** Se lee la salida y solo hay tres respuestas posibles, y el veredicto
**siempre se cualifica con la técnica y el nivel usados** («NO INYECTABLE con `--technique=B
--level=1`»), porque callar eso convertiría una limitación de la prueba en una propiedad del
objetivo:

| Señal en el log | Veredicto | Salida |
|---|---|---|
| `appears to be ... injectable` | INYECTABLE (+ parámetro, tipo, payload) | 0 |
| `all tested parameters do not appear to be injectable` **y sin frenos** | NO INYECTABLE (con técnica y nivel) | 0 |
| `HTTP error codes detected during run` con 429/503 | **NO DETERMINADO**: el WAF frenó la tanda | 1 |
| nada de lo anterior (CRITICAL, fallo de red, sqlmap roto) | **NO DETERMINADO** | 1 |

La tercera fila es la misma lección de la pieza 1 un piso más abajo: sqlmap no entiende de
`Retry-After` (solo tiene `--retry-on`, que mira el contenido) y ante un 429 concluye «no
inyectable». Ese «no» no se hereda.

**Confirmación y fase 2.** Si la fase 1 dice INYECTABLE, el script lo imprime con su evidencia y
pregunta **una sola vez** si se sigue a enumeración, diciendo cuántas peticiones se van a gastar
y que la petición se repite muchas veces. Si se acepta:

1. `--dbs` → lista de bases (y `--current-db`).
2. `--tables` → tablas de la base elegida: `SQLMAP_DB`, o la que elija el operador de la lista;
   sin elección y sin terminal, se para aquí.
3. `--dump` **solo** de la tabla que indique el operador (`SQLMAP_TABLA`, o un menú de las
   detectadas); sin elección, no se vuelca nada.

`--threads=1 --retries=1 --delay=<n> --time-sec=<n>` en todas las fases.

**Consentimiento: quién autoriza qué.** Son tres permisos distintos y ninguna variable los mezcla:

| Permiso | Cómo se salta | Qué autoriza |
|---|---|---|
| Repetir la petición (método no `GET`/`HEAD`) | `SQLMAP_SI=1` | la fase 1 |
| Enumerar bases y tablas | `SQLMAP_ENUMERAR=1` | `--dbs` y `--tables` |
| Volcar una tabla | `SQLMAP_TABLA=<db.tabla>` | `--dump` de esa tabla |

`SQLMAP_SI=1` **no** autoriza enumerar ni volcar: sin terminal y sin `SQLMAP_ENUMERAR`, la fase 2
no se ejecuta y el resumen lo dice. Es el anti-objetivo «un volcado que se dispare solo», escrito
como código.

**El volcado es una muestra.** `--dump` lleva `--stop=<SQLMAP_FILAS>` (50 por defecto) porque el
objetivo es demostrar que se lee la tabla, no exfiltrarla entera; `SQLMAP_FILAS=0` quita el tope.
El resumen distingue «volcada (muestra de 50)», «volcada completa», «cortada por tiempo» y «no se
llegó a volcar».

**Veredicto de las fases 2 y 3.** Cada fase tiene el suyo, y el resumen los da por separado; nunca
se resume el todo con el mejor resultado parcial:

| Fase | OK | FALLO | NO DETERMINADO |
|---|---|---|---|
| `--dbs` / `--tables` | lista obtenida | el motor devuelve error | `CRITICAL`, timeout o 429 |
| `--dump` | filas volcadas (con su cuenta) | el motor devuelve error | timeout o corte a mitad |

Salida del script: 0 si la fase 1 dio veredicto y ninguna fase falló; 1 si algo quedó
**NO DETERMINADO** o una fase falló. Enumeración omitida (sin permiso) no es fallo.

**Tope.** sqlmap no acepta un tope de peticiones, así que el tope es de reloj: `SQLMAP_MAX_SEG`
(900 s por fase) con `timeout`, más técnica/nivel/riesgo fijos. El script lo dice en voz alta en
vez de fingir un tope que no existe.

**Guardas heredadas.** Método distinto de `GET`/`HEAD` → misma confirmación que `http_inject.sh`,
con el recuento y el aviso de que sqlmap repite la petición muchas veces. Fuera de `scope.yaml` →
aviso, como el resto del framework.

**Salidas** (en `scans/sqlmap/<slug>/`, git-ignored):

| Fichero | Contenido |
|---|---|
| `sqlmap_<slug>_<n>_<param>.log` | salida completa de cada fase de ese `.req`, con `stderr` dentro |
| `sqlmap_<slug>_<n>_<param>.txt` | veredicto y evidencia de ese `.req` |
| `sqlmap_<slug>.txt` | resumen de la tanda: un bloque por `.req`, el peor veredicto arriba y las fases 2-3 |
| `dump_<slug>/` | `--output-dir` propio de sqlmap, con lo que volcó |

En modo directorio, `<n>_<param>` sale del nombre del `.req`: así dos ficheros del mismo objetivo
no se pisan. Un `.req` suelto se resume igual, con la tanda de un solo bloque.

**Salidas** (en `scans/sqlmap/<slug>/`, git-ignored):

- `sqlmap_<slug>.log` — salida completa de cada fase, con `stderr` incluido.
- `sqlmap_<slug>.txt` — resumen legible: objetivo, fichero, técnica, veredicto, parámetro, tipo,
  payload, bases, tablas, tablas volcadas, avisos y el recuento de peticiones estimadas.
- lo que sqlmap escriba en su propio `--output-dir`.

**Registro.** Se añade a `00_Config/lib/dangerous.txt` (no toma `Ejemplo:` y pide confirmación) y
el gestor lo descubre por su línea `Uso:`.

**Pruebas.**

- Con un `sqlmap` falso en `PATH`: pasa `--ignore-stdin`, pasa la técnica pedida, pasa
  `--force-ssl` cuando el esquema es https, **pide** la confirmación de método no-`GET`, **pide**
  la segunda confirmación antes de enumerar, y con `SQLMAP_SI=1` no pregunta pero **tampoco**
  enumera.
- Reescritura del `Host:`: con `[objetivo]` sin puerto se conserva el puerto del `.req`; con
  puerto, se usa el indicado.
- Con la salida falsa `CRITICAL ... does not exist`: veredicto NO DETERMINADO y exit 1 (no
  «no inyectable»). Con `HTTP error codes detected during run: 429`: NO DETERMINADO, exit 1.
- Con `sqlmap` real (si está) contra un fixture nuevo `tests/fixtures/sql_target.py` —sqlite con
  una tabla de dos filas—: la fase 1 lo declara INYECTABLE, `--dbs` devuelve una base y el
  resumen lo refleja. Coste medido: ~5 s.

## Lo que queda al que lo construya

- Nombres exactos de las variables de entorno y el formato del resumen (dentro de la casa: `Uso:`,
  `Ejemplo:`, mensajes en español, `exit 1` con bloque de uso).
- Cómo trocear la salida de sqlmap para el resumen (grep sobre el log, sin `2>/dev/null`).
- Si `/frena` debe frenar por parámetro o global en el fixture; basta con que el caso sea
  reproducible y barato.
- El texto exacto de las tres confirmaciones.

## Decisiones tomadas aquí (no del partner)

- `B` por defecto en vez de `BT`, por coste; `SQLMAP_TECNICA` lo cambia.
- Tope de reloj en vez de un tope de peticiones que sqlmap no ofrece.
- `--dump` nunca automático y acotado a 50 filas: tabla explícita o nada.
- Espera máxima 60 s: por encima de eso se corta en vez de dormir una hora.
- `sqlmap_request.sh` **no** reutiliza `SQLMAP_SI` para enumerar: tres permisos, tres variables.
- El veredicto «no inyectable» va siempre cualificado con técnica y nivel.
- `contexto.txt` en el directorio de evidencia, porque el esquema no viaja en el `.req`.
