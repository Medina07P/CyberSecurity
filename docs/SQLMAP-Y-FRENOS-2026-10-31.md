# Freno por 429/503 y `sqlmap -r` sobre la petición capturada

- **Fecha:** 2026-10-31
- **Diseño:** `docs/superpowers/specs/2026-10-31-freno-y-sqlmap-design.md`
- **Plan:** `docs/superpowers/plans/2026-10-31-freno-y-sqlmap.md`

## Qué se construyó y por qué

`http_inject.sh` ya probaba la petición real capturada en Burp, pero dejaba dos huecos que
`docs/BURP-HTTP-INJECT-2026-10-31.md` tenía anotados: un WAF que estrangula a mitad de tanda y
la distancia entre «hay diferencial» y «esto es lo que hay en la tabla».

| Pieza | Dónde | Qué hace |
|---|---|---|
| Freno 429/503 | `05_Exploitation/web/http_inject.sh` | Reintenta una vez respetando `Retry-After`; si insiste, corta la tanda y **no puntúa nada** |
| `sqlmap_request.sh` | `05_Exploitation/web/` | Lleva el `.req` ya validado a sqlmap en tres fases, cada una con su propio permiso |

El error que se cierra es el mismo de ayer en la dirección contraria: ayer el eco del payload se
leyó como hallazgo; un 429 sin tratar se habría leído igual, porque al no parecerse a la línea
base `http_inject.sh` lo registraba como `FUERTE` o incluso `CONFIRMADO`.

## Lo que se comprobó antes de diseñar (Kali, 2026-10-31)

Medido con sqlmap **1.10.6#stable** y curl **8.20.0**, contra servidores locales propios; la
tabla completa está en el diseño.

| Hecho | Evidencia |
|---|---|
| `sqlmap -r` con la entrada estándar en tubería **no prueba nada y sale con 0** | log `using 'STDIN'…` y `ending`; peticiones en el servidor: 0; `exit=0`. Con `--ignore-stdin` sí ataca |
| `-r` conecta al host del `Host:` del fichero; `--host` no lo redirige | tres ejecuciones con `-v 4` |
| `-r` sin puerto en el `Host:` cae a 80; el esquema sale del puerto (`443`→https, resto→http) | `lib/core/common.py` |
| Una tanda `--technique=B --level=1 --risk=1` cuesta ~51 peticiones; `BT`, ~58 en 4 s | contador del servidor de pruebas |
| sqlmap **no tiene tope de peticiones** | `sqlmap -hh`: solo técnica, nivel, riesgo, hilos, `--delay` y `--time-sec` |
| Un 429 con `Retry-After: 7` se lee con `-D` | curl 8.20 contra un 429 propio |

De ahí salen las dos decisiones que mandan en el código: `--ignore-stdin` no es opcional (sin él
un «no inyectable» es mentira), y el tope es de **reloj**, no de peticiones, porque el de
peticiones no existe.

## Uso

### Freno en `http_inject.sh`

No hay bandera nueva. Un `429` o `503` se detecta en cualquier respuesta, se espera lo que pida
`Retry-After` (segundos o fecha HTTP) y se reintenta **una** vez. Si el reintento vuelve a
frenar, se corta la tanda con aviso y código de salida 1. Si la línea base ya sale frenada, el
mensaje es propio («te están frenando antes de empezar») y no se escribe informe de hallazgos.

| Variable | Defecto | Qué hace |
|---|---|---|
| `HTTP_INJECT_FRENO` | `429 503` | Códigos que cuentan como freno |
| `HTTP_INJECT_ESPERA` | `10` | Segundos si no hay `Retry-After` utilizable |
| `HTTP_INJECT_ESPERA_MAX` | `60` | Tope de la espera pedida por el servidor |

### `sqlmap_request.sh`

```bash
cd CyberSecurity-Framework
# El .req que dejó http_inject.sh, o uno de Repeater, o "-" para pegarlo
./05_Exploitation/web/sqlmap_request.sh ../scans/web/http_inject_10.0.0.5_443/001_id_sqli_bool.req

# Con objetivo distinto del Host: (reescribe el vhost en una copia)
./05_Exploitation/web/sqlmap_request.sh peticion.req 10.0.0.5
```

Tres permisos, y **ninguno se hereda de otro**:

| Permiso | Variable | Qué autoriza |
|---|---|---|
| Repetir la petición si no es `GET`/`HEAD` | `SQLMAP_SI=1` | la fase 1 |
| Enumerar bases y tablas | `SQLMAP_ENUMERAR=1` | `--dbs` y `--tables` |
| Volcar una tabla | `SQLMAP_TABLA=<base.tabla>` | `--dump` de esa tabla |

Sin terminal, `SQLMAP_ENUMERAR` no se pregunta: un `--batch` no puede quedarse esperando una
respuesta que nadie va a escribir. Enumerar y volcar **no son fallos** si no hay permiso; el
resumen lo dice y se sale con 0.

Otras variables: `SQLMAP_DB`, `SQLMAP_TECNICA` (`B`), `SQLMAP_ESQUEMA`, `SQLMAP_DELAY`,
`SQLMAP_TIME_SEC`, `SQLMAP_MAX_SEG` (900) y `SQLMAP_FILAS` (50; `0` = sin tope).

## Qué significa cada veredicto

| Veredicto | Señal | Qué **no** significa |
|---|---|---|
| `INYECTABLE` | `appears to be … injectable`, con parámetro, tipo y payload | No significa que se haya volcado nada: es la puerta a la fase 2 |
| `NO INYECTABLE` | `not appear to be injectable` y sin frenos, **cualificado** con técnica y nivel | No es «el objetivo está limpio»: solo que no lo es para `--technique=B --level=1` |
| `NO DETERMINADO` | `CRITICAL`, fallo de red, timeout o un `429/503` en el log | No es ausencia de inyección; es ausencia de prueba. Sale 1 |

Ese `NO DETERMINADO` por 429 es la misma lección un piso más abajo: sqlmap no entiende de
`Retry-After` y ante un freno concluye «no inyectable». Ese «no» no se hereda.

Fases 2 y 3, cada una con su estado:

| Fase | OK | FALLO | NO DETERMINADO |
|---|---|---|---|
| `--dbs` / `--tables` | lista obtenida | error del motor | `CRITICAL` o timeout |
| `--dump` | filas con su cuenta (`completa` o `muestra de N`) | `CRITICAL` o sin poder contar | cortado por tiempo |

El volcado es una **muestra**: `--stop=50` por defecto, porque el objetivo es demostrar que se
lee la tabla, no exfiltrarla entera. Un volcado cortado o fallido cuenta como fase fallida y
sale 1. Al llegar al tope se dice «muestra» aunque el número salga exacto, porque no se puede
saber si había una fila más detrás.

## Salidas

`scans/web/` (git-ignored), del freno:

- el informe y el `.tsv` de siempre, con el aviso de freno en `== Avisos ==`;
- `errores.log` recibe el `stderr` de curl, incluidos los reintentos.

`scans/sqlmap/<slug>/` (git-ignored), de sqlmap:

| Fichero | Contenido |
|---|---|
| `sqlmap_<slug>_<nn>_<param>.log` | salida completa de cada fase de ese `.req`, con `stderr` dentro |
| `copia_<nn>_<param>.req` | la petición tal como se le pasó a sqlmap (con el `Host:` reescrito si tocaba) |
| `sqlmap_<slug>.txt` | resumen de la tanda: un bloque por `.req`, el veredicto, y las secciones de enumeración y volcado |
| `sqlmap_<slug>_dbs.log`, `sqlmap_<slug>_tablas.log`, `sqlmap_<slug>_dump.log` | logs de las fases 2 y 3 |
| `dump_<slug>/` | el `--output-dir` de sqlmap, con lo que volcó |

## Verificación

- `tests/run_tests.sh` → **274 asserts, 0 fallos** (incluye los cinco casos del diseño: `--frena`,
  `--frena-siempre`, `--frena-base`, `Retry-After` como fecha, y los tres veredictos de sqlmap
  con freno, `CRITICAL` y «no inyectable»).
- `tests/run_e2e.sh` → **11/0** · `tests/run_smoke.sh` → **0 fallos** · `tests/run_wizard.sh` → **58/0**.
- `bash -n` sobre **127** ficheros `.sh` y `.bash`, con `stderr` capturado: sin avisos.
- Con **sqlmap real** (1.10.6) contra el fixture sqlite de dos filas: la fase 1 lo declara
  INYECTABLE y el script sale 0 (`real: sqlmap confirma la inyección del fixture`).

## Límites conocidos

- Un servidor que contesta **403 a todo** sigue sin tratarse: no es un freno con código propio y
  el catch-all no lo cubre. Está anotado desde la fase Burp y sigue abierto.
- El tope de sqlmap es de reloj (`SQLMAP_MAX_SEG`), no de peticiones: no existe el de peticiones.
  El script lo dice en voz alta en vez de fingir un tope.
- La enumeración corre **una vez por tanda**, con la primera copia que salió INYECTABLE: si dos
  parámetros van a bases distintas, solo se enumeran las de la primera.
- Si se niega el permiso de enumerar, no se vuelca nada aunque se pase `SQLMAP_TABLA`: el
  volcado necesita la base, y sin `--dbs` no hay base salvo que se indique `base.tabla`.
- `multipart/form-data` y `Transfer-Encoding: chunked` se rechazan con mensaje, igual que en
  `http_inject.sh`.
