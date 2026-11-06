# Diseño — Fase Burp: petición capturada, inyección y validación por niveles

- **Fecha:** 2026-10-31
- **Estado:** pendiente de aprobación
- **Origen:** cierra el pendiente que dejó `2026-10-31-arreglos-framework-design.md` («POST/JSON no entra aquí. Se resuelve con la petición capturada en Burp, en la fase siguiente»).
- **Revisión:** pendiente del revisor independiente.

## Intención y por qué

El framework solo ataca URLs que él mismo construye: `sql_injection.sh` y `xss.sh` hacen GET
sobre una lista fija de parámetros (`id`, `user`, `q`…). Contra la aplicación del engagement del
31 —una SPA que autentica por cabecera y habla JSON por POST— esos scripts **no prueban nada** y
además imprimen «sin diferencias», que se lee como «objetivo limpio».

La pieza que falta no es otro escáner: es aceptar **la petición que el operador ya capturó en
Burp** y probar inyección sobre sus parámetros reales, con sesión y cuerpo incluidos. La
validación va por niveles porque el nivel debe salir de la evidencia, no de la corazonada: así no
vuelven los 90 falsos positivos del catch-all, y lo que no se puede confirmar queda visible en
vez de descartado.

## Lo que se comprobó antes de diseñar (Kali, 2026-10-31)

| Hecho | Evidencia |
|---|---|
| Burp instalado: **2026.3.2-0kali1, Community**, Java 25 | `dpkg -s burpsuite`, `java -version` |
| `--project-file` **se ignora**: «Disk-based projects are only supported on Burp Suite Professional» | diálogo de arranque, captura de pantalla |
| El arranque se detiene en un diálogo con botón **Start Burp**; no hay modo desatendido | ventana «Burp Suite Community Edition v2026.3.2» |
| `java -jar` directo se detiene además en un modal **JRE warning**; el wrapper `/usr/bin/burpsuite` ya pasa `--suppress-jre-check` y `--disable-check-for-updates-dialog` | dos arranques, uno por cada vía |
| Aceptado el diálogo, el título pasa a «… - Temporary Project» | `xdotool getwindowname` |
| Listener por defecto **127.0.0.1:8080**; en esta máquina el 8080 lo ocupa un `http.server` del operador | `ss -ltnp` |
| **No se pudo confirmar** que `--config-file` cambie el puerto del listener en Community: con el 8080 ocupado no apareció ningún listener, ni en 8080 ni en 8099 | `ss -ltnp` tras Start Burp |
| Community **no tiene Scanner ni REST API** | comportamiento y edición |

Consecuencia de diseño: el lanzador **no asume el puerto**, lo comprueba; y lo único que
sobrevive al cierre de Burp es el fichero de petición que el operador guarde, porque el proyecto
vive en memoria.

## Objetivo

1. `http_inject.sh` acepta una petición HTTP cruda (la de Repeater) y prueba inyección en sus
   parámetros reales de query, formulario y JSON, con cabeceras de sesión intactas.
2. Cada diferencia se clasifica por evidencia en **CONFIRMADO / FUERTE / DÉBIL**, con su porqué.
3. Todo hallazgo deja evidencia reproducible (petición y respuesta guardadas) para cerrarlo a mano
   en Repeater.
4. `burp_launcher.sh` arranca Burp desde el gestor, resuelve el puerto, verifica que captura y
   explica el flujo manual con el comando exacto ya rellenado.

## No objetivos

- Escanear con Burp. Imposible en Community: no hay Scanner ni API.
- Importar exportaciones de Burp (pieza aparte; necesita una exportación que hoy no existe).
- Soportar `multipart/form-data` en esta fase.
- Sustituir a `sqlmap`; lo complementa cuando la petición es POST/JSON.
- Automatizar la interfaz de Burp más allá de pulsar el botón de arranque.

## Anti-objetivos

- Llamar hallazgo a una diferencia de tamaño sin neutralizar antes el eco del parámetro.
- Llamar CONFIRMADO a un solo indicio, o a un indicio que no se repite.
- Enviar payloads destructivos (`DROP`, `id`, `ping`, borrados). Solo lectura y retardos.
- Matar procesos de Burp por nombre: se usa el PID que el propio lanzador guarda.
- Afirmar «sin hallazgos» cuando no se probó nada: si no hay parámetros inyectables, se dice y
  se sale con código 1.

## Restricciones

- Bash del estilo de la casa: sin `set -e`, mensajes en español, `Uso:`/`Ejemplo:` funcionales,
  LF, sin rutas absolutas ni dependencia del `cwd`.
- La librería de salidas ya existe (`00_Config/lib/scans.bash`): `scans_dir`, `scans_slug`.
- `Uso:` con huecos `<...>`/`[...]` y **sin `|`** dentro; los flags no van en la línea `Uso:` o
  el gestor pasaría el script a modo `manual`.
- `http_inject.sh` va a `dangerous.txt`: el gestor pedirá confirmación y no aceptará el valor del
  `Ejemplo:` como objetivo.
- Los tests corren en Git Bash sin terminal; lo que dependa de `python3` se salta con aviso, como
  ya hace la prueba de `zsh` en `run_tests.sh`.

## Enfoques considerados

| | Enfoque | Compromiso |
|---|---|---|
| **A** | `http_inject.sh` consume la petición capturada; Burp sigue siendo la herramienta de captura y revisión | **Elegido.** Burp no se automatiza, pero el hueco real (POST/JSON autenticado) queda cerrado y probado |
| B | Lanzador que arranca Burp como proxy de las sondas del framework y pulsa Start Burp | Automatiza la parte que no aporta (un visor), y es frágil: depende de la geometría de la ventana |
| C | Soporte de Burp Pro (proyecto en disco, API, exportación de hallazgos) | Aquí no se puede probar: se entregaría sin verificar |
| D | Importar y validar exportaciones de Burp | Necesita una exportación que hoy no existe |

**Elegido: A**, más un lanzador que automatiza solo el arranque y la explicación (lo que el
usuario pidió: «en el gestor esté la opción de lanzar el launcher y como una explicación»). B se
descarta como pruebas automáticas; su único resto es pulsar Start Burp con confirmación previa.

## Pieza 1 — `05_Exploitation/web/http_inject.sh`

### Interfaz

```
Uso: ./http_inject.sh <fichero> [objetivo]
Ejemplo: ./http_inject.sh /ruta/peticion.txt 10.10.10.5
```

- `<fichero>`: petición HTTP cruda. `-` lee de la entrada estándar (pegar y Ctrl-D).
- `[objetivo]`: IP o host al que conectar. Por defecto, el `Host:` de la petición. Si difiere,
  el `Host:` original **se envía tal cual** y la conexión va al objetivo (comportamiento tipo
  vhost, con `curl --resolve`).
- Va en `05_Exploitation/web/` porque explota, no descubre.

Opciones por entorno (no en la línea `Uso:` para que el gestor lo trate como `slots`):
`HTTP_INJECT_NIVEL` (`todas` por defecto, o `fuertes`), `HTTP_INJECT_PARAM`, `HTTP_INJECT_RETARDO`
(0,2 s), `HTTP_INJECT_ESQUEMA`, `HTTP_INJECT_PROXY` (si no, se respeta `http_proxy`/`https_proxy`).
La cabecera del script las documenta y el arranque imprime las que están en uso.

### Lectura de la petición

- Primera línea `MÉTODO ruta HTTP/1.x`; cabeceras hasta una línea en blanco; cuerpo después.
- Acepta CRLF y LF. Si `Content-Length` no cuadra con el cuerpo, se recalcula y se avisa.
- Rechaza con mensaje claro: `Transfer-Encoding: chunked` y cuerpos `multipart/form-data`.
- Esquema: `https` si el puerto es 443/8443, `http` en el resto; `HTTP_INJECT_ESQUEMA` lo fuerza.
- Cabeceras: se conservan todas (incluidas `Cookie` y `Authorization`); se reescriben `Host` (si
  hay que conectar a otro sitio) y `Content-Length`; se fija `Accept-Encoding: identity` para que
  los tamaños sean comparables.
- Sin `Host:` y sin `[objetivo]` → error de uso.

### Qué se inyecta

Solo **parámetros presentes en la petición**, uno a uno, sustituyendo su valor:

- query string (`GET` y también la query de un `POST`);
- cuerpo `application/x-www-form-urlencoded`;
- cuerpo `application/json` (hojas de tipo cadena, número o booleano; requiere `python3`, si no
  hay, se rechaza el JSON con mensaje y se siguen probando query/formulario);
- sin cuerpo: solo query.

`HTTP_INJECT_PARAM` limita a un parámetro.

### Payloads por clase

| Clase | Payloads | Señal estricta |
|---|---|---|
| SQLi booleana | `x' AND '1'='1` / `x' AND '1'='2`, y variante numérica `1 AND 1=1` / `1 AND 1=2` | la respuesta «verdadera» coincide con la línea base y la «falsa» no, 2 de 2 veces |
| SQLi por error | `'`, `"`, `')`, `';--` | firma de error de BD solo con payload (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) |
| SQLi por tiempo | `'||(SELECT 1 FROM pg_sleep(5))||'`, `1' AND SLEEP(5)-- -`, `';WAITFOR DELAY '0:0:5'-- -` | retardo ≥ base + 4 s, 2 de 2 veces |
| XSS | `<script>alert(1)</script>`, `"><svg onload=alert(1)>`, `'><img src=x onerror=alert(1)>` | payload presente **sin escapar** y `Content-Type` HTML/JS |
| Inyección de comandos | `; sleep 5`, `| sleep 5`, `$(sleep 5)`, `` `sleep 5` `` | retardo ≥ base + 4 s, 2 de 2 veces |
| SSTI | `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>` | aparece `49` y no aparece `7*7` en lo reflejado |

Ningún payload escribe, borra ni ejecuta comandos de lectura.

### Guardas

1. **Línea base por parámetro**: se sustituye el valor por un token aleatorio (`zq7xk1`) y se
   piden 3 respuestas. Si no coinciden entre sí, el parámetro se marca «línea base inestable» y
   todo lo suyo baja a DÉBIL con ese motivo escrito.
2. **Neutralización del eco**: antes de comparar, el cuerpo se normaliza sustituyendo el payload,
   el token y sus variantes (URL, HTML y JSON escapadas) por un literal fijo, y también patrones
   volátiles (CSRF, timestamps, hashes largos). Sin esto, el reflejo se cuenta como diferencia y
   entierra lo bueno.
3. **Detector de catch-all**: se pide un parámetro que no existe con un token aleatorio; si
   responde igual que la línea base, se avisa de que la aplicación contesta a todo y los DÉBILES
   se marcan como ruido.
4. **Sesión**: si la línea base es 401/403 o redirige a un login, se avisa «posible sesión
   caducada» antes de seguir; los hallazgos de esa tanda quedan como máximo FUERTES.
5. **Repetición**: todo lo que aspire a CONFIRMADO se repite 2 veces; el retardo se mide con
   `curl -w '%{time_total}'` contra el mínimo de la línea base.
6. **Efectos en el servidor**: una petición capturada no es una URL de laboratorio. Si el método
   no es `GET`/`HEAD`, antes de enviar nada se imprime el método, el endpoint y el número
   estimado de peticiones (parámetros × payloads × repeticiones) y **se pide confirmación
   explícita**; `HTTP_INJECT_SI=1` la salta (tests y automatización). `HTTP_INJECT_MAX` limita el
   total de peticiones por ejecución (400 por defecto). Una petición de alta de factura repetida
   200 veces es un efecto real en el cliente, no una prueba.
7. **Alcance**: se carga `scope_allows` de `session.bash`; si el objetivo o el `Host:` no están en
   `scope.yaml`, se avisa (no se bloquea, como ya hace el resto de la librería) y el aviso queda
   escrito en la cabecera del informe.

### Niveles

| Nivel | Regla |
|---|---|
| **CONFIRMADO** | La evidencia diferencial es reproducible y un valor benigno no puede producirla (par booleano, retardo, `49` de SSTI, reflejo sin escapar en HTML/JS) |
| **FUERTE** | La diferencia es específica del payload pero no demuestra impacto (error de BD solo con comilla, 403/WAF solo con payload, reflejo escapado, un único retardo) |
| **DÉBIL** | Cualquier otra diferencia con la línea base (código, tamaño o cuerpo normalizado), incluidos los parámetros con línea base inestable |

`CONFIRMADO` significa «diferencial reproducible», **no** «explotado»: el informe lo dice y cada
hallazgo lleva su petición y su respuesta para cerrarlo a mano en Repeater.

### Salidas

En `scans/web/` (mismo árbol que `sql_injection.sh`, ya ignorado por git):

- `http_inject_<slug>.txt` — informe legible, una sección por nivel, con la evidencia al lado.
- `http_inject_<slug>.tsv` — máquina: `nivel  param  clase  payload  codigo  tamano  ms  evidencia`.
- `http_inject_<slug>/` — pares petición/respuesta de CONFIRMADOS y FUERTES, truncados a 64 KB,
  listos para pegar en Repeater.

Consola: recuento por nivel (`2 confirmados, 5 fuertes, 12 débiles`) y recordatorio de la ruta.
`HTTP_INJECT_NIVEL=fuertes` filtra **la consola**, no el fichero: la evidencia no se tira.

Códigos de salida: `0` ejecutado (haya o no hallazgos), `1` error de uso, de parseo o de red, o
petición sin parámetros inyectables.

## Pieza 2 — `03_Scanners/web_scanners/burpsuite/burp_launcher.sh`

### Interfaz

```
Uso: ./burp_launcher.sh [puerto]
Ejemplo: ./burp_launcher.sh 8080
```

Subcomandos para la línea de comandos, fuera de la línea `Uso:`: `--estado` y `--parar`.

### Qué hace

1. Comprueba `burpsuite` (el wrapper, no `java -jar`) y `java`. Si falta, error claro y salida 1.
2. Elige puerto: el pedido; si no, 8080 si está libre; si no, el primero libre de 8080-8099.
3. Escribe en `scans/burp/` el config del listener y el `scope` con el objetivo de la sesión, si
   lo hay (`session_target`). El config se escribe **a la mejor de nuestras posibilidades**: no se
   pudo verificar que Community lo aplique, así que el lanzador no deduce nada de su contenido,
   comprueba el puerto real (paso 4) y, si no coincide, lo dice.
4. Arranca con `--project-file` y `--config-file` en segundo plano, guarda el PID y **espera hasta
   60 s** a que el puerto escuche. No asume que el config se aplicó: comprueba. `--project-file`
   se pasa por compatibilidad con Pro; en Community se ignora y **no se crea ningún `.burp`**.
5. Si el puerto no aparece y hay ventana de arranque, ofrece (con confirmación explícita) pulsar
   *Start Burp* con `xdotool`; si no hay `xdotool` o el usuario dice que no, explica cómo hacerlo.
   Si tras eso el puerto sigue sin escuchar —el caso probable cuando el 8080 está ocupado y el
   config se ignora— **no se aborta**: se indica exactamente qué cambiar en *Settings → Proxy →
   Proxy settings* y se ofrece `--estado` para volver a comprobar.
6. Verifica la captura con una petición de prueba al objetivo a través del proxy, forzando el uso
   del proxy (`--noproxy ''`), y anuncia por qué puerto está pasando.
7. Imprime la explicación del flujo manual: proxy del navegador, aceptar el CA, capturar en
   Repeater, guardar la petición, y el comando exacto ya rellenado apuntando a
   `scans/burp/peticion_<slug>.txt`. El lanzador **no crea ese fichero** (lo escribe el operador
   desde Repeater) y lo dice; `<slug>` es `scans_slug` del objetivo de sesión, la misma regla que
   usa `http_inject.sh` para nombrar sus salidas.
8. Avisa del límite: Community **no guarda proyectos**; al cerrar Burp se pierde el historial y lo
   único que sobrevive es la petición guardada.

### Salidas

`scans/burp/`: `config_<slug>.json`, `launcher.log`, `burp.pid` y, solo bajo Pro,
`burp_<slug>.burp`.

`--parar` mata **solo** el PID guardado; `--estado` informa de PID, puerto y si escucha.

## Integración con el gestor

- Los dos scripts aparecen solos en el menú de su módulo (`find *.sh`). `http_inject.sh` sale con
  `[intrusiva]` por `dangerous.txt` y pide confirmación; el lanzador sale como un script más.
- No se toca `cyber_framework.sh`: la explicación la imprime el lanzador, que es donde se lee.
  Si más adelante se quiere una línea descriptiva bajo cada script en el menú, es otro cambio.
- `run_all_*` no los incluye: `http_inject.sh` necesita un fichero que el orquestador no tiene, y
  el lanzador abre una GUI.

## Decisiones que tomo yo

1. `http_inject.sh` vive en `05_Exploitation/web/` porque explota; el lanzador en
   `03_Scanners/web_scanners/burpsuite/`, donde ya está `burp_config.xml`.
2. Solo se prueban parámetros presentes: la lista fija (`id`, `user`…) es lo que hoy produce
   ruido sobre endpoints que no los usan.
3. JSON exige `python3`; sin él se avisa y se sigue con query/formulario.
4. Los flags van fuera de `Uso:` para conservar el modo `slots` en el gestor.
5. El lanzador no pulsa Start Burp sin preguntar: es una acción sobre la interfaz del operador.
6. Los pares petición/respuesta se truncan a 64 KB para que un binario grande no llene `scans/`.
7. Repetir una petición capturada puede crear o cobrar algo en el cliente: por eso la confirmación
   explícita con el recuento estimado antes de cualquier método que no sea `GET`/`HEAD`, y el tope
   de 400 peticiones. El tope se puede subir con `HTTP_INJECT_MAX`, nunca saltar.
8. El `scope.yaml` avisa, no bloquea: es la misma política que el resto de la librería, y el aviso
   queda en el informe para que nadie lo pierda.

## Qué queda para el que construya

- Nombres y orden de los asserts, y el fixture de servidor de prueba (login JSON, parámetro que
  refleja, endpoint catch-all, línea base inestable).
- Umbrales exactos: 4 s de retardo, 2 repeticiones, 64 KB de evidencia.
- La lista cerrada de patrones volátiles que se neutralizan al comparar.
- Cómo se nombran los pares guardados y si se agrupan por parámetro.

## Verificación

- Casos RED→GREEN, uno por guarda: parámetro que solo refleja (no debe ser CONFIRMADO), endpoint
  catch-all (DÉBILES marcados como ruido), par booleano real (CONFIRMADO), retardo real
  (CONFIRMADO), JSON con sesión (CONFIRMADO), línea base inestable (baja a DÉBIL), petición sin
  parámetros (salida 1), cuerpo multipart (rechazo con mensaje), método `POST` sin
  `HTTP_INJECT_SI` (no envía nada y pide confirmación), tope `HTTP_INJECT_MAX` respetado, objetivo
  fuera de `scope.yaml` (aviso en consola y en el informe).
- `burp_launcher.sh` con un `burpsuite` de mentira en `PATH`: config generado, PID guardado,
  `--estado`, `--parar`, elección de puerto con el 8080 ocupado, y el caso «el config se ignora y
  el puerto elegido no escucha» (mensaje y salida, sin abortar). Ningún test abre una GUI.
- Las cuatro suites siguen en verde y los recuentos de `run_tests.sh` se actualizan (+2 scripts).
- `bash -n` capturando `stderr` en los scripts tocados.
- Prueba real: petición capturada contra el catch-all local del 31 (0 confirmados) y contra un
  servidor propio con login JSON y un parámetro vulnerable (1 confirmado con evidencia).
