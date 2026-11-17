# Diseño: OWASP ZAP como escáner automatizado (03_Scanners)

**Fecha:** 2026-11-17
**Estado:** propuesto, pendiente de aprobación
**Alcance:** integra el enfoque A de la memoria `zap-deps-integration-2026-11-15`
(daemon ZAP sin GUI + `python3-zapv2` para spider + pasivo), decidido por el
usuario en esa sesión y confirmado aquí. No construye ninguna otra parte del
backlog de ese documento (ya cerrada, ver `dependencias-tecla-d-2026-11-17`).

## Intención y por qué

`03_Scanners` ya tiene dos analizadores HTTP activos-pero-no-explotadores
(Nikto, Nuclei) y un lanzador manual de Burp (que no automatiza nada,
Community no lo permite). El usuario quiere un tercer analizador real y
automatizado: OWASP ZAP, con el mismo nivel de intrusión que Nikto/Nuclei
(tráfico activo de rastreo, nunca explotación), y que se encadene junto a
ellos en el flujo avanzado/`99`, no solo accesible a mano.

## Goals

- Nuevo script `03_Scanners/web_scanners/zap/zap_scan.sh` que, sobre una
  URL: levanta un daemon ZAP headless propio, espera a que su API esté
  lista, dispara **spider + escaneo pasivo** (nunca Active Scan de
  inyección), espera a que ambos terminen (con tope de tiempo explícito),
  escribe un informe de texto en `scans/zap/zap_<slug>.txt`, y **siempre**
  apaga su propio daemon al salir — éxito, fallo o interrupción.
- Entrada en el menú de `03` (opción 3 "Analizar una URL"), como tercera
  herramienta junto a Nikto/Nuclei, reutilizando `_scanners_read_target url`
  / `_scanners_confirm`.
- Encadenado en `run_all_scanners.sh` (avanzado/opción 5/`99`): por cada
  puerto web descubierto, correr ZAP además de Nikto y Nuclei — decisión
  explícita del usuario en esta conversación, con el coste de tiempo
  conocido y aceptado.

## Non-goals

- Nunca ZAP Active Scan (`ascan.*`), fuzzing de parámetros, ni ningún tipo
  de inyección/explotación. Solo `spider` (rastreo) + `pscan` (pasivo, lo
  que el rastreo ya vio pasar).
- Nunca AJAX Spider (`ajaxSpider.*`): necesita un navegador/webdriver,
  dependencia pesada que no aporta al alcance decidido.
- No gestiona autenticación/sesión en el objetivo (igual que Nikto/Nuclei:
  sin credenciales, sin login).
- No entra en `dangerous.txt`: mismo criterio que `nikto_scan.sh`/
  `nuclei_scan.sh`, que tampoco están ahí.
- No instala `zaproxy` (eso ya lo cubre la tecla `D`, ver
  `dependencias-tecla-d-2026-11-17`); el script solo lo comprueba con
  `scanner_require`.
- No reutiliza ni toca `00_Config/lib/consent/*` (el patrón `stable_cli.py`/
  consentimiento de otro trabajo en curso, sin aprobar — ver
  `AGENTS.md`). Este módulo sigue el patrón clásico de `03_Scanners`
  (`scanner_runtime.bash`), no ese otro.

## Anti-goals

- Que un spider sin tope se quede corriendo indefinidamente sobre un sitio
  grande, o que un timeout trunque en silencio sin decirlo (mismo principio
  que el tope duro de `rate_limit_probe.sh`).
- Que el daemon ZAP quede huérfano (puerto ocupado, proceso vivo) si el
  script falla a mitad o se interrumpe — cubierto por `trap` en
  EXIT/INT/TERM, *best-effort* (no ante un SIGKILL o una caída del padre;
  mismo límite documentado que otros módulos del framework, no una garantía
  absoluta). El daemon es propiedad exclusiva de esta única ejecución; nunca
  se diseña para persistir entre llamadas como Burp.
- Que las pruebas necesiten `zaproxy` real instalado (varios cientos de MB,
  JVM) para poder correr en CI/sandbox. Deben poder probar toda la lógica
  propia contra un API ZAP sintética.

## Constraints

- Mismo patrón de header (`Uso:`/`Ejemplo:`) y de salida
  (`OUTPUT_DIR=$(scans_dir zap)`, `SLUG=$(scans_slug "$URL")`) que
  `nikto_scan.sh`/`nuclei_scan.sh`.
- `scanner_require zaproxy` para la comprobación local; además una
  comprobación de que `python3 -c 'import zapv2'` funciona (paquete
  `python-owasp-zap-v2.4`, ya instalado en este Kali, pero no garantizado en
  cualquier máquina).
- Puerto siempre elegido por el kernel (`bind(('127.0.0.1', 0))`), nunca uno
  fijo — evita chocar con Burp (8080) u otra instancia ZAP. Mismo patrón que
  `tests/fixtures/http_target.py` usa para el servidor de pruebas.
- Tope de tiempo explícito y overridable por entorno
  (`ZAP_MAX_SEG`, por defecto 300s para spider+pasivo combinados), igual de
  explícito que `RATE_LIMIT_MAX_SEG`: al superarse, se corta (se llama
  `spider.stop()`), se avisa con texto claro de que es parcial, y sale 1 —
  nunca se presenta como informe completo.
- Nada de `set -e`; el fallo del daemon o de la API se reporta con mensaje
  explícito, igual que el resto de `03_Scanners`.
- El daemon se apaga por **dos vías en cascada**: primero `core.shutdown()`
  (API, cierre limpio), y si no responde en unos segundos, `SIGTERM` al PID
  capturado y `SIGKILL` si tampoco responde — un `trap` en el script cubre
  salida normal, fallo y señal (patrón ya usado por `ffuf` en el framework).
  El mismo `trap` borra el directorio de perfil temporal (ver más abajo).
- ZAP nunca escribe en el `$HOME` real: cada ejecución crea un directorio
  de perfil temporal propio y lo pasa al daemon con `-dir <tmp>`.
- La lógica de orquestación de la API (spider/pasivo/alertas/temporizador)
  va en un script Python nuevo (`00_Config/lib/zap/zap_driver.py`), no en
  bash: son muchas llamadas HTTP con sondeo y estado, el mismo motivo por el
  que `api_keys.py`/`report_engine.py`/`forensics_evidence.py` son Python en
  vez de bash. El bash wrapper solo gestiona el ciclo de vida del proceso
  (arrancar, esperar puerto, llamar al driver, apagar).

## Approaches consideradas

1. **(Elegida, enfoque A de la memoria) Daemon ZAP sin GUI + `python3-zapv2`,
   spider + pasivo, driver en Python + wrapper en bash.** Sigue el patrón de
   `03_Scanners` para el wrapper y el patrón de "lógica compleja en Python"
   ya usado en otros módulos para el driver. Automatizable de verdad, a
   diferencia de Burp Community.
2. **Lanzador manual tipo Burp (enfoque B, descartado en la sesión previa).**
   Redundante: ya existe Burp para eso, y el usuario pidió escaneo real, no
   otro lanzador.
3. **Vía Docker con `zap-baseline.py` (enfoque C, descartado en la sesión
   previa).** Dependencia innecesaria (Docker) cuando `python3-zapv2` +el
   paquete `zaproxy` de Kali ya cubren lo mismo sin contenedor; además
   `zap-baseline.py` no viene en el paquete de Kali (ver recon en la
   memoria), así que exigiría clonar las imágenes oficiales aparte.

## Decisiones de diseño (del usuario, en esta conversación)

- Encadenar ZAP en `run_all_scanners.sh` (avanzado/`99`), con el coste de
  tiempo adicional conocido y aceptado — no solo accesible a mano desde el
  menú.

## Decisiones tras el builder check

1. **Cobertura del camino feliz del wrapper:** el primer borrador dejaba un
   hueco real (ya señalado por AGENTS.md como clase de bug recurrente:
   salidas/rutas que dependen del `cwd` del llamador) — `run_zap.sh` probaba
   el driver contra una API falsa, y el stub de `zaproxy` para probar
   `zap_scan.sh` solo simulaba arranque/apagado, nunca servía esa API, así
   que el wrapper nunca llegaba a invocar al driver de verdad en ninguna
   suite. Se corrige: el stub de pruebas de `zaproxy` **sí** ata el puerto
   que recibe por argumento y sirve las mismas respuestas que
   `zap_fake_api.py` (mismo fixture, reusado como servidor real del stub),
   de modo que `tests/run_zap.sh` ejecuta `zap_scan.sh` completo de punta a
   punta (puerto libre → arranque → listo → driver real → informe →
   apagado) contra esa API sintética, sin ningún JVM real.
2. **Directorio de perfil/home de ZAP:** se aísla. `zap_scan.sh` crea un
   directorio temporal por ejecución y lo pasa con `-dir <tmp>` al daemon
   (ZAP no debe escribir en el `$HOME` real — mismo principio que el resto
   del framework, que nunca hardcodea ni ensucia rutas ajenas al módulo).
   El mismo `trap` que apaga el daemon borra ese directorio temporal.
3. **Garantía de "nunca huérfano":** es *best-effort* vía `trap` en
   EXIT/INT/TERM, igual que el resto del framework lo documenta en casos
   parecidos (p. ej. el coordinador de 08_Forensics entrega señales
   parent-only por pidfd, sin prometer cero huérfanos ante un SIGKILL o una
   caída del padre). No se añade un mecanismo más fuerte (pidfile,
   `PR_SET_PDEATHSIG`, submenú de "parar instancia" al estilo Burp): el
   anti-goal se reformula como "best-effort documentado", no como garantía
   absoluta.

## Decisiones de diseño (mías, a confirmar como parte de este doc)

### Estructura de archivos

- Crear `03_Scanners/web_scanners/zap/zap_scan.sh` — wrapper bash.
- Crear `00_Config/lib/zap/zap_driver.py` — driver Python (spider, pasivo,
  alertas, temporizador, informe de texto).
- Modificar `00_Config/lib/scanners_menu.bash`:
  - `scanners_check_tools`: añadir `zaproxy` a la lista de binarios
    comprobados localmente.
  - Opción 3 del menú ("Analizar una URL"): tercera entrada "ZAP — spider y
    pasivo (puede tardar varios minutos)".
- Modificar `03_Scanners/run_all_scanners.sh`: añadir
  `run_child web_scanners/zap/zap_scan.sh "$url"` junto a Nikto/Nuclei en el
  bucle de puertos web descubiertos.
- Crear `tests/fixtures/zap_fake_api.py` — servidor HTTP sintético que
  responde como la API JSON de ZAP (core/version, spider/scan,
  spider/status, pscan/recordsToScan, core/alerts, core/shutdown) para
  probar `zap_driver.py` sin el daemon real.
- Nueva suite `tests/run_zap.sh` (ver más abajo) + extender
  `tests/run_scanners_menu.sh` con la entrada de menú.
- Documentación: `docs/ZAP-2026-11-17.md`.

### Contrato de `zap_driver.py`

```
Uso: zap_driver.py --host HOST --port PUERTO --url URL --salida FICHERO
     [--max-seg SEGUNDOS]
```

- Se conecta a `http://HOST:PUERTO/` con `zapv2.ZAPv2(proxies=...)` (sin
  apikey: el daemon se lanza con `api.disablekey=true`, solo accesible en
  loopback).
- Lanza `spider.scan(url=URL)`; sondea `spider.status(id)` cada ~1s hasta
  100 o hasta agotar `--max-seg` (default 300). Si se agota, llama
  `spider.stop(id)` y marca el informe como parcial.
- Tras el spider (completo o cortado), sondea `pscan.records_to_scan` hasta
  que llegue a `0` o se agote el tiempo restante del mismo `--max-seg`
  global (no un segundo cupo aparte).
- Lee `core.alerts(baseurl=URL)`; escribe `--salida` con una línea de
  resumen (`SIN HALLAZGOS` / `N hallazgos`, mismo estilo que
  `scanner_nuclei_summary`) y, por hallazgo, nombre/riesgo/confianza/URL.
- Códigos de salida: `0` todo terminó dentro del tiempo (con o sin
  hallazgos), `1` error de conexión/API o tiempo agotado (informe parcial
  igual se escribe, marcado como tal).
- Nunca imprime ni guarda nada que no sea de la API de ZAP; no inventa
  hallazgos si la API falla a mitad.

### Contrato de `zap_scan.sh`

```
Uso: ./zap_scan.sh <URL>
Ejemplo: ./zap_scan.sh https://example.com
```

1. `scanner_url "$URL"`, `scanner_require zaproxy`, y
   `python3 -c 'import zapv2'` (si falla, mensaje explícito: falta
   `python3-zapv2`/`python-owasp-zap-v2.4`).
2. Puerto libre vía un pequeño `python3 -c 'import socket; s=socket.socket();
   s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'` (mismo truco que la
   fixture de pruebas).
3. Lanza `zaproxy -daemon -host 127.0.0.1 -port "$PUERTO" -config
   api.disablekey=true -config api.addrs.addr.name=.* -config
   api.addrs.addr.regex=true` en segundo plano; guarda el PID.
4. `trap` en EXIT/INT/TERM: intenta `core.shutdown()` vía una llamada corta
   de `zap_driver.py --apagar` (o un curl directo al endpoint
   `JSON/core/action/shutdown/`), y si el proceso sigue vivo tras un plazo
   corto, `kill -TERM`, luego `-KILL`.
5. Sondea `http://127.0.0.1:$PUERTO/` (vía `core.version` o un `curl` simple)
   hasta que responda o hasta un tope de arranque (p. ej. 30s) — el daemon
   JVM tarda en levantar.
6. Ejecuta `zap_driver.py` con el `OUTPUT_DIR`/`SLUG` ya resueltos.
7. Imprime el mismo estilo de cierre que `nuclei_scan.sh`
   (`✅`/`📁 Resultados:`).

### Pruebas

- `tests/fixtures/zap_fake_api.py`: servidor HTTP mínimo (sin `zapv2` real
  del lado servidor, solo respuestas JSON fijas/parametrizables) que imita
  `core/version`, `spider/scan`, `spider/status`, `pscan/recordsToScan`,
  `core/alerts` y `core/action/shutdown`. Toma el puerto por argumento —
  esto es lo que permite reusarlo en los dos niveles de prueba siguientes,
  sin triplicar la lógica de la API falsa.
- `tests/run_zap.sh` (nuevo), dos niveles:
  1. **Driver directo:** arranca `zap_fake_api.py` en un puerto propio y
     ejecuta `zap_driver.py` contra él sin pasar por `zap_scan.sh`: spider
     que avanza de 0→100 en varias llamadas, pscan que baja a 0, alertas
     con 0 y con N hallazgos, timeout que corta y marca parcial, error de
     conexión que sale 1 sin inventar nada.
  2. **Wrapper de punta a punta:** el stub de `zaproxy` en el `PATH` cerrado
     de la prueba, al recibir `-daemon -port N ...`, **arranca
     `zap_fake_api.py` atado a ese mismo puerto N** (no solo simula un PID)
     y responde a la señal de apagado cerrándolo. Así `zap_scan.sh` se
     ejecuta completo — puerto libre → arranque → espera de API lista →
     `zap_driver.py` real → informe → apagado — sin que el camino feliz del
     wrapper quede sin probar (hueco señalado por el builder check: es
     justo la clase de bug de rutas/`cwd` que `AGENTS.md` ya documentó una
     vez en este framework).
  3. Casos de ciclo de vida que no necesitan una API que responda: `SIGINT`
     a mitad de ejecución apaga el daemon igual; el directorio de perfil
     temporal se crea y se borra; dos ejecuciones seguidas usan puertos
     distintos.
- Extensión de `tests/run_scanners_menu.sh`: la opción 3 del menú ofrece
  ahora ZAP como tercera entrada.
- `run_all_scanners.sh`: assert de que el bucle de puertos web ahora llama
  tres `run_child` por puerto (nikto, nuclei, zap), no solo dos.

## Qué queda para quien implemente

- Los flags exactos de `zaproxy -daemon ...` son los documentados por el
  proyecto OWASP ZAP (no verificables en esta máquina: el binario no está
  instalado); confirmarlos contra `zaproxy --help`/`zap.sh -help` en el
  momento de implementar, instalando primero con la tecla `D` si hace falta
  probar de verdad contra un daemon real.
- Redactar el texto exacto del informe (`zap_<slug>.txt`) y de los mensajes
  de la opción de menú, mismo tono que el resto de `03_Scanners`.
- Decidir el valor exacto del tope de arranque del daemon (propuesto 30s,
  ajustable si la JVM tarda más en la máquina real).
