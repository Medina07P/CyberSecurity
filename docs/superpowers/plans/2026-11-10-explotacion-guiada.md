# Módulo 05: revisión integral — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mejorar navegación, fiabilidad y evidencia de 05 conservando íntegramente sus capacidades y validándolo con los objetivos reales configurados.

**Architecture:** Añadir runtime y evidencia propios de explotación, sin heredar el timeout obligatorio de enumeración. Mantener scripts y CLI, introducir navegación guiada y capturas por ejecución, y adaptar el descubrimiento de informes. La validación operacional usa herramientas y datos reales; un verificador local solo comprueba la evidencia que producen.

**Tech Stack:** Bash, Python 3 estándar, PyYAML ya instalado, herramientas existentes de Kali y bibliotecas del framework.

**Spec:** `docs/superpowers/specs/2026-11-10-explotacion-guiada-design.md`.

## Global Constraints

- «No añadir topes de intentos, tasas, diccionarios reducidos, límites de duración ni otras restricciones nuevas.»
- «Conservar los controles ya existentes, incluidos los permisos independientes de sqlmap, confirmaciones del gestor y frenos HTTP.»
- «No endurecerlos ni eliminarlos aprovechando esta revisión.»
- «La validación real no se reemplaza por suites aisladas.»
- «No instalar dependencias ni cambiar privilegios automáticamente.»
- «No publicar objetivos, claves, respuestas ni credenciales; no hacer push.»
- «No crear vulnerabilidades ni desplegar payloads automáticamente para conseguir un positivo.»
- Suites antiguas destructivas: exclusivamente clon limpio sin evidencia real, si se ejecutan como regresión complementaria.
- Conservar scope.yaml modificado fuera de los commits. Aviso informativo exacto del diseño; no añadir confirmaciones.
- Bash sin set -e; fuentes LF; valores por stdout e interfaz por stderr; usar `${BASH_SOURCE[0]:-$0}` en bibliotecas.
- El usuario rechaza sustituir pruebas reales por aisladas: no crear mocks/fixtures ni exigirlos para la validación operacional. Adaptar el ciclo prueba-corrección a reproducciones reales y verificaciones locales sin tráfico cuando corresponda.

## Review Focus

1. Contraseña MySQL vacía y configuraciones heredadas de clientes: acceso corresponde exactamente a la credencial declarada (tarea 3).
2. URL con query, ruta y TLS en puerto no estándar: ninguna reinterpretación silenciosa ni mezcla de evidencias (tarea 4).
3. Dos ejecuciones simultáneas o un fallo después de un éxito: no colisión ni resurrección del éxito anterior (tarea 2).
4. EOF, espacios y datos con semántica distinta — fichero, LHOST, interfaz — no se convierten en objetivo de sesión (tarea 6).
5. Corte por señal o herramienta faltante en una pipeline: fallo real visible, sin credenciales/hallazgos heredados (tareas 2 y 5).

## Mapa de archivos y límites de responsabilidad

Rutas relativas a `CyberSecurity-Framework/` salvo `docs/`.

| Archivo | Responsabilidad |
|---|---|
| `00_Config/lib/exploitation_runtime.bash` (nuevo) | Captura sin topes nuevos, diagnóstico y estado de ejecución |
| `00_Config/lib/exploitation_evidence.py` (nuevo) | Metadata, clasificación por protocolo, selección de último intento y visor |
| `00_Config/lib/exploitation_menu.bash` (nuevo) | Navegación y argumentos por semántica |
| `05_Exploitation/show_results.sh` (nuevo) | Entrada CLI del visor |
| `05_Exploitation/` scripts actuales | Mantener operaciones, corregir ejecución y conclusiones |
| `cyber_framework.sh` | Source y despacho del menú de 05 |
| `11_Reports/lib/sources.py`, `engine.py`, `parsers/exploitation.py` (nuevo) | Descubrimiento, selección de evidencia actual e interpretación sin secretos |
| `tests/verify_exploitation_real.py` (nuevo) | Comprobaciones de evidencia real; nunca lanza herramientas ni modifica archivos |
| `.superpowers/sdd/2026-11-10-explotacion-guiada/` (local ignorado) | Inventario privado, referencias a datos, registro de comprobaciones y logs de desarrollo |
| `docs/EXPLOTACION-2026-11-10.md`, README de 05, manual | Uso, cambios, cobertura real y pendientes sin datos privados |

No modificar bibliotecas de 03/04 para reutilizar su timeout. No reestructurar las tres hojas extensas de petición capturada salvo corrección respaldada por evidencia; integrar sin cambiar sus permisos.

### Tarea 1: Inventario privado y contrato de comprobación real

**Files:** crear `tests/verify_exploitation_real.py`; registros privados bajo `.superpowers/sdd/2026-11-10-explotacion-guiada/`.

**Interfaces:** CLI `python3 tests/verify_exploitation_real.py MANIFEST --case NOMBRE`; salida 0 comprobación satisfecha, 1 discrepancia, 2 faltan datos/cobertura. Solo lectura. Manifest JSON `{version:1,cases:[{name,capability,evidence,expected_state,actual_state,rc,checks:[{path,contains?,not_contains?,sha256?}]}]}`; rutas relativas al manifest o absolutas. Los estados aportados deben contrastarse con metadata/evidencia, no validarse solo contra sí mismos.

- [ ] Leer spec, traspaso, contratos completos de todas las hojas y estado git antes de editar; registrar lista de capacidades del diseño y hashes de fuentes/configuración/evidencia existente en local, sin volcar valores secretos al terminal.
- [ ] Leer localmente targets.txt, scope.yaml y .session; crear mapa de objetivos explícitos, puertos, solicitudes capturadas y herramientas disponibles sin sincronizar claves ni alterar configuración. Wildcards/CIDR no se expanden por conjetura: requieren una entrada concreta para cada ejecución.
- [ ] Enumerar comandos reales por capacidad a partir de la CLI actual; marcar datos ausentes — DC/dominio, fichero HTTP, tabla, LHOST/LPORT, interfaz — y pedirlos cuando sean necesarios. Esto no elimina la capacidad.
- [ ] Registrar una reproducción real de un defecto disponible sin sobrescribir pruebas anteriores; si la hoja actual truncaría evidencias, conservarlas antes o posponer la reproducción hasta corregir la escritura. Guardar esperado/observado y rc. No ejecutar 99.
- [ ] Implementar verificador de lectura con validación de schema/rutas, comprobación de archivos y estados; `assert case.actual_state == case.expected_state` solo después de obtener actual de evidencia verificable. Ausencia de un positivo no permite fabricar un fallo ni afirmar cobertura.
- [ ] Ejecutar el verificador contra la reproducción: esperar 1 si el defecto se reprodujo, 2 si faltan datos. Añadir hash del árbol de evidencias antes/después para demostrar que el verificador no escribe.
- [ ] Commit explícito del verificador y del diseño/plan; nunca añadir manifest, objetivos o configuración real.

### Tarea 2: Captura por ejecución y evidencia fiable

**Files:** crear `00_Config/lib/exploitation_runtime.bash`, `exploitation_evidence.py`; ampliar casos privados de tarea 1.

**Interfaces:** `exploit_init TOOL HOST PORT [URL]` → 0/1 y `EXPLOIT_RUN_DIR`, `EXPLOIT_FAILED=0`; `exploit_capture NAME COMMAND [ARGS...]` → rc real y `EXPLOIT_RC`, archivos NAME.stdout/NAME.stderr; `exploit_publish NAME KIND` → estado por stdout; `exploit_finish` → 0 sin operaciones indeterminadas, 1 con errores. Python `classify(kind: str, output: str, error: str, rc: int) -> str`; `read_run(path: Path) -> dict`; `show_results(root: Path, host: str = '') -> None`.

- [ ] Comprobar con evidencia real disponible que una ejecución fallida posterior no aparece como éxito actual; registrar aserto `latest.state != 'CONFIRMADO'` para ese caso y referencias a ambas ejecuciones.
- [ ] Crear ejecuciones exclusivas con mktemp dentro de `<repo>/scans/<tool>/exploitation_<host-port-hash>_<id>/`; permisos privados para solicitudes, credenciales y salidas sensibles. No cambiar permisos globales del operador.
- [ ] Implementar captura sin introducir timeout/rate/attempt limit; preservar stdout, stderr, rc y señales. No envolver una pipeline que oculte el rc: capturar binario y mostrar después o recoger PIPESTATUS inmediatamente.
- [ ] Publicar metadata version=1 con host, puerto, url, herramienta, fecha, estado, rc y `module='05'`, `run_id`; estados del enum existente. Manifiesto de ejecución con pasos y completitud; publicación atómica. Inicio/interrupción debe quedar NO_DETERMINADO, nunca heredar un éxito.
- [ ] Seleccionar última ejecución por destino/herramienta usando metadata, incluyendo fallidas; cada ejecución guarda todos sus artefactos. Dos instancias generan directorios distintos; registrar comprobación sin lanzar ataques duplicados, invocando solo init/capture con comandos locales inocuos.
- [ ] Ejecutar comprobaciones del verificador, bash -n con stderr vacío y compilación Python sin escribir pyc en fuentes. Commit explícito de ambos archivos.

### Tarea 3: MySQL, PostgreSQL y Redis

**Files:** modificar `05_Exploitation/database/{mysql_attack,postgres_attack,redis_attack}.sh`; clasificaciones en `exploitation_evidence.py`.

**Interfaces:** CLI histórica `<TARGET> [PUERTO]`; runtime de tarea 2; clasificadores `mysql_version`, `postgres_version`, `redis_info`, `redis_keys`, `redis_config`.

- [ ] Registrar esperado/observado con conexiones reales disponibles: rechazo no es acceso; salida vacía no confirma ni descarta credenciales; ejecución B no usa credenciales de A. Si no hay caso real para una rama, marcar pendiente, no introducir fixture.
- [ ] Mantener literalmente todas las entradas CREDENTIALS y consultas. MySQL: `--no-defaults` en posición correcta, contraseña vacía explícita sin prompt; PostgreSQL: neutralizar PGHOSTADDR/PGSERVICE/PGPASSFILE y demás defaults que cambien el destino/credencial declarados, seleccionando base explícita compatible con consulta. No cambiar configuración del HOME.
- [ ] Asociar credencial encontrada a variable del run actual y éxito verificable de SELECT version(); no leer ficheros históricos para decidir enumeración. Credenciales en archivo privado, no informe general. Conservar enumeración y searchsploit actuales.
- [ ] Analizar respuestas RESP de Redis; NOAUTH/NOPERM/ERR nunca son acceso. Ejecutar y clasificar INFO/KEYS */CONFIG GET * conservando comportamiento funcional, sin añadir operaciones modificadoras.
- [ ] Repetir validaciones reales aplicables y comprobar versión/denegación contra respuestas guardadas, rc, host y puerto correctos. Registrar lo no probado. Commit de archivos explícitos.

### Tarea 4: Web y peticiones capturadas

**Files:** modificar `05_Exploitation/web/{web_attack,sql_injection,xss}.sh`; integrar `http_inject.sh`, `sqlmap_request.sh`, `rate_limit_probe.sh` solo donde sea necesario para conservación de evidencia; `exploitation_evidence.py`.

**Interfaces:** mantener host/puerto/ruta; añadir `--url URL` a las tres hojas históricas sin reinterpretar argumentos antiguos. Metadata común de tarea 2. Las tres hojas de captura mantienen exactamente CLI y variables actuales.

- [ ] Registrar con solicitudes/respuestas reales los casos disponibles de eco/alert preexistente, baseline estable y fallo de transporte; asertos: no XSS confirmado solo por palabra alert, no SQLi confirmado solo por tamaño/código, no catch-all como hit ffuf.
- [ ] Implementar URL explícita con parsing estándar y conservación de query, ruta, TLS/puerto; mantener todos los PARAMS/PAYLOADS y sqlmap actual. Codificar valores correctamente y conservar query existente al añadir parámetros.
- [ ] Capturar baseline y respuestas con código/rc real; separar diferencial SQLi, reflexión XSS y explotación confirmada. Comparar reflexión exacta con baseline, sin afirmar ejecución de navegador no observada. Contar hits ffuf desde results; conservar fuzzing y listas originales.
- [ ] Aplicar el freno HTTP ya exigido por AGENTS: 429/503 no son diferenciales, reintento con Retry-After y corte si persiste; sin modificar las guardas actuales de http_inject/rate_limit/sqlmap ni añadir límites fuera de ese contrato existente.
- [ ] Revisar almacenamiento de las tres hojas capturadas para no pisar evidencia previa; mantener contexto.txt, pares req/resp y referencias de consumidores. Preferir directorio único por run con nombres reconocidos dentro antes que copiar o reescribir peticiones con sesión.
- [ ] Validar realmente con las peticiones disponibles: http_inject, rate_limit y fases sqlmap autorizadas mediante sus permisos existentes; la tabla debe estar identificada, no elegida al azar. 429/503 o retardo solo se dan por probados si se observaron realmente; no provocar una sobrecarga artificial para obtenerlos.
- [ ] Registrar URL con query/puerto no estándar cuando exista en configuración y comprobar destino exacto. Verificador verde para casos presentes; cobertura pendiente explícita. Commit de fuentes concretas.

### Tarea 5: Red, Kerberos, CVE, plantillas, shell y WiFi

**Files:** modificar hojas bajo `05_Exploitation/network/`, `active_directory/`, `exploits/`, `custom_exploits/`, `wireless/`, `web/reverse_shell_php.sh`; conservar `payloads/`.

**Interfaces:** todas las CLI existentes; clasificadores `hydra`, `ssh_users`, `kerberos`, `connection`, `wifi_scan`; runtime sin límites añadidos.

- [ ] Registrar casos reales disponibles de fallos ocultos por tee, Hydra sin credenciales, kinit rechazado y conexiones fallidas; verificador exige rc/estado real, no presencia de archivo.
- [ ] Mantener usuarios, diccionarios, concurrencia, flags y fases originales; guardar stderr y resultados por ejecución, comprobar wordlist y dependencia legibles sin reemplazarlas por listas menores. No presentar usuario/credencial encontrado solo por existencia del output.
- [ ] Evitar que kinit use o reemplace tickets personales mediante cache exclusiva por ejecución; conservar todos sus usuarios y peticiones. No afirmar enumeración de usuario sin respuesta probatoria.
- [ ] Corregir información engañosa de CVE usando referencias oficiales de la vulnerabilidad antes de editar versión/requisitos; retirar solo afirmaciones falsas, no operaciones. Banner indica candidato no CVE confirmada; el sondeo SSH no debe abrir una shell accidentalmente como efecto de verificar banner.
- [ ] Validar LHOST/LPORT antes de generar PHP para evitar código/ruta malformados; conservar generación y muestras. Identificar reverse_shell.py como shell activa; preservar conexión/ejecución. Plantillas devuelven error real cuando falla la conexión; WiFi conserva iwlist y su necesidad de privilegios/hardware.
- [ ] Ejecutar capacidades reales con los datos disponibles; shell solo con LHOST/LPORT y receptor propios concretos, WiFi solo con interfaz identificada. No desplegar payload ni instalar/reconfigurar hardware para cubrir un caso. Guías se validan como guías, no como exploits ejecutados.
- [ ] Ejecutar verificador, sintaxis y commit de fuentes seleccionadas; no versionar payload generado ni credenciales.

### Tarea 6: Menú guiado y visor

**Files:** crear `00_Config/lib/exploitation_menu.bash`, `05_Exploitation/show_results.sh`; modificar `cyber_framework.sh` source y module_exploitation.

**Interfaces:** `exploitation_menu`, `exploitation_check_tools`, `_exploitation_read KIND DEFAULT LABEL` → dato solo por stdout/0, cancelación/1, EOF/2. Kinds host/port/url/file/interface/lhost. Reutilizar execute_script `--prepared` y lista completa; no modificar dangerous.txt para añadir bloqueos.

- [ ] Registrar navegación actual y ausencia de menú dedicado; comprobación esperada: nuevo menú ofrece todas las familias, ambos run_all y lista completa. Capturar EOF/cancelación sin invocar herramientas contra objetivos.
- [ ] Implementar orden: herramientas, web capturada, web URL/host, SSH/FTP, DB, Kerberos, CVE, payload/shell, WiFi, plantillas, flujos completos, resultados, lista completa, volver. Submenús no suprimen ninguna entrada.
- [ ] Mostrar aviso exacto del spec sin nueva pregunta de permiso. Conservar confirmaciones existentes de execute_script, no autorizar automáticamente permisos sqlmap ni usar SI=1 por defecto.
- [ ] Leer parámetros por semántica; fichero/LHOST/interfaz sin default tomado del objetivo remoto; conservar espacios con arrays. Mantener CLI manual para flags avanzados y listas originales.
- [ ] Implementar visor basado en show_results del módulo nuevo: filtrar host/puerto/URL, mostrar intento actual/historial/no atribuible y ocultar secretos por defecto sin borrar evidencia privada.
- [ ] Comprobar navegación real del gestor con entrada manual: entrar/salir, EOF, archivos con espacios, 0/! y lista completa no producen tráfico. Ejecutar una elección real aplicable con configuración del usuario y verificar argumentos/destino en evidencia. Commit concreto.

### Tarea 7: Flujos completos e integración de informes

**Files:** modificar ambos `05_Exploitation/run_all_*.sh`; `11_Reports/lib/{sources,engine}.py`; crear `11_Reports/lib/parsers/exploitation.py`.

**Interfaces:** run_all `<TARGET>` intacto, conserva fases/puertos; rc 0 evaluación completada sin errores, 1 fallo o nada evaluable. Parser `parse(path: Path, scans_dir: Path) -> ParseResult`, registro kind `exploitation`; discovery usa metadata module=05 y selecciona último run por destino/herramienta antes de parsear. Históricos siguen accesibles al visor.

- [ ] Registrar antes/después con objetivos reales disponibles: hijo fallido o discovery fallido no imprime éxito global; archivo anterior no se usa para inventar puerto abierto.
- [ ] Autolocalizar run_all; preservar exactamente familias y puertos, sin añadir explotación nueva ni suprimir ninguna fase. Descubrimiento actual con salida nueva; cerrados/filtrados no equivalen a fallo DNS. Registrar conteos ejecutadas/fallidas/omitidas sin limitar hijos.
- [ ] Integrar nuevos directorios con sources; priorizar archivos canónicos de cada paso y no parsear duplicados raw/stdout. Última ejecución fallida/denegada no hace revivir la anterior como actual. Metadata inválida implica no evaluable, no fallback a nombre histórico.
- [ ] Parser conserva distinción hallazgo, diferencial, reflexión, guía y no evaluado; no incluir claves, contraseñas, cuerpos de sesiones ni filas volcadas en informes generales. Mantener parsers y formatos capturados compatibles donde ya funcionan.
- [ ] Ejecutar ambos flujos reales solo cuando la matriz privada tenga sus datos y dependencias; no usar 99 ni convertirlo en smoke test. Recoger efectos y rc por hijo.
- [ ] Generar informes con report_engine.py sobre evidencia real hacia salida nueva; comprobar atribución, no duplicados, no secretos y no positivos de errores. Verificador verde en casos efectivamente presentes; commit explícito.

### Tarea 8: Revisión final, documentación y cobertura demostrada

**Files:** `05_Exploitation/README.md`, `docs/MANUAL-GESTOR.md`, nuevo `docs/EXPLOTACION-2026-11-10.md`; manifest local de validación.

- [ ] Completar matriz inventario → archivo/entrada CLI → operación → ejecución real → evidencia → resultado; marcar no validado por falta de dato/servicio/hardware sin confundirlo con retirada de función.
- [ ] Comprobar que ninguna lista de usuarios, CREDENTIALS, PARAMS/PAYLOADS, flags de concurrencia, puertos de flujos ni consultas se redujo y no existen topes nuevos. Comparar con snapshot de tarea 1; revisar individualmente cualquier diferencia funcional.
- [ ] Repetir validaciones reales afectadas por cambios posteriores, no ataques completos por rutina. Ejecutar verificador sobre cada caso documentado. Comprobar hashes de configuración y evidencia previa; cualquier diferencia inesperada se investiga antes de declarar cierre.
- [ ] Ejecutar bash -n de fuentes cambiadas capturando stderr; compilar Python con salida pyc fuera del árbol de fuentes; git diff --check. Opcionalmente ejecutar suites previas solo en clon limpio, sin configuración/secretos/evidencias reales y sin presentar eso como validación real.
- [ ] Revisión final independiente de preservación funcional, protocolo, evidencia y privacidad, usando skill requesting-code-review; no entregar objetivos secretos al revisor. Corregir discrepancias y repetir comprobaciones pertinentes.
- [ ] Documentar aviso, cada herramienta real, permisos actuales y cobertura/pendientes. Sustituir referencias inexistentes por instrucciones correctas sin afirmar nuevas capacidades ni éxitos no medidos.
- [ ] Commit explícito de documentación/fuentes finales. Confirmar scope.yaml fuera de commits, datos ignorados y ausencia de push; cierre distingue implementación, comprobaciones reales superadas y capacidades todavía no verificadas.

## Autorrevisión del plan

- Cobertura: inventario tarea 1/8; no recortes tarea 8; runtime/evidencia tarea 2; DB tarea 3; web y controles existentes tarea 4; resto de familias tarea 5; interfaz tarea 6; automatización/informes tarea 7; validación real transversal y cierre tarea 8.
- Interfaces: las hojas consumen exclusivamente exploit_* de tarea 2; visor consume show_results; informes consumen metadata version=1/module=05; verificador solo lee manifest/evidencia real.
- Casos Review Focus asignados: defaults DB tarea 3; URL tarea 4; simultaneidad/histórico tarea 2; semántica/EOF tarea 6; señales/pipeline tareas 2/5.
- No se exige resultado positivo vulnerable como aceptación ni se finge prueba de una rama no observada. Si faltan datos concretos, se solicita ese dato durante ejecución y se mantiene la capacidad disponible.
