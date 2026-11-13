# Post-explotación guiada (06) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Conservar todas las capacidades de 06, registrar su ejecución y evidencia atribuible, ofrecer un menú/visor útil e integrar sus resultados fiables en informes.

**Architecture:** Seguir el contrato de 05 con biblioteca y motor de evidencia exclusivos de 06; cada operación conserva su interfaz histórica y publica metadata por ejecución bajo `scans/<herramienta>/postexploitation_<hash>_<id>/`. El menú invoca hojas explícitas, el flujo encadena solo las aptas para ejecución no interactiva, y el motor de informes descubre los runs de 06 por separado de los de 05.

**Tech Stack:** Bash, Python 3 (stdlib), `unittest`; bibliotecas existentes `scans.bash`, `session.bash`, `11_Reports/lib`.

**Spec:** `docs/superpowers/specs/2026-11-10-postexplotacion-guiada-design.md` (aprobada mediante «Continúa»; su cabecera aún dice «borrador»).

## Global Constraints

- 06 conserva sus 14 hojas y sus argumentos, consultas, diccionarios, payloads y automatizaciones; no convertir herramientas activas en guías ni retirar controles existentes.
- Aviso literal en menú y documentación: «Usar exclusivamente en objetivos autorizados y en un entorno controlado. Estas operaciones pueden modificar el sistema, crear persistencia o borrar huellas».
- Sin topes nuevos de intentos, tasas, duración o diccionarios; sin instalación ni cambio automático de privilegios. Persistencia y limpieza quedan fuera del flujo no interactivo, pero accesibles con las confirmaciones actuales.
- Evidencia privada por run bajo `<repo>/scans/<herramienta>/postexploitation_<hash>_<id>/`, atribuida a host:puerto del objetivo de sesión; `run.json` versionado con `module='06'`, metadata por paso y `errores.log`. Nunca incluir cuerpos, passwords ni claves en visor o informes.
- No ejecutar operaciones de post-explotación reales como smoke test ni `99`; tests con fuentes y herramientas inocuas en copias temporales, sin escribir scope.yaml, targets.txt, `.session` ni evidencias reales. Suites antiguas solo en clon limpio sin evidencias.
- No push ni `git add -A`; cualquier commit local solo con rutas explícitas de fuente/tests/docs y sin `scope.yaml`.

## Review Focus

1. Objetivo de sesión vacío, `host:puerto` inválido o puerto fuera de rango: avisar antes de ejecutar, sin crear run atribuible falsamente (Task 1/4 tests).
2. Salida vacía, permiso denegado con rc 0 y rc no cero/señal: no convertir existencia del archivo o eco de un comando en hallazgo (Task 1 tests).
3. Contraseña/secretos en argumentos de PSExec o loot: conservarlos en evidencia privada si procede, nunca imprimirlos en metadata, visor, resumen de flujo ni informe (Tasks 2/3/5 tests).
4. Última ejecución fallida o incompleta tras una anterior confirmada del mismo host: visor e informe no reviven el éxito histórico (Tasks 2/5 tests).
5. Herramienta ausente, fallo a mitad de la cadena o ejecución desde otro cwd: registrar diagnóstico, contabilizar fallo/omisión según proceda y continuar solo con los pasos independientes (Tasks 3/4 tests).

---

### Task 1: Runtime y clasificación de evidencia de 06

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/postexploitation_runtime.bash`
- Create: `CyberSecurity-Framework/00_Config/lib/postexploitation_evidence.py`
- Test: `CyberSecurity-Framework/tests/test_postexploitation_runtime.py`

**Interfaces:**
- Consumes: `scans_root()` de `scans.bash`; contrato de `exploitation_runtime.bash`/`exploitation_evidence.py` como referencia, sin compartir ni alterar `MODULE='05'`.
- Produces: `postexploit_init TOOL HOST PORT [URL]` → rc y `POSTEXPLOIT_RUN_DIR`; `postexploit_capture NAME CMD [ARGS...]` → rc real y `POSTEXPLOIT_RC`; `postexploit_publish NAME KIND` → estado por stdout; `postexploit_finish` → rc 0 solo para run conclusivo exitoso; `POSTEXPLOIT_FAILED`, `POSTEXPLOIT_SCANS_ROOT` para pruebas. CLI Python `init|step|publish|finish|classify|list`, con `read_run`, `classify`, `latest`, `show_results`.

- [ ] **Step 1: Write failing tests** in `test_postexploitation_runtime.py`: inicialización host/puerto y módulo 06, run privado con nombre exclusivo por ejecución y hash de destino, overrides en temporal; captura stdout/stderr/rc y señal, fallo sin herramienta; publish/finish (incluido sin pasos o incompleto), validación de inputs y kinds `suid`, `capabilities`, `cron`, `credentials`, `history`, `loot`, `screenshot`, `persistence`, `lateral`, `cleanup`, `command`. Asertar `CONFIRMADO` solo con señal probatoria del kind, `EJECUTADO` cuando una operación es concluyente sin hallazgo, `DENEGADO` ante rechazo explícito y `NO_DETERMINADO` ante fallo/eco/vacío sin prueba; metadata sin texto sensible y `rc` intacto.
- [ ] **Step 2: Run** `cd CyberSecurity-Framework && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_postexploitation_runtime.py' -v`; expect FAIL porque no existe el runtime.
- [ ] **Step 3: Implement** los dos archivos con mismas convenciones de captura atómica, permisos 700/600 y manifest `version,module,run_id,host,puerto,url,herramienta,started,fecha,estado,rc,complete,steps`; `.meta.json` incluye `kind,estado,rc,fecha`. Separar clasificación de credenciales de su contenido: evidencia confirmatoria estructural, jamás mera presencia del archivo. No modificar la biblioteca de 05.
- [ ] **Step 4: Run** el comando del Step 2; expect PASS; además `bash -n CyberSecurity-Framework/00_Config/lib/postexploitation_runtime.bash` y `python3 -B -m unittest ...` sin escritura de bytecode.
- [ ] **Step 5: Commit** únicamente estos tres archivos, con `git add <rutas explícitas>` y `git commit -m 'feat: add postexploitation evidence runtime'`.

### Task 2: Visor por objetivo y último intento

**Files:**
- Create: `CyberSecurity-Framework/06_PostExploitation/show_results.sh`
- Test: `CyberSecurity-Framework/tests/test_postexploitation_runtime.py`

**Interfaces:**
- Consumes: `postexploitation_evidence.py list --root ROOT --host HOST [--port PORT]`, `session_target`, `scans_root`.
- Produces: `show_results.sh [objetivo]`, listado solo lectura por host:puerto/herramienta con último intento e historial marcado; sin volcar cuerpos.

- [ ] **Step 1: Write failing tests** con dos hosts, dos puertos y dos runs del mismo destino (primero confirmado, último fallido/incompleto); comprobar aislamiento, estado actual, historial sin hallazgo actual, ausencia de credenciales, `cwd` externo y carpeta de resultados vacía.
- [ ] **Step 2: Run** el comando unittest de Task 1; expect FAIL al faltar visor o filtro.
- [ ] **Step 3: Implement** `show_results.sh` autolocalizado y adaptar `latest`/`show_results` de 06 a host:puerto (sin tocar el visor de 05); si no se indica objetivo, usar la sesión y distinguir `host:puerto` sin romper hosts simples.
- [ ] **Step 4: Run** el comando unittest y `bash -n CyberSecurity-Framework/06_PostExploitation/show_results.sh`; expect PASS, sin operación de red.
- [ ] **Step 5: Commit** rutas de visor, tests y motor 06 explícitas.

### Task 3: Hojas de 06 sin perder capacidades

**Files:**
- Modify: `CyberSecurity-Framework/06_PostExploitation/{privilege_escalation,credential_access,loot,persistence,lateral_movement,cleanup}/*.sh` (las 14 hojas, incluida la plantilla generadora `lateral_movement/ps_exec.sh` y `privilege_escalation/linpeas.sh`)
- Test: `CyberSecurity-Framework/tests/test_postexploitation_runtime.py`

**Interfaces:**
- Consumes: las cuatro funciones `postexploit_*` de Task 1; objetivo/puerto de sesión para atribuir ejecuciones locales, parámetros explícitos existentes para herramientas remotas. Sin alterar el contrato posicional histórico ni el efecto de las operaciones.
- Produces: captura publicable de operaciones reales con `kind` apropiado, fallos propagados y artefactos históricos preservados bajo `06_PostExploitation/loot/`/`persistence/` cuando ya existían.

- [ ] **Step 1: Write failing tests** por familias con copias en temporal y PATH cerrado (simular `find`, `getcap`, `crontab`, `ssh`, `psexec.py`, captura de pantalla, etc. sin operaciones reales): invocaciones/argumentos históricos, evidencia y rc ante éxito/ausencia/denegación, y autolocalización de `port_forward`, `ps_exec` (validar cuerpo generado, no ejecutar un PSExec real), `logs_cleaner`, `cron_persistence`, `ssh_jump`, `screenshot_collector`. Comprobar que el output no contiene password ni contenido de loot.
- [ ] **Step 2: Run** unittest de Task 1; expect FAIL por hojas sin runtime/rutas desde cwd externo.
- [ ] **Step 3: Integrate** cada hoja en el runtime, sin cambiar sus payloads, comandos, parámetros ni límites; conservar ficheros históricos de módulo, publicar evidencia aislada adicional y propagar rc real (evitar `tee` ocultando fallo). No reescribir los datos existentes; editar cuerpo de generadores en vez de ejecutar el generador contra el checkout. Para hojas locales sin host conocido, exigir atribución explícita de sesión para publicar y mantener invocación histórica sin romper su función.
- [ ] **Step 4: Run** unittest, `bash -n` sobre las 14 hojas capturando también warnings en stderr, y `git diff --check`; expect PASS y ninguna alteración de árboles reales.
- [ ] **Step 5: Commit** solo las hojas y tests modificados (paths explícitos).

### Task 4: Flujo completo y menú integrado

**Files:**
- Modify: `CyberSecurity-Framework/06_PostExploitation/run_all_post.sh`
- Modify: `CyberSecurity-Framework/00_Config/lib/postexploitation_menu.bash`
- Test: `CyberSecurity-Framework/tests/test_postexploitation_menu.py`

**Interfaces:**
- Consumes: `execute_script`/`run_module_scripts` del gestor, `session_target`, visor Task 2 y hojas Task 3.
- Produces: `run_all_post.sh <TARGET>` autolocalizado, resumen `Ejecutadas/Fallidas/Omitidas` y rc 1 si hay fallos; menú 06 con comprobación local, categorías, flujo, visor, lista completa 9+ y aviso literal.

- [ ] **Step 1: Write failing tests** con gestor copiado a temporal, sesión sintética y comandos simulados: entrar en 06 no ejecuta herramientas, 1 solo comprobación local, 2–7 conservan entradas y confirmaciones, 8 pasa TARGET, visor muestra último intento, 9+ lista completa. Para `run_all_post.sh`, verificar ocho hojas sin argumentos (`linpeas`, `suid_check`, `capabilities_check`, `cron_check`, `linux_creds`, `history_parser`, `file_collector`, `screenshot_collector`); screenshot se omite justificadamente si falta entorno gráfico o dependencia. Las de movimiento lateral requieren parámetros/credenciales y se omiten; persistencia y limpieza nunca se lanzan. Comprobar conteos de ejecución/fallo/omisión, stderr anexado a `errores.log`, invocación desde cwd externo, falta/validez TARGET y ausencia de timeout nuevo.
- [ ] **Step 2: Run** `cd CyberSecurity-Framework && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_postexploitation_menu.py' -v`; expect FAIL.
- [ ] **Step 3: Implement** el flujo manteniendo explícitas todas las hojas encadenables sin parámetros, y la navegación existente añadiendo visor sin perder 9+; pasar objetivo de sesión a hijos por variable de entorno de runtime, sin inventar argumentos para hojas históricamente sin parámetros. Avisar de omisiones reales; log de stderr en salida privada, sin imprimir secretos.
- [ ] **Step 4: Run** unittest, `bash -n` de ambos scripts (capturar stderr), `git diff --check`; expect PASS.
- [ ] **Step 5: Commit** rutas explícitas de Task 4.

### Task 5: Descubrimiento, parser y catálogo de informes

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/postexploitation.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/catalog.py`
- Test: `CyberSecurity-Framework/tests/test_postexploitation_reports.py`

**Interfaces:**
- Consumes: `run.json`/`<name>.meta.json` de Task 1 y `ParseResult`, `Evidence`, `build`, `register` existentes.
- Produces: fuente `postexploitation` para `scans/<tool>/postexploitation_*/run.json`; reglas `postexploitation.hallazgo`, `postexploitation.ejecutado`, `postexploitation.denegado` con textos y severidades acordes a resultado operativo, no vulnerabilidad implícita.

- [ ] **Step 1: Write failing tests** sobre scans sintéticos: descubrimiento del run 06 sin confundirlo con 05; validación de módulo, versión, host, puerto, `complete`, steps, sidecars y rc concordantes; `CONFIRMADO` con prueba → hallazgo sin secreto, `EJECUTADO` → registro informativo, `DENEGADO` → registro de denegación, fallos/incompletos/malformed → no evaluable; selección del último por host+puerto+herramienta aun si falló, con 05 y 06 coexistiendo.
- [ ] **Step 2: Run** `cd CyberSecurity-Framework && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_postexploitation_reports.py' -v`; expect FAIL.
- [ ] **Step 3: Implement** parser sin leer cuerpos; ampliar `_PARSER_MODULES`, `_classify` y selección de última fuente en `sources.py` sin alterar semántica de 05; registrar tres reglas y familia en `catalog.py`. No usar estado de `run.json` como hallazgo si faltan pasos/sidecars fiables.
- [ ] **Step 4: Run** unittest nuevo y `cd CyberSecurity-Framework && PYTHONDONTWRITEBYTECODE=1 bash tests/run_reports.sh` en clon temporal limpio; expect PASS, sin evidencias reales.
- [ ] **Step 5: Commit** solo parser, sources, catálogo y tests explícitos.

### Task 6: Verificador aislado, suite y guías de uso

**Files:**
- Create: `CyberSecurity-Framework/tests/run_postexploitation.sh`
- Create: `CyberSecurity-Framework/tests/test_postexploitation_verify.py`
- Create: `CyberSecurity-Framework/tests/verify_postexploitation_real.py`
- Modify: `CyberSecurity-Framework/06_PostExploitation/README.md`
- Create: `docs/POSTEXPLOTACION-GUIADA-2026-11-10.md`

**Interfaces:**
- Consumes: contratos de runtime, visor, menú y parser; referencia `tests/run_exploitation.sh`, `tests/verify_exploitation_real.py` (verificador de solo lectura, casos sintéticos).
- Produces: `bash CyberSecurity-Framework/tests/run_postexploitation.sh` (guardas de fuentes/config/sesión y descubrimiento de `test_postexploitation_*.py`); `verify_postexploitation_real.py MANIFEST --case NAME` solo lectura, códigos 0 satisfecho / 1 discrepancia / 2 faltan datos.

- [ ] **Step 1: Write failing tests** en `test_postexploitation_verify.py`: contrastar estado y rc declarados con `run.json`/sidecar, formato/versión/caso desconocido, checks `contains`, `not_contains`, `sha256`, rutas relativas al manifest, nunca escritura; guardas hash+modo de `scope.yaml`, `targets.txt`, `.session`, hojas 06, bibliotecas 06 y evidencia real antes/después de suite.
- [ ] **Step 2: Run** unittest de verify; expect FAIL por verificador ausente.
- [ ] **Step 3: Implement** verificador de solo lectura y suite; documentar aviso literal, métodos de ejecución, evidencia por host:puerto, omisiones/confirmaciones, límites de la clasificación, fallos, y prueba sintética frente a validación operacional real. Documentar síntomas/causas/fixes y evidencia realmente observada, sin afirmar escaneos no realizados.
- [ ] **Step 4: Run** suite nueva en copia aislada con `PYTHONDONTWRITEBYTECODE=1`, `bash -n` de fuentes modificadas con stderr comprobado, `python3 -B -m unittest discover -s tests -p 'test_postexploitation_*.py' -v` y `git diff --check`; expect PASS. Si se requiere regresión antigua, clon temporal limpio excluyendo scope/credenciales/sesión/scans/loot, nunca el checkout con evidencias.
- [ ] **Step 5: Commit** rutas explícitas de tests y docs, sin datos de objetivos ni push.

## Final verification and handoff

- Revisar inventario de 14 hojas y que la opción 9+ sigue accesible; comprobar permisos y diffs antes de cualquier commit.
- Ejecutar suites nuevas con configuración aislada; ejecutar regresión antigua exclusivamente en clon limpio sin evidencias reales, sin iniciar herramientas activas ni flujo `99`.
- Confirmar metadata `module='06'`, atribución host:puerto, selección último intento e informes sin secretos; registrar qué pruebas sintéticas se ejecutaron y qué validación operacional quedó pendiente.
