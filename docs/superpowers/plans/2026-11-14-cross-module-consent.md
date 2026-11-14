# Consentimiento local y Burp — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Corregir S-I1/S-I3 y sus efectos adyacentes sin ejecutar operaciones reales durante desarrollo.

**Architecture:** Frontends públicos Bash estables delegan políticas/operaciones locales en un paquete privado Python. El aislador existente recibe una selección cerrada independiente para estos casos; no se mezcla con discovery09 ni con los25grants históricos.

**Tech Stack:** Bash, Python3, unittest, Bubblewrap/seccomp/Landlock existentes, dobles de backend.

**Spec:** `docs/superpowers/specs/2026-11-14-cross-module-corrections-design.md` §§1–6,12–14.

## Global Constraints

- «No push ni mergeadevelop sin petición expresa posterior.»
- «Pruebas SOLO en copias allowlist, HOME/sesión/config/wordlists/salidas sintéticos, PATHcerrado y dobles obligatorios de backend/red/GUI/sudo.»
- «Fuentes RO y scratch nuevo por caso. Sin fallback, `--unsafe`, suiteglobal ni discoverydeotrosrunners por comodidad.»
- «Preservar fixturesfinales, fuentes, recibos/logs y todos los runsanteriores.»
- «Nunca ejecutar cleanup, descarga/linpeas, PSExec, capturaBurp o loginreal como smoke.»
- Ninguna prueba/helper/import del repo, launcher o probe se ejecuta en host antes de revisión estática y autorización exacta del controlador. Scripts de bookkeeping de skills y AST/JSON/Git como datos no son ejecución de producto.
- No instalación, sudo, GUI, red o datos reales. La aprobación de este plan no autoriza operaciones reales.

## Review Focus

- `--help`, argumento desconocido o EOF en cleaner: ninguna apertura destructiva, incluso si sudo no requiere contraseña; Task2.
- Puerto ocupado por un proceso ajeno: no afirmar captura ni señalar ese PID; Task3.
- Recibo legacy/forjado o PID reutilizado: parar falla cerrado; Task3.
- Perfil nuevo intenta reclamar un grant09 o cambiar su caseID: bloquear antes del fork; Task1.
- Cancelar menú conservando sesión remota: no convertirla en autorización para actuar localmente; Task4.

## Interfaces, archivos y verificación

Rutas relativas a `CyberSecurity-Framework/` salvo `docs/`.

| Unidad | Archivos / responsabilidad |
|---|---|
| Selección nueva | Crear `tests/cross_module_selection.py`, `cross_module_cases.json`, `cross_module_fixture.py`, `test_cross_consent.py`; mapas cerrados, permisos y fixtures |
| Entrada/worker | Modificar `tests/automation_sandbox_{launch,inside}.py`, `automation_{suite_selection,case_worker,case_scope}.py` y contratos afectados; preservar aislamiento |
| Fuentes/runtime | Modificar manifiestos exactos `automation_sandbox_{sources,manifest}.json`; copiar solo fuentes existentes y utilidades necesarias |
| Políticas locales | Crear `00_Config/lib/consent/{__init__,files,cleanup,cleanup_cli,burp,burp_cli}.py`; sin descubrimiento como herramientas |
| Frontends | Modificar `06_PostExploitation/cleanup/logs_cleaner.sh`, `03_Scanners/web_scanners/burpsuite/burp_launcher.sh` |
| Menús/guías | Modificar `00_Config/lib/{scanners,postexploitation}_menu.bash`, guías03/06, `docs/MENU-OPCIONES.md` y manual |

Nuevo comando previsto: `python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --cross-consent`.
Es una selección fija, no una API para ejecutar comandos. Cada RED/GREEN requiere revisión/gate de ese SHA y autorización separada del controlador. Regresión09: mismo launcher con `--suite`, también autorizado por separado.

## Solicitud específica de descartables sintéticos

Se propone autorizar SOLO los siguientes nueve IDs, exclusivamente sobre objetos NUEVOS de su scratch Landlock verificado. No se modifica `automation_preservation_cases.json` ni sus25IDs. No autoriza destruir `/source`, `/evidence`, datos reales ni runs anteriores; los árboles finales y logs se conservan.

Prefijo común: `test_cross_consent.ConsentTests.`

| Sufijo de ID | Operaciones observadas / límites |
|---|---|
| `test_cleanup_nonexecution_is_inert` | Fixture/HOME nuevos para descubrir escrituras indebidas del cleaner antiguo |
| `test_cleanup_requires_both_flags` | Consentimiento y argumentos inválidos; nunca sudo real |
| `test_cleanup_local_plan_and_partial_failure` | Operaciones mediante adaptador simulado y ficheros nuevos sintéticos |
| `test_cleanup_refuses_links` | Enlaces/metadata dentro del caso; ningún referente real |
| `test_burp_open_is_not_network_consent` | GUI/ss/curl/sleep dobles, fuente y estado nuevos |
| `test_burp_status_has_no_side_effects` | Estado ausente/legacy sin escrituras ni sockets |
| `test_burp_verify_explicit_url` | Curl doble captura argv; nunca conexión |
| `test_burp_stop_pins_owned_identity` | Solo hijo sintético propio/pidfd; ningún PID ajeno |
| `test_menu_cancel_and_coordinator_exclusions` | Frontends/coordinadores sustituidos por registradores inertes |

Permiso propuesto, pendiente de confirmación explícita junto al plan. Sin ese permiso los casos que lo requieran quedan BLOCKED-preservation; no se amplía por conveniencia ni se declara verde un subconjunto.

### Task 1: Preparar selección cerrada y regresiones antes de producción

**Files:** unidad selección/entrada/worker/fuentes/runtime y tests de la tabla anterior; tests existentes del aislador afectados por su contrato.

**Interfaces:**
- `cross_module_selection.group_cases(selector: str) -> tuple[str, ...]`: solo `--cross-consent` y lista exacta de IDs, sin glob/discovery arbitrario.
- `cross_module_selection.group_grants(selector: str) -> frozenset[str]`: IDs autorizados de ese grupo, no unión universal.
- `automation_sandbox_inside.validated_selection() -> str | None`: selector fijado en memoria por el controlador tras validación/probes, no por entorno o argumentos de un test.
- `automation_suite_selection.case_disposable_allowed(case_id: str) -> bool`: exige controlador/selección genuinos; para09 conserva el inventario25; para cross exige pertenencia exacta al grupo. Worker y scope comprueban la misma decisión.
- `CrossModuleFixture(group: str)` expone `repo`, `framework`, `home`, `bin`, `records()` y `run_leaf(relative, args=(), stdin='')`; copia fuentes exactas, sin fallback al host ni finalizadores de borrado.

Contratos nuevos en `test_automation_sandbox_boundary.SandboxBoundaryTests`, todos sin permiso destructivo: `test_cross_selector_is_closed`, `test_cross_grants_are_selection_bound`, `test_cross_root_and_protected_paths_remain_blocked`, `test_suite_excludes_cross_modules`. Se ejecutan por UNIT_MODULES, con dobles para identidad/controlador; no fork, syscalls de aislamiento ni sondas adicionales. Estos cuatroIDs también se incluyen en la revisión estática de selección.

Contrato común de todas las selecciones cross: ejecutar primero UNIT_MODULES; cargar después únicamente los IDs completos del mapa del grupo, comprobar igualdad entre IDs cargados/esperados y permisos exactos antes de fork. ImportError, test ausente, duplicado o selección vacía son FAIL/BLOCKED explícito, nunca PASS por omisión. Cada caso va por el worker existente y `selection_outcome`; recibos propios sin colisión con suite/races. Cada bloque escribe TODOS sus métodos antes del primer RED, aunque los helpers productivos se creen por tareas. Los fallos de tareas posteriores siguen visibles hasta el cierre del bloque.

- [ ] Escribir primero los cuatro contratos de selección/permisos enumerados: selector desconocido, caso/grant cruzado, ID cambiado, raíz sustituida y mutación de `/source`/`/evidence` se rechazan; `--suite` sigue usando exactamente sus25grants y no descubre `test_cross_*`.
- [ ] Escribir los nueve métodos de `ConsentTests` con importaciones de helpers propuestos dentro de métodos para permitir RED por código ausente. Casos precisos en Tasks2–4; expectativas literales, no calculadas con el productor.
- [ ] Crear fixture y mapas cerrados; no copiar scope/targets/.session reales. Añadir fuentes de producción nuevas al manifiesto solo cuando existan en su tarea, nunca placeholders ejecutables.
- [ ] Extender host/inside/worker al único selector nuevo y permiso ligado a selección validada; reutilizar supervisión, probes, recibos, seccomp y Landlock sin otro supervisor ni nestedbwrap.
- [ ] Añadir runtime ordinario necesario: `/usr/bin/mawk` como `/usr/bin/awk`, `/usr/bin/cut`, `/usr/bin/seq`, `/usr/bin/sleep`, `/usr/bin/tee`. Validar archivos regulares/procedencia y cierre ELF estático; si falta alguno, BLOCKED, sin instalación. Nunca añadir curl/ss/sudo/burpsuite reales.
- [ ] Mantener presupuestos actuales: host900s, pruebas de frontera10s, selección600s, caso60s y cargaNPROC256; perfiles nuevos no reciben más privilegios o montajes.
- [ ] Revisión estática independiente del conjunto completo antes de cualquier preparación/lanzamiento. Pruebas de infraestructura escritas primero, ejecución diferida por este gate; no inventar un RED previo de la barrera.
- [ ] Controlador autoriza comandos exactos: primero `--suite` para verificar regresión del aislador; después `--cross-consent` para observar RED funcional. Expected: infraestructura segura pasa; fallos de consentimiento/versiones nuevas quedan registrados como FAIL, no ocultos como SKIP/BLOCKED.
- [ ] Commit scoped de soporte/tests e informe con todos los IDs, fuentes, permisos y resultados reales. No marcar producción corregida.

### Task 2: Cleaner con preview y aplicación explícita local

**Files:** `consent/files.py`, `cleanup.py`, `cleanup_cli.py`, wrapper cleaner y sus cuatro casos ya escritos.

**Interfaces:**
- `plan_cleanup(home: Path) -> tuple[CleanupOperation, ...]`, dataclass inmutable con `kind: str`, `path: Path | None`: cuatro logs fijos, historial de usuario, limpieza de memoria del hijo y snapshot de accesos; no efectos al planificar.
- `apply_cleanup(plan, report_root: Path, ops: CleanupOps) -> CleanupResult`: frontera de operaciones real por defecto; tests sustituyen transporte/operaciones, no la lógica de consentimiento ni de resultados. Resultado contiene rc y resultado por operación.
- CLI pública: sin argumentos/`--preview`; `--help`; aplicar `--execute` y confirmaciónTTY específica o `--confirm-local-cleanup` en modo no interactivo. Opciones incompatibles/desconocidas: rc2 antes de efectos.

- [ ] Comprobar RED de cada uno de los cuatro casos sobre el frontend antiguo en la copia confinada, con HOME nuevo y sudo/last dobles; conservar sentinelas/recibos, nunca ejecutar cleaner en host.
- [ ] `test_cleanup_nonexecution_is_inert`: variantes `[]`, `--preview`, `--help`, `--estado`, `--parar`, desconocida, EOF/no; ninguna operación ni creación previa. Los tres argumentos no soportados retornan2, preview/ayuda0.
- [ ] `test_cleanup_requires_both_flags`: `--execute` sin consentimiento retorna2; el flag de consentimiento solo retorna2; ambos seleccionan exclusivamente plan local, sin sesión remota y sin heredar una variable global de permiso.
- [ ] `test_cleanup_local_plan_and_partial_failure`: adaptador que registra cuatro rutas fijas y operaciones de historial/snapshot; un fallo devuelve1 con resultado parcial veraz, sin éxito completo ni stderr descartado. Operaciones reales de core se ejercitan sobre ficheros sintéticos equivalentes, no `/var/log` del host.
- [ ] `test_cleanup_refuses_links`: log/historial enlace, directorio u objeto especial se rechaza antes de operación. No leer cuerpos reales ni seguir referentes.
- [ ] Implementar CLI/core y helpers de archivos con no-follow, archivos nuevos0600/directorios0700. Snapshot exclusivo bajo `<repo>/scans/cleanup/<uuid>/`; no escribir ni retirar `/tmp/last_access.txt`. `history -c` solo se refiere a un Bash hijo y nunca se presenta como limpieza de memoria del shell padre.
- [ ] Dejar wrappers estables sin entrada automática destructiva, sin flags de test/override de destinos del sistema accesibles por CLI o entorno.
- [ ] Static review+gate del SHA; comando exacto `--cross-consent` autorizado por controlador. Expected: cuatro casos cleanup GREEN; fallos Burp/UI no implementados siguen explícitos.
- [ ] Commit y reporte RED→GREEN de casos cleanup; mantener artefactos.

### Task 3: Burp separar apertura, observación, verificación y parada

**Files:** `consent/burp.py`, `burp_cli.py`, wrapper Burp y cinco casos Burp/UI pertinentes.

**Interfaces/CLI:**
- `[puerto]` conserva aperturaGUI; `--help`, `--estado [--instance ID]` observan sin escritura/conexión.
- `--verificar URL --proxy-port N --execute --confirm-network` para verificación explícita no interactiva; enTTY consentimiento específico puede sustituir el último flag.
- `--parar --instance ID --execute` solo para una instancia administrativa propia. ID=`burp-`+32hex; sin ID se admite únicamente una instancia nueva inequívoca, nunca PIDlegacy no acreditado.
- `start_burp(framework: Path, port: int | None, ops: BurpOps) -> BurpInstance`; `observe_burp(root, instance_id, ops) -> BurpObservation`; `verify_proxy(url, port, authorized, ops) -> int`; `stop_burp(root, instance_id, ops) -> int`.

- [ ] Observar RED de apertura que invoca curl y estado que escribe usando casos existentes; nuevos CLI/helper ausentes fallan dentro de casos, no durante discovery.
- [ ] `test_burp_open_is_not_network_consent`: ss/GUI dobles simulan listener; con/sin sesión, apertura no llama curl. Mantener guía manual y asistencia GUI opcional; no prometer que la aplicación Burp completa carece de su propio tráfico.
- [ ] `test_burp_status_has_no_side_effects`: sin artefactos, legacy y falta ss: sin mkdir/escrituras/sesión registrada/socketfallback; NO_DETERMINADO cuando no pueda observar. No interpretar puerto ocupado como dueñoBurp.
- [ ] `test_burp_verify_explicit_url`: URL http/https completa sin userinfo/controles, puerto1–65535; sin ambos permisos/EOF no envía. Curl doble recibe soloGET/URL/proxy127.0.0.1:N/max-time5 de esa solicitud. No imprimir query con secretos; respuestaHTTP observada no certifica origen/captura.
- [ ] `test_burp_stop_pins_owned_identity`: recibo nuevo privado incluye pid/start_ticks/uid/boot_id y namespace de instancia. Abrir pidfd y revalidar identidad antes de TERM; esperar5s y KILL solo al mismo pidfd si sigue vivo. PIDlegacy/reutilizado/incongruente no recibe señales; falta de pidfd bloquea sin fallback por nombre/grupo.
- [ ] Guardar config/log/recibo exclusivos en `scans/burp/instances/<ID>/`; conservar archivoslegacy y recibos previos. No glob de HTML/outputs ni adopción del primer PID. No afirmar control de procesos que daemonizan/escapan.
- [ ] Static review+gate; controlador autoriza exacto `--cross-consent`. Expected: casos Burp GREEN, sin backend/GUI/red real. Integración de menú pendiente queda explícita hasta Task4.
- [ ] Commit y reporte, sin certificar compatibilidad operacional de Burp.

### Task 4: Integrar menús, documentar y cerrar el bloque

**Files:** menús03/06, guías03/06/manual/MENU, tests de interfaz y contratos afectados09.

**Interfaces:**03.4 sigue aperturaGUI; nueva03.6 ofrece controlBurp con `03.burp.0`volver, `.1`estado, `.2`verificar, `.3`parar. Cleaner06.7 ofrece preview por defecto y selección de aplicación local, pasando flags solo tras consentimiento específico. Flujos run_all no adquieren nuevas acciones.

- [ ] Completar `test_menu_cancel_and_coordinator_exclusions`: cero/EOF/no no despachan aplicación; aceptar apertura no acepta tráfico; verificación recibe URL/puerto explícitos; cleanup advierte LOCAL y nunca usa IP de sesión como destino. Coordinadores inertes confirman exclusiones de Burp/cleanup.
- [ ] Actualizar extracción/mutaciones/filas de nuevas opciones03 y comportamiento06 sin debilitar inventario completo ni el contrato de flags por canal. Adaptar tests heredados de Burp para no depender de curl real/puertos reales; solo se ejecutan sus equivalentes seleccionados en este bloque.
- [ ] Guías separan propósito/gates/efectos y migraciónCLI; no llamar inocuo a parar ni afirmar efecto en memoria del shell padre. No ejecutar acciones excluidas para concordar con prosa vieja.
- [ ] Conciliar únicamente baselines de fuentes intencionalmente modificadas, con diff/procedencia por archivo; no refresh universal. Los25grants09 y sus tests conservan significado.
- [ ] Static review final del bloque y gate. Controlador autoriza por separado `--cross-consent` y `--suite`. Expected: selección nueva sin fallos/errores/bloqueados,09 sin regresiones; SKIPpwsh permanece explícito si no existe runtime revisado.
- [ ] Revisión independiente del bloque completo; cierre acotado con SHAs, comandos, recibos y todos los casos. No cierre global, merge ni push.

## Self-review / handoff

Cobertura:§5→Task2;§6→Task3; consumidores→Task4; seguridad§12→Task1 y todos los gates. Cinco riesgos de ReviewFocus tienen casos explícitos. Los comandos producen evidencia solo al ejecutarse después de permisos/revisión; este documento NO los ejecuta.

Plan preparado para confirmación. Método subagentes ya elegido: no volver a pedirlo. La solicitud de descartables exactos se acepta o rechaza expresamente antes de ejecutar sus casos.
