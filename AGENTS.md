# AGENTS.md

**Herramientas adicionales en la tecla `D`, 2026-11-18 — integrado en
`develop` (revisión de código aplicada), sin push:** la opción `2` del menú de
`D` instala/verifica `ollama` (+ catálogo de 4 modelos con guardrail de
recursos: General, Qwen2.5-Coder oficial recomendado, Foundation-Sec-8B-
Instruct de Cisco, DeepHat/WhiteRabbitNeo sin censura con aviso), `avml`
(con token de GitHub opcional) y `nmap-vulners`; cada una con su propia
confirmación literal (`OLLAMA_SI`/`AVML_SI`/`NMAP_VULNERS_SI`,
`CONTINUAR_IGUAL` para forzar el guardrail de recursos). `lime` y
`volatility` (v2) siguen solo informativos, sin cambios — `lime` cruzaría la
decisión ya tomada en 08_Forensics de nunca cargar un módulo de kernel por
cuenta propia, y `volatility` (v2) está descontinuado a favor de
`volatility3`. De paso se corrigió un hallazgo de investigación: la ruta por
defecto de `nmap-vulners` comprobaba `nmap-vulners.nse`, que no es el nombre
real del script del proyecto (`vulners.nse`) — con el nombre antiguo la
detección nunca habría reconocido una instalación hecha por el método
oficial. Nuevo fichero `00_Config/lib/dependencies_models.bash`.
`code-review high` sobre la rama no encontró hallazgos críticos; dos huecos
de cobertura importantes (Review Focus del plan: `avml` ya instalado no debía
reinstalar, y las dos ramas de fallo de la instalación de `ollama` no debían
ofrecer el catálogo) se corrigieron con TDD antes de este merge, más un nit
de estilo (`sudo nmap --script-updatedb` ya no descarta su `stderr`) y una
inconsistencia del spec de diseño (comando de token de GitHub obsoleto).
`tests/run_dependencies.sh` sube a 96 asserts (dobles de `curl`/`git`/`sudo`/
`ollama`, nunca red/sudo reales) y `tests/run_smoke.sh` cubre la opción `2`
del menú. Diseño en
`docs/superpowers/specs/2026-11-17-dependencias-herramientas-design.md`
y plan en `docs/superpowers/plans/2026-11-17-dependencias-herramientas.md`.
Ninguna instalación real se ejecutó durante el desarrollo. Merge local
`feat/dependencias-herramientas` → `develop`; sin push.

**Asistente IA local, 2026-11-17 — integrado en `develop` (revisión de código
aplicada), sin push:** tecla `I` del gestor (`00_Config/lib/ai_menu.bash`),
núcleo en `00_Config/lib/ai/`, entrada `09_Automation/ai/ai_assistant.py`, guía
`docs/ASISTENTE-IA-2026-11-17.md`. Aditivo y aislado: lee solo docs y resultados
del objetivo, excluye/redacta secretos, nunca ejecuta nada; datos en
`09_Automation/ai/data/` (ignorado por git). `code-review high` sobre la rama
encontró 9 hallazgos; 8 corregidos con TDD (dos de seguridad: deny-list de
salidas de fuerza bruta por nombre real de fichero, contraseña numérica tras
`-p` sin redactar; cinco de corrección: pérdida de turnos al guardar resumen,
excepción sin capturar en el cliente Ollama, config sin chequeo de tipos,
mensaje de `estado` mezclando dos modelos, cabecera sin refrescar disponibilidad
de Ollama en sesión; uno de integración: `ollama` ausente de la tecla `D`).
**Pendiente, NO regresión de esta rama:** la redacción de secretos solo protege
la ingestión del asistente; `report_engine.py` y el empaquetado de evidencia
(`10_Evidence/`) no redactan nada sobre los mismos datos de `scans/` — brecha
preexistente en otros módulos, sin dueño asignado todavía. Evidencia: `tests/run_ai.sh`
119 tests rc0 con guardas intactas, `tests/run_smoke.sh` y `tests/run_dependencies.sh`
(36 tests) sin fallos, con Ollama simulado. Sin validación operativa con un modelo
real (no hay Ollama instalado en esta máquina) ni ejecución de las suites antiguas.
Merge local `feat/asistente-ia-local` → `develop`; sin push.

**Rectificación del cierre local, 2026-11-15 — NO APROBADO:** la nota anterior
que declaraba Tasks1–6 completadas y revisión independiente por tarea era
prematura. La revisión final propia sobre `d89a371` encontró defectos abiertos
en gates Linpeas, preservación/rutas Labs y clasificación/IO de ping; además,
el plan de menores/conciliación global no está implementado. Los recibos
históricos PASS (local12, web7, consentimiento9, suite179 con1SKIP pwsh)
se conservan, pero no cubren estos hallazgos ni acreditan cierre global.
Ver `docs/LOCAL-ESTABILIDAD-TRANSVERSAL-2026-11-14.md` y
`.superpowers/sdd/2026-11-14-cross-module-local/final-integration-review.md`.
El usuario solicitó terminar la revisión personalmente: es revisión propia,
NO independiente. Sin nuevas ejecuciones, push, merge ni borrado de artefactos.
No cerrar Task4/Task9/global09 ni declarar compatibilidad operacional.

**Reanudación e integración hacia09, 2026-11-14:** usuario autorizó corregir
también fallos funcionales de otros módulos y el merge local de develop
`1e6d0fe` hacia el worktree09 basado en `c80da1a`; NO integración inversa ni push.
Conservar ambos históricos, logs y artefactos. La revisión semántica independiente
de130hojas/217filas está en el workspace09: detectó discrepancias pendientes,
por lo que Task9/global09 NO están cerrados. develop ya elimina el empaquetado
automático de informes; no repetir ese arreglo. Integración global de develop
documentada en `docs/INTEGRACION-PRUEBAS-GLOBALES-2026-11-14.md`: sus resultados
no verifican esta combinación. Las restricciones de pruebas aisladas y revisión
previa siguen vigentes; no ejecutar suites/helpers/probes ni herramientas reales
por completar este merge. Bloques de estados anteriores conservados como historia.

**Estado actual Task4/aislador09, 2026-11-14 — LISTO PARA REVISIÓN FINAL
INDEPENDIENTE, NO APROBACIÓN GLOBAL:** sobre1fde308 el controlador verificó
suite rc0:60sandbox units PASS y159legacy/integration,0fallos0errores1SKIP
dinámico por pwsh ausente del runtime;25casos con permiso ejecutados, workers
Landlock ABI7 observado. Carreras rc0:20recibos×8=160PASS. Cancelación externa
controlada después de race01: SIGINT130/24descendientes observados salidos y
SIGTERM143/23salidos, señal solo al launcher directo por pidfd según controlador.
Recibos: `/tmp/opencode/automation-isolated-483f2446911e4dd99e8573f69b952e8a/`,
`/tmp/opencode/automation-isolated-f3855feac6bd45d0b985542ca5cf6831/` y
`/tmp/opencode/automation-outer-cancel-a879a56f3bf748eab64f5b3395a1fbe7/`.
Runs parciales/fuentes/evidencias/logs y el incidente Nmap histórico se conservan.
Entrega documental actual NO ejecuta ni autoriza nuevos helpers/tests/probes.
Falta review final independiente/controlador: no cerrar Task4/Task9/global ni
ledger como aprobado. M1 terminal-receipt diferido; metadata/ioctl Landlock ABI3
no cubiertos, sin certificado kernel/hostil ni garantías realtime/cgroupsper-tree.
No compatibilidad Windows/Docker ni rama/suites antiguas completas verdes.
No auditoría/red/install/sudo/push/merge/cleanupglobal. Ver guía/reporteTask4.
**Los bloques fechados de seguimiento anteriores son históricos respecto a su
estado.** Las reglas generales y de seguridad siguen vigentes; ningún bloque
autoriza nuevas ejecuciones por sí solo.

**Enmienda Task4 Landlock, 2026-11-14 — ESTÁTICA NOT RUN:** usuario autorizó
descartar temporales sintéticos NUEVOS de25casos; estados intermedios run.json
son descartables, no evidencia de engagement. Worker por caso escrito con
Landlock ABI>=3, scratch nuevo fijado, registro exacto IDs y pipe/logs nuevos;
guard default sin excepción fuera de worker/caso25. ABI ausente bloquea sin
fallback. Revisión enfocada/controlador antes de helpers/tests/probes/syscalls.
Outer bwrap/seccomp/mounts/producto intactos; fuente/evidencia/logs/previos y
árboles finales preservados, fixture.close no borra. ABI3 no media chmod/xattrs/
utime: límite documentado, NO certificado kernel/hostil. Runtime histórico
ea414a9:60unit+109elegibles sin fallos,1SKIP/rc2; ni25casos ni160carreras nuevas
acreditados. Ver reporteTask4/guía; sin auditoría/install/push/merge/cleanupglobal.

**Aislador test-only09 — Task4 estática sobre367b9db, 2026-11-13:** Tasks1/2
revisadas; el controlador observó seis probes PASS/rc0 en367b9db, con
tests_started=false. Integración fixture persistente/discovery por manifiesto,
unit tests interiores y selección cerrada escrita NOT RUN, pendiente de revisión
independiente y autorización explícita ANTES de cualquier nuevo run/helper/import/
probe/suite. Listado exacto de25casos BLOCKED-preservation en
`CyberSecurity-Framework/tests/automation_preservation_cases.json`; no borrar ni
mockear cleanup/replace de producto para pasar. Wrapper ya delega al launcher
fijo (el bloque anterior es histórico), sin nested bwrap/flags arbitrarios.
Ver `docs/AUTOMATION-TEST-ISOLATION-2026-11-13.md` y ledger del aislador.
NPROC256 aplica al workload, bootstrap hereda límite host sin elevar; mapping
userns se interpreta en padre inmediato con composición VFS canary400. No cuota
cgroups por árbol ni certificado kernel. Task3 unit/cancel externo, Task4 runtime,
Task9/I1/global09 siguen pendientes. Ninguna auditoría/instalación/push/merge ni
eliminación autorizada; conservar workspace y todos los artefactos históricos.

**Task9 round1 sobre09e16c8 — NEEDS_CONTEXT / EJECUCIÓN BLOQUEADA:** revisión
estática encontró I1–I3. I1 permanece abierto: no hay aislamiento SO heredado
acreditado. Runner ahora solo printf/exit2 builtins, sin discovery/imports,
probes/hijos/fallback/env-bypass. Audithook adicional local rechaza todo Popen;
no acepta basename ni /tmp/opencode/automation-* como identidad. No ejecutar
framework/tests/negativos/pwsh/probes/backends hasta revisión estática
independiente y autorización explícita del controlador. I2 corregido (K.4
sin confirmación adicional) sin tocarK. I3 namespaces fuente/contrato y
mutaciones ampliados; pruebas hijo/nieto solo doubles sintéticos para bloqueo,
escritas SIN ejecución, no prueba de sandbox. M1 diferido. Solo AST/Bash-n/diff
en este round; ningún nuevo RED/GREEN ni conteo de pruebas. Resultados debajo
son históricos y no acreditan aislamiento ni autorizan nuevos runs. Conservar
incidente/evidencia y no cerrar Task9/global; sin instalaciones/push/merge.

**09_Automation — Task9, 2026-11-13:** documentación/runner/contratos implementados
sobre72c6a9c, pendientes de revisión independiente del controlador, NO cierre
global. `09_Automation/USE.md` explica previews/permisos y conservación;
`docs/MENU-OPCIONES.md` inventaría módulos00–13, teclas, submenús y130hojas por
fuentes; no cambiar comportamiento ajeno ni fichas-modulos. Suite09 final113tests
rc0; carreras20×8=160 rc0 bajo supervisor sintético, sin supervivientes vivos.
Regresiones solo en copia fuentes/config sintética: config19/scanners27/enum39,
reports28checks+78tests/e2e11 y explotación sin red54 verdes. Smoke solo
subconjunto23checks sin99; explotación web/run_tests/SSTI no ejecutados. Ver
`docs/AUTOMATION-2026-11-13.md` y reporte local Task9. **Incidencia del harness**:
una prueba negativa invocó Nmap real a192.0.2.1 por clasificación incorrecta de
ejecutable relativo; se comunicó, conservó evidencia y corrigió guarda más stub
de respaldo. No afirmar que toda la sesión fue exclusivamente sintética ni
operacionalmente autorizada/validada. Sin instalaciones, Docker build/up,99,
merge ni push; conservar todos los logs/workspace. Nota de próxima sesión bajo
este bloque es histórica:09 sí fue solicitado posteriormente.
**Integración local de correcciones globales cerrada, 2026-11-14:** por petición
expresa del usuario se creó `87d7ce8` y develop avanzó por fast-forward desde
`8435c05`. Premerge sintético: global520/0, runtime7/7, SSTI e informes rc0.
Posmerge desde develop en copia sintética: global520/0 en129.343s, runtime7/7,
SSTI5 métodos/7casos e informes29shell/78Python rc0. Guardas hash/modo intactas;
detalle en `docs/INTEGRACION-PRUEBAS-GLOBALES-2026-11-14.md`. scope.yaml/targets.txt y
notas locales preservados fuera del commit. La pausa siguiente es histórica,
superada por reanudación y petición expresa de merge. Conservar worktree/logs;
sin push ni iniciar otro módulo. Nunca ejecutar run_tests sobre datos reales.

**Pausa solicitada, 2026-11-14:** usuario quiere corregir fallos de la suite
global, pero primero parar y limpiar contexto. No iniciar fixes ni otro módulo
hasta reanudación expresa. Leer `docs/RETOMAR-PRUEBAS-GLOBALES-2026-11-14.md`.
Develop en8435c05,11 ya integrado; scope.yaml/targets.txt locales preservados.
Desajustes identificados de recuentos/rutas SQLi/cleanup; timeout180s sin causa
confirmada. No ejecutar run_tests en checkout con datos; copia/config/HOME
sintéticos, sin red externa. Nota/AGENTS sin commit, sin push.

**Integración local 11, 2026-11-14:** por petición expresa del usuario, los dos
bloques de informes se consolidaron en `1682fa1` y se integraron por fast-forward
en develop desde `e558207`. Posmerge desde develop:
`tests/run_reports_evidence.sh`175tests/rc0/GUARD OK; hash y modo de scope.yaml/
targets.txt locales intactos. Se conservó el plan inicial no versionado en
`/tmp/opencode/merge-reports-6di_p716/untracked-initial-plan.md` antes de incorporar
su versión actual. Evidencia y límites en `docs/INTEGRACION-11-2026-11-14.md`;
guía `11_Reports/USE.md`. Worktree, rama de informes y logs conservados; sin push.
Revisión propia, no independiente; run_tests global heredada mantiene sus cuatro
fallos observados/timeout. No declarar rama completa verde, compatibilidad
operacional universal ni custodia legal. No iniciar siguiente módulo sin petición.

**Integración local 10, 2026-11-13:** usuario confirmó merge; `develop`
avanzó por fast-forward de `3a63550` a `1979d7f` (código revisado `8518c91`,
último commit solo documentación). Verificación posmerge desde develop:
145 tests/rc0/GUARD OK; hash y modo de scope.yaml/targets.txt locales intactos.
Las notas siguientes de integración pendiente son históricas. Worktree, rama
y logs conservados; sin push. Estado detallado en
`docs/EVIDENCIAS-INTEGRAL-2026-11-13.md`. No declara rama completa verde,
compatibilidad operacional, autenticidad ni custodia legal.

**Cierre de revisión 10, 2026-11-13 (integración pendiente):** las ocho tareas
y la ola global I1/I2 tienen revisión independiente aprobada sobre `8518c91`.
Verificación del controlador: `tests/run_evidence.sh` 145 tests/rc0/GUARD OK;
9 Bash sin stderr y 18 AST Python correctos, diff sin incidencias. Cinco
regresiones sintéticas rc0 según reporte final. Evidencia de cierre en
`.superpowers/sdd/2026-11-13-evidence-integral/final-fix-review.md` y
`controller-verification.log`. No implica rama completa verde, compatibilidad
operacional ni custodia legal. Conservar worktree/logs y pendientes ajenos.
Sin push; integración en develop requiere confirmación final.

**Fixes globales 10, 2026-11-13 (re-review e integración pendientes):**
I1 corregido en `5a02c8c`: ownership acreditado antes de entregar INT/TERM,
cleanup conserva interrupción y no borra reemplazos ajenos; copia larga sigue
interrumpible. I2 en `ebc19fb`: fase reconoce `FILE:` con espacios en raíz/subárboles
de seis categorías; excluye `logs/runs` y enlaces, sin leer cuerpos ni hashes.
Fixtures legacy compartidos con inventario. Reporte/logs de esta ola en
`.superpowers/sdd/2026-11-13-evidence-integral/final-fix-report.md`.
No equivale a revisión global aprobada, integración, compatibilidad operacional,
custodia legal ni rama completa verde. Conservar workspace/logs; sin push.

**Entrega implementación 10, 2026-11-13 (pendiente revisión global/integración):**
Tasks1–7 revisadas según controlador; Task8 entregables1–6 añade runner allowlist
y guardas de fuentes permitidas (hash/modo/layout sin leer config/evidencia real),
HOME/scope/targets/session sintéticos y PATH cerrado. Suite dedicada actual:
`tests/run_evidence.sh` (142 tests). Contratos en `10_Evidence/{README,USE,FLUJO}.md`,
`docs/MANUAL-GESTOR.md` y `docs/EVIDENCIAS-INTEGRAL-2026-11-13.md`.
Tres wrappers conservados, núcleo `00_Config/lib/evidence/`: cinco tipos públicos,
SHA-256 nuevo/MD5 legacy no migrado, empaquetado bloqueante confidencial sin
cifrado, captura solo explícita y sin sudo/instalaciones. `10` no adopta TARGET;
fase done significa presencia, no integridad. `<TARGET>` antiguo retorna2 sin
adquirir: no se declara reparado99. Pruebas exclusivamente sintéticas/stubs,
no compatibilidad operacional, autenticidad ni custodia legal. Regresiones solo
en archivo git versionado con configuración/HOME sintéticos; nunca sobre este
checkout con datos. Revisión independiente e integración son gates del controlador,
no aprobados por esta nota; no declarar rama completa verde. Conservar workspace,
logs, pendientes ajenos y notas históricas; sin push ni tocar checkout original.

**Próxima sesión, 2026-11-13:** usuario pide continuar con `09_Automation`;
leer `docs/RETOMAR-09-2026-11-13.md`. No iniciar09 ahora ni asumir diseño
aprobado. 08 cerrado según bloque siguiente; preservar ledger/logs y pendientes.

**Cierre integral08, 2026-11-13:** Tasks1–8 y correcciones globales aprobadas.
I1–I4 resueltos en `25912ef`; N1 pre-GO resuelto en `278ec1b`, con revisión
independiente aprobada y verificación del controlador:296tests/rc0, Bash/AST
sin incidencias. Ocho regresiones rc0 sobre `25912ef`; último diff solo helper
y pruebas,296unittest/296runner verdes sobre `278ec1b`. Integridad corrupta
no evita cleanup autenticado tras reapear escritores,
recibos independientes `cleanup.json` no reparan ni validan análisis corrupto;
Scalpel usa imagen posicional (Foremost -i); coordinador entrega INT/TERM parent-only
por pidfd y espera hoja/cleanup sin deadline; intento offline sin identidad bloquea
ACTUAL conservadoramente, sin unir identidades. Evidencia/API/estado en
`.superpowers/sdd/2026-11-11-forensics-integral/final-fix-report.md` y
`final-fix-logs/`, `n1-fix-report.md` y `n1-fix-review.md`. Cierre de implementación
y revisión, NO compatibilidad operacional, custodia legal ni rama completa verde.
M1 Task5/Task7 permanecen DEFERRED, sin recrear históricos ni pulido. Conservar
workspace/logs, cuatro pendientes ajenos y nota histórica; sin push. No iniciar09
sin petición del usuario.

**Actualización histórica 08_Forensics, 2026-11-12:** Tasks1–7 aprobadas tras sus fixes,
base Task8 `d8967b2`; no repetir implementación. Task8 añade verificador/suite
aislada y documentación; revisiones posteriormente terminadas según cierre
2026-11-13 anterior. Guías vigentes: `08_Forensics/USE.md`
bajo el framework y `docs/FORENSE-INTEGRAL-2026-11-11.md`; ledger en
`.superpowers/sdd/2026-11-11-forensics-integral/progress.md`.
08 abre menú por fuentes explícitas, sin IP de sesión ni adquisición/instalación/
montaje por entrar. Diez entradas y métodos originales conservados; defaults
sensibles cambiaron por aprobación expresa, ver USE. Copias por analizador y
raíces privadas; verificador solo lectura no relee originales ni certifica
custodia legal o compatibilidad operacional. Pruebas solo sintéticas/stubs y
regresiones antiguas solo en copia limpia; nunca evidencia real/flujo99.
Task5 M1 logs históricos perdidos no recreados y Task7 M1 seis avisos fixture
siguen diferidos a revisión global, sin pulido fuera alcance. run_tests heredada
374/11 (SSTI intermitente sin causa determinada), no declarar rama verde.
Conservar scope/tres pendientes06, sin push ni instalaciones reales.

**Pausa histórica, superada por la reanudación — 2026-11-12 — 08_Forensics:** leer
`docs/RETOMAR-FORENSE-2026-11-12.md`. Tasks1–3 aprobadas hasta `3d3eeab`,
97 pruebas independientes rc0; Task4 PCAP/Volatility con cuatro rutas de trabajo
sin commit ni revisión aprobada al guardar. Subagente confirmó PAUSED, sin procesos
propios en curso; consultar su reporte antes de reanudar. Faltan Tasks4–8 y revisión global.
Ledger: `.superpowers/sdd/2026-11-11-forensics-integral/progress.md`.
No repetir Tasks1–3, no descartar parciales ni los cuatro pendientes ajenos,
no usar evidencia real ni suites antiguas sobre este checkout; sin push.

**Actualización mantenimiento 07, 2026-11-11:** Task 1 está en `045d2c8`.
`07` abre un menú de mantenimiento: 1 disponibilidad mediante `command -v`
(no ejecuta binarios), 2 guía local, 11 listado original de diez entradas y
0 volver; EOF retorna sin acciones. La presencia en PATH no acredita hardware,
permisos ni auditoría. `wifi_handshake.sh` imprime guía, no captura ni verifica
automáticamente. Las diez fuentes originales y los cuatro pendientes ajenos
se conservan por hash/modo; no se ejecutan hojas, radio, sudo o instalaciones.
Documentación y regresión entregadas en `7bcc5bc` y descritas en
`docs/WIRELESS-MANTENIMIENTO-2026-11-11.md`. Ambas tareas tienen revisión de
especificación y calidad aprobadas; la revisión global aprobó el cierre del
mantenimiento, entregado y revisado. Evidencia definitiva del controlador:
`/tmp/opencode/wireless-maint-avl4ag6x/` (cinco suites rc 0 sobre `7bcc5bc`).
No declarar implementado el plan operacional integral de 07 ni toda la rama
verde: `run_tests` sigue heredada en rojo (último cierre de 06: 374 pasan,
11 fallan, incluido SSTI intermitente sin causa determinada). Suites antiguas
solo en copia limpia con configuración sintética; sin push.

**Actualización 2026-11-11:** la nota de pausa siguiente es histórica. El bloque
de infraestructura de 06 está en el commit local `37bdd16`; el cierre de
**mantenimiento** (menú, informes, validación y pruebas aisladas) se documenta
en `docs/CIERRE-MANTENIMIENTO-06-2026-11-11.md`, con su estado de verificación.
No confundirlo con integración operacional de las hojas o el flujo completo:
no se declaran terminados. Los cambios previos de scope.yaml, cleanup,
port_forward y run_all_post se conservan fuera del commit de mantenimiento.
No repetir 05 como si estuviera pendiente desde la nota antigua ni iniciar 07
sin leer los documentos actuales. Sin push; suites antiguas solo en copia
limpia sin configuración/evidencia real.

**Pausa 2026-11-10:** 03/04 terminados y diez suites pasando en clon limpio.
Commits locales autorizados después de la pausa, sin push; scope.yaml permanece
como configuración local fuera de los commits. El permiso api_keys.py se incluye.
Próximo trabajo: revisión del **módulo 05**, sin retirar capacidades.
Leer `docs/RETOMAR-2026-11-10.md` al retomar; no ejecutar suites antiguas sobre
evidencias reales ni comenzar explotación como smoke test.

Red-team / pentest framework: 118 Bash scripts (plus 4 more under `tests/`) plus a few Python helpers, targeted at Kali Linux. `README.md` is the pitch; this file is the working knowledge.

## Current state (2026-11-06)

Read `docs/CLEANUP-2026-10-30.md` before changing anything: it records the cleanup session (44 files quarantined outside the repo, 8 bugs fixed, every absolute path replaced with self-location) and the evidence backing it. Both tasks it left open are done, same day: the scan-output convention was unified in `docs/SCANS-PATHS-2026-10-30.md` (every script now writes to `<repo>/scans/<tool>/`, resolved from its own location — the two `scans/` trees were merged) and `12_Knowledge_Base/cheatsheets/linux_priv_esc.md` was expanded to parity with the Windows sheet. The interactive manager was then rebuilt around a session target and a `Uso:` parser (`docs/GESTOR-2026-10-30.md`). Session state is also stored in `ck` (`/ck:resume CyberSecurity`).

On 2026-10-31 the framework ran for real on Kali against the local host. Nine bugs appeared and were fixed — including the outputs that depended on the caller's `cwd` — plus the `:8443`-is-not-HTTP scheme assumption. `docs/PATHS-KALI-2026-10-31.md` has the symptoms, causes, fixes and evidence; read it before touching any output path.

The same day the framework was pointed at a real web app (a recurring-billing SPA, authorized by its owner; the host is deliberately not recorded here), which exposed a different class of defect: tools reporting "findings" that were only their own echo, and failures that looked like clean results. Eleven fixes followed — the shared `scans.bash` library (paths, slugs, catch-all baseline, ffuf hit counting), zsh-safe library paths, `run_all_recon.sh` honouring its target, target-named outputs, `stderr` into `errores.log`, `splitext` for the JSON report, reports labelled as templates, and generated reports out of git. `docs/ARREGLOS-FRAMEWORK-2026-10-31.md` records each one with its evidence. The engagement report itself stays in `CyberSecurity-Framework/11_Reports/final_report/`, which is git-ignored: never commit real targets or clients.

La misma jornada se cerró la fase que el spec anterior dejó abierta («POST/JSON no entra aquí: se resuelve con la petición capturada en Burp»). `05_Exploitation/web/http_inject.sh` acepta una petición cruda de Repeater y prueba inyección en sus parámetros de query, formulario y JSON con la sesión intacta, clasificando por evidencia (`CONFIRMADO` / `FUERTE` / `DEBIL`) con guardas contra el eco y el catch-all; `03_Scanners/web_scanners/burpsuite/burp_launcher.sh` arranca Burp desde el gestor y explica el flujo manual. Burp Community no escanea ni guarda proyectos: el lanzador lo dice y comprueba el puerto real en vez de asumirlo. `docs/BURP-HTTP-INJECT-2026-10-31.md` lo documenta.

Y encima de esa base, los dos huecos que aquel documento dejó anotados. `http_inject.sh` ya no puntúa un `429`/`503`: reintenta una vez respetando `Retry-After` (segundos o fecha HTTP) y, si insiste, corta la tanda y sale 1 sin escribir hallazgos. `05_Exploitation/web/sqlmap_request.sh` lleva el `.req` ya validado a sqlmap en tres fases (`--dbs`, `--tables`, `--dump`) con **tres permisos separados** (`SQLMAP_SI`, `SQLMAP_ENUMERAR`, `SQLMAP_TABLA`) y traduce su salida a `INYECTABLE` / `NO INYECTABLE` / `NO DETERMINADO`: el «no inyectable» que sqlmap concluye ante un 429 no se hereda. El volcado es una muestra de 50 filas. `docs/SQLMAP-Y-FRENOS-2026-10-31.md` lo documenta.

Para cerrar el hallazgo ALTO de aquel informe (20 × `401` y cero `429` en el login, medido a mano), `05_Exploitation/web/rate_limit_probe.sh` repite la petición de login capturada N veces (20 por defecto, tope duro 200) variando **solo el campo de contraseña** con `wrong-1…wrong-N` —no hay diccionario—, deja una fila por intento en un `.tsv` con código, ms, tamaño y `Retry-After`, y emite `FRENADO` / `FRENADO (por retardo)` / `SIN FRENO` / `NO DETERMINADO`. Corta en el primer freno (no manda el intento siguiente), copia el `Retry-After` literal sin dormirlo, y un `403`, un `200` con credenciales falsas o un `000` son `NO DETERMINADO`, nunca `FRENADO`. Está en `dangerous.txt` (pide confirmación: la cuenta se puede bloquear) y su fixture tiene ocho logins, uno por cada forma de frenar. `docs/RATE-LIMIT-2026-10-31.md` lo documenta.

On 2026-11-06 the deterministic report engine landed (`docs/superpowers/specs/2026-11-05-informes-automatizados-design.md`, state: approved and implemented). `11_Reports/report_engine.py` reads `scans/` and produces `findings.json` plus two reports — `informe_tecnico.md/.html` and `informe_cliente.md/.html` — attributed to the session target. `11_Reports/report_generator.sh` is the friendly wrapper (`Uso: ./report_generator.sh [tipo]`, slots mode). `R` in the manager menu triggers it; the profile (`cliente`/`auditor`) is stored in `11_Reports/.report_profile` (git-ignored). `09_Automation/python/report_generator.py` is now an obsolescence shim that delegates to the engine. The new suite `tests/run_reports.sh` (57 Python asserts plus shell checks for the wrapper, the menu, the documentation and syntax) covers the parser rules, the attribution, the traps (keywords, catch-all, `NO DETERMINADO`) and the doc checks. `docs/MANUAL-GESTOR.md` is the user-facing guide in Spanish.

Ese mismo día se cerró el agujero de `01_OSINT`: `run_all_osint.sh` no declaraba parámetros y llamaba a sus cinco hijos sin argumentos, así que todos imprimían su `Uso:` y él anunciaba «✅ OSINT completado» con `exit 0` sin haber ejecutado nada. Ahora pide `<dominio> [archivo]`, pasa el dominio a emails/WHOIS-DNS/subdominios, deriva el nombre de empresa para redes sociales (y lo anuncia), ejecuta metadatos solo si le das un archivo local, y un hijo que falla se cuenta y hace salir 1 con su stderr en `01_OSINT/osint_errores.log`. Es el sexto `run_all_*` que se autolocaliza. `docs/OSINT-RUNALL-2026-11-06.md` lo documenta con los 14 asserts nuevos.

Y el objetivo de sesión dejó de ser cosa de dos ficheros: `session_set_target` registra lo que fijas también en `scope.yaml` (IP en `targets.ips`; dominio **y** `*.dominio` en `targets.domains`, con `.bak`, validación PyYAML y descarte del temporal si el YAML deja de parsear — el original no se toca —) y en `targets.txt` (`<host>|—|—|Registrado al fijar el objetivo|B`). Idempotente, sin distinguir mayúsculas, y un fallo avisa sin cancelar la sesión. Se arregló de paso que `scope_allows` no coincidiera con una entrada de dominio sin comodín y que devolviera «no determinado» cuando el `scope.yaml` no tenía IPs. Consecuencia asumida: la comprobación de alcance pasa a ser un registro de lo usado, no una barrera. `docs/ORIGEN-AUTOMATICO-2026-11-06.md` y `docs/MANUAL-GESTOR.md` lo explican; la suite subió a 386 asserts por entonces, incluida una guarda de `md5sum` que impide que los tests toquen el `scope.yaml` y el `targets.txt` reales.

Las claves de API dejan de ser un fichero por herramienta que nadie recuerda rellenar. `00_Config/scripts/api_keys.py` mantiene un registro único (`00_Config/credentials/api-keys.yaml`, `600` en directorio `700`, ignorado por git) y escribe desde ahí los seis destinos: `~/.theHarvester/api-keys.yaml`, `~/.shodan/api_key`, `~/.h8mail_config.ini`, `~/.config/amass/datasources.yaml` (amass v5.1.1 no lee `config.ini`), `~/.recon-ng/keys.db` y `~/.spiderfoot/spiderfoot.db`. Órdenes: `estado [--json|--faltan H]`, `poner H CAMPO VALOR|-`, `pedir H [--campo C]`, `sincronizar [H]` e `importar H`; el gestor las reúne en la opción `K`. Reglas asumidas: el registro manda campo a campo pero un valor no vacío que solo esté en el fichero de la herramienta se conserva y se reporta (nunca se borra por sorpresa; `diverge` lo delata); `-` sí borra en ambos sitios; ninguna salida imprime el valor, solo presencia y longitud; `sincronizar` no crea ficheros vacíos; y una base de datos ausente es `sin inicializar`, nunca un fichero inventado. La suite nueva es `tests/run_keys.sh` (141 asserts, con `HOME`/`KEYS_FILE`/`KEYS_HARVESTER_*` aislados). `docs/API-KEYS-2026-11-06.md` lo documenta.

## Where it runs

Actualización Enumeración 2026-11-10: `04` tiene menú específico por servicio,
URL explícita, comprobación local, visor por objetivo y lista completa con las
16 entradas originales; no se retiraron métodos HTTP, accesos, usuarios,
fuzzing, consultas Redis ni generadores. Bibliotecas `enumeration_*` bajo
`00_Config/lib/` centralizan validación, clasificación y evidencia. Nuevos
resultados por host/puerto y hash web con `.meta.json` y `.attempt.json`;
el último intento fallido no se presenta como evidencia actual exitosa.
Los informes admiten nuevas fuentes SSH/MySQL/API y rechazan sidecars
inválidos sin revivir resultados históricos. HTTP HEAD usa `--head`; ffuf
se limpia al recibir SIGTERM. Postgres ignora PGHOSTADDR heredado. Nueva
suite segura `tests/run_enumeration.sh` (39 métodos); pruebas antiguas solo
en clon limpio. Guía y límites: `04_Enumeration/README.md` y
`docs/ENUMERACION-2026-11-09.md`. No lanzar el flujo completo como smoke test.

Actualización Escáneres 2026-11-09: `03` abre un menú específico (comprobación
local sin red, básico de 100 puertos TCP sin NSE, URL explícita Nikto/Nuclei,
Burp manual y acceso avanzado a las diez entradas). La biblioteca
`00_Config/lib/scanner_runtime.bash` valida entradas y conserva el historial
de `errores.log`; las hojas propagan fallos y `run_all_scanners.sh` cuenta
ejecutadas/fallidas/omitidas. Nmap de red acepta IPv4/dominio, no IPv6 literal.
Smart completo sigue siendo el perfil CLI por defecto; `basico` es el segundo
argumento opcional. Nikto rechaza comas literales y exige evidencia fresca de
evaluación completa, no solo rc=0. RustScan publica stdout solo tras éxito;
Masscan guarda JSON; Nuclei usa HTTP a 10 peticiones/s, sin Interactsh ni
comprobación de actualización, y conserva texto `.txt` legible por informes.
Nueva suite segura: `tests/run_scanners_menu.sh` (27 métodos unittest, fuentes
copiadas a temporal y PATH cerrado). Detalles: `docs/SCANNERS-2026-11-09.md` y
`03_Scanners/README.md`. Las suites antiguas siguen requiriendo clon limpio.

Actualización OSINT 2026-11-09: el contrato anterior de run_all descrito arriba
queda sustituido por `<dominio> [archivo] [empresa]`. Las seis entradas delegan
en `00_Config/lib/osint/`, comparten fuentes y producen resultados con evidencia
y cobertura, no URLs construidas. APIs directas opcionales: Brave/GitHub/Hunter,
lectura de claves sin sincronización. theHarvester CLI se anuncia omitido porque
sus reintentos y errores opacos no permiten garantizar límites. Subdominios admite
`<dominio> [directorio_salida] [diccionario] [resolver]`: diccionario local activa
DNS acotado con `DNS_SI`, nunca implícito desde run_all; sin AXFR ni credenciales.
Salidas por ejecución en árboles ignorados del módulo; códigos 0/1/2 y detalles
en `01_OSINT/README.md`. Nueva suite aislada: `tests/run_osint.sh`.

Actualización Configuración 2026-11-09: `00 → api_keys.py` abre `keys_menu`, el
mismo menú guiado de K, retornando al módulo; no invoca la CLI vacía ni cambia
su contrato. `run_all_config.sh` se autolocaliza y usa cuatro pasos explícitos de
solo lectura (validar, verificar, parse_targets --summary, api_keys estado), sin
asistente ni sincronización de claves. Propaga fallos con exit 1 y stderr visible.
Los validadores de estructura devuelven 1 al faltar archivos; parse_targets
devuelve 1 ante errores de lectura/escritura, sin traceback. Nueva suite aislada
`tests/run_config_menu.sh`: navegación real y claves/objetivos sintéticos.

**Precaución con las suites antiguas:** `tests/run_tests.sh` elimina carpetas y
logs compartidos (`scans/burp`, `scans/sqlmap`, logs de nmap/nikto/masscan y
fixtures de http_inject). Ejecuta la regresión completa en worktree limpio o
clon local temporal, nunca sobre un checkout con evidencias reales. La
verificación postmerge de OSINT se hizo en clon limpio del commit integrado.

- On Kali it runs for real (this clone, `/home/kali/Documentos/CyberSecurity`). Tooling gaps as of 2026-10-31: `rustscan`, `volatility3`, `foremost` and `nmap-vulners` are not installed; `masscan` needs root; no WiFi/Bluetooth adapter.
- The Windows checkout cannot run it. Scripts need Linux tooling (`nmap`, `sudo masscan`, `dig`, `md5sum`, `apt`) that is not installed there. WSL has no distro; Git Bash (`C:\Program Files\Git\bin\bash.exe`) only enables syntax checks.
- Verification available without running a tool: `bash -n <file>` (all 122 `.sh` — 118 outside `tests/` plus the 4 under it — and the 6 `.bash` currently pass), and `python -m py_compile` for the `.py` files (all 8 pass). The six suites under `tests/` (`run_tests`, `run_e2e`, `run_smoke`, `run_reports`, `run_wizard`, `run_keys`) are the real check for the manager; none of them is wired into a runner, they are run by hand. Do not claim a scan or audit result you did not produce.
- `bash -n` exits 0 on an **unterminated heredoc** — it only prints a warning to stderr. Two scripts (`01_OSINT/scripts/social_media_search.sh`, `05_Exploitation/web/reverse_shell_php.sh`) were truncated that way until 2026-10-30. When verifying, capture stderr, not just the exit code.
- Keep `.sh`/`.py` LF — `core.autocrlf=true` is set in this clone.

## Layout: two layers

- `CyberSecurity-Framework/` is the product. `cyber_framework.sh` is the interactive manager (`00`–`13` modules, `99` runs every phase's `run_all_*.sh`); it discovers scripts recursively and must be started from the framework root.
- The root holds only documentation and generated data: `README.md`, `.gitignore`, `AGENTS.md`, the generated `scans/`, and `CyberSecurity-Framework/`. The 31 bootstrap files that used to live here were quarantined on 2026-10-30 (`MANIFEST.md` in `%TEMP%\opencode\cybersec-root-cleanup-20261030` explains each one and how to restore it). Two of them were ported rather than dropped: the old `run_all_enum.sh`'s `timeout`/closed-port handling now lives in `04_Enumeration/run_all_enum.sh`, and `readme03.sh` became `03_Scanners/README.md`. `project_manager.sh` and `workflow_orchestrator.py` were dead: nothing referenced them, both hardcoded `~/CyberSecurity-Framework`, and `cyber_framework.sh` is the only entry point (it does not manage projects — the `00_Config/projects/` + `status.json` concept had no consumer anywhere).
- The framework's own bootstrap generators were quarantined in a second batch (9 files removed; 7 are recoverable in the `framework-generators/` subfolder of the same quarantine — two `creacion.sh` copies were lost to a filename collision, see that folder's `MANIFEST.md`): `run.sh`, `converter.sh`, `05_Exploitation/creacion.sh`, `07_Wireless/creacion.sh`, `12_Knowledge_Base/creacion.sh`, `04_Enumeration/corregir.sh`, `10_Evidence/setup_10_evidence.sh`, `11_Reports/setup_11_reports.sh`, `13_Labs/setup_13_labs.sh`. Every file they wrote already existed. `run.sh` regenerated four `run_all_*.sh`; `converter.sh` rewrote every script in place; `corregir.sh` would have reintroduced the `scans/` path bug fixed in `show_results.sh`.
- Generated data, not source: `scans/` at the repo root (scan results) and, anchored to each module, `01_OSINT/{domains,emails,metadata,social_media,subdomains}`, `02_Recon/{dns,fingerprinting,host_discovery,screenshots}`, `06_PostExploitation/{loot,persistence}`, `07_Wireless/captures`, `08_Forensics/{analysis,recovered}`, `10_Evidence/{screenshots,pcaps,logs,proofs,findings,credentials}` and `11_Reports/{executive,technical,final_report}`; plus `captures/memory/` (memory dumps) and `02_Recon/recon_<target>_<timestamp>/` inside the framework. Do not delete or "tidy" them.
- Two directories inside the framework are not tools: `00_Config/lib/` (the manager's library, `.bash` extension so it never shows up as a runnable script) and `tests/` (six test scripts: the library, the end-to-end run, the smoke menu, the config wizard, the report engine and the API-key registry, plus `tests/fixtures/`). `run_all_config.sh` only iterates `scripts/*`, so it never executes the library, and it skips `config_wizard.sh` because that one waits for keyboard input.
- Git: branch `develop`, remote `https://github.com/Medina07P/CyberSecurity.git`. Since 2026-10-30 the framework is versioned in an initial import split by module. The root `.gitignore` excludes every generated tree (`scans/`, `loot/`, `captures/`, `dns/`, `fingerprinting/`, `02_Recon/recon_*/`, evidence, generated reports and payloads): those hold real IPs, banners and credential lists from past sessions and must not reach a public remote. `00_Config/.gitignore` covers credentials and the manager's `.session`. When you add a new output directory, add it there too.

## Generator wrappers are not the tool

These files are `cat > <path> << 'EOF' … EOF` heredocs that *write* the real script to a home-directory path:

- `04_Enumeration/smb/enum_smb.sh`
- `04_Enumeration/web/deepseeenum_web.sh` (writes `enum_web.sh` beside it)
- `06_PostExploitation/lateral_movement/ps_exec.sh`
- `06_PostExploitation/privilege_escalation/linpeas.sh`

These are the only wrappers left; more of them (and all the `creacion.sh` / `setup_*.sh` run-once generators) were removed in the 2026-10-30 cleanup.

`05_Exploitation/exploits/reverse_shell.py` and `09_Automation/python/auto_audit.py` used to belong to this list: they were bash wrappers that rewrote *themselves* into real Python on first run. On 2026-10-30 that payload was materialised directly, so they are now ordinary Python scripts and every `.py` in the framework passes `python -m py_compile`.

`01_OSINT/scripts/osint_harvester.sh` was the same case in bash: its `TARGET_FILE` was its own path, so the first run replaced the wrapper with its payload and the manager's `[generador]` mark disappeared with it. On 2026-10-31 it was materialised, like the Python pair. It is now an ordinary script, and `tests/run_smoke.sh` checks the `[generador]` mark in `06`.

Edit the body between the `cat` line and the closing `EOF`. Editing the wrapper changes what gets generated, and its target path points outside this repo.

## The manager and its library

`cyber_framework.sh` is the only entry point. Since 2026-10-30 it sources four files from `00_Config/lib/` (all `.bash`, so `find -name '*.sh'` never lists them as tools):

| File | Contract |
|---|---|
| `params.bash` | Reads each script's own `Uso:` line: `params_mode` → `none` / `manual` / `slots`; `params_slots` → `posicion / nombre / obligatorio / tipo`; `params_example_values` → defaults from `Ejemplo:` only when its token count matches the slot count |
| `session.bash` | `session_target` / `session_set_target` / `validate_target`, `targets_from_config`, `scope_allows` (best effort, warns rather than blocks), `scope_add_target` / `targets_add_entry`. Persists in `00_Config/.session` and registers the target in `scope.yaml` + `targets.txt`; all three paths are overridable (`SESSION_FILE`, `SESSION_SCOPE_FILE`, `SESSION_TARGETS_FILE`) so tests never touch the real ones |
| `phase_status.bash` | `phase_state` → `done` / `pending` / `na`, deduced from evidence on disk (files under `scans/`, `02_Recon/recon_*`, …) — no state file |
| `prompt.bash` | `prompt_for_slots` → **values on stdout, all UI on stderr**. That split is the fix for the original bug, where the prompt text was captured as the argument |
| `dangerous.txt` | One framework-relative path per line; those ask for confirmation and do not take `Ejemplo:` defaults |

Two rules worth keeping:

- Any function that returns a value to a caller must print **only** the value to stdout. This is the bug that made the manager unusable: it printed the prompt to stdout and the caller captured the whole block.
- A `Uso:` line with `--flags` or a bare first token (`monitor` in `interface_manager.sh`) is passed through in **manual mode**: the manager shows the usage and you type the whole argument line. It never guesses positions for those.

Verify with `tests/run_tests.sh` (library and scripts, 388 asserts), `tests/run_e2e.sh` (a script really receives the typed value, 11 asserts), `tests/run_smoke.sh` (menu navigation with piped input, including `K`), `tests/run_wizard.sh` (58 asserts), `tests/run_reports.sh` (57 Python asserts plus shell checks) and `tests/run_keys.sh` (141 asserts, isolated by `HOME`/`KEYS_FILE`/`KEYS_HARVESTER_DIRS`/`KEYS_HARVESTER_TEMPLATE`). All run on Windows/Git Bash without a terminal, and they pass in a clean clone (no `scans/` present) because the phase tests build their own fixture.

## Running a script

- Scripts self-locate: no result path depends on the `cwd`. Scan results resolve the repo root from `${BASH_SOURCE[0]}` and go to `<repo>/scans/<tool>/`, so `cd 03_Scanners && ./run_all_scanners.sh <TARGET>`, `bash 03_Scanners/run_all_scanners.sh <TARGET>` and a launch from `/tmp` all land in the same place. Module-owned artifacts (loot, captures, emails, evidence, reports) are anchored to their module with `MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"`, never to `$PWD`.
- Invoking siblings as `./hermano/...` is a different story: that **does** depend on the `cwd`, so a `run_all_*.sh` that does it must `cd "$(dirname "${BASH_SOURCE[0]}")"` first. As of 2026-11-06 six do: `run_all_recon.sh`, `run_all_scanners.sh`, `run_all_enum.sh`, `run_all_evidence.sh`, `run_all_reports.sh`, `run_all_osint.sh` (plus `show_results.sh`). The other nine (`00_Config`, `05_Exploitation` ×2, `06`, `07`, `08`, `09`, `12`, `13`) still assume they are started from their own directory — the manager always does that, so it has not bitten yet.
- Contract: `run_all_*` take one positional target; leaf scripts add port/URL (`./enum_web.sh <IP> [PUERTO]`). Missing args print a `Uso:`/`Ejemplo:` block and `exit 1`.
- `cyber_framework.sh` detects the required parameter from the filename and the `Uso:`/`Ejemplo:` lines, so those lines are functional, not decoration.

## Orchestrators are dead code

- `09_Automation/python/orchestrator.py` resolves the framework root from its own location (`Path(__file__).resolve().parents[2]`), so it works wherever the repo is cloned. `09_Automation/workflows/*.yaml` are declarative only; nothing parses them (`yaml` is imported only by `orchestrator.py`; pyyaml is installed).
- `python3 09_Automation/python/report_generator.py --input <dir> --output <file>` is the one self-contained Python entrypoint.

## Config and data formats

- `00_Config/targets.txt`: `IP|PORT|PROTO|DESCRIPTION|PRIORITY` (C/A/M/B), `#` comments. `parse_targets.py` needs ≥3 pipe-separated fields; `02_Recon/run_all_recon.sh` greps for `|` and uses only the first 3 targets. `00_Config/scripts/config_wizard.sh` is the guided way to add entries: it writes the same format, offers to append (marking the batch with a dated comment) or to start a new list (the old one becomes `targets.txt.bak`), and never touches `scope.yaml`.
- `00_Config/scope.yaml`: project scope, allowed ports, rules of engagement, authorization. Parses with PyYAML and is LF-normalised (it used to be CR-only, so `wc -l` said 0 and `grep` saw one line).
- `00_Config/credentials/` exists with `README.md` + `.gitkeep`; `00_Config/.gitignore` ignores its contents but not those two files. `validate_config.sh` and `verify_00_config.sh` both pass with 0 errors.
- `README.md` no longer tells you to copy a `scope.yaml.example` (never existed; edit `scope.yaml` directly).
- Output names derive from the target (`:` and `/` become `_`), e.g. `scans/nuclei/nuclei_http___127.0.0.1.txt`.

## Writing new scripts

- Match the house shape: `#!/bin/bash`, header block with `Uso:` and `Ejemplo:`, argument validation with `exit 1`, results under `<repo>/scans/<tool>/` via `OUTPUT_DIR=$(scans_dir <tool>)`, Spanish user-facing messages.
- No script uses `set -e`. Prefer not to hide tool failures: in `03_Scanners/` each tool invocation writes `2>>"$OUTPUT_DIR/errores.log"` and the script announces the log when it is non-empty (`run_all_scanners.sh` lists the non-empty ones at the end). A discarded `2>/dev/null` turns "the tool failed" into "0 findings" — that ambiguity is what the `errores.log` convention exists to kill. Only probes (`command -v`, a `grep` over a file that may not exist) keep `2>/dev/null`.
- La petición capturada es la entrada de `http_inject.sh`: nunca inventes parámetros cuando el operador ya tiene la petición real. Los valores de query y formulario se codifican al sustituir; los de JSON, no.
- `http_inject.sh` deja `contexto.txt` (`esquema=`, `host=`, `metodo=`) junto a cada par `.req`/`.resp`; `sqlmap_request.sh` lo lee para no adivinar el TLS, porque sqlmap deduce el esquema del puerto (`443`→https, resto→http). Sus tres permisos (`SQLMAP_SI`, `SQLMAP_ENUMERAR`, `SQLMAP_TABLA`) son independientes a propósito: repetir no autoriza enumerar y enumerar no autoriza volcar.
- Un `429`/`503` no es un diferencial: cualquier sonda nueva debe tratarlo como corte (reintento con `Retry-After` y, si insiste, salir sin puntuar), no como hallazgo.
- En una prueba de login se varía **solo el campo de contraseña** (`wrong-1`, `wrong-2`, …) y nunca un diccionario: un bloqueo por intentos fallidos deja fuera al usuario de verdad, así que es una demostración acotada, no un ataque de credenciales.
- Output names carry the target: `SLUG=$(scans_slug "$TARGET")` and files go to `<tool>_${SLUG}.txt`. Without it two runs overwrite each other and the last target wins. Ports and schemes build the URL, the slug names the file.
- Use the shared library instead of hand-built paths. `source` `00_Config/lib/scans.bash` and use `OUTPUT_DIR=$(scans_dir <tool>)` (creates it), `scans_slug`, `scans_signature <url>` → `code:size`, `scans_ffuf_count <json>` → real hits from `results`, and `scans_baseline_size <url>` → the catch-all body size, `0` when the server 404s properly. Any fuzzing or injection probe must compare against a baseline first: against a SPA that answers `200` to everything, an unbaselined probe reports every candidate as a finding (90 false positives on the 2026-10-31 engagement).
- No script may hardcode a home path (`~/CyberSecurity-Framework`, `~/Documentos/...`). The library resolves the repo root from its own location, so `scans_dir` works from any `cwd`. If you must resolve a path by hand: `SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"` — one `..` per directory level between the script and the parent of `CyberSecurity-Framework/`, so `03_Scanners/<cat>/<tool>/x.sh` needs four, `<module>/<sub>/x.sh` needs three, `<module>/x.sh` needs two. Python uses `Path(__file__).resolve().parents[2]`. Every stale absolute path was removed on 2026-10-30 — do not reintroduce them.
- Library files are sourced, so they must resolve their own path without `BASH_SOURCE` alone: `${BASH_SOURCE[0]:-$0}`, because zsh leaves `BASH_SOURCE` empty and `$0` then holds the sourced file. Without it every library path silently becomes the framework root.
- Outputs that are not scan results (loot, captures, evidence, reports, emails) belong to their module: `MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"` for `<module>/<sub>/x.sh`, then `OUTPUT_DIR="$MODULE_DIR/<dir>"`. A raw `../loot` or `$(pwd)` depends on the caller's `cwd` and writes outside the ignored trees when the manager runs the script from the framework root (this was fixed on 2026-10-31; see `docs/PATHS-KALI-2026-10-31.md`).
- Slot names in the `Uso:` line are parsed as `pos|nombre|obligatorio|tipo`, so never put `|` inside `<...>` or `[...]`: use `<red>` and document the alternatives in a comment. `tests/run_tests.sh` asserts the slot count and types (`ping_sweep.sh` is the canary).
- The `nmap_smart.sh` duplicate is gone (2026-10-30): `03_Scanners/network_scanners/nmap/nmap_smart.sh` is the only copy and the one `run_all_scanners.sh` uses. The removed `nmap/scripts/nmap_smart.sh` was the older, `-Pn`-less variant. Beware `nmap_scripts.sh`: its `OUTPUT_DIR` is `$SCANS_DIR/nmap/scripts`, an output folder, not a script folder.

## Safety

All execution must stay inside authorized scope (`00_Config/scope.yaml`). `run_all_*` and menu option `99` chain brute-force, persistence and cleanup scripts against every configured target — never launch them as a casual smoke test.
