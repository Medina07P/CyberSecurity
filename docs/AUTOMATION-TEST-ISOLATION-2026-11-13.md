# 09: aislador exclusivo de pruebas, no modo de auditoría

## Estado y autorización

**Combinación actual,2026-11-14 (Task3 Phase A sobre fdf578f):** datos del run
del controlador conservado en
`/tmp/opencode/automation-isolated-4c408f2a815143d99afa09605769f2c3/evidence/`:
60units PASS;179integration,10fallos0errores1SKIP; host/inside rc1, estado FAIL,
tests_started=true. Los únicos tres casos fallidos son contratos10legacy:
`test_every_menu_option_explained`(1), `test_new_special_source_options_require_rows`(8),
`test_special_namespace_row_deletion_mutations`(1). Los25casos de informes GREEN
son evidencia previa del controlador, no una ejecución nueva de esta entrega.

Phase A reconcilia esas fuentes/docs y amplía el caso CLI09 existente para
exigir ficha antes de opciones en puente real, cero/EOF/lista original inertes.
El nuevo comportamiento aún requiere RED observado y Phase B productiva tras
revisión independiente. No se lanza runner/discovery de module_intro ni se cambia
manifiesto/selector/worker/grant25. Ningún comando de esta guía autoriza runs.

### Historia del aislador (no acredita esta combinación)

**Sobre1fde308: implementación/verificación histórica lista PARA revisión final
independiente, NO aprobación global.** El controlador verificó suite rc0:
60sandbox units PASS y159legacy/integration,0fallos0errores1SKIP dinámico pwsh;
los25IDs con permiso ejecutados y workers Landlock ABI7. Carreras rc0:
20recibos×8=160PASS. Cancelación externa controlada tras race01: SIGINT130,
24descendientes observados salidos; SIGTERM143,23salidos. Según controlador,
señales solo por pidfd al launcher directo. Los parciales se conservan.
Esta entrega es solo documental: no reruns ni nueva autorización de ejecución.
Falta review final independiente/controlador del aislador/global09; no se cierra
Task4/Task9/global por estos recibos. El usuario YA concedió excepción
acotada para25IDs y ruling posterior aclara que estados intermedios sintéticos
NUEVOS son descartables, no evidencia de engagement; no necesitan before-images
de cada versión. No repetir esa petición ni ampliar el permiso.
Según ledger, el controlador ejecutó ea414a9:60unit tests y109elegibles sin
fallos, un SKIP pwsh yrc2 esperado por25exclusiones; no toda la suite verde.
El RED anterior826ca17rc1 y todos sus artefactos se conservan. No ejecutar los
comandos de esta guía por su existencia. Tasks1/2 tienen revisión estática. En
367b9db el controlador observó rc0 y seis checks PASS de probes en
`/tmp/opencode/automation-isolated-fbdac899a3cd48daa8870d192c25d105/evidence/`:
fds iniciales, NPROC/identidad, hijo Python, hijo Bash, nieto Bash y cancelación
propia. `tests_started=false`: **ningún unittest ni suite de aplicación**.
Fuente del historial:
`.superpowers/sdd/2026-11-13-automation-test-isolation/namespace-diagnosis-outcome.md`.
Los ledgers anteriores, el incidente de Nmap real y sus evidencias se conservan.
No se afirma que la sesión histórica fuera exclusivamente sintética.

### Recibos finales leídos como datos (sin reejecutar)

| Comando del launcher fijo | Resultado verificado por controlador/recibos | Evidencia |
|---|---|---|
| `python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --suite` |60unit PASS;159legacy/integration,0fallos0errores1SKIP;25con permiso ejecutados,ABI7; probes6PASS,inside/host rc0 | `/tmp/opencode/automation-isolated-483f2446911e4dd99e8573f69b952e8a/evidence/` |
| mismo launcher con `--races` |20recibos,8casos cada uno,160PASS;ABI7,inside/host rc0 | `/tmp/opencode/automation-isolated-f3855feac6bd45d0b985542ca5cf6831/evidence/` |
| launcher con `--races`, señal externa controlada después de race01 |SIGINT130/24descendientes observados salidos;SIGTERM143/23salidos | `/tmp/opencode/automation-outer-cancel-a879a56f3bf748eab64f5b3395a1fbe7/{SIGINT,SIGTERM}.json` |

Parciales de cancelación conservados:
`/tmp/opencode/automation-isolated-006d51fcb3cf48eda197942ff1b82883/` y
`/tmp/opencode/automation-isolated-9b5d756da824418ebe6f941e15c224a8/`.
Las60unidades se repiten como gate por selector: no sumarlas entre runs como
casos distintos ni llamar a estos resultados «rama completa verde». SKIP exacto:
`PowerShellTests.test_ps_mock_contract_and_ast`, pwsh ausente del PATH preparado;
no ejecución dinámica PowerShell ni prueba Windows/Docker.

## Todas las opciones del runner test-only

Único wrapper: `bash CyberSecurity-Framework/tests/run_automation.sh [selector]`.
Delega al Python fijo con `-I -B`; no acepta comandos/targets/rutas arbitrarios.
Launcher y wrapper rechazan reentrada desde `/source`; discovery no los invoca.

| Selector | Finalidad y entrada | Efectos y límites |
|---|---|---|
| sin selector | Equivale a `--suite` | Mismos gates, nunca fallback al host. No autorización implícita. |
| `--probes` | Solo observaciones sintéticas de frontera | Preparación nueva y seis checks; no importa tests/producto. |
| `--suite` | Probes frescos,60unit tests puros y después suite09 | Cada caso legacy requiere worker Landlock ABI≥3 antes de setUp/run;25IDs permiten descartar temporales propios. Fallo de requisito=rc2, fallo real=rc1; solo ejecución observada puede acreditar PASS. |
| `--races` | Probes frescos, mismos unit tests y ocho casos internos fijos ×20 | Cada repetición/caso tiene worker/scratch/logs nuevos.160ejecuciones PASS observadas en el run1fde308 documentado; no aprobación automática de otros runs. Requisito ausente bloquea sin fallback ni scripts/nested bwrap. |
| cualquier otro argumento | Rechazo cerrado | rc2 antes de discovery; no `--unsafe`, token/env-bypass ni intérprete elegido por el usuario. |

Códigos:0 PASS de lo seleccionado y sin bloqueos,1 fallo real de probes/tests,
2 BLOCKED por requisito/preservación; cancelación host usa128+señal. Un fallo del
subconjunto sigue siendo fallo aunque existan bloqueos; consultar ambos recibos.
Timeouts: host900s (incluye preparación), probes10s, suite600s, races240s.
I/O de kernel no interrumpible no tiene garantía hard-real-time. No matar procesos
por nombre: se supervisa el hijo propio fijado. Cancelación externa del launcher
observada en dos runs autorizados tras race01; no se infiere solo del probe
interior ni garantiza todos los posibles puntos de cancelación futuros.

## Preparación, frontera y requisitos

Solo Linux x86_64/ELF64 little-endian y runtime local exacto Python3.13, Bash,
Bubblewrap existente, stdlib regular, PyYAML puro y ELF-deps cerradas. Ningún
helper/test/producto se importa en host para inventariar. Manifiestos fijos
`tests/automation_sandbox_{manifest,sources}.json`, sin selección externa. Fuentes
regulares sin symlinks ni configuración/evidencia; stdlib sin .pth/startup externo.
Un alias runtime específico fue corregido en3fbd9f9:
`_sysconfigdata__x86_64-linux-gnu.py` →
`_sysconfigdata__linux_x86_64-linux-gnu.py`; solo esa identidad/enlace exacto se
materializa como archivo regular. Alias desconocidos o sustituciones bloquean.
No `ldd`, instalación, sudo, Docker build/up ni descarga para satisfacer requisitos.

Pipeline fijo: staging → Bubblewrap (`--unshare-all`, sesión nueva, parent-death,
cap-drop ALL, entorno limpio) → gate NPROC → probes → selección interna. Mounts
runtime/source preparados read-only, work/evidence privados writeable, proc/dev
privados. No hostroot/HOME/config bin-directory binds ni backends/red reales.
Seccomp x86_64 bloquea socket/socketpair/io_uring y x32; arquitectura ajena mata.
AS2GiB, CPU600s, NOFILE256, FSIZE64MiB; fd heredados cerrados antes de exec.

### Correcciones NPROC e identidad: alcance real

Aplicar256 antes de Bubblewrap chocó con la contabilidad del UID host (>256hilos)
y produjo EAGAIN. Enmienda revisada: bootstrap **confiable** hereda soft/hard del
host sin elevarlos; el primer entrypoint workload fija y relee hard=soft256 antes
de forks, probes o imports de tests/producto. Hijos/nietos leen la herencia original
sin normalizarla. Recibos incluyen caps cero, UID no root y snapshot de hilos.

`uid_map` expresa el namespace **padre inmediato**, no el host. Parent0 no significa
hostroot. Se exige mapping singleton y composición VFS por canary400 NUEVO,
inode/metadatos fijados por host, traducción de propietario y apertura read-only
interior sin leer contenidos; host revalida descriptor/nombre. Alias/cambio o
ambigüedad => BLOCKED. Diagnósticos y fallos previos se conservan.

No cgroups quota per-tree, pids.max ni256plazas útiles garantizadas. Bootstrap no
comparte presupuesto agregado256 con workload; contabilidad UID/userns jerárquica
y ancestros/globales pueden agotar antes. Esto NO es certificado de kernel ni
seguridad frente a exploits hostiles, compatibilidad Windows/Docker o auditoría.

## Preservación literal y casos bloqueados antes de ejecutar

Cada staging nuevo `/tmp/opencode/automation-isolated-<uuid>/`700 conserva source,
runtime, work y evidence, aun fallando. El launcher crea `work/fixtures`700;
fixtures, negativos y casos unitarios crean únicamente bajo `/work/fixtures`,
dentro del mismo work persistente ya montado. No requieren `/tmp/opencode`
interior ni proyección de `/tmp` host. Close no borra nada; atexit antiguo solo
llama ese close inerte. Un helper test-only
renombra objetos sintéticos a `.preserved-<único>/nombre` antes de sustitución:
bytes y enlaces anteriores permanecen; recibo exclusivo `preservation.json`
registra origen/destino e identidad anterior/posterior, no se sustituye cleanup
del producto.
No rm/rmdir reales disponibles. Diagnósticos por defecto rechazan delete y
reemplazos/truncados; solo worker verificado/case25 puede descartar sintéticos
propios. **No son barrera heredada ni permiso**.

Lista nominal autoritativa, preparada por lectura/AST antes de cualquier run:
`CyberSecurity-Framework/tests/automation_preservation_cases.json` (25casos).
Versión2 conserva íntegramente25nombres y razones históricas bajo `blocked` y
añade `authorization`: los mismos25IDs, excepción explícita, scope únicamente
fixture registrada del caso actual y `landlock-abi3-current-case-worker` obligatorio.
`disposable_states` registra la aclaración de estados intermedios. No es un
switch de ejecución ni token/env/CLI. Se valida que los IDs no desaparezcan,
no se dupliquen ni difieran entre autorización e historia.
Incluye16casos RunnerTests, siete ReportTests y los casos de ejecución real-core
de AdapterTests/CliTests (revisar por nombre, no inferir un conteo verde).
RunStore reemplaza run.json y elimina temporales; publicación
limpia stage al fallar. Renombrarlos desde mocks cambiaría la semántica/aserción:
**prohibido**. Casos que rechazan antes de escribir (lock ocupado, SIGCHLD,
symlinks) y publicación con stage ya renombrado se conservan elegibles, sin mocks
nuevos de producto. Fuentes/pruebas originales siguen
presentes, sin eliminar ni convertir a skip general. El permiso específico YA se
concedió: delete/replace solo de temporales sintéticos NUEVOS descartables dentro
del caso actual, sin borrar fuentes/config real/evidencias/logs ni runs previos.
No permite limpieza global de fixtures/runlogs. Close sigue persistente.

### Gate implementado: worker por caso, Landlock ABI≥3 (ABI7 observado en estos runs)

Controlador validado dentro de bwrap crea `/work/fixtures/case-<único>`700, fija
descriptor O_PATH/no-follow y dev/ino/owner/mode, registra caseID y permiso25
en recibo exclusivo. Discovery solo crea SOURCES de bibliotecas para lectura;
fixtures nuevas del worker usan API interna `fixture_parent()` bajo SU scratch,
no env/argv. Cada caso, incluso no autorizado para destruir, recibe su scratch.

Worker fork cierra TODOS los fd heredados excepto stdio de logs NUEVOS, pipe de
resultado CLOEXEC y descriptor O_PATH de scratch hasta aplicar regla. Verifica
herencia NPROC sin repararla; no_new_privs y Landlock nativos x86_64 (syscalls
444/445/446) manejan WRITE_FILE, REMOVE, todos MAKE, REFER y TRUNCATE. Regla completa
write/create/delete/reparent/truncate: scratch de ESE caso. Segunda regla exacta
solo WRITE_FILE para `/dev/null` CHAR1:3 del dev privado bwrap: O_PATH/no-follow,
descriptor/nombre/metadatos revalidados antes/después de restrict y handles
cerrados. Ningún derecho TRUNCATE/REMOVE/MAKE/REFER para ese nodo, ni regla de
directorio /dev ni bind hostdev. Permite O_RDWR usado por subprocess.DEVNULL;
compatibilidad ejercitada en la suite1fde308, no garantía para cualquier runtime.
Read/execute siguen
permitidos para runtime/fuentes. Instalación o ABI<3 falla cerrado antes del
test. Rule/herencia fork/exec es SO, no audithook ni env-token. Regla no habilita
network/backends/root; outer bwrap/mounts/seccomp/probes quedan intactos.

`/source` sigue ro por outer; `/evidence` y demás fixtures/recibos quedan fuera
de la regla write del worker. Solo padre escribe recibos a partir de pipe acotado
(64KiB), con caseID/ABI/identidad cotejados; stdio del hijo escribe únicamente
logs nuevos explícitos preabiertos. Registro/logs y recibos YA creados permanecen
al fallar/cancelar. **M1 diferido:** interrupción puede dejar registro inicial
sin receipt terminal por caso; no se afirma que todo parcial tenga result.json.
Corrección I2 final (fuente estática, regresiones **NOT RUN**): el mismo pipe
transporta un evento fijo `READY` antes del recibo final acotado. Solo se emite
tras validar Landlock, grant, scratch y límites, inmediatamente antes de ejecutar
el caso. Timeout/crash tras READY es FAIL/rc1, con `ready`, razón y wait status
observado (null si aún no terminó); ausencia de READY/recibo no demuestra ABI
ausente y también falla conservadoramente. Solo un recibo BLOCKED explícito,
normal y anterior a READY acredita bloqueo de prerrequisito/rc2. El padre puede
escribir result.json de estos fallos de supervisión; no promete terminal durante
cancelación ni sustituye reap propio. No hay nueva validación runtime implícita.
No before-images intermedios descartables ni monkeypatch de
unlink/replace/cleanup operacional. Guard local deja descartar solo si caseID25,
scope actual fijado y Landlock ya instalado; otros/default siguen bloqueando.

Timeout propio60s/caso más budgets globales existentes. Controlador/worker son
subreapers; recolección usa únicamente lista kernel de hijos directos propios,
pidfd y waitpid, incluyendo adopción de nietos con sesión separada. Cancelación
en padre bloquea señales repetidas mientras mata/reapea hijos propios. No señal
por nombre/hostPID. Reap puede esperar kernel no interrumpible; outer deadline
no es garantía realtime. Resultado de caso/repetición conserva errores/bloqueos.

**Límites pendientes de revisión final:** Landlock ABI3 NO media chmod,
chown, utime, xattrs y varios ioctls; “read-only” aquí es para derechos manejados,
no certificación completa de metadatos frente a código hostil. DEVNULL,
subprocess y dos cancelaciones externas fueron ejercitados en el entorno de
los recibos indicados, NO en Windows/Docker/otros kernels ni en toda combinación.
Fd stdio/pipe explícitos son excepciones de I/O
confiable, no ficheros heredados arbitrarios. Sin claims de sandbox hostil ni
before-images universales. Si un requisito falla en ejecución se registra fallo/
BLOCKED, no se amplía regla a /work, /tmp, /dev o /evidence para obtener verde.

PowerShell dinámico: SKIP explícito si falta pwsh en runtime (no se incluye ni se
instala); fuentes PS, AST/contratos estáticos y fixture se mantienen. No confundir
ese SKIP opcional con los bloqueos anteriores. Suites antiguas de otros módulos
no están autorizadas aquí.

## Artefactos, espacio y reanudación

Recibos exclusivos, nunca reusados: launch, workload-nproc, probes, sandbox-units,
preservation (IDs/razones y elegibles), suite o races01–20, inside-result y host-wait;
stdout/stderr permanecen. El staging copia runtime por ejecución y fixtures por
caso: consume espacio y puede producir ENOSPC/rc2 o fallo, sin limpieza automática,
reuso ni borrado manual autorizado. Close solo libera handles propios.

Inventario de TODAS opciones/hojas se conserva en [MENU-OPCIONES](MENU-OPCIONES.md)
y [contratos de09](../CyberSecurity-Framework/09_Automation/USE.md); namespaces,
mutaciones y filas explicadas no se reducen. Añadir fuente implica actualizar
manifiesto exacto y explicación/review. `automation_operational_baseline.json`
fija hashes solo de fuentes operacionales de BASE367b9db, nunca config/evidencia.
Docker conserva allowlist exacta: ninguna infraestructura sandbox entra al producto.

Pendientes: revisión final INDEPENDIENTE del paquete/aislador y global09, decisión
del controlador y minors diferidos (M1 receipt terminal; históricos sin pulido).
La suite159,25casos con permiso,160carreras y cancelación externa aquí descritos
ya tienen evidencia; no repetirlos como si no existiera ni declarar aprobación
global solo por pasar. La excepción humana ya está concedida, no pendiente.
Task9/I1 no se cierran automáticamente por estos recibos; históricos en ledger09
`.superpowers/sdd/2026-11-13-automation-integral/` (consultar ledger original al
retomar, sin recrear logs). No repetir Tasks1–8/otros módulos. Operación autorizada
con Internet/datos reales queda separada e intacta; aquí no se autoriza auditoría,
ni push/merge ni eliminación de workspaces.
