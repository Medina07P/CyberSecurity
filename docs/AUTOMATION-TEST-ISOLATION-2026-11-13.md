# 09: aislador exclusivo de pruebas, no modo de auditoría

## Estado y autorización

Task4 es **implementación estática NOT RUN**, pendiente de revisión independiente
del diff completo y permiso explícito del controlador. No ejecutar los comandos
de esta guía por su mera existencia. Tasks1/2 tienen revisión estática. En
367b9db el controlador observó rc0 y seis checks PASS de probes en
`/tmp/opencode/automation-isolated-fbdac899a3cd48daa8870d192c25d105/evidence/`:
fds iniciales, NPROC/identidad, hijo Python, hijo Bash, nieto Bash y cancelación
propia. `tests_started=false`: **ningún unittest ni suite de aplicación**.
Fuente del historial:
`.superpowers/sdd/2026-11-13-automation-test-isolation/namespace-diagnosis-outcome.md`.
Los ledgers anteriores, el incidente de Nmap real y sus evidencias se conservan.
No se afirma que la sesión histórica fuera exclusivamente sintética.

## Todas las opciones del runner test-only

Único wrapper: `bash CyberSecurity-Framework/tests/run_automation.sh [selector]`.
Delega al Python fijo con `-I -B`; no acepta comandos/targets/rutas arbitrarios.
Launcher y wrapper rechazan reentrada desde `/source`; discovery no los invoca.

| Selector | Finalidad y entrada | Efectos y límites |
|---|---|---|
| sin selector | Equivale a `--suite` | Mismos gates, nunca fallback al host. No autorización implícita. |
| `--probes` | Solo observaciones sintéticas de frontera | Preparación nueva y seis checks; no importa tests/producto. |
| `--suite` | Probes frescos, unit tests prepare/policy/boundary y después suite09 | Selección de módulos exactos desde manifiesto, sin git. Los casos bloqueados no se ejecutan ni se cuentan PASS/SKIP; rc2 incluso si pasa el subconjunto elegible. |
| `--races` | Probes frescos, mismos unit tests y ocho casos internos fijos ×20 | Recibo propio por repetición; hoy los ocho tienen bloqueo de preservación y no deben contarse como160 ejecuciones verdes. No scripts externos/nested bwrap. |
| cualquier otro argumento | Rechazo cerrado | rc2 antes de discovery; no `--unsafe`, token/env-bypass ni intérprete elegido por el usuario. |

Códigos:0 PASS de lo seleccionado y sin bloqueos,1 fallo real de probes/tests,
2 BLOCKED por requisito/preservación; cancelación host usa128+señal. Un fallo del
subconjunto sigue siendo fallo aunque existan bloqueos; consultar ambos recibos.
Timeouts: host900s (incluye preparación), probes10s, suite600s, races240s.
I/O de kernel no interrumpible no tiene garantía hard-real-time. No matar procesos
por nombre: se supervisa el hijo propio fijado; cancelación externa completa del
launcher aún requiere evidencia autorizada, no la suple el probe interior.

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
No rm/rmdir reales disponibles. Diagnósticos adicionales del controlador rechazan
delete y reemplazos/truncados existentes; **no son barrera heredada ni permiso**.

Lista nominal autoritativa, preparada por lectura/AST antes de cualquier run:
`CyberSecurity-Framework/tests/automation_preservation_cases.json` (25casos).
Contiene nombres completos y razón; se valida que no desaparezcan del discovery.
Incluye16casos RunnerTests, siete ReportTests y los casos de ejecución real-core
de AdapterTests/CliTests (revisar por nombre, no inferir un conteo verde).
RunStore reemplaza run.json y elimina temporales; publicación
limpia stage al fallar. Renombrarlos desde mocks cambiaría la semántica/aserción:
**prohibido**. Casos que rechazan antes de escribir (lock ocupado, SIGCHLD,
symlinks) y publicación con stage ya renombrado se conservan elegibles, sin mocks
nuevos de producto. Fuentes/pruebas originales siguen
presentes, sin eliminar ni convertir a skip general. Para ampliar esa frontera
haría falta permiso específico del usuario para operaciones sobre descartables
sintéticos, seguido de revisión; esta guía no lo concede.

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

Pendientes: primer RED/GREEN diferido de nuevos unit tests y Task4, ejecución
segura del subconjunto, evidencia externa de cancelación, decisión de usuario
sobre25bloqueos, review global del aislador y global09. Task9/I1 no se cierran por
probes verdes; minors diferidos permanecen en el ledger09 de
`.superpowers/sdd/2026-11-13-automation-integral/` (consultar ledger original al
retomar, sin recrear logs). No repetir Tasks1–8/otros módulos. Operación autorizada
con Internet/datos reales queda separada e intacta; aquí no se autoriza auditoría,
ni push/merge ni eliminación de workspaces.
