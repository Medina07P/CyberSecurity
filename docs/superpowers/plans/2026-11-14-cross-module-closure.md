# Menores y conciliación final — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolver los menores restantes y conciliar todos los frentes sin presentar pruebas sintéticas como validación operacional.

**Architecture:** Cambios pequeños en tests09, un resumen seguro separado de las razones arbitrarias y un recibo terminal paterno exclusivo. Contratos documentales se contrastan con fuentes y dobles en una selección cerrada propia; el cierre reúne evidencia de los cuatro bloques.

**Tech Stack:** Python3/unittest, Bash, AST/JSON como datos, aislador existente y dobles sintéticos.

**Spec:** `docs/superpowers/specs/2026-11-14-cross-module-corrections-design.md` §§11–14.
**Prerequisites:** Los otros tres planes `2026-11-14-cross-module-{consent,web,local}.md` implementados y revisados en ese orden. No repetir S-I4, S-M7 ni previousM6, ya resueltos.

## Global Constraints

- «No push ni mergeadevelop sin petición expresa posterior.»
- «Pruebas SOLO en copias allowlist, HOME/sesión/config/wordlists/salidas sintéticos, PATHcerrado y dobles obligatorios de backend/red/GUI/sudo.»
- «Preservar fixturesfinales, fuentes, recibos/logs y todos los runsanteriores.»
- «Sin fallback, `--unsafe`, suiteglobal ni discoverydeotrosrunners por comodidad.»
- Fuentes RO, scratch nuevo por caso; no suites/helpers/imports/probes en host, ni configuración, claves, notas o evidencia real.
- Revisión estática independiente antes de cada combinación nueva y autorización exacta del controlador antes de RED/GREEN. Ningún comando de este documento se ejecuta por redactarlo o aprobar el diseño.
- Mantener gates/capacidades actuales. Las once correcciones documentales no autorizan cambiar producto para ajustarlo a una descripción equivocada.

## Review Focus

- Razón de excepción con secreto/saltos/ANSI o pasoID no confiable no se imprime en resumen; Task2.
- Falla antes de crear store: rc y motivo humano siguen disponibles sin inventar ruta; Task2.
- Cancelación antes/después de READY y después de result.json: recibo no afirma éxito ni reemplaza evidencia; Task4.
- Error al escribir recibo o reap: no oculta cancelación ni afirma reap completado; Task4.
- Alias cambia solo antes o solo después de copiar: pruebas ejercitan ambas barreras sin copiar runtime real; Task3.

## Archivos, interfaces y selección exacta

Rutas relativas al framework, excepto docs:
- Modificar `tests/test_automation_{plans,runner,reports,sandbox_prepare}.py` para previousM1/M2/M3/M7.
- Crear `00_Config/lib/automation/summary.py`; modificar `automation/{model,runner,cli}.py` en ese mismo directorio para previousM4.
- Modificar `tests/automation_case_worker.py`; crear `tests/test_cross_closure.py`, `tests/test_cross_documentation.py`.
- Ampliar `tests/cross_module_selection.py`, `cross_module_cases.json`, fuentes allowlist y contratos de selección. No ampliar runtime ni grants por este bloque.
- Modificar `docs/MENU-OPCIONES.md`, `docs/MANUAL-GESTOR.md`, `09_Automation/USE.md`, `docs/AUTOMATION-TEST-ISOLATION-2026-11-13.md`, guías específicas afectadas y texto de advertencia99 en `cyber_framework.sh`, sin ejecutar99.
- Crear `docs/CORRECCIONES-TRANSVERSALES-2026-11-14.md` con matriz y evidencia final; conservar los informes originales.

Selector fijo nuevo `--cross-closure`; comando previsto:
`python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --cross-closure`.
Los cambios de tests existentes se ejecutan mediante `--suite`, no por imports en host ni wrappers anidados.

IDs nuevos seleccionados exactamente (todos SIN permiso destructivo):

| Prefijo de ID | Sufijos |
|---|---|
| `test_cross_closure.SummaryTests.` | `test_cli_summary_is_safe`, `test_interactive_summary_and_pre_store_failure` |
| `test_cross_closure.TerminalTests.` | `test_cancel_before_and_after_ready`, `test_existing_result_is_preserved`, `test_receipt_io_failure_preserves_cancellation`, `test_reap_failure_is_not_success` |
| `test_cross_documentation.DocumentationTests.` | `test_dns_resolution_and_dictionary_gate`, `test_ftp_login_vs_listing`, `test_actual_exploitation_children`, `test_templates_and_ssh_have_real_effects`, `test_forensic_metadata_vs_private_hash_reads`, `test_scope_backup_vs_targets_append`, `test_forensic_menu_vs_cli_filters`, `test_99_warning_matches_omissions`, `test_wizard_defaults_and_resolved_components`, `test_key_cli_signatures`, `test_sqlmap_gates_by_channel` |

Nuevos métodos bajo `test_automation_sandbox_prepare.Preparation`, seleccionados por el UNIT_MODULES existente: `test_python_alias_manifest_mutations_rejected`, `test_python_alias_identity_before_copy_rejected`, `test_python_alias_identity_after_copy_rejected`. Sin permisos destructivos; fixtures nuevas sin finalizadores, identidades cambiadas mediante dobles, no reemplazos de archivos.

No se solicitan nuevos descartables aquí. Si un test necesita borrar/reemplazar algo, se bloquea y vuelve al controlador con ID/operación exactos; no hereda el permiso del test al que sustituya o que lo llame.

### Task 1: Precisión de tests null, readiness y advertencias

**Files:** tests plans/runner/reports existentes. **Produces:** mismos IDs y grants actuales, aserciones más precisas; ningún cambio funcional del producto.

- [ ] previousM1: en `test_stable_topology_and_defaults`, añadir timeout600 al YAML nulo y default válido explícito. Afirmar literalmente `Texto vacío o con controles` de `automation/validation.py`, no `Esquema workflow inválido`. Añadir control sin override que usa el default. El defecto del test se demuestra con la aserción específica sobre la fixture antigua, no con un fallo de producto inventado.
- [ ] previousM2: mantener ID `test_term_is_not_inherited_blocked` y marker/rc1. Envolver únicamente `automation.runner.subprocess.Popen`: llamar al original, esperar hasta5s un marker READY escrito por el hijo después de instalar handler, y solo entonces devolver Popen al runner. Comando con timeout1s, no dormir esperando startup; si falla readiness, terminar/reapear exclusivamente ese hijo en finally y fallar con causa propia. No cambiar límites/producto para hacer pasar la prueba.
- [ ] previousM3: capturar stderr local con `redirect_stderr(StringIO())` alrededor de cada compilación exitosa directa de `report_command` en los dos métodos citados. Afirmar literalmente `Aviso: report_input puede contener históricos; el informe no acredita que 09 haya ejecutado esas fases.\n`, una vez por llamada. El intento repetido que falla antes del aviso no debe emitirlo.
- [ ] Revisión estática independiente y autorización exacta de `--suite` para contraste de aserciones antiguas/corregidas sobre fuentes allowlist. No ejecutar revisiones antiguas del launcher; para RED usar las fixtures/aserciones propuestas en el aislador actual revisado.
- [ ] Esperado: se acredita causa específica, readiness precede timeout y diagnóstico esperado queda capturado sin silenciar otros avisos. Commit scoped y reporte que distingue mejora de prueba de bug operacional.

### Task 2: Resumen seguro de resultados09 por ambos canales

**Files:** model.py/runner.py/cli.py, nuevo summary.py y dos SummaryTests.

**Interfaces:** añadir al final de `RunResult` `reason_code: str = ''` (mantiene constructores posicionales antiguos). Valores cerrados producidos por runner: `completed`, `cancelled`, `timeout`, `backend_failed`, `setup_failed`, `storage_failed`; vacío/desconocido se muestra como resultado no determinado. `summary.render_result(result: RunResult) -> str` es puro; no abre run.json ni copia `StepResult.reason`. CLI e interactive_plan imprimen ese texto tras ejecutar y retornan el mismo rc.

- [ ] Escribir primero `test_cli_summary_is_safe`: execute_plan doble devuelve resultados rc0/1/2/130/143, con/sin ruta, razones de pasos que contienen `SYNTHETIC_SECRET`, newline y ANSI, y reason_code desconocido. Assert rc intacto, motivo cerrado visible, ninguna razón/id arbitrarios ni secreto/ANSI. Preview no imprime ejecución ni crea runs.
- [ ] `test_interactive_summary_and_pre_store_failure`: flujo interactivo con permisos exactos y execute_plan doble, fallo previoastore y fallo de almacenamiento. Assert ruta solo cuando existe en resultado, motivo sin excepción cruda, resumen emitido una vez por ejecución; cancelar/EOF no se describe como ejecución completada.
- [ ] Fijar formato: primera línea `Resultado: rc=N; motivo=TEXTO.`; tabla literal: `completado`, `cancelado por señal`, `tiempo agotado`, `fallo de backend`, `fallo de preparación`, `fallo de almacenamiento`, fallback `no determinado`. Segunda línea opcional `Run: RUTA` solo para Path absoluta sin controles/DEL/ANSI, máximo4096caracteres; ruta inválida se omite. No mostrar nombres/inputs/argv/stderr de pasos ni reason arbitraria.
- [ ] Incorporar todos los17IDs nuevos al selector cerrado antes del primer RED, con tests que importan helpers nuevos dentro de métodos. Revisión/gate y autorización `--cross-closure`; infraestructura debe funcionar aunque negocio todavía falle.
- [ ] Implementar reason_code en cada salida de runner, incluido retorno previoastore; cancelación tiene precedencia sobre errores de E/S. Mantener razones durables existentes y códigosrc, sin nueva lectura/escritura de evidencia ni redacción retroactiva de logs.
- [ ] Consumir resumen en cli.main e interactive_plan; en menú sustituir el mensaje redundante por `No se conservan permisos.`. No cambiar permisos/preflight como efecto de mostrar información.
- [ ] Revisión/gate; autorización `--cross-closure` y `--suite`, expected SummaryTests GREEN sin alterar cancelación ni rc. Commit e informe.

### Task 3: Mutaciones de alias y transición de identidad en prepare — previousM7

**Files:** test_automation_sandbox_prepare.py; producción solo si la nueva prueba acredita otro defecto y se revisa su corrección por separado.

**Consumes:** `_runtime_entries()`, `prepare(repo: Path) -> PreparedRun`, `copy_regular` existentes. **Produces:** tres métodos exactos declarados arriba, usando `persistent_case()` y doubles, nunca preparando runtime real durante estos tests.

- [ ] `test_python_alias_manifest_mutations_rejected`: load_json doble con manifiesto sintético; tabla de alias ausente,duplicado,origen/destino/categoría cambiados,claveextra y versión inválida. Afirmar IsolationBlocked antes de copiar. Control exacto válido llega al siguiente doble centinela y no bloquea por un requisito ajeno.
- [ ] `test_python_alias_identity_before_copy_rejected`: dependencias de prepare son registros sintéticos nuevos; `_python_alias_identity` devuelve identidad inicial y distinta justo antes del copy. Assert copy no se invoca para alias y blocked.json nuevo indica BLOCKED.
- [ ] `test_python_alias_identity_after_copy_rejected`: identidad inicial estable antes de copy; copy_regular doble entrega source_identity distinta, o cambia la observación posterior en subtests separados. Assert no PreparedRun usable y blocked.json nuevo conserva causa; source/reference permanecen intactos.
- [ ] Revisión/gate y `--suite` autorizado; expected controles positivos ejercitan la rama y negativos prueban bloqueo. Estos checks pueden pasar inicialmente: registrarlos como cobertura nueva, no falsear RED de un bypass inexistente ni quitar la barrera para fabricarlo.
- [ ] Commit scoped y reporte; no añadir aliases/runtime ni certificar host/kernel por esta cobertura.

### Task 4: Recibo terminal paterno best-effort ante cancelación — previousM8

**Files:** automation_case_worker.py y cuatro TerminalTests.

**Interfaces:** helper privado `_write_terminal(path: Path, value: dict) -> bool`, creación O_EXCL/O_NOFOLLOW0600, una escrituraJSON acotada64KiB y fsync. Colisión o error retornaFalse, nunca reemplaza. Ruta fijada por padre `/evidence/case-NNNNN.terminal.json`, separada de registry/result/stdout/stderr. No es API de permiso ni prueba de aislamiento.

- [ ] `test_cancel_before_and_after_ready`: unidad con controlador verificado simulado, `_collect_result` que lanza KeyboardInterrupt o SystemExit(143), fork/reap/pipe dobles sin procesos reales y E/S dirigida exclusivamente al scratch nuevo. READY observado se conserva por callback interno `_collect_result(case_id, pid, read_fd, on_ready=None)`; el callback solo fija booleano paterno. Assert reap precede terminal, excepción original continúa y no se devuelve PASS/BLOCKED.
- [ ] `test_existing_result_is_preserved`: normalidad con result existente y cancelación posterior, y colisión de terminal. Assert bytes/modo del resultado/terminal anterior intactos; no se reintenta con replace/unlink. Registros nuevos por subtest, sin borrar fixtures.
- [ ] `test_receipt_io_failure_preserves_cancellation`: ENOSPC/EACCES/shortwrite simulados; misma excepción/código original y reap invocado. No error de recibo sustituye cancelación ni se considera recibo parcial válido.
- [ ] `test_reap_failure_is_not_success`: doble reap falla; terminal no afirma reaped=True y propagación conserva cancelación principal, o fallo de reap cuando no había excepción principal. Descriptores/máscara de señal se restauran por finally.
- [ ] Revisión/gate y RED sobre implementación actual dentro de selección revisada. Nunca enviar señales al launcher/host ni lanzar un worker real para estas pruebas unitarias; cancelación externa real sería otro experimento que requiere autorización propia.
- [ ] Implementar captura de excepción primaria y resultado del reap antes de cerrar/desenmascarar. Esquema terminalv1: `case_id`, `state` (`CANCELLED`/`ERROR`), `ready`bool, `reaped`bool, `result_present`bool, `exception_type` de lista cerrada y `signal`INT/TERM/ALRM o null solo si acreditada. Sin texto crudo de excepción, success ni estadoDONE. Emitir solo en salida excepcional y sin modificar recibos de normalidad.
- [ ] Si reap falla simultáneamente, no enmascarar excepción principal; terminal deja reapedFalse y diagnóstico acotado. KILL, E/S imposible o muerte del padre no prometen terminal; conservar registry/partials y documentar límites.
- [ ] Revisión/gate; `--cross-closure` y `--suite` autorizados por separado. Expected cuatro métodos GREEN y timeout/crash mantienen clasificación previa. Commit e informe; no cerrar globalTask4 automáticamente.

### Task 5: Once precisiones documentales, sin nuevas operaciones

**Files:** test_cross_documentation.py, docs enumerados y advertencia99. **Interfaces:** métodos exactos de DocumentationTests en tabla; fixture común copia solo fuentes allowlist. Fuente leída como datos/AST cuando basta; dobles de transporte/dispatch/IO cuando se observa comportamiento. Nunca ejecutar99, una plantilla con transporte real o ayuda de una hoja insegura.

| ID | Método / afirmaciones literales que debe fijar |
|---|---|
| S-M1 | `test_dns_resolution_and_dictionary_gate`: resolver doble observa resolución/wildcard sin diccionario; DNS_SI solo ampara diccionario. Docs distinguen ambos. |
| S-M3 | `test_ftp_login_vs_listing`: transcripción anonymous USER/PASS/quit sin ls frente a enum_ftp con ls; no agregar listado. |
| S-M4 | `test_actual_exploitation_children`: despachadores dobles y AST fijan SSH/web/Postgres/MySQL/Redis y conjunto real de run_all_exploits; no prometer AD/discovery de exploits/. |
| S-M5 | `test_templates_and_ssh_have_real_effects`: socket/nc/Nmap/Hydra dobles fijan TCP80/nc22/NSE/listas de ambos canales; docs no llaman inertes las plantillas ni heredan topes09. |
| S-M6 | `test_forensic_metadata_vs_private_hash_reads`: fixture forense sintética/doble de lectura registra copia privada para hash, stdout sin cuerpos y original jamás abierto por visor. |
| S-M8 | `test_scope_backup_vs_targets_append`: dobles de operaciones y AST contrastan backupscope y appendtargets; no tocar persistencia/config real. |
| S-M9 | `test_forensic_menu_vs_cli_filters`: execute_script doble observa --prepared sin filtros; CLI tiene filtros documentados por separado. |
| S-M10 | `test_99_warning_matches_omissions`: AST+dispatchdoble sin ejecutar99 acredita fases/selección05 y exclusión06 de persistencia/lateral/cleanup. Warning mantiene peligro sin prometer esas llamadas. |
| S-M11 | `test_wizard_defaults_and_resolved_components`: wizard en HOME/targets sintéticos con descripciónEnter y defaultprotocolo; preservar descripciónopcional10 y objetivoobligatorio11 mediante fuente/AST, no motorreal. |
| previousM5 | `test_key_cli_signatures`: parser/AST como datos: `estado [--json|--faltan H]`; `pedir H [--campo C]`; nunca leer/sincronizar/importar claves. |
| previousM9 | `test_sqlmap_gates_by_channel`: capturas sintéticas GET/HEAD/POST y backenddoble; replaycondicionalCLI, enum si database, dump si table, base.tabla conocida sin database no exigeenum; menú conservador separado. |

- [ ] Escribir las once comprobaciones con expectativas independientes del texto corregido, ejemplos/docs actuales fallan por afirmaciones erróneas; no modificar lógica para hacer coincidir prosa.
- [ ] Revisión/gate y RED del selector antes de editar documentación. Si la fixture requiere operaciones no concedidas, bloquear y consultar, no simular lógica de negocio con no-ops.
- [ ] Corregir las filas/guías citadas en minor-reconciliation y el texto99. Conservar encabezados históricos fechados y distinguir correcciones presentes de resultados anteriores. No repetir componentes S-M11 resueltos ni S-I4.
- [ ] Revisión/gate y GREEN de `--cross-closure`; commit y tabla porID con fuente/contrato/test/evidencia. S-M2 remite al bloque local, no se cuenta doble.

### Task 6: Conciliación semántica y entrega final de los cuatro bloques

**Files:** docs/CORRECCIONES-TRANSVERSALES-2026-11-14.md, manual/MENU/guías afectadas, ledger de ejecución nuevo y AGENTS.md solo nota factual fechada si corresponde.

- [ ] Crear matriz de siete frentes, veinteIDs menores únicos y aliases. Cada fila incluye estado antes/después, SHA, capacidades conservadas, casos exactos, review y recibos. Los dos menores previamente resueltos siguen históricos; 18pendientes iniciales incluyen CIDR una sola vez.
- [ ] Reconciliar todas las hojas/filas del inventario semántico130hojas/217filas por fuente, incluyendo nuevas subopciones y cambios de CLI. Total actual puede crecer: registrar delta, no forzar el conteo viejo. Verificar entradas/slots/defaults/gates/IO/rutas/coordinadores; una coincidencia estructural no acredita semántica.
- [ ] Contraste independiente de capacidades antes/después: ninguna técnica original retirada, nuevos modos no convierten previews en ejecución completa, exclusiones no se revierten. Cualquier discrepancia vuelve a su tarea/review; no cierre con pendientes silenciosos.
- [ ] Revisar combinación final completa de fuentes/manifiestos/runtime/selectores/grants. Controlador autoriza separadamente comandos del launcher con `--suite`, `--races`, `--cross-consent`, `--cross-web`, `--cross-local`, `--cross-closure`; misma ruta fija indicada arriba. No anidar runners ni ejecutar suites antiguas en host. Expected: todas las selecciones completas sin fallos/errores/BLOCKED y carreras20×8 con recibos; SKIPpwsh explícito si sigue ausente. No fijar anticipadamente total de tests tras ampliaciones.
- [ ] Añadir resultados frescos SHA/rc/conteos/fallos/errores/omitidos/recibos; clasificar ejecuciones parciales y RED históricos sin borrarlos. El60/179 de compatibilidad sigue atribuido a su SHA, no a estos cambios.
- [ ] Revisión final independiente/controlador antes de cualquier cierre acotadoTask4/Task9/global09; si falta un gate, registrar PENDIENTE, no aprobarlo desde documentación. No declarar rama completa verde, compatibilidad operacional, Windows/Docker o custodia legal.
- [ ] Commit documental scoped y entregar enlaces. Conservar worktree, ramas, fuentes, parciales y artefactos. Sin push, mergeadevelop ni cleanupfinal; integración futura requiere autorización nueva.

## Self-review / handoff

Diseño§11: previousM1–3→Task1, M4→Task2, M7→Task3, M8→Task4, once documentales→Task5 y S-M2→planlocal. §12–13→todos los gates y Task6. Los cinco ReviewFocus tienen métodos precisos; resumen no consume razonessecretas y terminal no redefine el éxito. Los tres perfiles previos solicitan25IDs NUEVOS en total (9+5+11), distintos de los25históricos09; este bloque no solicita ninguno. Confirmación de planes/permisos precede implementación; método subagentes conservado.
