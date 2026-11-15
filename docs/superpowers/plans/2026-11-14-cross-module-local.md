# Herramientas estables, notas y CIDR — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolver S-I2/S-I7/S-M2 conservando todas las operaciones de SMB/PSExec/Linpeas, cinco plantillasLabs y descubrimiento de red explícito.

**Architecture:** Hojas públicas estables con modos explícitos y generación de lanzadores nuevos; helpers privados para generación, inicialización exclusiva y validación de destinos. Regresiones bajo una selección local cerrada del aislador del primer bloque.

**Tech Stack:** Bash/Python3 estándar, unittest, herramientas externas siempre dobles.

**Spec:** `docs/superpowers/specs/2026-11-14-cross-module-corrections-design.md` §§8–10,12–14.
**Prerequisite:** bloqueconsentimiento y bloqueweb cerrados, interfaces del aislador/fixtures revisadas. No reinterpretar sus gates como autorización de esta selección.

## Global Constraints

- «No push ni mergeadevelop sin petición expresa posterior.»
- «Preservar fixturesfinales, fuentes, recibos/logs y todos los runsanteriores.»
- «Pruebas SOLO en copias allowlist, HOME/sesión/config/wordlists/salidas sintéticos, PATHcerrado y dobles obligatorios de backend/red/GUI/sudo.»
- «Ninguna invocación reemplaza su fuente ni una fuente vecina.»
- «Si existe un archivo regular, incluso vacío, conservar bytes/modo e informar reuso sin reemplazarlo.»
- No ejecutar generadores actuales ni sus supuestas ayudas en host; no sudo/descarga/PSExec/Nmap/ping/IP real, ni leer notas o artefactos reales.
- No migración automática de árboles/cwd, no nuevos privilegios/técnicas, no permiso implícito de los run_all.

## Review Focus

- Dos llamadas iguales a la misma ruta no cambian significado ni hash/modo de fuente; Tasks1–3.
- Generar con destino existente/enlace/dentro del framework no sobrescribe ni ejecuta; Task1.
- Linpeas sin modo seleccionado o desde run_all no descarga ni obtiene sudo; Task3.
- README vacío/enlace/colisión de inicializaciones y cwd distinto conservan trabajo; Task4.
- IPindividual frente a CIDR con bits dehost/rango inválido nunca amplía destinos implícitamente; Task5.

## Archivos y selección

Rutas relativas a `CyberSecurity-Framework/`:
- Crear `00_Config/lib/consent/generate.py`, `stable_tools.py` y `stable_cli.py` para generación/dispatch de las tres hojas.
- Modificar wrappers públicos `04_Enumeration/smb/enum_smb.sh`, `06_PostExploitation/lateral_movement/ps_exec.sh`, `06_PostExploitation/privilege_escalation/linpeas.sh` y consumidores04/06/dangerous.
- Crear `00_Config/lib/labs_runtime.py`; modificar cinco setups13, `13_Labs/{main,setup_lab,run_all_labs}.sh` solo para raíces/rc/cwd afectados.
- Crear `00_Config/lib/recon_targets.py`; modificar `02_Recon/scripts/ping_sweep.sh`.
- Crear `tests/test_cross_local.py`; ampliar selección y fuentes exactas, no discovery09.
- Guías04/06/13, `docs/MENU-OPCIONES.md`, convenciones de salida e ignore de nuevas salidas necesarias.

Nuevo selector fijo `--cross-local`; comando previsto `python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --cross-local`. Gate y autorización exacta porSHA antes de cada RED/GREEN. Regresiones de perfiles anteriores/09 por comandos separados autorizados.

## IDs y solicitud específica de descartables

Métodos nuevos en `test_cross_local`:

| Clase | Método | Permiso propuesto |
|---|---|---|
| GenerationTests | `test_generation_is_exclusive_and_inert` | Sí |
| GenerationTests | `test_generated_launcher_requires_root_and_mode` | Sí |
| StableToolTests | `test_smb_keeps_all_methods_without_source_mutation` | Sí |
| StableToolTests | `test_psexec_preserves_argv_and_secret_privacy` | Sí |
| StableToolTests | `test_linpeas_requires_explicit_source_and_sudo` | Sí |
| StableToolTests | `test_linpeas_failures_preserve_artifacts` | Sí |
| LabTests | `test_five_templates_preserve_existing_notes` | Sí |
| LabTests | `test_lab_roots_names_and_menu_cwd` | Sí |
| LabTests | `test_lab_links_and_partial_failure` | Sí |
| ReconTests | `test_ping_target_parser` | No: puro |
| ReconTests | `test_ping_cli_records_only_selected_targets` | Sí |
| LocalMenuTests | `test_modes_marks_and_coordinator_omissions` | Sí |

Se solicita permiso explícito solo para los onceIDs marcados, sobre copias/datos NUEVOS del caso. Incluye copias sintéticas de fuentes para observar auto-reescritura antigua y sentinelas nuevos de notas: las fuentes originales `/source` quedan RO y se conserva su imagen de referencia. No autoriza datos/artefactos de otras pruebas ni limpieza del árbol final; no se amplían25grants09.

### Task 1: Generación útil y exclusiva sin auto-reescritura

**Files:** consent/generate.py, dos métodos GenerationTests, mapas/fuentes y validación de perfiles.
**Interfaces:** `emit_launcher(kind: str, destination: Path, framework: Path) -> Path`, kinds cerrados `smb`, `psexec`, `linpeas`. Destino existente siempre error; se exige padre existente sin enlaces, destino fuera del árbolframework y archivo nuevo0700. La raíz `framework` solo valida ubicación; no se incrusta en el resultado.

- [ ] Escribir `test_generation_is_exclusive_and_inert`: tres kinds; archivo nuevo ejecutable, ningún backend/descarga; existente vacío/no vacío/enlace/colgante/directorio y destino dentroFW rechazados sin cambios. El contenido no incluye raíz local, usuario/objetivo/credenciales de test ni permisos concedidos.
- [ ] `test_generated_launcher_requires_root_and_mode`: interfaz generada `--framework-root DIR <argumentos de hoja>`; sin raíz/raíz inválida o sin modo no opera. Con raíz explícita a una hoja centinela segura reenvía argv exactamente, sin añadir --execute ni eval/interpolación; unknownkind falla.
- [ ] Escribir también todos los métodos de Tasks2–6 antes del primer RED, imports de helpers nuevos dentro de métodos. Ampliar selector local con los doceIDs/case-grants exactos, revisión estática y RED antes de implementar helper. No ejecutar wrappers antiguos para «materializarlos» en checkout; los casos pendientes no se omiten para aparentar verde parcial.
- [ ] Implementar lanzamiento generado de cuerpo fijo por kind, parametrizado solo al ejecutar; creación exclusiva/no-follow y sin reemplazo atómico sobre destino ajeno. Si una escritura se interrumpe, conservar parcial propio con fallo, no borrar objetos anteriores.
- [ ] Revisión+gate y GREEN de los dos métodos; commit e informe. Los modos de hojas se implementan después, no prometer todavía su compatibilidad.

### Task 2: SMB y PSExec estables, argumentos preservados

**Files:** stable_tools.py/stable_cli.py, wrappersSMB/PSExec, casos correspondientes, menús04/06 afectados.
**Interfaces:** preview por defecto; operar `enum_smb.sh HOST [PREFIJO] --execute` y `ps_exec.sh HOST DOMINIO USUARIO PASS COMANDO --execute`; generar cualquiera con `--generate DESTINO` incompatible con --execute/argumentos sensibles. `run_smb(host: str, prefix: str | None) -> int`; `run_psexec(host: str, domain: str, user: str, password: str, command: str) -> int`.

- [ ] `test_smb_keeps_all_methods_without_source_mutation`: dos llamadas con argumentos iguales producen mismas operaciones bajo dobles y hash/modo de fuente intactos; sin --execute no llama backend. Mantener shares/RPC/enum4linux/NSE y las siete ADMIN$/IPC$/C$/public/share/documents/backup, con prefijo validado y fallos agregados.
- [ ] `test_psexec_preserves_argv_and_secret_privacy`: comando con espacios/metacaracteres sigue siendo un argumento del backend, sin ejecuciónlocal/eval; contraseña sintética no aparece en UI/generado/log de producto. Con/sin flags/missingposiciones y rcbackend0/1/2 preservados según contrato; no perder primera llamada ni cambiar ruta pública.
- [ ] Observar RED sobre copias confinadas, preservando referencias; luego implementar wrappers estables y dispatch tipado. No materializar payloads mediante ejecución del generador original.
- [ ] Validar host/controles y ambigüedad de campos de credenciales frente al formato de backend; errores claros, no transformaciones silenciosas. No afirmar que el sistema operativo oculta argv ni redacción universal de stdout del backend.
- [ ] Adaptar consumidores y marcas para modos explícitos; mantener ocultación de argumentos PSExec por ruta y todas las entradas. No sustituir SMB por enum_smb_advanced si ello pierde las siete pruebas comunes.
- [ ] Revisión/gate y GREEN de ambos métodos más generación; commit y matriz de capacidades.

### Task 3: Linpeas con selección y privilegios explícitos

**Files:** stable_tools.py/stable_cli.py, wrapperlinpeas, dos casosLinpeas y consumidores06.
**Interfaces:** `linpeas.sh --binary FILE --execute --allow-sudo` o `--download --execute --allow-sudo`; sin ambos permisos no ejecuta. `--generate DESTINO` conserva solo generación. `run_linpeas(binary: Path | None, download: bool, allow_sudo: bool, root: Path, ops: LinpeasOps) -> int`.

- [ ] `test_linpeas_requires_explicit_source_and_sudo`: noargs/preview/generación, binary+download incompatibles, falta --execute o --allow-sudo, ruta inválida/enlace: cero descarga/sudo. No adoptar `linpeas_real.sh` delcwd. Fuente local seleccionada se valida sin seguir enlaces.
- [ ] `test_linpeas_failures_preserve_artifacts`: curl/wget/sudo y script sintético son dobles propios; error de descarga nunca ejecuta, error de sudo no se vuelve éxito por tee, no se reemplazan fuentes/salidas previas. Validar retorno real y permisos privados; conservar parcial y diagnóstico.
- [ ] Revisión/gate y RED, luego implementar. Descarga usa solo URLhttps fija ya existente, hasta60s/16MiB, curl y wget solo si curl está ausente; no instalaciones/URLs nuevas ni descarga en desarrollo. Lo descargado no se presenta como autenticado.
- [ ] Datos nuevos en `scans/linpeas/<uuid>/`700/600; copiar fuente local explícita al run sin adoptar directorios ajenos. Ejecutar backend con argv, sin pipeline que oculte su rc; registrar stdout/stderr privados y ruta, sin prometer control de procesos que escapan.
- [ ] Menú06.2 ofrece subelección explícita local/descarga/cancelar antes de linpeas; añadir dangerous. run_all_post omite linpeas con motivo de selección requerida y no cuenta preview como ejecución completa. No retirar su accesoCLI/menu ni conceder --execute por defecto.
- [ ] Revisión/gate+GREEN de los casos y consumidores; commit e informe sin sudo/descarga reales.

### Task 4: InicializaciónLabs exclusiva y raíces coherentes

**Files:** labs_runtime.py, cinco wrappersSetup, main/setup_lab/run_all_labs y tres casosLabTests.
**Interfaces:** `initialize_lab(kind: str, name: str, output_root: Path | None = None) -> LabResult` inmutable con `path: Path`, `created_notes: bool`; kindscerrados `htb/thm/ad/web/cloud`. CLI original `<NOMBRE>` y opcional `--root DIR`; raíz significa padre inmediato de NOMBRE.

- [ ] `test_five_templates_preserve_existing_notes`: cinco tipos/nuevos, repetición con bytes/modo centinela, READMEvacío y árbolparcial. Segunda inicialización regular conservada retorna0/reuso, nunca append/reemplazo; todas las secciones de las plantillas originales permanecen.
- [ ] `test_lab_roots_names_and_menu_cwd`: default anclado por categoría a `{hackthebox,active_directory,web_apps,cloud}/machines` y`tryhackme/rooms`; raíz alternativa explícita en snapshotnuevo. Mismo resultado desdecwdajeno; espacios/Unicode válidos; vacío,`.`/`..`, separadores/controles rechazados antes de crear.
- [ ] `test_lab_links_and_partial_failure`: enlace/colgante/directorio/FIFO en notas y ancestroenlace, falta de permisos/error de creación y dos inicializaciones concurrentes; ningún referente/nota previa cambia ni se anuncia creación completa falsa. No test-then-write sin apertura exclusiva.
- [ ] Revisión/gate y RED de los tres métodos sobre copias y datos nuevos. ip es doble local; no inspeccionar interfacesreales.
- [ ] Centralizar plantillas como datos y crear README O_EXCL/O_NOFOLLOW, archivos600/directoriosnuevos700; conservar modos de objetos ya existentes. Errorreal retorna1, entradas inválidas2.
- [ ] Wrappers calculan categoría desde su propia ruta. Menú mantiene raíces seleccionadas solo en memoria de sesión, pasa --root explícito y usa la misma ruta para listar/editar; no modifica configscope ni migra/busca notas antiguas. Subshell/rutasabsolutas eliminan cd persistente; mensajes dependen del rc.
- [ ] Si falta informaciónVPN, etiqueta «no comprobada», no ausencia demostrada; conservar campos de plantilla sin volver esa consulta requisito de inicialización. Revisión/gate y GREEN; commit.

### Task 5: ParserCIDR y CLI sin destinos implícitos

**Files:** recon_targets.py, ping_sweep.sh y dos casosReconTests.
**Interfaces:** `parse_ping_targets(network: str, range_text: str = '1-254') -> tuple[str, ...]`; helperCLI privado imprime únicamente un destino por línea, código2 para entrada inválida. La hoja comprueba rc antes de usar mapfile o crear outputs.

- [ ] `test_ping_target_parser`: `192.0.2.7`→unhost; `192.0.2`/`192.0.2.0/24`/`192.0.2.9/24` con1-2→exactamente`.1,.2`;0-255 explícito→256destinos. Rechazar tresoctetos/24, /16, octetos>255, cerosinicialesambiguos, controles/opciones, rango invertido/negativo/>255; IPsola jamás se expande.
- [ ] `test_ping_cli_records_only_selected_targets`: ping/host dobles registran exactamente los destinosanteriores, inválidos0backend/0outputs, missingping/errorbackend no se anuncian hosts simplementeinactivos; retorno1 o diagnóstico de fallo según ejecución, no cobertura completa falsa.
- [ ] Revisión/gate+RED, implementar parser/CLI y propagación de error. Mantener Uso`<red> [rango]` y tipoTEXTO, normalizaciónCIDRvisible, formato/ruta de resultados y distinción entre aportes de esta ejecución e históricos.
- [ ] Revisión/gate+GREEN, commit y documentación. No lanzar run_all_recon ni redreal.

### Task 6: Integración, capacidades y regresión final

- [ ] `LocalMenuTests.test_modes_marks_and_coordinator_omissions`: frontendscentinela verifican modos/gates/ocultación,0/EOF sin despacho, marcasveraces y listaoriginalcompleta; coordinadores no ejecutan automáticamente las nuevas hojas sensibles.
- [ ] Reemplazar expectativas heredadas de auto-reescritura por equivalentes de estabilidad/capacidades; nunca borrar cobertura SMB, PASS tipado, generacionesopcionales o cancelación. No ejecutar runnersheredados en checkout.
- [ ] Actualizar docs04/06/13/recon/MENU, nuevas rutas e ignore; documentar migración sin mover/borrar datos y sin afirmar root/borrados/descargas autorizadas por este plan.
- [ ] Conciliar hashes solo de fuentes intencionalmente cambiadas y sus consumidores, cada una con procedencia. Runtime/manifiestos/IDs exactos revisados, no refresh ciego.
- [ ] Revisión/gate; controlador autoriza por separado `--cross-local`, `--cross-web`, `--cross-consent`, `--suite`. Expected: conjuntos completos sin fallos/errores/bloqueados; omisiones documentadas y artifacts preservados.
- [ ] Revisión final independiente, commit documental y cierre acotado, sin merge/push/global09.

## Self-review / handoff

Diseño§8→Tasks1–3;§9→Task4;§10→Task5; consumidores→Task6. Todas las firmas productoras tienen consumidores definidos; los cinco riesgos tienen casos concretos. Generación no incrusta autorizaciones ni pierde funciones. Plan y onceIDs descartables requieren confirmación explícita; método subagentes retenido.
