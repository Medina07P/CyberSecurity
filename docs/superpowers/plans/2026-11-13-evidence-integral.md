# Module 10 Integral Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reparar integralmente el módulo 10 manteniendo sus tres entradas, con gestión segura y verificable de evidencias y adquisición explícita.

**Architecture:** Interfaces Bash delgadas y un paquete Python estándar en `00_Config/lib/evidence/`. Almacenamiento, inventario/verificación, exportación y adquisición tienen límites separados; el menú solo prepara argumentos y confirma acciones. Las pruebas usan copias de fuentes permitidas y datos sintéticos, sin herramientas de red reales.

**Tech Stack:** Bash, Python 3 estándar, unittest, stubs de cutycapt/tcpdump/nmap; sin dependencias nuevas.

**Spec:** `docs/superpowers/specs/2026-11-13-evidence-integral-design.md`, aprobado por el usuario el 2026-11-13.

## Global Constraints

- Python 3 estándar, Bash y patrones del proyecto; sin dependencias nuevas.
- El auxiliar se aloja en `00_Config/lib/evidence/` para no aparecer como hoja.
- Directorios nuevos 700, archivos nuevos 600, independientemente del umask.
- No se rehasha evidencia antigua para declararla moderna o confiable.
- No se unen objetivos ni se atribuyen hallazgos por el objetivo de sesión.
- No se ejecutan evidencias, escaneos reales ni suites heredadas sobre datos reales; no se declara toda la rama verde por pruebas de este módulo.
- No se modifica 08, 09, el motor de informes ni se implementa un flujo 99 nuevo. Solo se ajustan las conexiones del gestor/estado necesarias para 10.
- La limpieza solo retira temporales propios de la operación.
- No se hace push.
- Trabajar en `/home/kali/.local/share/opencode/worktree/f6569d/module-10-evidence`, rama `feat/module-10-evidence`, base de producto `3a63550`; diseño en `03f2ba4`. No tocar scope/targets del checkout original ni su evidencia ignorada.
- La ayuda explícita retorna 0, la CLI inválida 2, el fallo operacional/verificación/parcial 1, INT/TERM 130/143. EOF/cancelación del menú retorna 0 sin efectos.
- Antes de cada arreglo, reproducir el defecto con una prueba fallida; antes de cada commit, ejecutar su verificación y revisar el diff. No implementar tareas siguientes para ocultar fallos de una anterior.

## Review Focus

1. Dos procesos importando/exportando simultáneamente, o colisión de ID: ningún registro/paquete ajeno se reemplaza (Tasks 1 y 3).
2. Un error de lectura en un subárbol, o JSON con claves duplicadas/NaN: no desaparece del inventario ni produce verificación positiva (Task 2).
3. Cambio de metadatos/contenido entre inventario, copia y publicación: abortar sin paquete ni registro positivo (Tasks 1 y 3).
4. Hijo que termina pero deja un descendiente con archivos abiertos: no retornar dejando procesos propios o publicar contenido todavía escrito (Tasks 4 y 5).
5. Cancelación/EOF en mitad de prompts y bypass por `--prepared`: no ejecutar ni exportar parcialmente lo seleccionado (Task 7).

---

## Mapa de archivos y decisiones de interfaz

Rutas siguientes relativas a `CyberSecurity-Framework/` salvo `docs/`, `.gitignore` y `AGENTS.md`.

| Archivo | Responsabilidad |
|---|---|
| `00_Config/lib/evidence/__init__.py` | Paquete inerte, sin acceso a datos/import-time effects. |
| `00_Config/lib/evidence/model.py` | Tipos y contratos compartidos de registros/inventarios. |
| `00_Config/lib/evidence/storage.py` | Rutas privadas, acceso regular/no-symlink, copia estable y publicación. |
| `00_Config/lib/evidence/inventory.py` | Esquema nuevo, legacy, inventario y verificación. |
| `00_Config/lib/evidence/package.py` | Snapshot verificado, manifiesto y tar privado. |
| `00_Config/lib/evidence/process.py` | Subprocesos/grupos propios, deadlines, señales y reap. |
| `00_Config/lib/evidence/capture.py` | Plan de captura, validadores, ledger y métodos. |
| `00_Config/lib/evidence/cli.py` | Parsers, despacho, mensajes/rc y coordinación. Ejecutable con Python por ruta. |
| `00_Config/lib/evidence_menu.bash` | Menú, prompts, inventario de hojas, confirmaciones. |
| `10_Evidence/{evidence_manager,auto_capture,run_all_evidence}.sh` | Wrappers que resuelven módulo/helper desde su ubicación, no desde cwd. |
| `tests/evidence_fixture.py`, `tests/run_evidence.sh` | Sandbox/copias allowlist, PATH cerrado y guardas. |
| `tests/test_evidence_{storage,inventory,package,process,capture,cli,menu,runner}.py` | Pruebas por frontera, con nombres explícitos en cada task. |
| `cyber_framework.sh`, `00_Config/lib/{phase_status,module_intro}.bash` | Conexión restringida de 10, introducción y estado liviano. |
| `tests/{run_smoke.sh,test_module_intro.py}` | Ajustes de expectativas del menú 10, sin debilitar guardas. |
| `10_Evidence/{README,USE,FLUJO}.md`, `docs/MANUAL-GESTOR.md` | Contrato del operador, cambios incompatibles y límites. |
| `.gitignore`, `AGENTS.md`, `docs/EVIDENCIAS-INTEGRAL-2026-11-13.md` | Ignorados de temporales, traspaso y evidencia del cierre. |

### Contratos comunes decididos para este plan

- CLI interna: `python3 -B <lib>/evidence/cli.py --root <module> manage|capture|run ...`. Los wrappers calculan y pasan `--root`; el usuario sigue usando las tres CLI aprobadas. Ninguna variable de entorno redefine la raíz productiva silenciosamente. La ruta interna de root permite fixtures explícitos, no añade una CLI pública nueva.
- `model.py`: `EvidenceError(Exception)` para rc 1 y `UsageError(EvidenceError)` para rc 2. Dataclasses `Record(id: str, kind: str, format: str, payload: Path, metadata: Path, target: str | None)`; `Issue(path: Path, code: str, message: str)`; `Inventory(records: list[Record], issues: list[Issue])`; `VerifiedRecord(record: Record, size: int, sha256: str, metadata_size: int, metadata_sha256: str)`; `Verification(entries: list[VerifiedRecord], issues: list[Issue])`, propiedad `ok: bool` exige entries no vacío y cero issues. `format` es `sha256-v1` o `legacy-md5`.
- Nuevos registros: UUID4 hex de 32 caracteres, payload de nombre fijo `artifact`, metadata `evidence.json`; `original_name` solo dato. JSON UTF-8, esquema 1 y claves `schema_version`, `id`, `type`, `original_name`, `stored_name`, `size`, `sha256`, `created_at`, `description`, `origin`, `target`, `run_id`, `method`. `stored_name='artifact'`; `origin='import'|'capture'`; `target` opcional; run_id/method nulos para importación y obligatorios para captura. UTC ISO-8601 con Z. Tamaño entero no booleano; SHA-256 minúsculo de 64 hex. ID y tipo coinciden con ubicación. Campos adicionales desconocidos se rechazan en esquema 1; JSON rechaza duplicados y constantes no finitas.
- Logs internos: `kind='log'`, método `scan` en `logs/results/`, `system` en `logs/audit/`. Solo los cinco tipos originales son importables desde `--add`.
- Nuevos IDs existentes producen fallo sin reemplazo; no se reintenta silenciosamente con contenido distinto. El mecanismo de publicación debe reservar el destino exclusivamente, publicar metadata completa al final y no permitir que una reserva incompleta cuente como registro válido. Staging privado identificable; mientras una operación está incompleta, verificación concurrente puede fallar conservadoramente. No se exige que lectores concurrentes siempre obtengan rc 0.
- Salida humana estable por estados/códigos, no por emojis. Nunca imprimir cuerpos; nombres/descripciones con controles se escapan. El listado vacío es informativo (rc 0), pero verify vacío es rc 1.

## Task 1: Importación privada y wrapper de gestión

**Files:** Create `model.py`, `storage.py`, `__init__.py`, `cli.py`, `tests/evidence_fixture.py`, `tests/test_evidence_storage.py`, `tests/run_evidence.sh` en las rutas del mapa; modify `10_Evidence/evidence_manager.sh` y `.gitignore`.

**Interfaces:**
- Consumes: contratos comunes y tabla de raíces de la spec §5.
- Produces: `storage.add(root: Path, kind: str, source: Path, description: str = '', target: str | None = None, *, origin: str = 'import', run_id: str | None = None, method: str | None = None) -> Record`.
- Produces: `storage.copy_regular(source: Path, destination: Path) -> tuple[int, str]` (creación exclusiva, streaming, tamaño/SHA-256, estabilidad de origen, destino privado), `storage.private_directory(path: Path) -> Path`, `storage.safe_text(value: str) -> str` y `cli.main(argv: list[str] | None = None) -> int`.
- Fixture: `sandbox()` context manager -> `Path`; `copy_sources(root: Path) -> Path` copia allowlist fija y devuelve framework; `closed_env(root: Path, stubs: dict[str,str] | None = None) -> dict[str,str]`; `snapshot(root: Path) -> dict` por lstat sin seguir enlaces. Fixture no importa código de producto antes de cada test que lo necesita ni copia datos de módulo.

- [ ] **Step 1: Escribir regresiones de importación** en `test_evidence_storage.py`: `test_relative_input_uses_callers_cwd`, `test_all_five_public_types`, `test_same_basename_and_second_never_overwrite`, `test_private_modes_under_umask_000`, `test_reject_symlink_ancestor_fifo_device_directory`, `test_changed_source_is_not_published`, `test_copy_or_metadata_failure_has_no_success`, `test_controls_are_escaped`, `test_concurrent_adds_and_forced_id_collision`. Afirmar bytes originales intactos, `stored_name == 'artifact'`, SHA-256 exacto, directorios 0700/archivos 0600, metadata completa y rc no cero en fallos. Simular errores con mocks de operaciones de archivo, no chmod dependiente de root; probar FIFO sin bloquear.
- [ ] **Step 2: Ejecutar RED.** `python3 -B -m unittest discover -s CyberSecurity-Framework/tests -p test_evidence_storage.py -v`; esperar fallos por comportamiento viejo o módulo ausente. Conservar salida con causa, no aceptar un fallo exclusivo de un fixture mal construido.
- [ ] **Step 3: Implementar almacenamiento/importación** y wrapper. Abrir archivos sin seguir enlaces y verificar tipo por descriptor; comprobar ancestros utilizados, identidad/tamaño/mtime antes/después y ruta aún referida al mismo archivo. Copiar con creación exclusiva y permisos explícitos, sin cargar archivos completos en memoria. Metadata privada y publicación sin reemplazo. Si el registro falla, limpiar solo staging/reserva propia comprobada. Descripciones como texto, sin interpretar shell. Wrapper usa `exec python3 -B ... manage "$@"`, no cd al módulo; helper ausente/Python ausente -> error visible rc 1.
- [ ] **Step 4: Implementar parser manage y runner inicial.** `--add`, `--help` y ayuda vacía/sobrantes con rc correcto; `--list/--verify/--package` se añaden en sus tasks, no se simula éxito de comandos aún inexistentes. Runner copia nombres de fuentes/tests permitidos sin buscar en evidencias y usa configuración sintética/PATH cerrado (solo intérpretes/utilidades locales requeridas, todo binario sensible como stub o ausente). Rechazar symlink source. Añadir `10_Evidence/.staging/` a gitignore si se usa staging de raíz; preferir staging anidado ya ignorado por categoría.
- [ ] **Step 5: Ejecutar GREEN** con el comando anterior y `bash CyberSecurity-Framework/tests/run_evidence.sh`; todos los tests existentes pasan, runner devuelve 0 y guardas de contenido/modo del origen intactas. Comprobar `git diff --check` y sintaxis del wrapper con stderr vacío.
- [ ] **Step 6: Commit** de los archivos de esta task: `feat: add private SHA-256 evidence imports`.

## Task 2: Inventario estricto y verificación compatible con legacy

**Files:** Create `inventory.py`, `tests/test_evidence_inventory.py`; modify `model.py`, `cli.py` y allowlist del runner.

**Interfaces:**
- Consumes: `Record`, `Issue`, `Inventory`, `VerifiedRecord`, `Verification`, `safe_text` y acceso regular de Task 1.
- Produces: `inventory.scan(root: Path) -> Inventory` (solo metadata/stat); `inventory.verify(root: Path) -> Verification`; `inventory.read_record(metadata: Path, root: Path) -> Record`. Lectura legacy en el mismo límite, no una migración. `scan` nunca hashea payloads.
- `VerifiedRecord` incluye SHA-256 tanto de contenido como de metadata exactamente leída, incluso legacy; `format` preserva MD5 heredado y su verificación obligatoria. Estos hashes internos se usan para comprobar snapshots de Task 3, no reescriben archivos legacy.

- [ ] **Step 1: Escribir RED**: `test_modified_payload_never_reports_global_success` reproduce contador perdido; `test_empty_inventory_is_not_verified`; `test_list_does_not_read_payload`; `test_legacy_spaces_and_md5_are_read_only`; `test_missing_or_orphaned_payload_or_metadata_fails`; `test_duplicate_json_keys_nan_wrong_version_and_bool_size_fail`; `test_metadata_paths_type_id_and_digest_are_confined`; `test_duplicate_legacy_file_reference_fails`; `test_unreadable_subtree_is_an_issue_not_omitted`; `test_no_follow_symlinks_and_unknown_files_fail`. Afirmar `verify.ok == False` y CLI rc 1 si hay problema, sin el mensaje de todas íntegras; legacy correcto -> rc 0 con advertencia MD5, snapshots históricos idénticos.
- [ ] **Step 2: Ejecutar** `python3 -B -m unittest discover -s CyberSecurity-Framework/tests -p test_evidence_inventory.py -v`; confirmar fallos por funcionalidad pendiente.
- [ ] **Step 3: Implementar scan/verify**. Recorrer las seis categorías conocidas sin seguir symlinks; ausentes no son error, inaccesibles sí. Reconocer exactamente registros nuevos y sidecars legacy. Legacy: separar clave y valor por primer `:`, preservar espacios de FILE salvo el único espacio de formato; basename seguro, TYPE conocido, HASH MD5 válido; exigir campos del formato original, permitir DESCRIPTION vacía y valores informativos no interpretados. Rechazar duplicados de claves de identidad/hash y referencias repetidas. Ignorar solo `.gitkeep` de directorios, nunca archivos desconocidos de contenido. Si un legacy importado se llama `foo.meta`, su sidecar será `foo.meta.meta`: resolver pares por referencias y no descartar todos los nombres `.meta` ciegamente. Si hay ambigüedad, fallo explícito.
- [ ] **Step 4: Conectar `--list` y `--verify`** a cli: listado declara `NUEVA — NO VERIFICADA`, `HISTÓRICA MD5 — NO VERIFICADA`, `SIN METADATOS` o `INVÁLIDA`, sin fingir que un hash se acaba de verificar. Verify muestra cada error y resumen veraz, `SIN EVIDENCIAS` rc 1 si vacío. Reservar `logs/runs/` para ledger válido de Task 4; hasta existir su esquema, un árbol desconocido no se excluye silenciosamente.
- [ ] **Step 5: Ejecutar GREEN** prueba de inventario, Task 1 y runner. Añadir caso `test_legacy_payload_named_meta_is_not_lost` al mismo ciclo RED/GREEN. Ninguna llamada a md5sum, grep, herramientas remotas o reescritura de históricos.
- [ ] **Step 6: Commit**: `fix: verify new and legacy evidence without false success`.

## Task 3: Exportación verificable y sin sobrescrituras

**Files:** Create `package.py`, `tests/test_evidence_package.py`; modify `cli.py`, `.gitignore` y runner.

**Interfaces:**
- Consumes: `inventory.verify(root) -> Verification`, `VerifiedRecord`, primitivas seguras de Task 1.
- Produces: `package.create(root: Path, name: str | None = None) -> Path`; `package.check_archive(path: Path) -> None` (lanza EvidenceError si el archivo temporal no coincide exactamente con el manifiesto; uso interno y en pruebas, no nueva CLI pública).
- Manifiesto schema 1: `schema_version`, `id`, `created_at`, `records` (`id`, `format`, `type`, rutas de payload/metadata), `members` (por miembro `path`, `size`, `sha256`), sin entrada autorreferente para manifest. Todos los miembros regulares, rutas relativas POSIX. Nombre por defecto `YYYYMMDD_evidence`; nombres explícitos `[A-Za-z0-9][A-Za-z0-9_-]{0,79}`, sin `.`, `/`, `\\` ni controles.

- [ ] **Step 1: Escribir RED**: `test_archive_contains_metadata_manifest_not_code`, `test_no_manifest_txt_is_touched`, `test_invalid_or_empty_inventory_blocks_publication`, `test_legacy_metadata_is_included_unchanged`, `test_package_name_cannot_escape`, `test_two_exports_and_forced_collision_never_replace`, `test_payload_or_metadata_changes_during_snapshot_abort`, `test_tar_or_output_failure_leaves_no_final_package`, `test_archive_member_set_and_hashes_are_exact`. Comprobar byte a byte metadata legacy, tar sin symlinks/absolutos/`..`, fuente/config/code/diagnósticos excluidos, permisos privados y ningún éxito por un archivo previo existente.
- [ ] **Step 2: Ejecutar** `python3 -B -m unittest discover -s CyberSecurity-Framework/tests -p test_evidence_package.py -v` y conservar el fallo inicial.
- [ ] **Step 3: Implementar create/check_archive** con staging privado dentro de `11_Reports/evidence/`. Copiar payload/metadata a snapshot y comparar tamaños/SHA-256 con `VerifiedRecord`, incluidos cambios de metadata. Volver a contrastar inventario y fuentes antes de publicar; cambio de miembros, referencia o contenido aborta. Exportar únicamente snapshot estable (no tar directo de fuentes vivas). Verificar tar temporal contra manifiesto con lectura streaming; publicar archivo final por creación/enlace exclusivo, sin `os.replace` sobre un paquete ajeno. No extraer el tar para validarlo.
- [ ] **Step 4: Conectar `--package [NOMBRE]`**: ayuda advierte confidencialidad y ausencia de cifrado; comando explícito no pide input interactivo. Rechazo de todos los problemas detectados, sin `--force`. Añadir ignorado de staging privado de exportación; conservar ignorado existente `11_Reports/evidence/*.tar.gz`.
- [ ] **Step 5: Ejecutar GREEN** pruebas de paquete + runner; comprobar snapshots de originales, código e históricos sin cambios, incluso ante fallo. Tests de intercalado/mocks fuerzan el cambio exactamente durante copia, no con sleeps de carrera.
- [ ] **Step 6: Commit**: `feat: export verified evidence snapshots with manifests`.

## Task 4: Supervisor de procesos y ledger de adquisiciones

**Files:** Create `process.py`, base de `capture.py`, `tests/test_evidence_process.py`; modify `inventory.py`, runner.

**Interfaces:**
- Consumes: `private_directory`, `EvidenceError`.
- Produces en `process.py`: `ProcessResult(returncode: int, timed_out: bool, stopped_by: str | None)`; `run_child(argv: list[str], stdout: Path, stderr: Path, *, timeout: float, interval_stop: bool = False) -> ProcessResult`; `CaptureInterrupted(EvidenceError)` con atributo `signum: int`.
- Cada hijo en sesión/grupo propio; conservar ownership hasta terminar grupo, incluso si líder sale primero. No capturar stdout/stderr en RAM. SIGINT/SIGTERM del controlador provoca limpieza y `CaptureInterrupted`; CLI traduce 130/143. Un grupo que requiere terminación forzada queda indicado por `stopped_by` y nunca habilita publicación exitosa de artefactos aunque el líder retornase 0.
- Produces en `capture.py`: `RunLedger(root: Path, actions: list[str])`, atributos `id: str`, `path: Path`; métodos `start(action: str) -> None`, `finish(action: str, status: str, rc: int | None, reason: str | None, evidence_ids: list[str]) -> None`, `close(status: str) -> None`. Acciones únicas en orden fijo web/traffic/scan/system.
- `run.json`: schema 1, ID, UTC started/finished, estado global y acciones con estado/tiempos/rc/causa/IDs; estados `pending`, `running`, `success`, `no-traffic`, `failed`, `interrupted`, `not-run`; stdout/stderr por acción en nombres fijos. Reservar `work/` para salidas no publicadas, siempre diagnósticas. Lectura del ledger valida esquema y nombres, no enumera contenido como evidencia.

- [ ] **Step 1: Escribir RED**: `test_deadline_stops_and_reaps_owned_group`, `test_parent_only_int_term_returns_130_143`, `test_descendant_remaining_after_leader_exit_is_stopped`, `test_unrelated_process_is_not_signalled`, `test_streams_are_private_and_failures_visible`, `test_run_ledger_is_not_evidence`, `test_malformed_run_directory_is_reported`. Usar stubs Python propios y pipes/archivos de readiness con timeout de seguridad del test, no binarios de red ni esperas ciegas. En esta task un harness mínimo convierte CaptureInterrupted en 130/143; las pruebas del wrapper real se añaden en Task 6, sin depender aquí de código futuro.
- [ ] **Step 2: Ejecutar** `python3 -B -m unittest discover -s CyberSecurity-Framework/tests -p test_evidence_process.py -v`; confirmar RED.
- [ ] **Step 3: Implementar supervisor** con `Popen(start_new_session=True)`, monitor de deadline y grupos Linux; al terminar el líder comprobar que no quedan descendientes que escriban. Parada normal de tráfico: SIGINT, gracia 2 s, SIGTERM 2 s, finalmente SIGKILL y reap. Otros deadlines: SIGTERM 2 s, SIGKILL y reap. Señales del controlador: detener grupo y esperar, preservar signum. Si un descendiente abandona explícitamente la sesión no se promete contención contra backend hostil; documentar ese límite, no matar por búsquedas de nombres de procesos. Restaurar handlers del llamador.
- [ ] **Step 4: Implementar ledger privado** y su validación en inventario. `logs/runs/<id>/` válido se excluye del conteo con aviso; archivos arbitrarios a ese nivel o run.json inválido son issues, nunca evidencia verificada. Ledger fallido válido no invalida evidencia previamente importada; solo describe la adquisición y sigue excluido del paquete.
- [ ] **Step 5: Ejecutar GREEN** proceso/ledger y runner. Afirmar hijos/descendientes propios terminados, proceso ajeno vivo, salida limitada al sandbox, registros interrumpidos no publicados como éxito.
- [ ] **Step 6: Commit**: `feat: supervise evidence capture processes and private run logs`.

## Task 5: Métodos de adquisición explícitos y validación de artefactos

**Files:** Extend `capture.py`; create `tests/test_evidence_capture.py`; modify runner allowlist.

**Interfaces:**
- Consumes: `run_child`, `RunLedger`, `storage.add(... origin='capture', run_id=..., method=...)`.
- Produces: dataclass `CapturePlan(web: str | None = None, traffic: str | None = None, interface: str | None = None, scan: str | None = None, scan_profile: str | None = None, system: bool = False, duration: int = 10, packet_limit: int = 100, authorize_network: bool = False)`; `validate_plan(plan: CapturePlan) -> None`; `capture(root: Path, plan: CapturePlan) -> int`.
- Produces: `validate_png(path: Path) -> None`, `pcap_packet_count(path: Path) -> int`, `validate_nmap(path: Path, host: str) -> None` para que las pruebas de formato no ejecuten subprocesos. Fallos -> EvidenceError, inputs inválidos -> UsageError.
- Deadlines decididos: web 60 s, scan basic 120 s, full 1800 s; tráfico duración 10 s (1–300), límite 100 (1–10000). Deadline no configurable en esta versión salvo duración de tráfico; pruebas inyectan reloj/supervisor por mocks, no amplían CLI.

- [ ] **Step 1: Escribir RED de validación**: `test_no_action_no_network_or_file_side_effects`, `test_network_requires_authorize_before_tool_or_ledger`, `test_duration_packet_bounds_and_required_pairs`, `test_host_url_interface_reject_option_filter_and_path_injection`, `test_https_port_path_and_ipv6_are_preserved`, `test_system_is_operator_not_target`. IPs con `ipaddress`, dominios ASCII por etiquetas (incluido localhost), sin CIDR, controles, wildcard, cadenas que empiezan por `-`; IPv6 literal permitido, sin zone ID. Interfaz Linux no vacía, sin espacios/control ni prefijo `-`, máx. 15 caracteres. URL http/https con host y puerto válido, sin userinfo/fragmentos/backslash/whitespace; no aceptar URL sin esquema. Opciones de tráfico sin traffic/perfil sin scan -> rc 2.
- [ ] **Step 2: Ejecutar RED** `python3 -B -m unittest discover -s CyberSecurity-Framework/tests -p test_evidence_capture.py -v`.
- [ ] **Step 3: Implementar validate_plan y acciones** en orden fijo, sin shell ni sudo/instalación. Dependencia ausente -> acción failed y rc global 1; otras seleccionadas pueden continuar. Cada método usa `work/` del ledger y solo importa tras finalizar todos sus escritores y validar. System usa stdlib (`getpass`, `socket`, `platform`, UTC), no entorno completo ni atribución remota.
- [ ] **Step 4: Añadir RED por backend**: `test_cutycapt_failure_or_non_png_never_imports`, `test_tcpdump_clean_interval_zero_packets_is_no_traffic`, `test_truncated_or_wrong_pcap_is_failed`, `test_nmap_basic_has_100_ports_no_nse_or_version`, `test_nmap_full_has_all_ports_version_no_min_rate`, `test_nmap_rc_or_missing_completion_never_imports`, `test_partial_run_is_rc1_and_only_successes_published`, `test_interrupt_does_not_publish_active_step`, `test_capture_then_package_excludes_failed_diagnostics`. Stubs escriben formatos mínimos sintéticos y registran argv; pruebas no llaman binarios reales.
- [ ] **Step 5: Implementar backend/validadores**. Cutycapt `--url=<URL> --out=<private path>`, rc 0, cabecera PNG de 8 bytes y bytes adicionales. tcpdump `-U -n -c N -i IFACE -w PATH host HOST`; aceptar pcap clásico endian/micro/nanosegundos, validar cabecera global y recorrer cabeceras/longitudes de paquetes hasta EOF (sin cargar archivo entero), rechazar truncamientos; cero paquetes válido `no-traffic`. Requerir rc 0 o cierre por SIGINT de intervalo sin escalado forzado; no importar tras SIGKILL ni si el supervisor tuvo que forzar el cierre de escritores restantes. Nmap `-n -sT --top-ports 100` o `-n -sT -sV -p-`, `-oN PATH HOST`; sin NSE/min-rate/sudo. Exigir rc 0 y footer `# Nmap done at ... -- ...` del formato normal `-oN`; una línea eco que contenga `Nmap done` no basta. Guardar stdout y stderr en ledger aunque haya salida `-oN`. No convertir puertos abiertos en hallazgos de vulnerabilidad.
- [ ] **Step 6: Ejecutar GREEN** captura, procesos y runner; afirmar artefactos nuevos verificables, éxito parcial global rc 1, ningún backend invocado si validación falla y confidencialidad de diagnósticos. Comprobar también límites exactos 1/300 s y 1/10000 paquetes.
- [ ] **Step 7: Commit**: `feat: acquire evidence only through explicit bounded actions`.

## Task 6: CLI de captura y coordinación sin éxito falso

**Files:** Modify `cli.py`, `10_Evidence/auto_capture.sh`, `10_Evidence/run_all_evidence.sh`; create `tests/test_evidence_cli.py`; update runner.

**Interfaces:**
- Consumes: gestión Tasks 1–3 y `CapturePlan`, `validate_plan`, `capture` de Task 5.
- Produces: `cli.main` completo para manage/capture/run; `run --offline` o `run --capture <opciones>`. Wrappers preservan argv/cwd/rc mediante exec; no ejecutan hermanos ni reinterpretan argumentos.

- [ ] **Step 1: Escribir RED**: `test_all_wrappers_help_missing_extra_args_and_external_cwd`, `test_legacy_target_returns_2_without_launching_tools`, `test_offline_never_calls_capture`, `test_capture_list_verify_failures_are_not_swallowed`, `test_signal_rc_not_replaced_by_followup_verify`, `test_spaces_in_import_and_description_survive_wrapper`, `test_invalid_options_leave_roots_absent`. Afirmar rc exactos 0/1/2/130/143; `--capture` no puede coexistir con `--offline`; `--offline` no acepta opciones de red.
- [ ] **Step 2: Ejecutar RED** `python3 -B -m unittest discover -s CyberSecurity-Framework/tests -p test_evidence_cli.py -v`.
- [ ] **Step 3: Implementar parsers completos** con argumentos explícitos, sin parse_known_args que oculte errores ni duplicados silenciosos de selectores. Validar todo antes de crear ledger o lanzar acción. `--system` no requiere flag de red; `--authorize-network` solo no selecciona ninguna acción. Help en español, cero efectos de escritura; error operacional claro sin traceback por fallos esperados.
- [ ] **Step 4: Implementar coordinación**: offline lista y verifica, rc 1 si vacío/error; capture ejecuta plan y luego listado/verificación, manteniendo rc 1 si cualquier etapa falla aunque otra pase. INT/TERM no continúa con etapas posteriores y preserva 130/143. Resumen distingue completo/parcial/fallido/sin evidencia; nunca usa un mensaje global de éxito tras fallo. La invocación `<TARGET>` imprime guía de selección explícita rc 2 y no extiende scope.
- [ ] **Step 5: Ejecutar GREEN** CLI y runner desde raíz y cwd temporal. Probar stdin cerrado para CLI explícitas (no deben quedarse esperando confirmación interactiva), Python ausente en PATH -> wrapper rc 1 visible y sin fallback a backend real.
- [ ] **Step 6: Commit**: `fix: propagate evidence workflow outcomes and require explicit capture`.

## Task 7: Menú seguro, inventario fijo y estado liviano

**Files:** Create `00_Config/lib/evidence_menu.bash`, `tests/test_evidence_menu.py`; modify `cyber_framework.sh` (sources, execute_script, run_module_scripts, module_evidence y leyenda 10), `00_Config/lib/phase_status.bash`, `00_Config/lib/module_intro.bash`, `tests/run_smoke.sh`, `tests/test_module_intro.py`, runner.

**Interfaces:**
- Consumes: tres wrappers y contratos CLI de Task 6, `ask_confirm` del gestor.
- Produces funciones Bash `evidence_original_entries`, `evidence_read`, `evidence_prepare`, `evidence_execute_script`, `evidence_menu`; `EVIDENCE_ARGS` array local dinámico como patrón de 08. Preparación pasa líneas completas como valores, no eval/shlex para rutas. Dispatch solo admite las tres rutas exactas no enlazadas. `execute_script` deriva 10 antes de cualquier cd/chmod/prompts genéricos.
- Menú fijo: 1 disponibilidad (`command -v python3 cutycapt tcpdump nmap`), 2 importar, 3 listar, 4 verificar, 5 empaquetar, 6 captura seleccionada, 7 flujo offline, 8 guía local, 9 tres entradas originales, 0 volver. Invocación avanzada de auto/run usa los mismos prompts/confirmaciones, no parser shell libre.
- `_evidence_has_records(root)` en phase_status: sondeo Bash de metadatos/pares regulares sin symlinks, no auxiliar Python en banner. Registros nuevos: directorio ID hex, `evidence.json` y `artifact` regulares; no certifica schema/hash. Legacy: metadata regular con FILE basename seguro y companion regular, sin leer payload ni hashear. Examinar todas las seis categorías conocidas y omitir logs/runs. `done` significa presencia reconocible, incluso si contenido luego falla verify, no integridad.

- [ ] **Step 1: Escribir RED**: `test_enter_exit_eof_and_help_have_no_effects`, `test_availability_never_executes_binaries`, `test_fixed_inventory_never_discovers_evidence_code`, `test_prepared_and_direct_dispatch_reject_unknown_and_symlink`, `test_cancellation_at_each_prompt_never_runs_partial_action`, `test_prepared_capture_and_package_still_confirm`, `test_import_paths_spaces_not_session_target`, `test_arguments_and_credentials_not_echoed`, `test_phase_all_categories_legacy_not_diagnostics`, `test_phase_never_reads_payload_or_invokes_python`. Añadir sentinelas de config/HOME/evidencia y stubs fail-closed.
- [ ] **Step 2: Ejecutar RED** `python3 -B -m unittest discover -s CyberSecurity-Framework/tests -p test_evidence_menu.py -v`; confirmar que descubrimiento viejo admite una hoja sintética de datos y que nuevo contrato aún no está implementado.
- [ ] **Step 3: Implementar menú/dispatch** con source inerte, ficha existente y cabecera reconocible de integración. Cancelar `0`/`!`/EOF retorna sin acciones. Captura pide selección y campos explícitos, muestra acciones/límites/perfil y pide confirmación antes de añadir `--authorize-network`. `--system` exige selección pero no autorización de red. Package confirma que puede incluir credenciales sin cifrado. No eximir confirmación por `--prepared`. Help/list/verify no requieren confirmación de red. Validar hojas no enlazadas y padres esperados antes de bash; no chmod. Lista original usa inventario fijo también en run_module_scripts.
- [ ] **Step 4: Implementar sondeo de fase y texto**. No copiar runtime de 08 ni modificar otros dispatches. Explicar en leyenda/ayuda que asterisco 10 es presencia, no integridad. Ficha mantiene propósito `Gestionar y capturar evidencia` y advertencia de escaneo/tráfico con acciones ahora explícitas. Ajustar smoke para navegar menú 10 -> originales sin perder prueba de modo manual de evidence_manager; adaptar test_intro si depende de menú genérico, conservando snapshot y prohibición de ejecutar herramientas. No ejecutar full_workflow como test; probar solo su dispatch aislado si necesario.
- [ ] **Step 5: Ejecutar GREEN** tests de menú y runner; `python3 -B -m unittest discover -s CyberSecurity-Framework/tests -p test_module_intro.py -v` (fuentes UI copiadas, ninguna evidencia real); inspeccionar primero fixture actualizado para permitir únicamente herramientas de lectura requeridas. Smoke completo solo en copia limpia sintética (Task 8).
- [ ] **Step 6: Commit**: `feat: add safe evidence menu and metadata-only phase presence`.

## Task 8: Guardas, documentación, revisión final e integración local

**Files:** Create `tests/test_evidence_runner.py`, `docs/EVIDENCIAS-INTEGRAL-2026-11-13.md`; modify `tests/run_evidence.sh`, `10_Evidence/{README,USE,FLUJO}.md`, `docs/MANUAL-GESTOR.md`, `AGENTS.md`, este plan/progreso.

**Interfaces:**
- Consumes: Task 1 fixture/runner y todas las interfaces completas.
- Produces: runner definitivo allowlist, logs de verificación privados bajo `/tmp/opencode/`, documentación/traspaso y rama revisada lista para integración local. No afirmar compatibilidad con capturadores reales por usar stubs.

- [ ] **Step 1: Escribir RED de guardas**: `test_runner_copies_only_fixed_sources_and_synthetic_config`, `test_runner_rejects_source_symlinks`, `test_runner_never_runs_backend_from_host_path`, `test_runner_detects_source_content_or_mode_changes`, `test_documented_commands_match_parser`. Colocar evidencias/config sintéticas venenosas en fixture del runner: no se copian, abren o ejecutan. Guardar en logs resultado/rc/commit y conjuntos de fuentes usados. Runner detecta cambios del origen de fuentes permitidas por hash/modo y layout; no hashea evidencia real para demostrar preservación.
- [ ] **Step 2: Ejecutar RED** `python3 -B -m unittest discover -s CyberSecurity-Framework/tests -p test_evidence_runner.py -v`.
- [ ] **Step 3: Completar runner y guías**. README/USE/FLUJO y manual incluyen cinco tipos, rutas con espacios, SHA-256/legacy, vacío/error, ausencia de atribución automática, empaquetado bloqueante/no cifrado, red explícita, límites/deadlines/perfiles, PNG/PCAP/Nmap validación limitada, permisos, supervisión/señales, cambio de TARGET y limitaciones de 99. Ejemplos solo reservados/sintéticos y no comandos que tests ejecuten en red. AGENTS registra alcance exacto y preserva notas previas.
- [ ] **Step 4: Ejecutar verificación dedicada**: `bash CyberSecurity-Framework/tests/run_evidence.sh`; todos los tests nuevos rc 0, guardas OK. Sintaxis `bash -n` de cada .sh/.bash cambiado capturando stdout/stderr: rc 0 **y stderr vacío**. AST parse de cada .py nuevo/cambiado con `python3 -B`, no py_compile. `git diff --check` sin incidencias.
- [ ] **Step 5: Ejecutar regresiones relacionadas solo en copia limpia sintética**. Construir copia desde `git archive HEAD` de fuentes versionadas (tras commits de implementación), sustituir scope/targets/session y HOME antes de lanzar pruebas; no copiar ignorados. Inspeccionar cada script y fixture antes de ejecutarlo. Suites candidatas: `tests/run_smoke.sh`, `tests/run_e2e.sh`, `tests/run_reports.sh`, `tests/run_config_menu.sh`, `tests/run_forensics.sh` y `test_module_intro.py`; registrar suites finalmente elegidas/descartadas y motivo, rc, totales y commit. `run_tests.sh` completa es opcional y solo en esa copia: comparar fallos heredados, no declarar rama verde ni repararlos fuera de alcance. Si una suite segura falla, diagnosticar antes de declarar cierre; un fallo nuevo de integración bloquea integración.
- [ ] **Step 6: Commit de cobertura/docs**: `test: verify isolated evidence workflows and document contracts`. Dejar ledger de tareas, fallos/deferred reales y logs asociados. No inventar históricos ni dar por hecho que una revisión siguiente aprobará.
- [ ] **Step 7: Revisión independiente de especificación y calidad** usando requesting-code-review; comparar base `3a63550` con HEAD, examinar criterios §10 y Review Focus. Si se elige método con subagentes habrá además gates por task; si ejecución nativa, revisión fresca de rama completa aquí. Resolver observaciones en ciclos TDD y repetir pruebas afectadas + suite dedicada sobre HEAD final. No integrar con observaciones bloqueantes abiertas.
- [ ] **Step 8: Preparar integración local verificada** usando finishing-a-development-branch. Comprobar estado actual de `develop` y checkout original sin abrir secretos; guardar hash/modo de sus dos archivos modificados conocidos sin imprimir contenido. No stash/reset/discard ni integrar si surge solapamiento no previsto. Si develop avanzó, actualizar rama sin reescribir trabajo ajeno y repetir regresiones sobre el candidato. Con revisión aprobada y fast-forward posible, `git merge --ff-only feat/module-10-evidence` desde checkout develop; si no, presentar estado y pedir decisión sobre integración no fast-forward. Verificar HEAD integrado y hashes/modos originales preservados; conservar worktree y logs. Sin push. Si integración no es segura, dejar rama lista e informar bloqueo, no forzarla.

## Matriz de cobertura y autorrevisión del plan

| Spec | Entrega / prueba |
|---|---|
| §1–3 intención, hallazgos, límites | Task 1 fixtures + regresiones por defecto; Task 8 traspaso/revisión/integración. |
| §4 wrappers/CLI/códigos | Tasks 1 y 6; test_evidence_cli. |
| §5 categorías, importación, privacidad | Task 1 + logs internos en Task 5. |
| §6 schema, legacy, huérfanos, vacío | Task 2; namespace de ledger Task 4. |
| §7 paquetes/manifiesto/no overwrite | Task 3; confidencialidad menú Task 7. |
| §8 web/tráfico/scan/system/límites/señales | Tasks 4–6; fake backends y pruebas de reap. |
| §9 menú/allowlist/estado | Task 7 y regresiones de UI. |
| §10 tests/compatibilidad/documentación | Todas las tasks, guardas y cierre en Task 8. |
| §11 aprobación y ejecución posterior | Aprobación de diseño registrada; este plan espera revisión y elección de ejecución. |

Autorrevisión: firmas compartidas definidas antes de consumirse; capture no usa
CLI para llamar storage, y package consume snapshots verificados, no salida
humana. Review Focus tiene pruebas en las tasks propietarias. No se promete
verificación de contenido por el listado ni el banner. No hay dependencia nueva,
instalación, migración automática o permiso para ejecutar herramientas reales.
Cada task tiene RED/GREEN y commit; las correcciones de revisión siguen el mismo
ciclo. El plan no autoriza omitir gates ni declarar integridad jurídica.
