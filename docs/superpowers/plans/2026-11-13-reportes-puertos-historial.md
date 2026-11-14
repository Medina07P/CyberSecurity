# Lectores de puertos e historial automático — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Ejecución propia sin subagentes; sin commits, integración ni push automáticos.

**Goal:** Incorporar observaciones de Masscan/RustScan y conservar cada generación de informes en un run exclusivo sin sobrescribir entregas anteriores.

**Architecture:** Añadir un lector específico de puertos al motor existente y una biblioteca de historial con reserva exclusiva y recibo final. La CLI entrega rutas efectivas; el gestor y la fase consumen esos recibos, sin deducir éxito de archivos sueltos.

**Tech Stack:** Python estándar, Bash, unittest y fixtures sintéticas; sin dependencias nuevas.

**Spec:** `docs/superpowers/specs/2026-11-13-reportes-puertos-historial-design.md` (aprobado por el usuario).

## Global Constraints

- No red, resolución DNS, instalaciones, sudo ni ejecución de herramientas.
- No lectura de datos/configuración reales durante pruebas. Conservar los cambios anteriores y los pendientes globales.
- Sin subagentes, commits, integración ni push automáticos, según el flujo acordado.
- Masscan/RustScan aportan observaciones info, nunca vulnerabilidades por abrir un puerto.
- No usar mtime, basename o errores.log compartido para inventar actualidad/finalización.
- Mantener archivos nuevos600 y directorios nuevos700; rechazar enlaces y archivos especiales.
- No migrar/borrar informes antiguos, crear latest ni añadir modo de sobrescritura.
- --salida y REPORT_OUT_DIR son raíces: cada generación crea DIR/runs/run-<UTC>-<uuid>/.
- COMPLETADO significa generación completada, no auditoría completada ni integridad de fuentes.
- Fuera: cambios en productores03, nuevos escaneos, PDF/IA, navegador de históricos, comparación automática y custodia legal.

## Review Focus

- Masscan multiobjetivo con nombre engañoso: ningún host ajeno o su detalle debe llegar al informe seleccionado (Task1).
- Evidencia vacía/conservada por fallo del productor: nunca afirmar último intento correcto o ausencia de puertos (Task1).
- Colisión y generación simultánea con destino existente: reservar runs distintos y no tocar informes previos (Task2).
- Fallo entre documentos y cierre del recibo: run incompleto conservado, sin éxito ni apertura automática (Tasks2–3).
- Cambios de ruta en rerender y fase11: entrada intacta, rutas reales y rc3 distinguido de evaluación completa (Tasks3–4).

## Base, estructura y verificación

Continuar en el worktree nativo actual, ya aislado; **no crear otro worktree
desde HEAD**, porque las correcciones anteriores están sin commit y son la base
funcional. Leer `docs/INFORMES-EVIDENCIAS-2026-11-13.md` y el ledger previo solo
para entender qué está hecho; no modificar sus artefactos ni repetir Tasks1–4.
Crear ledger de ESTE plan mediante el helper de executing-plans; capturar estado
y hashes/modos de fuentes modificables como punto de comparación sin leer datos.

El runner seguro es `bash CyberSecurity-Framework/tests/run_reports_evidence.sh`.
Base anterior:144 tests/rc0/GUARD OK; repetir antes de implementar. Si cambia,
diagnosticar y registrar, no asumir que la base sigue igual. Nuevas pruebas se
añaden a `tests/reports_fixture.py` y al runner ANTES de ejecutar sus casos rojos.
Todo RED/GREEN conserva log propio en el workspace de este plan.

Archivos nuevos:
- `11_Reports/lib/parsers/scanner_ports.py`: reconocimiento estructurado de ambos productores.
- `11_Reports/lib/history.py`: reserva, cierre y reconocimiento de runs publicados.
- `tests/test_reports_ports.py`: parsing/atribución/dedupe/cobertura.
- `tests/test_reports_history.py`: ciclo y fallos de publicación.
- `tests/test_reports_history_integration.py`: CLI/gestor/fase y rutas efectivas.

Las rutas de esa lista son relativas a `CyberSecurity-Framework/`. Los demás
archivos exactos a modificar aparecen en cada tarea. No reorganizar el motor
fuera de esas responsabilidades.

---

### Task 1: Puertos de Masscan/RustScan con confianza y atribución correctas

**Files:** crear `CyberSecurity-Framework/11_Reports/lib/parsers/scanner_ports.py` y `CyberSecurity-Framework/tests/test_reports_ports.py`; modificar `11_Reports/lib/{sources,catalog,engine,model}.py`, `tests/{reports_fixture.py,run_reports_evidence.sh}` bajo el framework.

**Interfaces:**
- Consume `Source`, `ParseResult`, `Finding`, `Evidence`, `catalog.build`, `collect` y las guardas existentes.
- Produce `parse_masscan(path: Path, repo_root: Path) -> ParseResult` y `parse_rustscan(path: Path, repo_root: Path) -> ParseResult`; registrar kinds `masscan` y `rustscan`.
- Descubrir solo `masscan/masscan_*.json` y `rustscan/rustscan_*.txt`; formatos/nombres desconocidos de esos directorios siguen como no soportados.
- Reglas nuevas `masscan.open_port`/`rustscan.open_port`, familia red y técnica real. Clave compartida histórica `nmap.open_port:<proto>:<host>:<port>`; no cambiar IDs existentes de Nmap.
- No añadir campos obligatorios al JSON canónico ni cambiar confianza de reglas ajenas.

- [ ] **Step1 — añadir tests y allowlist.** Los siguientes casos deben tener expectativas literales; escribir cada grupo antes de implementarlo:

  | Test | Entrada y aserciones |
  |---|---|
  | `test_masscan_open_ports_are_observations` | IP192.0.2.10, tcp80/udp53 abiertos → dos info/observacion, puertos/protocolos exactos, evidencia del archivo, sin CVE |
  | `test_masscan_types_and_truncation_are_not_guessed` | puerto True/0/65536, ip inválida, objeto raíz, ports no lista, JSON truncado → sin observaciones de esos registros y no_evaluable |
  | `test_masscan_nonopen_does_not_become_open` | status closed/filtered → cero abiertos; estado desconocido registra limitación |
  | `test_masscan_other_host_never_leaks` | nombre192.0.2.10 pero registros192.0.2.99 → cero del .99 en JSON/Markdown/HTML del .10; misma garantía con archivo mixto y banners-secretos |
  | `test_empty_sources_do_not_claim_clean_scan` | Masscan[], RustScan vacío y `192.0.2.10 -> []` → evaluadoFalse, cero hallazgos, limitación de finalización desconocida |
  | `test_rustscan_exact_formats_and_sgr` | Open192.0.2.10:8080, example.invalid ->[80,443], Open[2001:db8::10]:443 y variantes SGR → puertos TCP correctos; sin DNS |
  | `test_rustscan_control_and_mixed_lines` | escapes no SGR, basura con palabra open, IPv6 ambigua y línea válida → solo registro válido, limitaciones sin copiar cuerpos libres |
  | `test_repeated_ports_are_deduplicated` | dos lectores y XML Nmap en192.0.2.10 tcp80 → una observación, ID Nmap anterior, evidencia combinada y servicio/producto Nmap conservados; udp80 permanece separado |
  | `test_reading_ports_does_not_claim_last_attempt` | archivo RustScan previo más errores.log posterior → ninguna afirmación de último intento correcto; cobertura declara actualidad/finalización no acreditadas |

- [ ] **Step2 — ejecutar RED.** `bash CyberSecurity-Framework/tests/run_reports_evidence.sh > "$WORKSPACE/task1-red.log" 2>&1`; esperado rc distinto0 por lectores ausentes/contratos incumplidos; revisar nombres de fallos, no aceptar fallos de sandbox/importación accidental como prueba del contrato.
- [ ] **Step3 — implementar lectores.** Validar array/registros/puertos y gramáticas completas del spec; host normalizado desde registro, nunca desde banner. Masscan inválido/truncado no se recupera con regex. RustScan retira solo SGR. Duplicados conservan referencia sin repetir observaciones. Líneas inválidas describen formato/posición, no secretos ni IP ajena en texto libre.
- [ ] **Step4 — integrar cobertura y fusión.** Para kinds nuevos, `engine.collect` añade siempre el límite «finalización y actualidad no acreditadas». Una fuente con observaciones válidas puede ser evaluable; vacía sin recibo no. En empate de confianza/gravedad de la MISMA clave de puerto preferir ficha Nmap; enriquecer activo con servicio/producto Nmap si la observación mínima llegó primero. No alterar fusión CVE ni otras reglas.
- [ ] **Step5 — verificar GREEN.** Mismo runner a `task1-green.log`; esperado todos sus tests rc0 y GUARD OK, incluidos los144 existentes salvo cambios de expectativa autorizados de Masscan/RustScan que ahora tienen parser. Registrar qué expectativas se actualizaron y por qué. No commit.

### Task 2: Biblioteca de historial exclusivo con recibo final

**Files:** crear `CyberSecurity-Framework/11_Reports/lib/history.py`, `CyberSecurity-Framework/tests/test_reports_history.py`; modificar `11_Reports/lib/publication.py` solo para reutilizar creación privada sin duplicarla si hace falta, y `tests/{reports_fixture.py,run_reports_evidence.sh}`.

**Interfaces:**
- `ReportRun`: dataclass con `path: Path`, `run_id: str`, `metadata: dict`.
- `reserve(base: Path, objetivo: str | None, modo: str, tipo: str, entrada: str) -> ReportRun`: reserva base/runs/run-<UTC>-<uuid>, sin reemplazar y sin symlinks; UTC con precisión suficiente y UUID aleatorio, no identidad de evidencia.
- `finish(run: ReportRun, files: list[Path], rc: int) -> Path`: acepta rc0/3, valida archivos esperados del tipo, regulares inmediatos de ESE run; publica recibo final y devuelve su ruta.
- `published(run_dir: Path) -> bool`: valida SOLO recibo estructural y existencia no enlazada de documentos esperados, sin leer cuerpos, hashes ni originales; errores devuelvenFalse.
- `has_published(base: Path) -> bool`: recorre solo base/*/runs/run-* y delega en published; base es generated. No lectura de configuración ni de cuerpos técnicos.
- Recibo `run.json`: claves `schema_version=1`, `module="11"`, `run_id`, `started_at`, `finished_at`, `objetivo`, `modo`, `tipo`, `entrada`, `estado`, `rc`, `archivos`. `objetivo` vacío para agregación sin host; modo existente (`objetivo`, `todos`, `incluir_sin_objetivo`); entrada `scans`/`json`.
- ESCRIBIENDO: finished_at/rc nulos, archivos vacíos. Final: estado COMPLETADO/rc0 o NO_EVALUABLE/rc3, finished_at UTC y archivos relativos exactos del tipo MÁS findings.json. El recibo no se incluye en su propia lista; stdout incluirá también run.json.

- [ ] **Step1 — escribir tests del ciclo.** `test_two_reservations_preserve_previous`, `test_parallel_reservations_are_exclusive`, `test_uuid_collision_never_reuses_directory`: reservas distintas bajo mismo base, marcador anterior byte a byte intacto, colisión falla sin mutar. Inyectar UUID determinista solo en el borde de reserva para probar colisión.
- [ ] **Step2 — escribir tests de privacidad/cierre.** `test_new_history_is_private` exige run700/documentos600; `test_links_or_special_files_are_rejected` cubre ancestros, runs, recibo y documentos; `test_finish_accepts_only_expected_local_files` rechaza ../, absoluto ajeno, duplicados, archivo faltante y tipo incorrecto sin cerrar recibo.
- [ ] **Step3 — escribir tests de estado/fallo.** `test_incomplete_never_counts_as_published`, `test_rc3_is_published_but_not_evaluated`, `test_receipt_write_failure_preserves_incomplete_run`, `test_malformed_or_other_module_receipt_is_not_published`: estado ESCRIBIENDO nunca publicado; fallar escritura final conserva recibo inicial y entregaFalse; rc3 final válido sí es presencia, no prueba de evaluación; módulo05 u08 nunca se toma por11.
- [ ] **Step4 — ejecutar RED.** Runner a `task2-red.log`; esperado rc distinto0 por ausencia de biblioteca/contratos. Corregir fallos del harness antes de implementar; ver los casos fallar por el comportamiento esperado.
- [ ] **Step5 — implementar interfaces.** Reserva con mkdir exclusivo; sin reintentar silenciosamente usando directorio colisionado. Reutilizar write_private para recibos. Validar identidad, UTC con zona, tipos exactos sin booleanos como rc/version, set de documentos según tipo y confinamiento. No limpiar runs incompletos ni cambiar permisos de padres existentes. No transacción global ni latest.
- [ ] **Step6 — verificar GREEN.** Runner a `task2-green.log`: rc0/GUARD OK. Biblioteca aún no cambia el destino público de la CLI: ese cambio y actualización de consumidores se hacen juntos en Task3. No commit.

### Task 3: Historial automático en CLI, fase y gestor, sin romper recibos

**Files:** modificar `CyberSecurity-Framework/11_Reports/report_engine.py`, `report_generator.sh`, `run_all_reports.sh`, `CyberSecurity-Framework/cyber_framework.sh`, `00_Config/lib/phase_status.bash`; crear `tests/test_reports_history_integration.py`; modificar `tests/{test_report_engine.py,test_reports_evidence_contract.py,run_reports.sh,reports_fixture.py,run_reports_evidence.sh}`. Rutas sin prefijo en esta tarea son relativas al framework.

**Interfaces:** consume reserve/finish/published deTask2. Conservar `run(argv) -> int` y flags anteriores. `--salida`/REPORT_OUT_DIR seleccionan base; salida por defecto generated/<slug> o generated/_todos cuando --todos. stdout --json conserva resumen y `archivos` absolutos reales, añade `run_id` y usa `salida` para el directorio exclusivo, no base. `archivos` incluye run.json final.

- [ ] **Step1 — tests de rutas y conservación.** `test_cli_generates_distinct_runs_without_overwriting`: dos invocaciones mismo objetivo/base → dos IDs, anteriores intactos, sin documentos fijos nuevos en base; recibo apunta exactamente a documentos del run. Parametrizar --salida, REPORT_OUT_DIR, default y --todos con sesión presente (debe ir a _todos). Tipo tecnico/cliente/ambos produce3/3/5 documentos, más run.json en recibo.
- [ ] **Step2 — tests de fallos/rerender.** `test_invalid_input_does_not_reserve_run`; `test_write_failure_never_returns_receipt_or_opens_old_html` inyecta fallo real de E/S en un write_private del run y comprueba rc1, stdout vacío, run no publicado y anteriores intactos; `test_rc3_has_final_limited_receipt` exige NO_EVALUABLE/rc3; `test_rerender_never_mutates_input_or_reads_sources` exige run nuevo, entrada byte a byte intacta y generado_en UTC nuevo con tiempo controlado en el borde, no sleeps.
- [ ] **Step3 — tests de integración.** `test_menu_uses_receipt_for_custom_history_path` y `test_phase_wrapper_lists_only_current_run` mantienen stub únicamente en xdg-open/acciones externas. `test_phase_status_ignores_incomplete_and_accepts_final_and_legacy` cubre pendiente con ESCRIBIENDO/corrupto/enlaces/archivo faltante, done con rc0/rc3 publicados y done por presencia legacy. No inferir integridad ni auditoría completa de done.
- [ ] **Step4 — ejecutar RED.** Runner con los tests nuevos a `task3-red.log`; esperado rc distinto0 porque CLI todavía usa rutas fijas y fase no entiende recibos. Solo después actualizar los tests antiguos cuyo contrato de ruta/cantidad de archivos cambia; conservar sus pruebas de seguridad y demás aserciones.
- [ ] **Step5 — integrar publicación.** Resolver/validar entrada, objetivo y base antes de reserve. Preparar collected/meta y escribir cada run mediante helper común de CLI para normal/rerender; finish únicamente tras todos los documentos. Emitir stdout/abrir HTML solo después de finish válido. Mantener rc1/3 y metadatos de evidencia, actualizar fecha/generado_en de la nueva generación sin fingir relectura en rerender.
- [ ] **Step6 — integrar fase/consumidores.** Gestor/fase consumen las rutas del recibo; no buscan HTML por glob. En phase_status, helper Python mínimo con ruta de lib explícita importa `history.has_published` y devuelve solo exit status; si falta/no puede validar, ese run no cuenta. Conservar detección legacy y los contratos de otras fases. No buscar salidas personalizadas fuera del árbol normal de la fase.
- [ ] **Step7 — adaptar pruebas de rutas, no esconder fallos.** Tests CLI usan el recibo --json y fixture helper de test para obtener ruta nueva; tests directos de write_reports mantienen su contrato de bajo nivel (no reservan run por sí mismos). run_reports.sh comprueba runs publicados en salida temporal y shim09. Allowlist del runner y fixtures que prueban fase deben incluir history y publication; evitar dependencia circular y no cargar credenciales.
- [ ] **Step8 — verificar GREEN.** Runner a `task3-green.log` con todas las pruebas rc0/GUARD OK. En copia git+overlay de fuentes con HOME/config sintéticos ejecutar run_reports.sh, run_smoke.sh y run_e2e.sh; rc0. No ejecutar suites antiguas en este worktree ni relanzar explotación como smoke test. No commit.

### Task 4: Documentación, regresiones y entrega sin integración

**Files:** modificar `CyberSecurity-Framework/11_Reports/{README,USE,FLUJO}.md`, `docs/MANUAL-GESTOR.md`; crear `docs/INFORMES-PUERTOS-HISTORIAL-2026-11-13.md`. Actualizar solo el estado de este plan/spec y su ledger; conservar documentos/logs anteriores como históricos.

**Interfaces:** explicar nuevos destinos/recibos exactos deTask3, límites deTask1 y estado/finalización deTask2. No agregar funcionalidad adicional en esta tarea.

- [ ] **Step1 — documentar compatibilidad.** Ejemplos con --salida como raíz, directorio exclusivo en recibo, rerender en nuevo run, informes legacy intactos y rc3. Explicar que un parser de puertos no acredita último intento ni escaneo completo; Masscan vacío no es host limpio. Retirar únicamente las afirmaciones de no soporte que ahora cambian; audits09 y formatos desconocidos siguen limitaciones.
- [ ] **Step2 — verificación final dedicada.** Ejecutar runner a `final-suite.log` y leer salida: todos los tests rc0/GUARD OK; no fijar de antemano el número total. Bash -n de archivos tocados capturando stderr; AST de Python sin pycache; git diff --check. Ante fallo, reproducir antes de corregir y conservar RED/GREEN.
- [ ] **Step3 — regresiones seguras.** En nueva copia git+overlay allowlist de fuentes actuales, sin copiar configuración/datos reales, ejecutar run_reports.sh, run_scanners_menu.sh, run_enumeration.sh, run_evidence.sh, run_smoke.sh y run_e2e.sh. Registrar cada rc/log; no afirmar que una suite corrió sobre la última revisión si después se cambió su código. No incluir run_tests.sh como gate verde: su timeout/cuatro fallos anteriores quedan expresamente pendientes; si se vuelve a ejecutar, solo en copia sintética y con limpieza por identidad de fixtures propios.
- [ ] **Step4 — revisión propia separada.** Leer diff completo incluyendo archivos nuevos y contrastar Review Focus con pruebas. Revisar que no hubo cambios en productores03, configuración real, lectura de artefactos privados ni pérdida de capacidades. Registrar decisiones/desvíos y límites de revisión no independiente; no invocar subagentes.
- [ ] **Step5 — entrega.** Anotar base funcional sin commit, rutas de worktree/logs, comandos/resultados reales, cambios de rutas, límites de formatos y pendientes globales. Conservar trabajo/logs; sin commit, merge, push ni borrado del workspace. Integración requiere petición expresa futura.

## Autorrevisión del plan

- [x] Cobertura de spec: parsers/confianza Task1; reserva/recibos Task2; CLI/gestor/fase/rerender Task3; documentación/regresiones Task4.
- [x] Interfaces compartidas fijadas: ParseResult compatible, clave Nmap estable, ReportRun/reserve/finish/published/has_published y recibos con rutas efectivas.
- [x] Review Focus: sus cinco condiciones tienen pruebas asignadas en Tasks1–3.
- [x] Seguridad: conservación de base sin commit, allowlist, pruebas antiguas solo en copia sintética, sin adquisición ni acciones fuera de alcance.
- [x] Pasos comprobables: tests y expectativas observables, RED antes de código, GREEN por tarea, sin commits automáticos.
- [x] Revisión/aprobación de este plan por el usuario antes de implementar.

## Seguimiento de ejecución

- [x] Task1: lectores y fusión; RED/GREEN registrado.
- [x] Task2: historial exclusivo/recibo; RED/GREEN registrado.
- [x] Task3: integración y adaptación de rutas; RED/GREEN registrado.
- [x] Suite dedicada final175/rc0/GUARD OK y sintaxis/diff sin incidencias.
- [x] Task4: seis regresiones definitivas rc0, documentación de resultados y entrega sin integrar; revisión propia, no independiente.

Ledger: `.superpowers/sdd/2026-11-13-reportes-puertos-historial/progress.md`.
No repetir tareas completas; los cambios están SIN commit sobre la base funcional
anterior. Gate global run_tests heredado sigue pendiente, no forma parte de una
declaración de rama completa verde.
