# Compatibilidad09 tras incorporar develop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recuperar compatibilidad de informes, preflight, pruebas aisladas y ficha09
después del merge local66a61f5, sin revertir los arreglos de develop ni cerrar09
prematuramente.

**Architecture:** Conservar motor11 y su historial por generación;09 consume el
recibo de su propia invocación, no busca el informe más reciente. Actualizar
inventarios exactos de fuentes/dependencias y contratos de interfaz, manteniendo
la barrera de pruebas heredada y los permisos explícitos del producto.

**Tech Stack:** Python3, Bash, unittest, launcher existente Bubblewrap/seccomp/Landlock.

**Spec:** `docs/superpowers/specs/2026-11-13-automation-integral-design.md` y
`docs/superpowers/specs/2026-11-13-automation-test-isolation-design.md`, con los
rulings de sus dos ledgers; contrato vigente11 en `11_Reports/USE.md`.
Este plan concreta la reparación de compatibilidad bajo la ampliación de alcance
del usuario; no modifica las políticas operacionales ni autoriza ejecuciones.

## Global Constraints

- BASE:66a61f5adbfdc0a38ced0b4689191509935da5ad, worktree09 existente.
- Sin push, merge inverso, instalaciones, sudo, herramientas reales ni red externa.
- Preservar fuentes ajenas, configuración, evidencia, logs y todos los runs previos.
- No ejecutar framework/tests/helpers/probes/imports del repo en el host.
- Revisión estática independiente de la combinación completa ANTES de cualquier
  lanzamiento; autorización separada del controlador para el comando exacto.
- Único selector de integración previsto: `python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --suite`.
- Probes primero; Landlock ABI>=3 obligatorio; no fallback ni ampliación implícita
  de los25IDs de descartables sintéticos. Los fixtures finales se conservan.
- No cambiar el significado de rc0/3 del motor, agregado09, preview ni permisos.
- No llamar al resultado histórico60/168 una prueba de este merge.

## Review Focus

- Recibo que apunta a un run ajeno, objetivo distinto o ruta con enlaces: rechazar.
- Motor devuelve0/3 sin recibo o sin archivos completos: no publicar históricos.
- Dos pasos report en un plan: separar perfiles, recibos y generaciones.
- Dependencia transitiva ausente: rechazar todo el plan antes de cualquier paso.
- Entrar09 para consultar/cancelar: mostrar ficha sin heredar sesión ni ejecutar backend.

## Archivos y responsabilidad

- `00_Config/lib/automation/reporting.py`: dependencias, comando11 y validación de generación.
- `09_Automation/python/report_generator.py`: compatibilidad de publicación externa.
- `tests/automation_fixture.py`, `automation_sandbox_sources.json`: cierre exacto de fuentes copiadas.
- `tests/test_automation_reports.py`: recibos, publicación, aislamiento entre pasos y preflight.
- `tests/test_automation_sandbox_integration.py`: baseline conciliado, no regenerado a ciegas.
- `00_Config/lib/automation_menu.bash`, `module_intro.bash`: ficha09 coherente con el producto.
- `tests/test_module_intro.py`, `test_automation_cli.py`, `test_automation_contract.py`: contratos estáticos/UI.
- `docs/MENU-OPCIONES.md`, manual/USE09: describir combinación actual y límites.

Rutas anteriores relativas a `CyberSecurity-Framework/`, salvo `docs/`.

### Task 1: Restablecer cierre exacto de fuentes para la verificación aislada

**Interfaces:** consume inventarios exactos y25IDs existentes; produce fixtures
que contienen las fuentes actuales requeridas, sin ampliar montajes/runtime/grants.

- [ ] Contrastar imports y sources de motor11, gestor y menús10/09 contra
  `automation_fixture.py` y `automation_sandbox_sources.json` como datos.
- [ ] Incorporar únicamente fuentes requeridas concretas, incluidas dependencias11,
  `module_intro.bash`, `evidence_menu.bash` y núcleo10 necesario al gestor.
- [ ] Conciliar baseline del test de integración por archivo con commits originales;
  documentar motivo de cada digest cambiado, sin aceptar automáticamente toda diferencia.
- [ ] Mantener discovery y selección cerrados; no añadir otros runners ni suites
  con cleanup heredado al selector09. Contratos de module_intro solo estáticos
  o incorporados expresamente a una revisión posterior, no ejecutar su runner aquí.
- [ ] Revisión estática independiente del diff y del launcher sin ejecutarlo.
- [ ] Tras gate y autorización exacta, observar suite sobre el merge, conservando
  fallos reales de informes como RED; registrar cualquier bloqueo como BLOCKED,
  no como éxito ni fallo funcional. No relajar el aislamiento para reproducir.

### Task 2: Consumir solo la generación11 producida por el paso actual

**Interfaces:** mantener `report_command(step, run_dir, ctx) -> Command` y
`publish_reports(source, destination, parent_identity) -> None`.
Añadir `report_generation(run_dir: Path, step_id: str, target: str, rc: int) -> Path`
en reporting: resuelve y valida el recibo de la invocación de ese paso.

- [ ] Extender los casos existentes `test_legacy_output_names`,
  `test_report_engine_rc3`, `test_shim_does_not_trust_stale_reports_or_rc0_without_output`
  y `test_real_copied_engine_filters_target_and_no_evaluable_rc3` para el historial11.
  Actualizar doubles a `--json` y generación/recibo reales; no seguir produciendo
  archivos planos incompatibles. Conservar los mismos IDs autorizados.
- [ ] Añadir casos de lectura/validación sin RunStore para recibos ausentes,
  JSON inválido, objetivo distinto, run_id/ruta ajenos, rc incongruente, generación
  incompleta, enlaces y archivos enumerados fuera del run privado.
- [ ] Añadir regresión de dependencia ausente en cada nueva fuente transitiva;
  preflight debe fallar sin directorio de run ni primer paso ejecutado.
- [ ] Revisión estática y autorización exacta antes de observar RED de los casos
  nuevos con el selector previsto; conservar todas las evidencias.
- [ ] Ampliar ENGINE_SOURCES mediante inventario explícito de imports reales11.
- [ ] Añadir `--json` al comando11; leer JSON del log privado
  `logs/<step_id>.stdout.log` de esa ejecución. Exigir una sola generación bajo
  `report-<step_id>/reports/runs/<run_id>` y recibo `run.json` final coherente
  con target, tipo ambos, modo objetivo, rc0/3 y los cinco REPORT_FILES.
  Recorrer sin seguir enlaces y mantener las comprobaciones privadas existentes.
  No importar dinámicamente el motor, elegir por mtime, glob del último run,
  aceptar recibos iniciales ESCRIBIENDO ni adoptar generaciones ajenas.
- [ ] El shim publica únicamente desde report_generation de su paso report,
  conservando renameat2 sin reemplazo, identidad del padre y fallo EXDEV.
- [ ] Ajustar aserciones del caso real para hallar los datos por el recibo validado;
  comprobar ambos targets y exclusión cruzada entre los dos pasos.
- [ ] Revisión estática y autorización exacta antes de GREEN/suite. Si falla,
  diagnosticar; no cambiar esperados para ocultar incompatibilidades.

### Task 3: Ficha09 y documentación de la combinación

**Interfaces:** conservar `automation_menu()` y despacho específico09;
`module_intro('09_Automation')` solo presenta texto.

- [ ] Escribir contrato que exige ficha09 en el puente, sin volver al dispatcher
  genérico, y corrige la aserción anterior en `test_module_intro.py`.
- [ ] Mostrar ficha antes del menú09 sin consulta de sesión, instalación ni backend;
  actualizar texto a planes/YAML consumidos, preview, ejecución y permisos explícitos.
- [ ] Verificar cancelación/EOF con caso sintético existente de CLI, dentro del
  selector revisado; no ejecutar global/smoke/99 ni runner ajeno en host.
- [ ] Actualizar únicamente apartados09 y compatibilidad11 afectados en USE/manual;
  marcar bloques históricos como históricos y no declarar cierre global.
- [ ] Revisión final independiente del conjunto y evidencia final del selector
  autorizado. Anotar gaps restantes sin extrapolar Windows/Docker ni carreras
  y cancelación históricas a este SHA.

## Secuencia posterior: alcance ampliado que NO se abandona

Este bloque de compatibilidad precede a los fallos funcionales independientes:
rate_limit (esquema sin tráfico previo y403 indeterminado), composición de login,
conservación de notas Labs, /24 de ping_sweep, generadores sin auto-sustitución
oculta, Burp sin petición implícita y confirmación real antes de cleanup.
Cada uno requiere contrato y regresión sintética propios; no son autorización
para ejecutar red, limpieza real, sudo o fuerza bruta como smoke test.

También siguen incluidos todos los menores semánticos y deferred anteriores por
la petición explícita «arregla todo». S-I4 ya resuelto por develop no se repite.
El inventario130/217 previo debe reconciliarse con menús10/11 nuevos, no reciclarse
como garantía semántica actual. No declarar cerrado09 al terminar solo este plan.

## Handoff

Plan aprobado por el usuario con «Sí, dale». Método previo: subagentes;
no volver a pedir elección de método. Gates de ejecución separados del diseño/plan.
Estado de tareas, revisiones y ejecuciones en el ledger propio de este plan.
