# Config guided menu Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hacer utilizable todo 00_Config desde el gestor, con claves guiadas y errores fiables.
**Architecture:** Reutilizar keys_menu desde execute_script, conservar CLI de api_keys y asistente; run_all explícito y de solo lectura, comprobaciones con estados propagados.
**Tech Stack:** Bash, Python3 estándar y PyYAML existentes; unittest.
**Spec:** `docs/superpowers/specs/2026-11-09-config-guided-menu-design.md`

## Global Constraints
- Worktree aislado; no tocar claves, scope, targets, resultados ni permisos locales del checkout habitual.
- Sin red, instalaciones ni cambios automáticos de credenciales en run_all.
- Cada valor devuelto por funciones va solo a stdout; interfaz no debe entrar en argv.
- No ejecutar suites antiguas sobre evidencias reales. Commits locales y merge autorizados; sin push.

## Review Focus
- Selección de API keys desde módulo y K: mismo menú, sin lanzar CLI vacía ni duplicar pausas.
- Clave sintética con caracteres especiales: persiste solo en HOME/registro temporal, no en pantalla ni argv.
- Fallos reales de validación: exit1; run_all parcial no imprime éxito global.
- cwd ajeno, rutas con espacios, archivos ausentes/no legibles: sin falso éxito ni traceback.
- Cancelación/EOF: no escribir configuración ni dejar el gestor en otro directorio.

### Task 1: Navegación guiada
**Files:** modificar `CyberSecurity-Framework/cyber_framework.sh`; crear
`CyberSecurity-Framework/tests/test_config_menu.py`, `CyberSecurity-Framework/tests/run_config_menu.sh`.
**Interfaces:** `execute_script(script_path,module_dir)` redirige únicamente la
entrada API keys a `keys_menu [return_label]` desde FRAMEWORK_DIR, conserva cwd;
`keys_menu()` sin argumento mantiene retorno al menú principal.
- [ ] Tests reales de navegación 00→5 (cancelar, ver estado, pedir shodan sintético),
  K existente, asistente cancelado, validaciones y resumen de objetivos.
- [ ] Ejecutar `bash CyberSecurity-Framework/tests/run_config_menu.sh`; observar RED.
- [ ] Implementar dispatch exacto a menú existente y mensaje explícito de ejecución
  directa, sin alterar CLI de api_keys ni pedir secretos mediante prompt_for_slots.
- [ ] Reejecutar pruebas de navegación GREEN; commit local.

### Task 2: Validaciones y ejecución completa fiables
**Files:** modificar `CyberSecurity-Framework/00_Config/run_all_config.sh`,
`CyberSecurity-Framework/00_Config/scripts/{validate_config.sh,verify_00_config.sh,parse_targets.py}`,
tests nuevos anteriores; actualizar `CyberSecurity-Framework/00_Config/README.md`, `docs/MANUAL-GESTOR.md`, `AGENTS.md`.
También aislar HOME/KEYS_FILE en la comprobación de integración existente de
`tests/run_wizard.sh`, ahora que run_all consulta el estado de claves.
**Interfaces:** validadores devuelven 0/1; `parse_targets.main() -> int` y
`sys.exit(main())`; run_all invoca `validate`, `verify`, `parse --summary`,
`api_keys estado`, informa por paso y sale 1 ante cualquier fallo.
- [ ] Tests directos de archivos ausentes, exportación fallida, cwd ajeno y
  run_all con fallos de hijos; demostrar RED antes de modificar código.
- [ ] Autolocalizar run_all y declarar pasos explícitos de solo lectura, sin ocultar
  stderr ni disparar interactividad. Propagar errores reales sin traceback.
- [ ] Verificar flujo completo desde menú 00→1, EOF sin bloqueo ni claves escritas,
  conservar modo de éxito de fixtures válidos y fallos claros cuando faltan archivos.
- [ ] Documentar qué hace cada opción y códigos; suite nueva GREEN y commit.
- [ ] Ejecutar las ocho suites y sintaxis Bash/Python, diff check y revisión
  independiente. Corregir importantes con regresiones RED→GREEN, sin segunda revisión.
- [ ] Merge a develop conservando scope y chmod local de api_keys; repetir suites
  sobre clon limpio integrado. Guardar progreso en commits para cortes eléctricos.

## Progreso
- [x] Diseño/elección guiada aprobados; aislamiento y ejecución nativa heredados.
- [x] Task 1 completa: 8 pruebas de navegación real RED→GREEN, incluidas
  alta de clave sintética sin eco, K, cancelación/EOF y cwd externo.
- [x] Task 2 implementada: nuevas regresiones RED→GREEN; 18 tests config-menu,
  smoke sin fallos, wizard 59/59 y keys 141/141 pasando. Sintaxis verificada:
  133 Bash sin avisos y 40 Python compilados. Pendiente regresión completa/revisión.
- [x] Primera regresión completa: ocho suites pasando. Revisión independiente:
  un importante (stat de input fuera del try ante padre inaccesible), corregido
  RED→GREEN con prueba real POSIX sin root. Suite config-menu: 19 tests pasando;
  sin menores ni comportamientos declinados. Pendiente repetición final tras fix.
- [ ] Task 2 completa.
- [ ] Revisión, merge y verificación integrada.
