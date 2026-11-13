# Scanners guiados Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hacer intuitivo el módulo 03 y evitar resultados aparentemente limpios tras fallos de herramientas.

**Architecture:** Menú específico de 03 en una biblioteca Bash, integrado con el gestor y sus prompts existentes. Las hojas mantienen su CLI y nombres de salida; las pruebas ejecutan copias temporales con herramientas simuladas.

**Tech Stack:** Bash, Python 3 unittest, herramientas falsas en PATH.

**Spec:** `docs/superpowers/specs/2026-11-09-scanners-guiados-design.md`

## Global Constraints

- Ningún escaneo real, instalación, push ni commit automático en esta revisión.
- scope.yaml y el permiso pendiente de api_keys.py permanecen intactos.
- Las pruebas nuevas son autocontenidas; las antiguas solo en clon temporal limpio.
- Mantener mensajes en español, archivos LF, rutas autolocalizadas y stdout puro para funciones que devuelven valores.
- No copiar evidencias, claves, sesión ni objetivos reales a fixtures.

## Review Focus

- EOF o cancelación en cualquier pregunta: cero invocaciones de herramientas.
- Resultado antiguo y fallo actual: no leer el antiguo como resultado nuevo.
- URL con esquema, puerto y ruta: argv intacto y sin descubrimiento de red implícito.
- Dependencia ausente o error parcial: estado explícito, no éxito ni cero hallazgos.
- Salidas y registros: conservar convenciones del motor de informes y no borrar logs anteriores.

---

### Task 1: Reproducciones automatizadas y hojas fiables

**Files:**
- Create: `CyberSecurity-Framework/tests/test_scanners_menu.py`
- Create: `CyberSecurity-Framework/tests/run_scanners_menu.sh`
- Create: `CyberSecurity-Framework/00_Config/lib/scanner_runtime.bash`
- Modify: las ocho hojas no Burp de `CyberSecurity-Framework/03_Scanners/`.

**Interfaces:**
- Consume `scans_dir`, `scans_slug` de scans.bash.
- Produce `scanner_require <comando>` y `scanner_run <log> <orden...>`: retornan 0/estado de fallo; no confunden stderr informativo con fallo.
- Produce validadores `scanner_host`, `scanner_url`, `scanner_ports`, `scanner_severity`: 0 válido, 1 inválido, sin red.
- Cada hoja devuelve 1 ante fallo, 0 ante ejecución correcta aunque sin resultados.

- [x] Escribir fixtures en TemporaryDirectory bajo `/tmp/opencode`, copiando únicamente fuentes necesarias y configuración sintética. Los stubs registran argv, crean resultados o fallan de forma controlada; nunca delegan en herramientas reales.
- [x] Reproducir con tests por hoja: orden sale 7 y wrapper debe salir distinto de cero; Smart con .nmap anterior y fallo actual no debe ejecutar servicios/NSE.
- [x] Ejecutar `bash CyberSecurity-Framework/tests/run_scanners_menu.sh` y confirmar los fallos esperados antes de corregir.
- [x] Implementar control de estados, validación y mensajes inequívocos, con logs acumulados delimitados por ejecución; migrar hojas a rutas y slugs compartidos.
- [x] Añadir casos: puertos cerrados, open|filtered no abierto, ausencia de binario, URL inválida, opción inyectada, puertos fuera de rango, severidad inválida y segunda ejecución sin borrar log anterior.
- [x] Contrastar ayuda local de Nuclei/RustScan/Masscan, sin escanear ni actualizar recursos; corregir flags incompatibles y verificar argv con stubs. No afirmar compatibilidad real si el binario está ausente.
- [x] En NSE usar selectores válidos y no añadir 25/445 fuera de los puertos elegidos; comprobar argv.
- [x] Reejecutar suite y verificar que el caso vacío correcto sale 0 sin inventar vulnerabilidades.

### Task 2: Orquestador con estados honestos

**Files:** `CyberSecurity-Framework/03_Scanners/run_all_scanners.sh`, pruebas de Task 1.

**Interfaces:** Consume estados de hojas; conserva `<TARGET>` como host/IP. Produce resumen de ejecutadas/fallidas/omitidas y salida 0/1.

- [x] Añadir tests que fallan: hijo fallido, descubrimiento fallido, Masscan sin permisos, script ausente, 8080/8443 abiertos y ejecución desde otro cwd.
- [x] Ejecutar suite y comprobar los fallos nuevos.
- [x] Eliminar cierre verde incondicional, contar estados, explicar omisiones y limitar resumen de errores a esta ejecución; mantener el objetivo explícito en todas las llamadas.
- [x] Confirmar que una omisión opcional se anuncia pero no se presenta como escaneo realizado; ausencia/fallo de Nmap es fallo requerido.
- [x] Ejecutar suite: argv de URLs con puerto correcto y rc=1 en fallo parcial.

### Task 3: Entrada intuitiva del módulo 03

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/scanners_menu.bash`
- Modify: `CyberSecurity-Framework/cyber_framework.sh`, función `module_scanners` y punto de carga de bibliotecas.
- Modify: `CyberSecurity-Framework/03_Scanners/network_scanners/nmap/nmap_smart.sh` para un perfil básico opcional documentado.
- Modify: `CyberSecurity-Framework/00_Config/lib/dangerous.txt` para entradas intensivas de 03.
- Test: `CyberSecurity-Framework/tests/test_scanners_menu.py`.

**Interfaces:** `scanners_menu` usa sesión, execute_script, ask_confirm y pause del gestor; vuelve al menú principal con 0 o EOF. `scanners_check_tools` solo consulta disponibilidad local. Perfil básico de Smart: `--top-ports 100 -sV --version-light`, sin NSE ni detección de SO; perfil heredado completo conserva su comportamiento tras confirmación avanzada.

- [x] Escribir pruebas de navegación real `03 → comprobaciones → volver`, básicos, web, Burp y avanzados; stub de cada herramienta registra ejecución para detectar llamadas imprevistas.
- [x] Añadir cancelación, EOF, elección inválida, sin objetivo de sesión y URL `https://example.invalid:9443/ruta` intacta; ejecutar y confirmar fallos.
- [x] Implementar menú con etiquetas humanas, objetivo visible y resumen previo confirmado; reutilizar prompts y ejecución en vez de eval o ensamblar comandos de texto.
- [x] Separar perfil básico de Smart del completo, y registrar en pruebas que el básico no usa `-p-`, NSE, Masscan ni privilegios.
- [x] Conservar lista avanzada genérica de las diez entradas; marcar/confirmar run_all, Smart completo, Nmap agresivo/NSE, Masscan y RustScan. No cambiar menús de otros módulos.
- [x] Ejecutar suite y comprobar que ninguna salida de menú se captura como argumento.

### Task 4: Documentación y regresión aislada

**Files:** `03_Scanners/README.md`, `03_Scanners/USE.md`, `docs/MANUAL-GESTOR.md`, nueva nota `docs/SCANNERS-2026-11-09.md`.

**Interfaces:** Documentación del menú y diferencias entre básico, avanzado, fallo y omisión; ninguna primera prueba invita a lanzar run_all.

- [x] Actualizar guías con navegación, requisitos, URLs y alcance; corregir dependencia del cwd documentada de forma obsoleta.
- [x] Ejecutar suite nueva en checkout actual: solo debe escribir en su temporal y verificar hashes de configuración real.
- [x] Crear clon local temporal limpio y aplicar únicamente cambios de fuentes/documentos de esta entrega; ejecutar allí las suites antiguas, nunca en el checkout con evidencias.
- [x] Ejecutar `bash -n` sobre archivos Bash modificados capturando stderr; exigir código 0 y stderr vacío.
- [x] Revisar diff completo y compatibilidad de nombres/formato con informes, especialmente salida CVE de Nuclei.
- [x] Registrar resultados exactos, limitaciones de binarios ausentes y pruebas simuladas frente a reales. Marcar checkboxes solo con evidencia.

## Ejecución

Aprobado por el usuario el 2026-11-09. Ejecución nativa en esta sesión, sin subagentes de implementación ni commits automáticos. Registro de avance y pruebas en `.superpowers/sdd/2026-11-09-scanners-guiados/progress.md` (ignorado por git); los resultados finales se resumen en `docs/SCANNERS-2026-11-09.md`.
