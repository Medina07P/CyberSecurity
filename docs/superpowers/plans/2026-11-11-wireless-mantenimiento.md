# Mantenimiento de 07_Wireless — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development, solicitado expresamente por el usuario al aprobar este plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir navegación de mantenimiento y diagnóstico de dependencias sin modificar ni ejecutar las operaciones inalámbricas existentes.

**Architecture:** Una biblioteca Bash separada contiene menú, comprobación mediante command -v y explicación de límites. El gestor delega en ella y conserva el listado genérico como acceso a las diez entradas originales. Tests Python ejecutan gestor/biblioteca copiados con herramientas simuladas.

**Tech Stack:** Bash, Python estándar/unittest y Git local; sin dependencias nuevas.

**Spec:** `docs/superpowers/specs/2026-11-11-wireless-mantenimiento-design.md` (aprobado).

## Global Constraints

- «No modificar, eliminar ni ejecutar las diez hojas/flujo existentes de 07».
- «No ampliar desautenticación, captura, craqueo o automatización inalámbrica».
- No instalar dependencias, usar sudo, transmitir por radio, cambiar interfaces/servicios ni leer capturas reales.
- Sin nuevo runtime de captura, parser o evidencia operacional inventada.
- Ediciones limitadas al checkout actual; pruebas en copias de fuentes con HOME, PATH y configuración sintéticos en /tmp/opencode. Ninguna suite antigua sobre el checkout con evidencia real.
- Preservar scope.yaml y cambios pendientes de 06; commits locales de rutas explícitas, sin push.
- No corregir ni debilitar fuera de alcance los fallos heredados de run_tests; documentarlos, no presentar toda la rama como verde.

## Review Focus

1. Entrar, EOF, opción inválida y guía no ejecutan herramientas ni hojas.
2. Una herramienta disponible en PATH no acredita hardware compatible, permisos o auditoría realizada.
3. Ausencia de dependencias no dispara instalaciones ni escalada.
4. Opción 11 conserva la frontera de listado original y sus confirmaciones, sin lanzar automáticamente ninguna operación.
5. Bibliotecas y menú no cambian la sesión/alcance ni leen capturas; se conservan hash/modo/inventario de los diez scripts.

### Task 1: Menú de mantenimiento e integración mínima

Completada en `045d2c8`; Spec y quality aprobados según el traspaso del
controlador. Los cinco pasos siguientes corresponden a esa entrega.

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/wireless_menu.bash`
- Modify: `CyberSecurity-Framework/cyber_framework.sh`
- Create: `CyberSecurity-Framework/tests/test_wireless_maintenance.py`
- Create: `CyberSecurity-Framework/tests/run_wireless_maintenance.sh`

**Interfaces:**
- `wireless_check_tools`: stdout de disponibilidad, sin invocar los binarios. Lista exacta: sudo, ip, iw, airodump-ng, aireplay-ng, aircrack-ng, hcitool, bluetoothctl, sdptool, gatttool.
- `wireless_maintenance_guide`: explica que handshake es guía y no prueba captura/verificación; no imprime recetas activas nuevas ni lee archivos de evidencia.
- `wireless_menu`: opciones 1 comprobación, 2 guía, 11 lista original y 0 volver. Consume clear_screen/pause/run_module_scripts del gestor; EOF vuelve sin despachar acciones.
- `module_wireless` llama wireless_menu, con source de biblioteca desde LIB_DIR.
- Runner descubre solo test_wireless_maintenance.py; captura código de unittest sin pipelines que lo oculten.

- [x] **Step 1: Pruebas rojas.** Tests de entrada/EOF/inválida, opción 1 con dependencias presentes/ausentes, guía sin operaciones, opción 11 y retorno; fuente del gestor desde cwd externo. Stubs de todos los binarios de radio/privilegios escriben marcador y fallan si se invocan. Frontera de listado sustituida por marcador inocuo; no ejecutar hojas originales. Guardas de hash/modo/config/capturas sintéticas.
- [x] **Step 2: Observar rojo.** `PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/opencode python3 -B -m unittest discover -s tests -p test_wireless_maintenance.py -v` en copia de fuentes; fallo por menú/interfaz inexistentes, nunca por herramienta real.
- [x] **Step 3: Implementar mínimo.** Biblioteca Bash de solo UI/command -v, integración de dos puntos en gestor y runner. Mantener stdout limpio para cualquier función que devolviese valores; aquí todas las funciones son UI, sin capturar argumentos.
- [x] **Step 4: Observar verde.** Repetir unittest y runner; `bash -n` de gestor/biblioteca/runner con stderr vacío. Comparar los diez scripts originales y los pendientes ajenos por hash/modo.
- [x] **Step 5: Commit local.** Solo los cuatro archivos de esta tarea, después de revisar diff/pruebas.

### Task 2: Documentación, regresión y cierre

**Files:**
- Modify: `CyberSecurity-Framework/07_Wireless/README.md`
- Modify: `CyberSecurity-Framework/07_Wireless/USE.md`
- Modify: `docs/MANUAL-GESTOR.md`
- Modify: `AGENTS.md`
- Create: `docs/WIRELESS-MANTENIMIENTO-2026-11-11.md`
- Versionar el diseño y este plan aprobados, sin incluir los planes operacionales anteriores sin seguimiento.

**Interfaces:** documentación describe solo comportamiento implementado por Task 1; no convierte disponibilidad o texto de guía en captura/auditoría real.

- [x] **Step 1: Corregir documentación.** Describir menú y opciones, lista original conservada, handshake como guía y diferencia entre comprobar dependencias y ejecutar operaciones. No añadir comandos de ataque nuevos.
- [x] **Step 2: Regresión aislada.** Suite wireless_maintenance, postexploitation, smoke, e2e y reports en copia limpia; conservar logs y rc. Comparar hash/modo de scripts originales y pendientes ajenos; git diff --check y sintaxis con stderr. No declarar run_tests satisfactoria: su estado heredado documentado es rojo.
- [x] **Step 3: Revisión independiente.** Ambas tareas aprobadas en especificación y calidad. Revisión global de mantenimiento sin críticos/importantes; único menor documental atendido en la pasada final, sin operaciones activas.
- [x] **Step 4: Commit y traspaso.** Entregas locales `045d2c8` (Task 1) y `7bcc5bc` (Task 2), con rutas explícitas y sin push; mantenimiento entregado y revisado, no implementación del plan operacional integral.

La revisión global `ses_e329500e4ffeR1bjD7XXwthgjS` indicó «Ready to cerrar: Sí».
Evidencia definitiva del controlador sobre `7bcc5bc`:
`/tmp/opencode/wireless-maint-avl4ag6x/` (cinco suites rc 0 y
`suite-results.json`). El historial local registra los commits entregados y
la pasada documental final; su re-revisión acotada corresponde al controlador.
No se repiten suites por esta corrección documental: diffcheck, referencias,
inventario y guardas de hash/modo verifican el cambio, con código intacto.
El plan operacional integral de 07 no está implementado y la rama no está toda
verde: `run_tests.sh` conserva el rojo heredado (último cierre de 06: 374/11).

## Self-review

Los cinco puntos de revisión se cubren en Task 1 y guardas de Task 2. No se
modifican hojas ni flujo wireless; no hay dependencias entre nuevas fuentes
operacionales o informes. Solo se añade biblioteca/UI y pruebas propias.
