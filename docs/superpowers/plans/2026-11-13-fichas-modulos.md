# Fichas introductorias de módulos — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mostrar automáticamente una ficha educativa breve en los menús de los catorce módulos, sin añadir interacción ni cambiar herramientas.

**Architecture:** Una biblioteca Bash centraliza textos estáticos y una función de impresión. El gestor, sus seis menús especializados y el menú propio de Labs la usan al dibujar sus pantallas de entrada; ninguna ficha inspecciona el sistema ni ejecuta herramientas.

**Tech Stack:** Bash, Python 3 unittest y subprocess con fuentes copiadas a temporales bajo `/tmp/opencode`.

**Spec:** `docs/superpowers/specs/2026-11-13-fichas-modulos-design.md` (aprobado).

## Global Constraints

- Cubrir los catorce módulos, del 00 al 13.
- Mostrar la ficha bajo la cabecera del menú de entrada y antes de sus opciones.
- Mantenerla visible cuando ese menú se redibuja, sin pausas ni preguntas nuevas.
- Cambio informativo: no cambiar validaciones, argumentos, numeración, permisos, confirmaciones, selección de objetivo ni ejecución de herramientas.
- No implementar ni rediseñar 09_Automation ni reabrir trabajos cerrados.
- Preservar menús especializados, archivos de configuración locales, resultados y evidencias; no ejecutar flujo 99, herramientas reales ni consultas externas.
- Sin push. No incluir `00_Config/scope.yaml` ni `00_Config/targets.txt` en commits.
- No ejecutar suites heredadas sobre este checkout. Conservar LF y comprobar stderr de `bash -n`.

## Review Focus

1. Pantallas que se limpian o redibujan: la ficha sigue visible antes de opciones, sin mostrarse solo en el wrapper que luego desaparece (Task 2).
2. Forensics por stderr y funciones que devuelven valores: no contaminar stdout ni argumentos (Task 2).
3. Menús cargados individualmente por pruebas antiguas: no introducir `command not found` si no se ha cargado la nueva biblioteca (Task 2).
4. Lectores principiantes: no confundir herramientas listadas con instalación, integración operacional o una auditoría acreditada (Task 1).
5. Labs independiente y con EOF heredado: probar renderizado y salida explícita 11 sin arreglar ni desencadenar bucles o acciones ajenas (Task 2).

## Mapa de archivos

- Crear `CyberSecurity-Framework/00_Config/lib/module_intro.bash`: textos y única interfaz pública `module_intro`.
- Crear `CyberSecurity-Framework/tests/test_module_intro.py`: contenido, efectos laterales y navegación aislada.
- Crear `CyberSecurity-Framework/tests/run_module_intro.sh`: runner unittest siguiendo `run_wireless_maintenance.sh`.
- Modificar `CyberSecurity-Framework/cyber_framework.sh`: cargar biblioteca y dibujar fichas en menú genérico.
- Modificar los seis `CyberSecurity-Framework/00_Config/lib/{scanners,enumeration,exploitation,postexploitation,wireless,forensics}_menu.bash`: ficha en sus pantallas principales.
- Modificar `CyberSecurity-Framework/13_Labs/main.sh`: cargar biblioteca por ruta propia y mostrar ficha en `main_menu` después del banner.
- Modificar `docs/MANUAL-GESTOR.md`: documentar presentación y que el recorrido no obliga a pasar por todos los módulos.

---

### Task 1: Biblioteca de fichas y contrato de contenido

**Files:** crear `module_intro.bash`, `test_module_intro.py` y `run_module_intro.sh` en las rutas anteriores.

**Interfaces:** `module_intro <module_dir>` imprime texto plano en stdout y retorna 0; acepta los nombres exactos `00_Config`…`13_Labs`. Argumento ausente o desconocido: silencio y retorno 0. Cargar la biblioteca no imprime, no lee stdin, no cambia cwd/variables del llamador y no ejecuta comandos externos.

- [ ] **1. Escribir pruebas RED.** En `ModuleIntroTests`, añadir `test_all_fourteen_cards_have_fields`, `test_unknown_and_missing_are_silent`, `test_source_has_no_effects` y `test_stdin_is_not_consumed`. Para cada identificador exigir los campos `Para qué sirve:`, `Entrada:`, `Incluye:` y `Precauciones:`; máximo ocho líneas no vacías por ficha, sin ANSI propio. Comprobar stdin con `module_intro 01_OSINT; IFS= read -r value; printf 'RESTO:%s\n' "$value"` e input `sentinela\n`: debe conservar `RESTO:sentinela`. Cargar/llamar desde cwd externo con PATH cerrado y comparar snapshots de fuentes, configuración sintética y HOME.
- [ ] **2. Ejecutar RED:** `bash CyberSecurity-Framework/tests/run_module_intro.sh`; debe fallar por biblioteca o función ausente, no por fallo de fixture.
- [ ] **3. Contrastar contenido con código.** Leer entradas versionadas y documentación actual de los catorce módulos; no ejecutar hojas. Registrar en comentarios de cada caso las rutas fuente que respaldan el resumen. No confiar en README comerciales ni etiquetas de scripts para atribuir capacidades no implementadas.
- [ ] **4. Implementar la biblioteca con `case` y `printf` incorporado.** Cuatro campos por ficha, frases breves y agrupación de herramientas; nombres exactos obtenidos en paso 3. Requisitos específicos de copia y pruebas:
  - 00: configuración, objetivos y claves; aclarar que registrar un objetivo no equivale a autorización.
  - 01: información pública, dominio/empresa/archivo según acción; WHOIS, DNS, certificados, correos y perfiles. Incluir `IP privada`, `Metasploitable` y orientación a `02`, `03` y `04`; no llamarlo totalmente pasivo: también contacta sitios y DNS.
  - 02–04: diferenciar reconocimiento, escaneo y enumeración; IP/red/dominio/URL según acción, tráfico al objetivo y autorización. No afirmar que todo acepta cualquier tipo de entrada.
  - 05–06: explotación y acciones posteriores, autorización explícita e impacto potencial. No certificar integración operacional de todas las hojas de 06.
  - 07: `mantenimiento`, disponibilidad y guía; listar grupos WiFi/Bluetooth como entradas conservadas, no auditoría integrada ni herramientas ejecutadas al entrar.
  - 08: archivos/fuentes explícitos, no IP de sesión; análisis offline y adquisición local separada y sensible. No afirmar custodia legal ni compatibilidad operacional.
  - 09: scripts de automatización presentes y adaptador de informes; workflows declarativos no consumidos. No prometer automatización integral validada ni implementar nada en este módulo.
  - 10: gestión/captura de evidencia; avisar que algunas acciones también escanean o capturan tráfico, no solo organizan archivos.
  - 11: informes desde resultados existentes; no son escaneos nuevos ni prueba de ausencia de vulnerabilidades.
  - 12: búsqueda y consulta de guías locales; ejemplos no se ejecutan al mostrar la ficha.
  - 13: organización de laboratorios, opciones VPN y herramientas según código; algunas acciones modifican sistema/red, no un entorno aislado garantizado.
- [ ] **5. Ejecutar GREEN:** runner nuevo con todas las pruebas de contenido anteriores; exigir además tokens críticos (`mantenimiento` en 07, `offline` en 08, `declarativos` en 09) y rechazo de promesas falsas explícitas identificadas al revisar fuentes. Confirmar rc 0 y ausencia de marcadores de comandos prohibidos.
- [ ] **6. Checkpoint:** revisar diff de estos tres archivos y crear commit local de alcance explícito si el usuario autoriza commits; si no, dejar cambios revisados sin commit. Nunca `git add -A`.

### Task 2: Integración, navegación y documentación

**Files:** modificar gestor, seis menús, `13_Labs/main.sh`, `docs/MANUAL-GESTOR.md`; ampliar `test_module_intro.py`.

**Interfaces:** consumir `module_intro <module_dir>` de Task 1. En 08 redirigir la ficha a stderr como el menú existente. En bibliotecas de menús usar `if declare -F module_intro >/dev/null; then ...; fi` para conservar compatibilidad con cargas individuales sin helper; el gestor siempre carga el helper. Labs carga el mismo helper desde `SCRIPT_DIR/../00_Config/lib`, sin depender de cwd.

- [ ] **1. Escribir pruebas RED de integración.** Reutilizar el patrón de copia temporal y PATH cerrado de `tests/test_wireless_maintenance.py`, no importar fixtures que apunten a configuración real. Parametrizar las catorce funciones `module_*` del gestor. Crear hojas inertes con marcador, herramientas peligrosas denegadas y datos sintéticos. Sobrescribir únicamente utilidades visuales (`clear_screen`, `sleep`, `pause`) y probes locales necesarios, nunca el menú bajo prueba. Para genéricos permitir las utilidades locales de descubrimiento sobre el fixture, sin usar herramientas reales de pentesting.
  - `test_each_entry_card_precedes_options`: la ficha aparece después de cabecera y antes de primera opción; entrada de salida original (0 en 00–12, 11 en Labs) basta, no hay pausa añadida ni dispatch de hojas.
  - `test_redraw_keeps_card`: recarga R en genéricos/opción inválida en especializados y vuelta; cada redibujo muestra la ficha. Usar timeout y no ejecutar acciones seleccionables.
  - `test_forensics_keeps_stderr`: ficha y opciones en stderr; stdout vacío al abrir/volver, sin cambio en prompts que devuelven valores.
  - `test_standalone_specialized_menus_without_helper`: source de cada biblioteca sin helper, con dependencias de UI stub; abrir/volver sin error de función ausente.
  - `test_eof_preserved_for_manager_menus`: EOF retorna sin herramienta ni pausa; excluir el bucle heredado de Labs, no corregirlo en este cambio.
  - `test_labs_own_screen_and_direct_launch`: en copia completa sintética ejecutar `main.sh` con 11; stub de clear/ip y probes locales, sin VPN real. Verificar ficha en pantalla propia. Para redibujo ejercitar la función de dibujo extraída en el harness de prueba, no añadir guardas de ejecución al producto por comodidad del test. Probar también fallback del gestor sin `main.sh`.
  - En todos los casos comparar hashes/modos de configuración sintética, HOME y árboles de evidencia; marcador de hojas/comandos prohibidos inexistente.
- [ ] **2. Ejecutar RED:** runner nuevo; las pruebas de Task 1 pasan y las de integración fallan por ficha ausente.
- [ ] **3. Integrar mínimamente.** Source del helper en el gestor antes de menús; llamada en `run_module_scripts` después de cabecera y dentro del bucle; llamada en cada menú especializado después de su cabecera. En `forensics_menu` dividir el `printf` existente en cabecera y opciones para intercalar ficha sin cambiar texto, stream ni lectura. En Labs llamar después de `show_banner`, antes de estadísticas/opciones; no dejar la ficha solo en `module_labs`, pues Labs limpia pantalla. No cambiar submenús de herramientas.
- [ ] **4. Actualizar manual.** Explicar campos visibles y ausencia de pausas/acciones automáticas; añadir ejemplo de Metasploitable con IP privada y recorrido 02–04. Aclarar que no hay que recorrer todos los módulos y que 99 no es una comprobación rápida. No reescribir el manual entero.
- [ ] **5. Verificar GREEN:** ejecutar runner nuevo y `bash -n` de todos los `.sh`/`.bash` modificados capturando stderr; exigir rc 0 y stderr vacío. Revisar diff para confirmar que solo cambian carga de helper, impresión y documentación. Guardar salida de verificación en `/tmp/opencode`.
- [ ] **6. Regresión segura.** En copia limpia y aislada de las fuentes finales, con configuración sintética, correr `run_config_menu.sh`, `run_scanners_menu.sh`, `run_enumeration.sh`, `run_exploitation.sh`, `run_postexploitation.sh`, `run_wireless_maintenance.sh`, `run_forensics.sh`, `run_smoke.sh` y `run_module_intro.sh`. No ejecutar suites contra evidencia original. Ante fallo usar systematic-debugging; no ampliar alcance ni declarar rama verde. Registrar comando, rc y log por suite.
- [ ] **7. Revisión final y checkpoint.** Revisar exactitud de las catorce fichas contra fuentes, diff y requisitos del diseño. Solicitar revisión según método de ejecución elegido; corregir solo problemas del alcance. Comprobar `git status --short` y que las modificaciones locales preexistentes se conservan. Commit local solo con autorización, paths explícitos; sin push. Entregar rutas y resultados reales, sin afirmar una auditoría operacional.

## Autorrevisión del plan

- Cobertura: los campos, los catorce módulos y las advertencias están en Task 1; ubicación, redibujo, integración y manual están en Task 2.
- Contrato único: `module_intro <module_dir>`; stdout por defecto y redirección explícita a stderr para 08.
- Cada riesgo de Review Focus tiene prueba asignada. Labs mantiene navegación y defectos heredados fuera de alcance.
- Implementación pendiente: este plan y el diseño aprobado no significan que las fichas ya se hayan añadido.
