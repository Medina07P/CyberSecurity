# Mantenimiento de 07 — 2026-11-11

Estado: **mantenimiento entregado y revisado**. Ambas tareas tienen revisión de
especificación y calidad aprobadas; la revisión global aprobó el cierre del
mantenimiento, sin hallazgos críticos ni importantes. Esta pasada documental
corrige el único menor señalado (referencia a evidencia y estado de cierre).
No se declara implementado el plan operacional integral de 07 ni realizada una
auditoría real.

## Alcance entregado

Task 1 (`045d2c8`) añadió `wireless_menu.bash`, su integración en el gestor y
la suite aislada de once tests. El menú ofrece 1 comprobación local, 2 guía,
11 lista original y 0 volver. EOF retorna sin acciones; entrada inválida avisa.
La comprobación usa solo `command -v` para sudo, ip, iw, airodump-ng,
aireplay-ng, aircrack-ng, hcitool, bluetoothctl, sdptool y gatttool.

No se ejecutan esos binarios: disponibilidad no demuestra adaptador compatible,
permisos ni funcionamiento operacional. La guía no lee capturas ni valida
evidencia. La opción 11 conserva el acceso a las diez entradas originales y
sus confirmaciones, sin ejecutarlas automáticamente.

README/USE del módulo y el manual corrigen la descripción histórica:
`wifi_handshake.sh` **imprime una guía**, no captura ni verifica un handshake
automáticamente. No se cambió ese script para hacer cierta la documentación
anterior ni se añadieron recetas de ataque.

## Verificación de la entrega

Regresión requerida: `run_wireless_maintenance.sh`, `run_postexploitation.sh`,
`run_smoke.sh`, `run_e2e.sh` y `run_reports.sh`. La evidencia definitiva del
controlador corresponde al commit completo `7bcc5bc`, en copia de fuentes con
Git local, HOME y configuración sintéticos en `/tmp/opencode`.
La ejecución previa del implementador usó fuentes de `045d2c8`, superponiendo
exclusivamente las siete rutas documentales de Task 2; sus comandos, logs,
códigos de salida y guardas se describen en
`.superpowers/sdd/2026-11-11-wireless-mantenimiento/task-2-report.md`.
No se usan los resultados de baseline como evidencia de esta entrega.

Resultados de esta entrega (todos rc 0):

| Suite | Resultado |
|---|---|
| wireless_maintenance | 11 tests |
| postexploitation | 84 tests |
| smoke | 0 fallos |
| e2e | 11 comprobaciones, 0 fallos |
| reports | 78 tests Python y 28 checks shell |

Logs definitivos y `suite-results.json` del controlador:
`/tmp/opencode/wireless-maint-avl4ag6x/` (commit completo `7bcc5bc`, cinco suites
rc 0). Cada log se llama `<runner>.log`, por ejemplo
`run_wireless_maintenance.sh.log`.
La primera tanda del implementador, `/tmp/opencode/wireless-maint-9k7pda9_/`,
es histórica; su copia final fue `/tmp/opencode/wireless-maint-w_4askln/`.
Los tres checks de sintaxis de esa copia final terminaron con rc 0 y stderr
vacío; las 14 guardas coinciden con `preserved-sources.json`.
Estos resultados no certifican radio,
captura ni operaciones de las hojas.

Se comprueba sintaxis con `bash -n` de gestor, biblioteca wireless y runner,
capturando stderr (un rc 0 con advertencias no bastaría), además de
`git diff --check`. La guarda compara SHA-256 y modo de las diez fuentes
originales de 07 y de los cuatro pendientes ajenos, sin mostrar su contenido.
No se ejecutan hojas reales, sudo, instalaciones ni operaciones por radio.

## Regresión heredada, no resuelta aquí

No se repite ni debilita `run_tests.sh` para forzar verde. El último resultado
documentado en `CIERRE-MANTENIMIENTO-06-2026-11-11.md` es **374 pasan,
11 fallan, rc 1**. Diez fallos se reprodujeron sobre `eb67d1a`; además reapareció
`ssti: 49 es CONFIRMADO`, intermitente y sin causa determinada. No se atribuye
su causa a 07 ni se presenta la rama entera como satisfactoria.

## Preservación y traspaso

Las diez hojas/flujo de 07 permanecen intactas y sin validación operacional.
No se lee evidencia real, scope, objetivos, sesión o credenciales; scope solo
se trata como digest/modo para la guarda autorizada. Permanecen fuera del
commit los cambios previos de scope.yaml, logs_cleaner.sh, port_forward.sh y
run_all_post.sh, y los diseños/planes operacionales anteriores sin seguimiento.

Diseño y plan de **mantenimiento** aprobados se versionaron junto a las cinco
rutas de documentación de Task 2 en `7bcc5bc`, tras Task 1 en `045d2c8`.
Ambas tareas fueron aprobadas en especificación y calidad; la revisión global
`ses_e329500e4ffeR1bjD7XXwthgjS` indicó «Ready to cerrar: Sí», con un menor
documental atendido en esta pasada. El historial local registra los commits;
sin push. El controlador hará la re-revisión acotada de este diff documental,
no una nueva revisión global. No se implementó el plan operacional integral
de 07 ni se declara toda la rama verde.
