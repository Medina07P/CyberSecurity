# Mantenimiento de 07_Wireless — diseño breve

Estado: aprobado expresamente por el usuario el 2026-11-11.

## Intención y alcance acordado

El usuario aceptó continuar con 07 usando el alcance de mantenimiento:
navegación, comprobación local de dependencias, documentación y pruebas
aisladas. No implementar el plan operacional integral anterior de Wireless.

## Enfoque

Se propuso continuar el mismo enfoque de mantenimiento de 06 y el usuario lo
eligió. Mantener Bash y las funciones existentes del gestor evita reescribir
herramientas o crear otro punto de entrada. Una revisión operacional integral
es otro alcance y queda excluida; una corrección solo documental no cubriría
la navegación y comprobación local aceptadas.

## Cambios mínimos

- Añadir `00_Config/lib/wireless_menu.bash`: menú de mantenimiento, comprobación
  de dependencias mediante `command -v` y explicación local de límites.
- `module_wireless` abre ese menú. Mantener la lista original accesible en la
  opción 11 mediante `run_module_scripts`, sin alterar confirmaciones ni CLI.
- La comprobación informa presencia/ausencia de `sudo`, `ip`, `iw`,
  `airodump-ng`, `aireplay-ng`, `aircrack-ng`, `hcitool`, `bluetoothctl`,
  `sdptool` y `gatttool`. No invoca binarios, radio, interfaces ni servicios;
  presencia no prueba hardware compatible ni permiso o capacidad operativa.
- La guía del menú solo explica alcance/limitaciones: no ejecuta las hojas.
- Corregir README/USE: `wifi_handshake.sh` es una guía, no captura ni verifica
  un handshake automáticamente. No copiar recetas de ataque nuevas a la guía.
- Añadir pruebas sintéticas de navegación, EOF, cancelación, dependencias
  ausentes/presentes y preservación del inventario original de diez scripts.

## Restricciones y antiobjetivos

No modificar, eliminar ni ejecutar las diez hojas/flujo existentes de 07.
No ampliar desautenticación, captura, craqueo o automatización inalámbrica.
No añadir runtime de captura, informes o metadata para operaciones no
implementadas. No leer capturas reales ni modificar scope/objetivos/sesión.
No instalar dependencias, elevar privilegios ni cambiar estado del adaptador.
Los tests sustituyen herramientas por stubs y el listado por una frontera
inocua: ninguna operación activa se usa como smoke test.

## Verificación y cierre

TDD para el menú nuevo; regresión aislada del gestor, informes y 06. Suites
antiguas exclusivamente en copias limpias; conservar sus incidencias conocidas
sin debilitar asertos. Verificar hashes de las diez fuentes originales antes
y después, sintaxis Bash incluyendo stderr, revisión independiente y commits
locales con rutas explícitas, sin push. Preservar cambios previos de 06/scope
y los diseños/planes operacionales sin seguimiento.

El cierre se denomina **mantenimiento de 07**, no implementación del plan
operacional integral ni auditoría de redes/dispositivos reales.
