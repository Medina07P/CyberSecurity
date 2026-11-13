# Revisión integral de 07_Wireless sin recortes

Estado: aprobado por el usuario el 2026-11-11; pendiente de implementación.

Revisión 2026-11-11: el usuario confirma conservar la guía de handshake y
añadir un modo opcional de captura real. Esta confirmación no aprueba todavía
el diseño completo ni autoriza ejecuciones inalámbricas reales.

El usuario confirma también restaurar el estado inicial de la interfaz tras
operaciones que cambien temporalmente su modo o canal, al terminar, fallar o
cancelar.

Aclaración posterior del usuario: mejorar sin quitar ninguna funcionalidad.
Se mantienen desautenticación, craqueo, salto de canales, gestión de interfaces,
WiFi, Bluetooth y las automatizaciones existentes, con acceso desde el menú y
desde sus scripts. No sustituir operaciones por guías ni eliminar argumentos,
diccionarios o controles existentes como parte de esta revisión.

## Intención y acuerdos

Mejorar el menú, las herramientas y las automatizaciones existentes de 07,
manteniendo todas sus capacidades e interfaces históricas válidas. Corregir un
argumento erróneo de una herramienta no significa conservar ese error.
La autorización para diseñar o implementar no autoriza por sí sola tráfico
inalámbrico real. Los objetivos IP configurados no acreditan autorización sobre
las redes y dispositivos cercanos. La validación física requiere adaptadores y
objetivos expresamente autorizados; queda separada de las pruebas sintéticas.

Mostrar este aviso informativo en el menú y documentarlo: «Usar exclusivamente
en objetivos autorizados y en un entorno controlado. Estas operaciones pueden
modificar el estado del adaptador, capturar tráfico o interrumpir conexiones».
El aviso no añade confirmaciones, bloqueos ni restricciones nuevas.

No añadir topes de intentos, tasas, diccionarios reducidos, límites de duración
ni otras restricciones nuevas. Conservar los controles ya existentes, incluidas
las confirmaciones del gestor para scripts intrusivos y los permisos separados.
No endurecerlos ni eliminarlos aprovechando esta revisión.

## Alcance y antiobjetivos

- Conservar cada herramienta, parámetros históricos, payloads, diccionarios,
  capturas y automatizaciones existentes.
- No transformar herramientas activas en simples avisos o guías.
- No revisar funcionalidades ajenas a 07; se permiten los cambios mínimos de
  integración en gestor, biblioteca e informes. No ejecutar el flujo global 99
  como verificación.
- No instalar dependencias ni cambiar privilegios automáticamente. La ausencia
  de una dependencia se informa; no se confunde con un resultado negativo.
- No modificar configuración real, sesión, credenciales ni evidencias previas
  como efecto secundario de una prueba de interfaz o de una suite de regresión.
- No publicar objetivos, claves, respuestas ni credenciales; no hacer push.
- Los commits locales están autorizados, seleccionando fuentes explícitamente y
  dejando scope.yaml fuera; nunca usar git add -A.

## Inventario que debe conservarse

| Familia/entradas | Operaciones conservadas |
|---|---|
| run_all_wireless.sh | Flujo completo de auditoría wireless |
| wifi/wifi_scan.sh | Escaneo de redes WiFi |
| wifi/wifi_monitor.sh | Activación de modo monitor |
| wifi/wifi_handshake.sh | Guía histórica y modo opcional de captura real WPA/WPA2 |
| wifi/wifi_deauth.sh | Ataque de desautenticación |
| wifi/wifi_crack.sh | Craqueo de handshake |
| bluetooth/bt_scan.sh | Escaneo Bluetooth |
| bluetooth/bt_discover.sh | Descubrimiento de dispositivo Bluetooth |
| scripts/interface_manager.sh | Gestión de interfaces (list/monitor/managed) |
| scripts/channel_hopper.sh | Salto de canales |

## Navegación y compatibilidad

Biblioteca dedicada bajo `00_Config/lib/` e integración en `module_wireless`.
Entrar en 07 muestra el aviso, pero no ejecuta herramientas.
Ofrecer comprobación de dependencias, escaneo WiFi, modo monitor, handshake,
deauth, craqueo, Bluetooth, gestión de interfaces, flujo completo y visor de
resultados/capturas. Conservar la lista completa de scripts en la opción 11.

### Requisito confirmado: menú intuitivo sin recortes

El usuario pide mejorar expresamente la facilidad de uso del menú guiado.
Los siguientes criterios concretan esa petición. El usuario aprobó la
organización del menú mostrada abajo; todavía no se ha implementado.

#### Organización del menú aprobada

```text
07 · SEGURIDAD INALÁMBRICA

WiFi:       sin seleccionar
Red/BSSID:  sin seleccionar
Bluetooth:  sin seleccionar

Usar exclusivamente en objetivos autorizados.
Los cambios de modo/canal pueden interrumpir conexiones.

PREPARACIÓN
  1. Comprobar herramientas y adaptadores
  2. Seleccionar y gestionar interfaz WiFi

WIFI
  3. Buscar redes
  4. Handshake: ver guía o capturar
  5. Desautenticación
  6. Analizar captura con diccionario
  7. Salto de canales

BLUETOOTH
  8. Buscar dispositivos y consultar servicios

RESULTADOS Y AUTOMATIZACIÓN
  9. Consultar resultados y capturas
 10. Ejecutar flujo wireless existente
 11. Lista completa de scripts

  0. Volver
```

El submenú de handshake aprobado contiene:

```text
HANDSHAKE WPA/WPA2
  1. Ver guía paso a paso
  2. Capturar handshake
  3. Comprobar una captura existente
  0. Volver
```

Las cabeceras reflejan los valores seleccionados cuando existan. Seleccionar
una categoría no equivale a ejecutar todas sus herramientas. La lista completa
queda en la opción 11, sin reutilizar ese número para otra acción.

- Organizar la navegación por tareas comprensibles: preparar adaptador,
  explorar WiFi, handshake (guía/captura), desautenticación, analizar captura
  con diccionario, Bluetooth, resultados y flujo existente. Mantener además
  acceso a la lista completa y al salto de canales.
- Mostrar contexto visible: interfaz seleccionada, modo y canal conocidos,
  BSSID seleccionado cuando corresponda y controlador Bluetooth independiente.
  Mostrar «sin seleccionar» o «no determinado» cuando falte información;
  no reutilizar una IP de sesión como objetivo inalámbrico.
- Permitir seleccionar una interfaz existente por número o introducirla
  explícitamente. Distinguir adaptadores WiFi de interfaces de red generales;
  no asumir `wlan0` ni nombres terminados en `mon`.
- Pedir únicamente los datos necesarios para la tarea elegida, con ejemplos
  explicativos y validación que permita corregir el dato sin reiniciar el
  recorrido. No usar objetivos de ejemplo como valores efectivos por defecto.
- Para capturas y diccionarios, aceptar rutas con espacios y explicar qué
  archivo se necesita. Permitir elegir capturas previas sin sobrescribirlas.
- Explicar antes de ejecutar qué hace la opción, qué adaptador/objetivo usa y
  si cambia modo/canal o puede interrumpir conexiones. Conservar las
  confirmaciones existentes, sin duplicarlas por cada capa del menú.
- Entrar en 07 no ejecuta operaciones. La comprobación local es una acción
  explícita y no transmite, instala herramientas ni modifica interfaces.
- Usar `0` para volver/cancelar de forma consistente; EOF nunca ejecuta una
  operación pendiente. Las preguntas van a stderr y solo los valores a stdout.
- Tras cada operación mostrar resultado real, diagnóstico si lo hay, ubicación
  de la evidencia y estado de restauración; después volver al contexto previo
  sin lanzar la siguiente herramienta automáticamente.
- Si falta hardware, dependencia o permiso, explicar la causa y el paso manual
  pertinente sin afirmar éxito, instalar automáticamente ni ocultar la opción.
- Probar navegación, cancelación, entradas inválidas, rutas con espacios y
  conservación de todas las entradas con herramientas simuladas en temporales.

La interfaz identifica el adaptador local, no la red auditada. La atribución
usa el modelo inalámbrico descrito abajo. Los manifiestos tienen una única
ubicación canónica bajo `scans/wireless/`; las capturas binarias pertenecen al
árbol privado `07_Wireless/captures/`, sin duplicar fuentes de informes.

## Handshake: compatibilidad y captura opcional

Acuerdo confirmado por el usuario el 2026-11-11:

- La invocación histórica `wifi_handshake.sh <INTERFACE>` conserva la guía;
  imprimir instrucciones no se registra como captura realizada.
- Un modo explícito adicional permite ejecutar la captura real. El menú debe
  distinguir «Ver guía» de «Capturar»; entrar en el menú no inicia ninguna.
- Decisión técnica propuesta para aprobación global: el modo de captura solicita
  interfaz, BSSID y canal, verifica las capacidades y el estado del adaptador,
  y conserva los artefactos en un directorio privado exclusivo por ejecución.
- La captura no inicia desautenticación automáticamente. La operación de
  desautenticación existente permanece separada, con sus controles actuales.
- Crear un `.cap` o recibir rc 0 no demuestra un handshake válido: su presencia
  y su validación se registran por separado. Sin comprobación concluyente no
  se anuncia «handshake confirmado».
- La cancelación conserva la captura parcial y el diagnóstico, detiene solo
  procesos propios y no convierte la interrupción en éxito.
- Sintaxis adicional propuesta: `wifi_handshake.sh <INTERFACE> --capture <BSSID>
  <CHANNEL>` y `wifi_handshake.sh --verify <CAPTURE> [BSSID]`. Mantener la
  invocación histórica de guía. Reflejar los modos en `Uso:` sin romper el
  parser de parámetros del gestor; el menú pasa argumentos preparados.

## Correcciones operativas y compatibilidad

- `wifi_scan.sh`: usar escaneo compatible con managed; no forzar monitor antes
  de `iw scan`. Si debe cambiar temporalmente de modo, aplicar el contrato de
  restauración. Registrar salida completa antes de generar resúmenes.
- `wifi_monitor.sh` y `interface_manager.sh`: compartir comprobación del modo
  efectivo y propagar fallos intermedios. No inventar sufijos de interfaz.
- Validar interfaz existente, tipo de adaptador, privilegios requeridos y rfkill
  sin desbloquearlo automáticamente. Validar MAC/BSSID y frecuencia/canal frente
  a capacidades y dominio regulatorio observados, no una lista fija de 2,4 GHz.
  Si la información no está disponible, explicar el diagnóstico sin afirmar
  que el canal es válido ni cambiar el dominio regulatorio.
- `channel_hopper.sh`: conservar el salto y su intervalo histórico; derivar los
  canales utilizables del adaptador y no intentar canales prohibidos/no
  disponibles. No ampliar implícitamente permisos de transmisión en DFS.
- `wifi_crack.sh`: conservar `<HANDSHAKE_FILE> [WORDLIST]`; pasar la captura como
  archivo posicional a aircrack-ng, nunca como argumento de `-b`. Añadir filtro
  BSSID opcional explícito, sin cambiar los dos posicionales históricos. Si una
  captura contiene varias redes, pedir selección en el menú o diagnóstico
  explícito en CLI, sin escoger la primera silenciosamente.
- Captura y diccionario deben ser legibles; el diccionario predeterminado sigue
  siendo `/usr/share/wordlists/rockyou.txt` cuando se omite el argumento. Un
  diccionario explícito inválido no se sustituye silenciosamente por otro.
- Diferenciar clave recuperada, diccionario agotado, captura sin handshake
  utilizable, formato no admitido, dependencia ausente y fallo de herramienta.
  No recortar diccionarios ni añadir topes de intentos o duración.
- `wifi_deauth.sh`: conservar su operación y parámetros; abortar si falla la
  preparación del canal y conservar rc/señales reales. El mensaje de envío no
  demuestra que un cliente se desconectó. No cambiar su alcance en esta revisión.
- Bluetooth: conservar `hcitool`, `bluetoothctl`, SDP y consulta GATT, indicando
  disponibilidad por backend y diferencias Classic/LE. Un backend ausente no
  elimina los demás; conservar resultado y fallo por paso, sin convertir
  cobertura parcial en consulta completa.
- Permitir selección explícita de controlador Bluetooth, manteniendo las CLI
  históricas sin argumento de controlador. Si hay varios, el menú solicita
  elección; la CLI usa el controlador predeterminado observable del sistema y
  lo registra, o falla si no se puede determinar.
- Una dirección Bluetooth aleatoria no identifica de forma estable al mismo
  dispositivo en diferentes ejecuciones. Registrar su tipo si se conoce y no
  fusionar dispositivos por nombre visible.
- Propagar códigos de herramientas sin que `tee`, `head`, `grep` o un mensaje
  final los oculten. Ausencia de coincidencias no equivale a fallo del escáner.
  No descartar stderr operativo; conservarlo privado en `errores.log` por run.

## Estado de interfaz y restauración

- Antes de modificar temporalmente una interfaz, registrar su identidad,
  modo, estado administrativo (up/down) y canal/frecuencia cuando sean
  observables. No inventar valores iniciales que el sistema no proporciona.
- Al terminar, fallar o recibir SIGINT/SIGTERM, detener primero los procesos
  propios y restaurar los valores iniciales que se hayan cambiado. La limpieza
  debe ser idempotente y conservar el resultado original de la operación.
- Verificar la restauración y registrar su resultado por separado. Si falla,
  mostrar un diagnóstico y los pasos de recuperación pertinentes; no anunciar
  que la interfaz quedó restaurada. Una operación con restauración fallida no
  se presenta como éxito completo.
- No reiniciar servicios, desconectar interfaces ajenas, matar procesos globales
  ni modificar rfkill automáticamente para intentar recuperar el adaptador.
- SIGKILL, pérdida de alimentación o retirada del adaptador pueden impedir la
  restauración: documentar esta limitación y conservar el estado previo para
  orientar la recuperación posterior, sin aplicar cambios automáticamente al
  volver a abrir el menú.
- Distinción de diseño: las órdenes explícitas de gestión `monitor` y `managed`
  buscan dejar la interfaz en el modo solicitado; tras éxito no se deshacen.
  Si fallan a mitad del cambio, se intenta recuperar el estado inicial.
- Pruebas con herramientas simuladas: éxito, fallo intermedio, SIGINT/SIGTERM,
  limpieza repetida, interfaz retirada y fallo de restauración. Ninguna prueba
  cambia interfaces o servicios reales.

## Propiedades del runtime (wireless_runtime.bash)

- Funciones: `wireless_init`, `wireless_capture`, `wireless_publish`,
  `wireless_finish` (análogas a `exploit_*` de 05), atribuidas a la interfaz
  y al comando ejecutado.
- Biblioteca de evidencia exclusiva `00_Config/lib/wireless_evidence.py`; no
  copiar sin revisión las heurísticas de 05/06 ni cambiar su semántica.
- Runs exclusivos en `scans/wireless/wireless_<hash>_<id>/` con `run.json`,
  stdout/stderr, `errores.log` y sidecars por paso. Capturas binarias nuevas en
  `07_Wireless/captures/runs/<run_id>/`. Directorios 700 y archivos 600 desde
  su creación; no cambiar permisos de capturas antiguas ni de entradas ajenas.
- Manifest version 1, `module="07"`, `run_id`, `operation`, `herramienta`,
  `interfaz`, `controller`, `target_type`, `target_id`, `started`, `fecha`,
  `estado`, `rc`, `complete`, `steps`, `artifacts`, `restore`. Campos de hardware
  desconocidos/offline son null, nunca nombres inventados.
- `target_type`: `wifi_bssid`, `bluetooth_mac`, `capture_sha256`,
  `local_interface` o `discovery`. Identificadores canónicos; para discovery el
  contexto es el adaptador, no una red particular. Registrar dispositivos
  observados aparte del objetivo seleccionado. SSID/nombre no es identificador.
- Análisis offline usa SHA-256 de la captura y BSSID si existe. Registrar hash
  del diccionario como contexto sin publicar su contenido. Hash de destino y
  nombres de salida no incluyen claves ni SSID arbitrarios.
- Cada paso tiene nombre fijo, kind, estado, rc, timestamps, señal y cobertura;
  sidecar con identidad coincidente y hashes de sus artefactos. `restore`
  conserva estado previo observable, resultado de recuperación y diagnóstico.
- Separar `complete` (finalización del runtime), estado operativo e indicadores
  de evidencia como `handshake_validated`, `key_recovered`, `cancelled` y
  cobertura `completa/parcial/no_determinada`. Conservar rc de cada herramienta
  incluso cuando una operación cancelada haya dejado artefactos utilizables.
- Estados: `EJECUTADO`, `CONFIRMADO`, `DENEGADO`, `OMITIDO`,
  `NO_DETERMINADO`. `CONFIRMADO` requiere prueba estructural del kind, no texto
  de un echo, archivo existente, palabra suelta o rc 0. Una red detectada es
  inventario; monitor verificado es operación, no vulnerabilidad.
- Validar handshake con herramienta offline y BSSID concordante; la extensión
  `.cap`, un encabezado de pantalla o su tamaño no bastan. Si la versión de la
  herramienta no permite conclusión fiable, devolver no determinado.
- Clave recuperada solo con evidencia inequívoca de la herramienta. Diccionario
  agotado con captura válida es análisis ejecutado sin clave, no prueba de
  contraseña segura. No intentar autenticación posterior automáticamente.
- Visor `show_results.sh` de solo lectura: filtros por objetivo, operación y
  adaptador; historial separado del último intento. Clave de selección:
  `(target_type, target_id, operation, adaptador/controlador, BSSID offline)`.
  Orden por inicio del run, desempate por run_id; una ejecución antigua que
  termina tarde no reemplaza a un intento más reciente.

## Procesos, interrupciones y datos privados

- Captura, salto de canales y descubrimiento Bluetooth son operaciones que
  pueden permanecer activas. Mostrar cómo detenerlas y esperar cancelación o
  finalización de la herramienta; no usar `head` como control de duración.
- Gestionar PID/grupo propio y esperar hijos al terminar. Nunca `killall` ni
  `pkill` global. No permitir operaciones propias concurrentes incompatibles
  sobre el mismo adaptador: informar de conflicto y liberar el bloqueo al salir.
- `bluetoothctl` se controla mediante una sesión propia: finalizar el escaneo
  iniciado por esta ejecución sin apagar el controlador ni detener sesiones
  ajenas. Si ya existía descubrimiento externo, no apropiarse de él para luego
  desactivarlo; informar y conservar ese estado.
- SIGINT/SIGTERM registran interrupción y ejecutan limpieza/restauración;
  ninguna señal se presenta como éxito completo. Las capturas parciales se
  conservan y pueden verificarse offline mediante una ejecución separada.
- No incluir claves recuperadas, contenido de paquetes ni argumentos sensibles
  en metadata, visor, pantalla del gestor o informes. Guardar resultados
  sensibles solo en evidencia privada; no pasar claves como argumento de CLI.
- Tratar SSID, nombres Bluetooth y nombres de archivo como datos no confiables:
  sin evaluación shell, sin escapes de terminal activos ni rutas fuera del run.
  Rechazar traversal/symlinks que permitan escribir fuera de los árboles propios.

## Comportamiento de run_all_wireless.sh

- Acepta interfaz posicional (INTERFACE) y se autolocaliza.
- Conserva y mejora la cadena existente: escaneo WiFi, activación de monitor y
  escaneo Bluetooth. Corregir propagación de fallos, dependencias y estado de la
  interfaz no debe retirar ninguna de esas etapas.
- Desautenticación y craqueo se mantienen plenamente disponibles mediante sus
  scripts y opciones del menú. Actualmente no forman parte de esta cadena;
  no confundir conservarlas con añadir su ejecución automática a un flujo que
  no las ejecutaba. Cualquier ampliación de la cadena se debe definir y aprobar
  expresamente, no introducirla de forma implícita.
- Cuenta ejecutadas/fallidas/omitidas y sale 1 si hay fallos.
- Las tres etapas históricas son requeridas: una dependencia/hardware ausente
  cuenta como fallo explicado, nunca como «todo completado». Una etapa que no
  puede seguir por un fallo previo se marca omitida con causa; Bluetooth puede
  continuar como etapa independiente. No añadir bucles infinitos a la cadena.
- La activación de monitor dentro del flujo es temporal: se restaura al acabar
  el flujo, incluso tras fallo Bluetooth. La orden independiente de activar
  monitor conserva el modo solicitado, como se define arriba.
- stderr de cada hijo a `errores.log` del directorio de salida.
- No añade topes ni timeouts.

## Scripts que deben autolocalizarse

`run_all_wireless.sh`, `wifi_scan.sh`, `wifi_monitor.sh`, `wifi_handshake.sh`,
`wifi_deauth.sh`, `wifi_crack.sh`, `bt_scan.sh`, `bt_discover.sh`,
`interface_manager.sh`, `channel_hopper.sh` deben resolver `MODULE_DIR` desde
`BASH_SOURCE`, no desde `$PWD`, y escribir bajo su módulo o `scans/` según
corresponda.

## Tests aislados

- `tests/run_wireless.sh`: guardas de fuentes/config/sesión + descubrimiento de
  `tests/test_wireless_*.py`.
- `tests/test_wireless_runtime.py`: contrato del runtime (init, capture, publish,
  finish) con comandos inocuos en árbol temporal.
- `tests/test_wireless_menu.py`: navegación del menú con entrada piped.
- `tests/test_wireless_verify.py`: contraste de metadata y rc.
- Añadir `test_wireless_leaves.py`, `test_wireless_reports.py` y
  `test_wireless_processes.py`: argumentos históricos, correcciones reales,
  señales/hijos, restauración, concurrencia e informes atribuibles.
- PATH cerrado con herramientas simuladas, HOME/config/sesión sintéticos y
  fuentes copiadas a `/tmp/opencode`; ninguna herramienta real de radio,
  sudo, interfaz, historial o servicio se ejecuta en estas pruebas.
- Casos obligatorios: sin adaptador, rfkill, privilegios insuficientes, canales
  inválidos, varias interfaces/controladores/redes por captura, backend BT
  ausente, captura truncada, diccionario inexistente, salida vacía, stderr con
  rc 0, fallo parcial y último intento fallido/incompleto después de uno válido.
- Comprobar permisos, hashes de artefactos, nombres con espacios/control de
  terminal, sidecars corruptos, escapes de ruta y ausencia de claves en todas
  las salidas públicas. Guardas de contenido y modo para configuración, sesión,
  fuentes y evidencia previa, incluyendo detección de ficheros nuevos indebidos.
- Verificador `tests/verify_wireless_real.py MANIFEST --case NAME` de solo
  lectura: códigos 0 coincide, 1 discrepancia, 2 faltan datos; contrasta identidad,
  estados, rc, sidecars y hashes. No genera tráfico ni reemplaza prueba física.
- Suites antiguas exclusivamente en clon limpio sin evidencia ni datos reales.
  `bash -n` debe comprobar también stderr; Python sin bytecode en fuentes reales.

## Integración con informes

- Parser `11_Reports/lib/parsers/wireless.py` que lee `run.json` y `.meta.json`
  de `scans/wireless/wireless_*` y produce `ParseResult`, sin volcar cuerpos.
- Registro en `sources.py` (`_PARSER_MODULES`).
- Reglas `wireless.inventario`, `wireless.handshake`, `wireless.key_recovered`,
  `wireless.ejecutado`, `wireless.denegado`: inventario, handshake y denegación
  son informativos, no vulnerabilidades automáticas. Recuperación de clave se
  describe en el contexto exacto del diccionario usado, sin publicar su valor
  ni asignar gravedad alta genérica a cualquier operación exitosa.
- Validar módulo, versión, tipos, identidad, complete, pasos, rc y sidecars
  concordantes y hashes antes de aceptar evidencia. Manifest sin pasos,
  inconcluso, inválido o con restauración fallida no produce hallazgo de éxito.
- Un intento posterior fallido/incompleto no revive éxito histórico. Si no es
  posible atribuir un manifest corrupto, señalar cobertura no evaluable y no
  presentar el resultado histórico potencialmente afectado como resultado actual.
- `lib/attribution.py`, `sources.py` y `engine.py` requieren integración mínima
  explícita para identidades inalámbricas: no pasar MAC por normalización IP/URL
  ni asignar resultados a la IP de sesión. En informes por IP/dominio, fuentes
  inalámbricas quedan fuera salvo asociación explícita aportada por el operador;
  el informe inalámbrico usa un selector tipado separado de `--objetivo` legado.
- Propuesta de selector de informes: `--wireless-target TYPE:ID` (BSSID/MAC o
  hash), mutuamente excluyente con `--objetivo`; `--todos` las incluye con su
  identidad real. No registrar MAC/BSSID automáticamente en scope.yaml o
  targets.txt ni cambiar el comportamiento de informes existentes de 03–06.

## Documentación

- `docs/WIRELESS-GUIADO-YYYY-MM-DD.md` con síntomas/causas/fixes/evidencia.
- `07_Wireless/README.md` actualizado con menú guiado, evidencia y visor.
- Actualizar `07_Wireless/USE.md` y `docs/MANUAL-GESTOR.md`; documentar argumentos,
  restauración, interrupción y recuperación después de apagado, permisos,
  privacidad, versiones de herramientas verificadas y límites de hardware.

## Enfoques considerados

1. Revisión integral: biblioteca + runtime + evidencia + menú + tests + informes.
   Mayor trabajo, evita inconsistencias. Recomendación técnica coherente con la
   petición de mejorar todo el módulo sin retirar capacidades.
2. Revisión por bloques: mismos objetivos, entregas sucesivas. Facilita parciales.

El usuario ha aprobado el menú y los acuerdos explícitos al inicio. La solución
integral detallada aquí y los contratos técnicos quedaron aprobados globalmente
el 2026-11-11. Esa aprobación autoriza preparar el plan, no ejecutar operaciones
inalámbricas reales.

## Criterios de aceptación y decisiones del implementador

- Las diez entradas originales (nueve hojas y run_all) permanecen disponibles;
  ninguna operación activa se transforma en una guía. La guía histórica de
  handshake permanece y los dos modos nuevos son adicionales.
- Menú aprobado navegable con cancelación/EOF, sin ejecución por entrar, con
  todas las funciones y confirmaciones existentes conservadas.
- Fallos reales, señales, cobertura y recuperación son visibles y contrastables;
  evidencia privada por run, correctamente atribuida y sin éxito heredado.
- No afirmar compatibilidad de hardware, captura válida ni auditoría real por
  el mero paso de tests sintéticos. Documentar validación física pendiente.
- El implementador elige nombres de funciones auxiliares, distribución interna
  de tests y parsers de versiones respaldados por fixtures; no puede cambiar
  el menú aprobado, contratos CLI, operaciones conservadas ni criterios de prueba.
