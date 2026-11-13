# Módulo 10 — revisión integral de evidencias

Fecha: 2026-11-13. Estado: revisión independiente completada; pendiente de
aprobación del usuario.

Revisión de planificabilidad: sesión `ses_e29e50f1cffeIzQaj5CtEy6No3`;
resultado `nothing important left`. No es aprobación del usuario ni revisión
de una implementación.

## 1. Intención y acuerdos

El usuario solicita revisar y mejorar integralmente `10_Evidence`, trabajando en
un worktree local para su posterior integración en `develop`. Ha elegido el
enfoque 2: conservar los tres scripts como interfaz y centralizar la gestión de
evidencias en un auxiliar Python. Se mantienen importación, listado, verificación,
empaquetado, screenshot web, captura de tráfico, escaneo y contexto del operador.
No se retiran capacidades; los comportamientos peligrosos o engañosos cambian
como se propone abajo, sujetos a aprobación de este documento.

Worktree: `/home/kali/.local/share/opencode/worktree/f6569d/module-10-evidence`.
Base observada: `3a63550`, también HEAD de `develop` al crear el worktree. El
checkout original contiene modificaciones locales de `scope.yaml` y
`targets.txt`, que no se copian, publican ni modifican. No se hace push.

### Enfoques considerados

1. Reparación exclusivamente en Bash: pequeña, pero mantiene parsers de
   metadatos y operaciones de archivos frágiles.
2. Interfaces Bash y núcleo Python, **elegido por el usuario**: facilita
   validación, SHA-256, publicación sin sobrescrituras y paquetes verificables;
   añade un auxiliar interno y pruebas específicas.
3. Plataforma de casos y custodia: demasiado alcance; no se introduce base de
   datos, servicio, usuarios, firma digital ni gestión jurídica de expedientes.

## 2. Hallazgos y evidencia de partida

Reproducción en copia temporal con contenido sintético, sin red:

- `--verify` imprime `HASH MODIFICADO`, luego `Todas las evidencias están
  íntegras` y retorna 0. Causa: contador dentro del subshell de una tubería.
- `--package` incluye `evidence_manager.sh` y excluye todos los `.meta`.
  Causa: `tar` sobre `.` con `--exclude='*.meta'`.
- Los tres scripts pasan `bash -n` sin stderr. Esto no acredita comportamiento.

Hallazgos por lectura que deben tener reproducción/prueba antes de corregirse:

- `--add` cambia de cwd antes de resolver la entrada relativa, usa nombres con
  precisión de segundos y no comprueba `cp`, escritura de metadatos o hash.
- El lector `.meta` corta nombres con espacios y no valida campos/rutas.
- El empaquetador puede sobrescribir salidas, acepta un nombre como ruta,
  sobrescribe/borra `manifest.txt` y confunde existencia con creación exitosa.
- `auto_capture.sh` fuerza HTTP, oculta stderr, anuncia screenshot y nmap sin
  comprobar éxito, inserta el objetivo en rutas y lanza un escaneo completo.
- `run_all_evidence.sh` ignora fallos de hijos y termina anunciando éxito.
- El gestor descubre recursivamente scripts dentro de árboles de evidencias;
  el módulo 10 necesita un inventario fijo y un despacho restringido.
- La marca de fase actual considera suficiente que exista cualquier archivo.

## 3. Objetivos, límites y restricciones

### Objetivos

- Resultados y códigos de salida veraces, sin equiparar ausencia de datos,
  fallo, modificación o ejecución parcial con éxito.
- Entradas de archivos independientes del cwd y sin interpretación por shell.
- Importación por copia, sin cambiar el original, sin sobrescribir históricos.
- Integridad técnica SHA-256 y metadatos estructurados para nuevas evidencias.
- Compatibilidad de lectura con evidencias antiguas, sin migración automática.
- Exportación explícita de evidencia y metadatos, no del código del módulo.
- Acciones de red/locales sensibles solo por selección explícita.
- Pruebas aisladas con fixtures/stubs; guías en español acordes al contrato.

### No objetivos y antimetas

- No se modifica 08, 09, el motor de informes ni se implementa un flujo 99 nuevo.
  Solo se ajustan las conexiones del gestor/estado necesarias para 10.
- No se afirma cadena de custodia legal, autenticidad del origen, resistencia
  frente a un atacante con escritura sobre evidencia y metadatos, ni auditoría
  operacional con herramientas reales. Hash y manifiesto no son firmas.
- No hay descifrado/cifrado automático, firma, borrado, saneado de credenciales,
  subida, extracción de paquetes ni instalaciones/sudo automáticos.
- No se rehasha evidencia antigua para declararla moderna o confiable.
- No se unen objetivos ni se atribuyen hallazgos por el objetivo de sesión.
- No se ejecutan evidencias, escaneos reales ni suites heredadas sobre datos
  reales; no se declara toda la rama verde por pruebas de este módulo.

Python 3 estándar, Bash y patrones del proyecto; sin dependencias nuevas.
El auxiliar se aloja en `00_Config/lib/evidence/` para no aparecer como hoja.
Todo acceso a datos se limita a raíces explícitas del módulo o de tests. Los
defaults no dependen de `$PWD`, `$HOME` ni del objetivo de sesión.

## 4. Arquitectura e interfaces

- `10_Evidence/evidence_manager.sh`: wrapper de gestión, mantiene `--add`,
  `--list`, `--verify`, `--package`, `--help`; delega preservando argv y rc.
- `10_Evidence/auto_capture.sh`: wrapper de adquisición explícita; el núcleo
  coordina subprocesses con listas de argumentos, sin `shell=True`.
- `10_Evidence/run_all_evidence.sh`: wrapper de coordinación; no captura por
  recibir únicamente un target. La captura exige `--capture` y las selecciones
  explícitas descritas abajo; sin captura ofrece `--offline` para listar y
  verificar. Nunca anuncia completado si un paso falla o queda parcial.
- `00_Config/lib/evidence/`: gestión de archivos/registros, CLI, adquisición y
  exportación; separación interna concreta a criterio del implementador.
- `00_Config/lib/evidence_menu.bash`: UI guiada, argumentos en arrays y
  mensajes en stderr. Puede reutilizar patrones de 08, no su runtime completo.

Ayuda sin argumentos: ayuda y rc 2; `--help`: rc 0. Argumentos desconocidos,
sobrantes o inválidos: rc 2. Fallo de operación/verificación, evidencia parcial o
dependencia requerida ausente: rc 1. Acción solicitada completa: rc 0. Cancelar
el menú/EOF vuelve sin acciones y rc 0. No existe código de éxito para una
operación vacía presentada como verificación positiva.

## 5. Almacenamiento e importación

Se conservan las categorías actuales:

| Tipo | Raíz de registros nuevos |
|---|---|
| screenshot | `screenshots/web/` |
| pcap | `pcaps/traffic/` |
| credential | `credentials/found/` |
| finding | `findings/vulnerabilities/` |
| proof | `proofs/access/` |
| log (uso interno de captura) | `logs/results/` o `logs/audit/` |

Cada registro nuevo se publica en un directorio de ID aleatorio único, con un
archivo de contenido y `evidence.json`. No se reutilizan rutas por basename,
fecha, objetivo o descripción. Los metadatos contienen: versión de esquema,
ID, tipo, nombre original como dato, nombre almacenado relativo seguro, tamaño,
SHA-256, fecha UTC, descripción, origen `import`/`capture`, etiqueta de objetivo
opcional explícita y, para captura, ID de ejecución y método. No se guardan
credenciales de URL ni el cuerpo del archivo en metadatos/salida. El contexto
del operador se distingue del sistema objetivo.

`--add <TIPO> <ARCHIVO> [DESCRIPCION] [--target ETIQUETA]` conserva los cinco
tipos públicos originales. Resuelve el archivo relativo al cwd del llamador
antes de cualquier cambio de directorio. `--target` es una etiqueta opcional,
no autorización ni validación del contenido. Nuevas etiquetas no modifican
scope/targets/sesión. No se adopta automáticamente la sesión del gestor.

Importación solo de archivos regulares, no enlaces simbólicos, dispositivos,
FIFO o directorios. Usar descriptor del origen, copia en streaming y comprobación
de estabilidad (identidad/tamaño/mtime antes y después); si cambia, fallar sin
publicar éxito. La copia no prueba que la fuente permaneciera inmóvil frente a
un atacante capaz de restaurar metadatos: se documenta ese límite.

Crear staging privado y publicar el registro completo sin reemplazar un destino
existente. Directorios nuevos 700, archivos nuevos 600, independientemente del
umask. Raíces y descendientes usados deben ser directorios reales, sin enlaces;
los metadatos no pueden escapar de su registro. No se intenta defender de un
adversario local privilegiado ni reparar permisos de históricos silenciosamente.
Fallos dejan diagnósticos claros, no registros incompletos marcados como válidos.
La limpieza solo retira temporales propios de la operación.

## 6. Listado y verificación, nuevos e históricos

Listado solo de datos y estado, sin ejecutar ni mostrar cuerpos/contraseñas.
Escapar caracteres de control al imprimir nombres/descripciones. Mostrar ID,
tipo, formato, etiqueta explícita si la hay y estado: nuevo verificable,
histórico MD5, sin metadatos, inválido o modificado. El listado no reescribe ni
certifica integridad; la comprobación de contenido corresponde a `--verify`.

`--verify` examina las seis raíces de datos conocidas, no `find .` sobre código.
Valida estructura, versión, campos, rutas confinadas, archivo regular, tamaño y
SHA-256 de registros nuevos. No sigue symlinks; metadatos malformados, duplicados,
contenido ausente, hash/tamaño discordante y archivos de evidencia no registrados
son problemas. Ningún error queda oculto por una tubería. Verificar cero
evidencias retorna 1 con `SIN EVIDENCIAS`, no `todas íntegras`.

Históricos `.meta`: lectura estricta no destructiva de las claves originales
`TYPE`, `DATE`, `FILE`, `DESCRIPTION`, `HASH`, `USER`; conservar espacios del valor
de FILE, exigir basename seguro y MD5 de 32 hex. Rechazar claves de identidad/hash
duplicadas, referencias repetidas o rutas ajenas. Permitir descripción vacía y
campos informativos antiguos sin interpretarlos como comandos.
Una evidencia válida de este formato es `HISTÓRICA — MD5 COINCIDE`, no SHA-256 ni
prueba de autenticidad. Permite rc 0 si todo lo presente está cubierto y coincide,
con advertencia explícita del algoritmo heredado. Históricos sin `.meta` se
listan pero impiden un resultado global de verificación positiva.

Diagnósticos de adquisición en `logs/runs/` son un namespace reservado, con
esquema de ejecución validado, fuera del inventario de evidencias; no basta
depositar archivos arbitrarios allí para que se consideren verificados. Se
informa de su exclusión. Un registro de ejecución no acredita sus evidencias.
No se crea/adopta metadata histórica para ocultar el problema.

## 7. Empaquetado

`--package [NOMBRE]` mantiene el comando, pero NOMBRE es solo un nombre simple,
sin separadores, puntos de navegación ni caracteres de control. Se genera
`11_Reports/evidence/<nombre>_<id-unico>.tar.gz`; no reemplaza paquetes previos.
Permisos privados y staging en ese mismo árbol, excluido de git.

Precondición: inventario no vacío y verificación completa satisfactoria. Si hay
archivos sin metadata, referencias inválidas, modificaciones o lecturas fallidas,
no se publica paquete. El diagnóstico identifica el problema sin mutar datos.
No hay `--force` que convierta una verificación fallida en exportación fiable.

El paquete contiene únicamente las copias de contenido y metadatos de registros
verificados, manteniendo rutas relativas confinadas, y `manifest.json` generado
en staging. No contiene scripts, documentación, configuración, fuentes originales
externas, diagnósticos de ejecución ni paquetes anteriores. Los registros legacy
incluyen su `.meta` original; el manifiesto los identifica como legacy MD5, sin
reescribirlo. SHA-256 de los bytes exportados permite verificar el paquete, no
eleva la confianza histórica de la evidencia.

Manifiesto versionado con ID de paquete, UTC, lista exacta de miembros, tamaños y
SHA-256 por miembro de datos/metadatos; no intenta hashearse a sí mismo. El
contenido se copia a staging y se contrasta con la verificación antes de publicar;
cualquier cambio durante la exportación aborta. El archivo temporal se comprueba
contra su manifiesto antes de publicación. Los miembros no son symlinks, rutas
absolutas ni `..`. No se escribe/borra `10_Evidence/manifest.txt`.

Advertencia explícita: puede incluir credenciales y material confidencial; no
hay cifrado automático. La acción de empaquetar exige confirmación en el menú,
pero el comando CLI explícito no necesita una segunda confirmación interactiva.

## 8. Captura explícita y coordinación

Contrato propuesto de `auto_capture.sh`:

```
auto_capture.sh [--web URL] [--traffic HOST --interface IFACE]
                [--scan HOST --scan-profile basic|full] [--system]
                [--duration SEGUNDOS] [--packet-limit N]
                [--authorize-network]
```

Al menos una acción. No hay acción por omisión. `--web`, `--traffic` o `--scan`
requieren `--authorize-network`, que afirma autorización del operador pero no
extiende el alcance configurado ni garantiza que este sea una barrera efectiva.
En el menú se pide confirmación explícita y luego se pasa ese flag. CLI sin flag
falla antes de lanzar herramientas. Los límites y la acción se muestran antes
de la confirmación. `--system` es explícito y solo recoge contexto del host
operador, no datos remotos.

- Web: URL HTTP/HTTPS explícita, puerto/ruta preservados, sin credenciales ni
  controles. Rechazar fragmentos y sintaxis ambigua. No construir HTTP a partir
  de un target. Usar cutycapt con deadline; sin instalación automática. No se
  promete confinamiento de subrecursos/redirecciones de un navegador: la
  autorización debe incluirlos y la ayuda lo advierte. Validar rc, contenido
  no vacío y cabecera PNG antes de importar como screenshot válido.
- Tráfico: HOST único validado (IP o dominio, sin CIDR/opciones/filtro libre),
  interfaz explícita; tcpdump con argumentos separados y filtro construido a
  partir de ese único host, sin comandos shell. Duración por defecto 10 s,
  configurable 1–300 s; límite por defecto 100 paquetes, configurable 1–10000.
  No ejecutar sudo. Finalizar de forma controlada al alcanzar duración y esperar
  reap del hijo; comprobar resultado/cabecera/longitud PCAP. Una captura válida
  sin paquetes se etiqueta `SIN TRÁFICO`, no demuestra fallo del target. Un
  timeout normal del intervalo no equivale a fallo si hubo cierre y salida válida.
- Escaneo: HOST único validado y perfil obligatorio. `basic`: TCP connect, 100
  puertos, sin NSE/versionado. `full`: conserva capacidad `-sV -p-`, sin
  `--min-rate 1000` implícito; se advierte coste/intrusividad. Ambos sin sudo,
  deadline total; valor exacto de deadline queda al implementador y debe
  documentarse. Guardar stdout/stderr y comprobar rc y señal de finalización de
  Nmap, no solo existencia del archivo. No importar salida parcial como exitosa.
- Sistema: UTC, usuario, hostname y uname con etiqueta inequívoca `OPERADOR`.
  Evitar secretos de entorno y no usarlo para atribuir OS/usuario al target.

Captura secuencial con ID único por ejecución. Guardar stdout/stderr privados y
`run.json` en `logs/runs/<id>/`: acciones pedidas, estados, tiempos, rc, causas de
omisión/fallo y IDs de evidencia publicados. Evitar argumentos con secretos;
URLs admitidas no llevan credenciales. Dependencias faltantes no se instalan ni
se confunden con éxito. Las acciones independientes seleccionadas pueden
continuar tras un fallo; el resultado global es rc 1 si alguna falla o queda
parcial. Cada éxito produce un registro nuevo verificable mediante el mismo
núcleo; los fallos solo diagnósticos privados, no evidencia positiva.

INT/TERM: no publicar éxito del paso interrumpido, terminar y esperar procesos
propios y sus descendientes mediante grupo de procesos propio, sin matar otros
procesos de la sesión. No dejar capturadores ejecutándose tras retornar.
Escalado acotado de terminación y rc 130/143 para señal; no se imita el contrato
especial de montaje de 08, aquí no hay montajes ni recursos kernel propios.

`run_all_evidence.sh --capture <opciones anteriores>` coordina captura, listado y
verificación, conservando estado parcial/fallido. `--offline` lista y verifica
sin red. La invocación heredada `<TARGET>` devuelve rc 2 con guía para elegir
acciones explícitas; no lanza capturas ni escaneos. Esto también evita adquisición
implícita desde 99: se documenta la incompatibilidad del contrato activo antiguo,
sin afirmar que el flujo 99 global quede reparado.

## 9. Gestor, descubrimiento y estado

`10` abre menú guiado con comprobación de disponibilidad solo `command -v`,
importación por archivo explícito, listado, verificación, empaquetado, captura
por acciones seleccionadas, coordinación offline y acceso a las tres entradas
originales. No hay red, lectura de cuerpos, escritura de registros, sincronización
de claves o selección de objetivo al entrar, consultar ayuda o salir/EOF.

Inventario fijo de los tres scripts originales tanto en la lista avanzada como
en `execute_script`, con rechazo de rutas no permitidas y scripts enlazados.
No se hace `chmod` ni se ejecuta `.sh`/`.py` recuperado/importado. Los prompts
de archivos aceptan un valor por línea (incluyendo espacios), sin eval ni
splitting de shell. Los argumentos de importación y URLs no se ecoan enteros
por el gestor. El despachador respeta confirmaciones también en modo preparado;
un flag de preparación no evita confirmar capturas o exportación.

Actualizar la ficha de módulo y sus advertencias de forma consistente con la
introducción existente. `phase_state` para 10 consulta únicamente presencia de
registros/evidencias reconocibles en las seis categorías, sin releer cuerpos,
crear ficheros ni ejecutar herramientas. `done` significa `hay evidencia`, no
`integridad verificada`; explicitar ese significado en ayuda. No sustituirlo por
un sello persistente de verificación. Un archivo arbitrario o solo diagnóstico
no basta. Detalle del sondeo liviano queda al implementador; debe incluir legacy.

## 10. Pruebas y criterios de aceptación

Suite dedicada aislada, con fuentes copiadas a temporal bajo `/tmp/opencode`,
HOME/scope/targets/session sintéticos y PATH controlado. Nunca usar evidencias
reales. Crear regresiones que fallen antes de cada corrección. Cobertura mínima:

1. Wrappers: argv con espacios, cwd externo, rc y ayuda/errores de CLI.
2. Importación: todos los tipos, mismo basename/segundo, no overwrite, permisos,
   lectura/escritura fallida, origen que cambia, symlinks/FIFO/dispositivos y
   rutas/controles maliciosos; preservación de originales e históricos.
3. Metadata/hash: esquema, campos/rutas/tamaños, corrupción, desaparición,
   duplicados, JSON inválido, legacy con espacios/MD5, huérfanos e inventario
   vacío; nunca éxito global tras error.
4. Exportación: manifiesto/metadatos incluidos, solo miembros autorizados,
   sin código/secretos externos/diagnósticos, paquetes sin reemplazo, fallos de
   escritura/lectura, cambios durante copia y archivo final verificable.
5. Capturas con stubs: cero acciones implícitas, confirmaciones, URL HTTPS/puerto,
   validación HOST/interface/límites, dependencia ausente, rc no cero,
   PNG/PCAP inválidos, PCAP sin tráfico, finalización Nmap, resultados parciales,
   señales y reap de descendientes. Ningún binario de red real se ejecuta.
6. Menú: entrada/salida/EOF sin efectos, prompts con espacios, inventario fijo,
   rechazo de código dentro de datos incluso por `execute_script --prepared`,
   confirmaciones de red/exportación y ninguna IP de sesión implícita.
7. Estado de fase para seis categorías y legacy, exclusión de diagnósticos y
   cuerpos nunca leídos por el sondeo; gitignore de todas las salidas nuevas.

Regresiones de gestor/introducciones/informes y librerías relacionadas se
ejecutan solo en copia limpia con configuración sintética, tras inspeccionar sus
efectos. Sintaxis Bash capturando stderr y AST Python sin escribir pyc.
La suite heredada completa tiene fallos conocidos: documentar comparación si se
ejecuta, sin declarar rama verde ni ampliar alcance para repararla.

Aceptación: pruebas dedicadas y regresiones seleccionadas satisfactorias;
ninguna evidencia/configuración real alterada; errores reproducidos resueltos;
guías `README.md`, `USE.md`, `FLUJO.md` y nota de cierre alineadas con las CLI;
revisión de especificación y calidad antes de integrar. Integración local en
`develop` preservando el checkout original sucio, sin push y sin borrar el
worktree/logs como limpieza automática.

## 11. Decisiones propuestas por el agente y pasos siguientes

El usuario eligió el enfoque, no ha aprobado aún los contratos detallados.
Son propuestas del agente: registros nuevos por UUID/SHA-256, legacy de solo
lectura, exportación bloqueada ante evidencia no verificable, selección activa
explícita (cambio de contrato de TARGET), límites de tráfico, perfiles Nmap,
auxiliar Python estándar y alcance mínimo del indicador de fase.

Tras revisión independiente y aprobación del usuario, redactar plan de
implementación con tareas, TDD, verificación y revisiones. No implementar antes.
