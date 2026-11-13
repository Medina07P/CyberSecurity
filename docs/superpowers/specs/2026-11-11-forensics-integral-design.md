# Revisión integral de 08_Forensics — diseño

Estado: aprobado expresamente por el usuario el 2026-11-11. El usuario eligió
revisión integral con biblioteca común, además de menú y documentación. La
aprobación del diseño no autoriza ejecución operacional sobre evidencias reales.

Acuerdo posterior: dispositivos físicos accesibles únicamente mediante un
modo explícito de adquisición/recuperación o inspección de metadata. El análisis
de archivos se mantiene separado. No exigir una copia íntegra previa a ddrescue
cuando el origen esté dañado.

## Intención

Conservar las diez entradas originales y sus métodos, corregir fallos reales de
ejecución y proteger originales y resultados previos. Una ejecución concluida
no significa «sin incidentes» y una coincidencia de texto no prueba credenciales
válidas ni una vulnerabilidad. La IP de sesión no identifica una evidencia
forense y no debe proponerse como archivo o atribuirse automáticamente.

## Enfoques considerados

1. **Biblioteca común y revisión integral (elegido):** centralizar entrada,
   directorios privados por ejecución, captura/rc, integridad y resumen. Más
   trabajo inicial; evita diez contratos contradictorios.
2. **Correcciones por script:** menor acoplamiento y cambios iniciales, pero
   repite lógica y mantiene riesgo de resultados sobrescritos/éxitos falsos.

Se conserva Bash para hojas/CLI y gestor. Propongo Python estándar para
manifiestos, SHA-256, validación y visor; sin dependencias Python nuevas.
El diseño concreto de esas interfaces es propuesta técnica, no un requisito
que el usuario hubiese especificado previamente.

## Inventario que se conserva

| Entrada | Función conservada |
|---|---|
| requirements.sh | Comprobación y acceso explícito a instalación de dependencias |
| run_all_forensics.sh | Flujo forense coordinado, con selección explícita de fuentes |
| memory/memory_dump.sh | Adquisición AVML/LiME/dd donde sean utilizables |
| memory/volatility_analysis.sh | Análisis de procesos, árboles, conexiones, DLL e historial |
| memory/strings_analysis.sh | Strings, patrones, URLs y correos |
| disk/disk_forensics.sh | Identificación/particiones/filesystem y listado sobre copia montada |
| disk/file_carving.sh | Foremost, Scalpel y ddrescue |
| logs/log_analyzer.sh | Estadísticas, niveles, errores, autenticación, SSH e IPs |
| pcaps/pcap_analyzer.sh | Información, protocolos, conversaciones, DNS, HTTP y artefactos |
| timeline/timeline_creator.sh | Línea temporal, fuentes locales históricas y selección offline |

Las posiciones válidas actuales de las hojas se mantienen. Los argumentos
adicionales tienen ayuda explícita; `Uso:` no contiene separadores `|` dentro
de slots y los ejemplos no activan adquisiciones/montajes/instalaciones.
No convertir analizadores en guías ni retirar métodos porque falte un binario.

## Separación de adquisición y análisis

El menú se abre sin ejecutar herramientas. Separa:

- comprobación local de dependencias, sin ejecutarlas ni instalar;
- selección explícita de archivos de trabajo para análisis offline;
- adquisición local de memoria/eventos, claramente identificada y separada;
- análisis de disco y recuperación, con explicación de acceso y espacio;
- flujo por fuentes elegidas, visor de resúmenes y lista completa original.

No se toma `/dev/sda1`, `/dev/mem`, logs del sistema o capturas encontradas por
glob como defecto de una prueba offline. La lista original conserva acceso a
las diez entradas, pero se identifican las acciones que cambian el sistema o
adquieren información local; sus confirmaciones cubren también el acceso directo
desde el listado, no solo el menú nuevo.

### Cambios de comportamiento propuestos que requieren esta aprobación

- `requirements.sh` sin argumentos comprueba disponibilidad y explica límites;
  instalar queda disponible mediante acción explícita, con lista visible y
  confirmación. No se instala por entrar en 08 ni como efecto de un diagnóstico.
  La implementación/pruebas nunca ejecutan apt/sudo reales.
- `run_all_forensics.sh` sin fuentes muestra selección/ayuda; con entrada no
  interactiva vacía sale sin trabajo, nunca captura memoria silenciosamente.
  El recorrido histórico de adquisición local permanece como modo explícito.
- El montaje automático de un dispositivo original deja de ser un paso
  implícito: el análisis básico obtiene metadata sin montarlo. El listado
  montado permanece disponible explícitamente sobre una copia de trabajo,
  con solo lectura y sin recuperación/replay del journal.

Estos cambios conservan capacidades, pero intencionadamente dejan de ejecutar
por defecto instalaciones/adquisiciones/montajes sensibles. No se consideran
compatibilidad semántica exacta de esos defaults antiguos.

## Protección de entradas y resultados

Las hojas offline validan archivo existente, regular y legible antes de crear
una ejecución; rechazan dispositivo/pipe/socket cuando el modo exige un archivo.
Se admiten rutas con espacios y nombres no interpretables como opciones; no
usar eval ni desdoblamiento de argumentos para construir comandos.

Cada análisis utiliza copia de trabajo privada, no pasa el original a una
herramienta que pueda modificarlo. Se conservan digest SHA-256, tamaño y modo
del original antes/después y se comprueba integridad de la copia. Copiar/hash
archivos grandes requiere tiempo y espacio: mostrarlo antes de empezar, sin
recortar ni muestrear silenciosamente el archivo. Si falta espacio o falla la
copia, no iniciar la herramienta ni anunciar análisis terminado.

Excepción explícita para soporte físico: metadata y recuperación ddrescue
aceptan dispositivo de bloques identificado por el operador en modo físico.
No se monta ni se pasa a analizadores offline. ddrescue lee el origen directo
y escribe una imagen y mapfile NUEVOS en un directorio privado; el origen nunca
es destino de escritura. No se hace hash exhaustivo previo del soporte dañado
ni se reintentan lecturas para fingir una comprobación de integridad completa.
Se registra identidad observada del dispositivo, tamaño si es legible,
herramienta/rc, mapa y cobertura. Una recuperación con sectores pendientes o
ilegibles queda PARCIAL aunque exista imagen; sin interpretar el mapa no se
afirma recuperación completa. Hash de la imagen producida cuando sea posible,
sin equipararlo a hash del soporte original. Foremost/Scalpel analizan la imagen
recuperada por selección explícita, no el dispositivo físico directamente.

Las decisiones técnicas siguientes son propuestas del constructor para hacer
concreto el diseño, sujetas a aprobación del documento completo:

- Cada analizador obtiene una copia independiente desde el original elegido;
  no comparte una copia mutable con otros analizadores. Verificar al completar
  copia y al acabar el análisis. Si cambia contenido/tamaño/modo del original
  o el contenido de la copia, preservar resultados como evidencia no confiable,
  estado FALLIDO con motivo de integridad y bloquear sus pasos dependientes.
  Una lectura incompleta no produce una entrada válida para pasos posteriores.
  Esto detecta cambios observables; no garantiza detectar cambios transitorios
  ni sustituye snapshot externo/escritura bloqueada. No restaurar el original.
- `OUTPUT_DIR` explícito conserva su significado de raíz elegida por operador,
  incluso externa al repositorio. Debajo se crea siempre subdirectorio de run
  nuevo y privado; no se cambia modo/contenido del directorio padre existente.
  Rechazar destinos solapados con el archivo original o una fuente/árbol de
  entrada, symlinks en la ruta de salida y colisiones. Validar artefactos solo
  respecto a raíces de ese run; el visor no recorre destinos externos por
  iniciativa propia: recibe manifiesto/run explícito. Advertir que salidas
  externas no quedan protegidas por gitignore del proyecto y contienen datos
  sensibles; el usuario gestiona su ubicación/retención. El manifiesto propio
  registra la relación sin copiar cuerpos al árbol de código.

La protección es de contenido y permisos de los archivos, no una garantía de
cadena de custodia legal o inmutabilidad física. La propia lectura puede
actualizar atime según el filesystem. Para originales físicos se requiere
procedimiento forense/copia y, cuando corresponda, bloqueo de escritura externo.
No afirmar que `mount -o ro` por sí solo neutraliza todos los journals.

Los resultados nunca pisan nombres fijos de una ejecución anterior. Directorios
700 y archivos 600 desde creación; salidas existentes o symlinks no se truncan.
Los cuerpos, cadenas sensibles, PCAP y memoria permanecen privados. La consola,
visor y resúmenes no imprimen credenciales, paquetes, historial ni argv completos.
Los textos derivados de nombres de archivo se muestran sin controles de terminal.

## Arquitectura y artefactos

Bibliotecas nuevas de 08 bajo `00_Config/lib/`:

- `forensics_runtime.bash`: inicialización, copias/outputs privados, captura de
  stdout/stderr/rc por paso, finalización y propagación de errores.
- `forensics_evidence.py`: esquema, hashes, validación, clasificación de estado,
  selección de intentos y visor de solo lectura, sin escribir bytecode al leer.
- `forensics_menu.bash`: navegación y argumentos preparados, sin usar objetivos
  IP de sesión ni disparar operaciones al entrar/cancelar/EOF.

Los artefactos son forenses, no resultados de escaneo: conservarlos en árboles
ignorados del módulo. Manifiestos y productos de análisis bajo
`08_Forensics/analysis/runs/<run_id>/`; recuperados bajo
`08_Forensics/recovered/<run_id>/`; adquisición RAM bajo
`CyberSecurity-Framework/captures/memory/<run_id>/`.
Los dos últimos se referencian explícitamente desde su manifiesto. Overrides
de raíces para pruebas; cada run tiene identidad impredecible, sin colisiones.
No mover, migrar ni borrar resultados históricos. Ampliar gitignore solo si
una salida nueva no queda ya cubierta.

`run.json` v1 incluye module=08, run_id, operación, modo offline/local,
identidad/digest de entrada o fuente local explícita, inicio/fin UTC,
estado, complete, rc y pasos. Cada paso registra nombre seguro, herramienta,
rc real/señal, estado, cobertura y referencias confinadas a artefactos propios.
No incluir argumentos completos ni contenidos sensibles. Si un paso se publica
después de otro, usa el rc de su captura, no el último rc global del shell.

Estados: `COMPLETADO`, `PARCIAL`, `FALLIDO`, `OMITIDO`, `NO_EVALUABLE`,
`CANCELADO`. COMPLETADO significa que el trabajo solicitado concluyó, no que
exista/esté ausente una intrusión. Sin pasos ejecutados no hay éxito.
Una fuente vacía válida es distinta de falta de permisos, backend incompatible
o formato corrupto. `grep` sin coincidencias no es fallo; fallo de lectura sí.
Una consulta/tabla vacía no se eleva a hallazgo.

CLI: 0 solo para trabajo solicitado completo; 1 ante fallo, cobertura parcial
o cancelación; 2 para uso inválido/precondición no cumplida antes de comenzar.
Los rc de herramientas se conservan íntegros en pasos, aunque el wrapper use
su código de contrato. Un error de metadata también hace fallar la operación.

## Reglas por familia

- **Memoria:** verificar dependencia y permisos sin escalada nueva automática.
  Conservar métodos de adquisición existentes; no cargar módulos del kernel ni
  instalar extractores automáticamente. Solo anunciar volcado tras rc válido
  y archivo regular no vacío; validar integridad antes de usarlo después.
  Volatility conserva backend v2 y distingue v3: no aplicar `--profile` a v3,
  ni inventar perfiles/símbolos. Detectar familia real y plugins compatibles;
  faltas/incompatibilidad se reflejan como cobertura, no «cero procesos».
  No asumir que un volcado Linux es una imagen Windows.
  Concretamente, COMPLETADO para adquisición significa comando solicitado
  terminado sin fallo y artefacto estructuralmente aceptable, no prueba de RAM
  íntegra/consistente: registrar por separado `completitud_memoria=no_verificada`.
  AVML se admite si existe su CLI reconocida; LiME requiere backend ya preparado
  y compatible, no se presume que un módulo de kernel tenga CLI `lime -o`.
  Sin backend reconocido, conservar método visible como NO_EVALUABLE. El método
  dd histórico limitado a 1GiB sigue accesible explícitamente y se etiqueta
  PARCIAL/muestra, nunca volcado completo. No aumentar su volumen por defecto.
  Distinguir archivo producido de adquisición fallida o vacía.
  Volatility v3 se implementa realmente para análisis Windows offline con
  símbolos locales: pslist, pstree, netscan, dlllist y cmdscan/consoles solo si
  existen en la instalación. V2 mantiene los siete análisis históricos Windows
  con perfil proporcionado o detectado sin inventarlo. Otras familias de imagen
  se diagnostican como cobertura no soportada en esta entrega, no como ausencia
  de procesos. No se descargan símbolos ni se consulta red en modo offline;
  símbolos ausentes => paso NO_EVALUABLE y resumen PARCIAL/FALLIDO según trabajo
  efectivamente completado. La compatibilidad se limita a formatos/backend
  reproducidos con fixtures; no se promete soporte de todas las versiones OS.
- **Disco:** metadata sin montaje por defecto. El montaje explícito trabaja
  sobre copia, tiene opciones por filesystem que eviten escritura/replay,
  usa punto propio y limpieza idempotente de sus recursos. Si no puede
  garantizar el modo requerido, no monta y explica cobertura no evaluable.
  SIGINT/SIGTERM no desmontan puntos ajenos ni borran directorios ajenos.
  Cobertura inicial de montaje: imágenes de filesystem ext2/ext3/ext4 y XFS;
  ext3/ext4 con `ro,noload`, XFS con `ro,norecovery`, ext2 con `ro`. Usar loop
  de solo lectura propio, verificar estado antes de listar. Para imagen de
  disco completo, la metadata de particiones permanece disponible; el listado
  requiere offset y extensión de partición seleccionados explícitamente y
  validados contra el tamaño de imagen, sin escoger la primera partición.
  Otros filesystems se identifican pero su montaje queda NO_EVALUABLE en esta
  entrega. No reemplazar opciones específicas por `ro` genérico silenciosamente.
- **Recuperación:** conservar los tres backends y destinos separados dentro
  de run único. Distinguir cero recuperados de fallo/ausencia de herramientas;
  no sobrescribir una imagen ni log de recuperación anterior.
- **Strings/logs:** preservar filtros actuales, distinguir indicadores de
  incidentes probados, manejar archivos vacíos y errores de lectura; resumen
  de conteos sin imprimir líneas sensibles.
- **PCAP:** `capinfos`/`tshark` leen solo copia local, nunca captura en vivo.
  Operaciones actuales preservadas; formato inválido, permisos y herramienta
  ausente no equivalen a «sin tráfico». Captura completa privada antes de
  resumir; no dejar que una tubería oculte el fallo del productor.
- **Timeline:** fuentes offline elegidas, sin consultar journal/logs del host
  en ese modo. Conservar recorrido local como opción explícita. Registrar
  fuentes, zona temporal, límites históricos de salida y cobertura: no llamar
  completa una línea temporal construida con fragmentos/ausencias.
  Entradas offline concretas: journal exportado en formato JSON por línea,
  log de autenticación/syslog de texto y log dpkg de texto; wtmp como archivo
  explícito para backend `last -f` si está disponible; árbol de archivos de
  trabajo explícito para metadata de modificaciones, sin seguir symlinks fuera
  de él. Se preserva así la sección histórica de archivos modificados sin
  recorrer `/` en modo offline. Una fuente ausente no se sustituye por la del
  host actual. Los eventos estructurados llevan origen y timestamp UTC cuando
  puede determinarse; texto sin año/zona usa los valores aportados por operador
  o se conserva sin fecha resuelta en sección separada, nunca se inventa orden
  cronológico. No interpretar conteos/orden de líneas como cronología probada.

## Flujo y visor

El flujo recibe fuentes explícitas y solo encadena operaciones aplicables.
Cuenta ejecutadas/fallidas/omitidas; dependencia o entrada fallida impide pasos
dependientes, no otros análisis independientes. No instala ni adquiere memoria
en modo offline. Memoria adquirida se entrega por ruta exacta validada, nunca
por glob de todos los volcados históricos. Cualquier fallo/partial se propaga.

Añadir `08_Forensics/show_results.sh` de solo lectura: filtra por ejecución,
operación o identidad de entrada y muestra estado/cobertura/rc/hashes, no cuerpos.
Ordenar por instante UTC de inicio, no texto de zona horaria ni fin tardío de
un análisis antiguo. Incompleto, fallido o manifiesto inválido no revive un
éxito anterior como vigente. Identidades diferentes no se mezclan.

No añadir parser al motor global de vulnerabilidades de 11 en esta entrega:
forense e IP objetivo son dominios distintos y no se inventará esa atribución.
La ficha/resumen privado de cada run y el visor cubren trazabilidad de 08.

## Verificación y restricciones

Ejecución con subagentes y revisiones independientes, como en el módulo 07.
TDD por biblioteca/familia y pruebas de integración del menú/flujo. Fuentes,
HOME/PATH/configuración y evidencias sintéticos en /tmp/opencode; todos los
backends, sudo, montaje, journal y adquisición son stubs, sin fallback real.
No leer memoria, discos, logs, capturas o credenciales reales para pruebas.

Guardas de hash/modo/inventario de fuentes y evidencias sintéticas; comprobar
preservación de los pendientes ajenos de 06 y scope mediante digests, sin
exponer contenidos. Testear rc, stderr, ausencias, vacío, señales, espacios,
symlinks, archivos duplicados y metadata contradictoria o incompleta.
Los tests de visor/validación no crean bytecode ni escriben en ninguna copia
de evidencia/código. Sintaxis Bash con stderr y AST Python sin bytecode.

Regresión de módulos ya mantenidos exclusivamente en copias limpias; conservar
el estado rojo conocido de run_tests sin debilitar asertos ni atribuir causas
no demostradas. Sin instalaciones, montajes, adquisiciones o análisis reales,
sin flujo99. Commits locales con rutas explícitas; sin push. Conservar logs de
pruebas y reportes. No declarar validación operacional ni cadena de custodia
probada por el resultado de stubs.
