# Uso de 08_Forensics

## Antes de empezar

Solo fuentes y sistemas autorizados. Para operar las hojas se requiere Bash,
Python >=3.11 y Linux con pidfd/prctl utilizables: no hay fallback inseguro del
supervisor. Dependencias presentes en PATH no acreditan permisos, versiones ni
compatibilidad de imágenes. La comprobación `requirements.sh`/`--check` usa solo
`command -v`, no ejecuta binarios ni instala. No necesita objetivo de sesión.

El menú `08`: 1 dependencias, 2 strings, 3 logs, 4 PCAP, 5 Volatility,
6 disco/recuperación, 7 timeline offline, 8 local/adquisición, 9 flujo offline,
10 visor, 11 listado original, 0 volver. `!`, cancelación y EOF descartan la
selección incompleta. Nunca se usan valores sensibles de Ejemplo como defaults.
Opciones avanzadas admiten comillas mediante shlex, no eval.

### Cambios de defaults aprobados

- Sin argumentos, requirements solo comprueba; `--install` permanece explícito.
- Flujo sin fuentes: ayuda/rc2 sin trabajo, no RAM/logs host/globs automáticos.
- Timeline sin fuentes: NO_EVALUABLE/rc2; `--local` conserva recorrido histórico.
- Disco: metadata sin montar; montaje solo de copia seleccionada y confirmado.
- Memory dump sigue siendo acción local explícita al invocarlo, pero exige
  confirmación directa incluso sin argumentos. Nunca se invoca por abrir 08.

No es equivalencia semántica con los defaults antiguos; se conservan métodos y
posiciones válidas de las diez entradas enumeradas en [README](README.md).

## Copias, privacidad e integridad

Cada analizador prepara su propia copia independiente desde el original
seleccionado, verifica SHA-256/tamaño/modo antes y al finalizar y bloquea
dependientes si falla. No hay muestreo silencioso: prever tiempo de hash y
espacio para copias completas, salidas y memoria/discos grandes. Una copia
fallida impide iniciar el backend. Los árboles rechazan TODOS los symlinks,
incluso internos; no se siguen dispositivos, pipes ni sockets como archivos.
Los nombres con espacios se mantienen como un argumento. Los resultados
alterados se conservan como no confiables, nunca se restaura el original.

Directorios700/archivos600 desde creación, runs exclusivos, sin truncar enlaces
o resultados previos. No se imprimen cuerpos, credenciales o argv completos.
Metadata/rutas también son sensibles. Lecturas y hashes pueden cambiar atime;
no detectan cambios transitorios restaurados ni sustituyen snapshot o bloqueo
de escritura externo. Un propietario/escritor secuencial por run, sin garantía
contra escritura maliciosa del mismo UID ni cadena de custodia legal.

Layout normal:

```text
08_Forensics/analysis/runs/run-<32hex>/run.json
  sources.json, work/, analysis/, steps/   (metadata/copia/streams privados)
08_Forensics/recovered/run-<32hex>/        (productos de recuperación)
captures/memory/run-<32hex>/               (bajo raíz del framework)
```

Overrides: `FORENSICS_ANALYSIS_ROOT` (se añade `/runs`),
`FORENSICS_RECOVERED_ROOT`, `FORENSICS_MEMORY_ROOT`. `OUTPUT_DIR` de timeline
es raíz directa de runs; en carving/memory es padre de productos, no cambia la
raíz del manifiesto. Debajo se crea siempre run nuevo, sin chmod del padre ya
existente. Se rechazan solapamientos, symlinks y colisiones. Salidas externas
NO quedan protegidas por gitignore del proyecto: gestionar permisos/retención
y exclusión propios. No mover raíces silenciosamente.

Raíces recovered/captures se autorizan con registro privado `roots.json`, clave
`.roots-key`, HMAC-SHA256 y recibo `.forensics-owner.json`, enlazados con ruta,
run, inode/dev/UID. JSON por sí solo no autoriza una ruta. El lector valida
firma, identidad, permisos, confinamiento y hashes. Esto detecta redirecciones,
NO protege frente al mismo UID capaz de leer clave y reescribir recibos.

## Análisis offline

Comandos desde la raíz del framework (seleccionar archivos propios primero):

```bash
bash 08_Forensics/memory/strings_analysis.sh '/trabajo/memoria.raw'
bash 08_Forensics/logs/log_analyzer.sh '/trabajo/auth.log'
bash 08_Forensics/pcaps/pcap_analyzer.sh '/trabajo/red.pcap'
bash 08_Forensics/memory/volatility_analysis.sh '/trabajo/windows.raw' --backend v2 --profile Win7SP1x64
bash 08_Forensics/memory/volatility_analysis.sh '/trabajo/windows.raw' --backend v3 --symbols '/trabajo/simbolos locales'
bash 08_Forensics/disk/disk_forensics.sh '/trabajo/imagen.img'
bash 08_Forensics/disk/file_carving.sh '/trabajo/imagen.img' '/salida/recuperados'
bash 08_Forensics/timeline/timeline_creator.sh --auth '/trabajo/auth.log' --year 2026 --timezone UTC
bash 08_Forensics/run_all_forensics.sh --log '/trabajo/auth.log' --pcap '/trabajo/red.pcap'
```

Son operaciones, no instrucciones para probar evidencia real casualmente.
Strings usa strings -n8 y filtros sensibles/URLs/correos; logs conserva niveles,
errores, autenticación, SSH e IPs. Coincidencias/conteos son indicadores, no
credenciales válidas ni incidentes confirmados. Vacío válido y grep sin hits
no equivalen a errores de lectura; estos últimos se conservan como fallos.
PCAP usa capinfos/TShark sobre copia con `-n -r`, nunca captura viva. Valida
formato antes de dependientes y preserva rc del productor antes de resumir DNS,
HTTP/indicadores, protocolos/conversaciones y artefactos privados. Cero tráfico
válido no es fallo ni prueba de ausencia de actividad.

### Volatility: Windows no es memoria Linux adquirida

`--backend auto|v2|v3`, `--profile PROFILE`, `--symbols DIR` se pasan en pares,
no `--flag=valor`. Se reconoce familia real por ayuda/opciones/plugins.
V2 conserva imageinfo, pslist, pstree, netscan, dlllist, cmdscan y consoles,
con perfil Windows proporcionado o sugerido por backend, nunca inventado.
V3 usa windows.info.Info y plugins Windows anunciados para procesos, árbol,
conexiones, DLL e historial cuando existan, siempre `--offline`, símbolos
locales copiados y cache privada. No admite `--profile`. Ausencia de símbolos,
plugins o requisitos insatisfechos: NO_EVALUABLE/cobertura parcial, no «0 procesos».
No descarga símbolos ni consulta red. La entrega reproduce fixtures TShark4.2.0,
Volatility2.6.1 y Volatility3 Framework2.26.2 Windows, no todas las versiones OS.
Linux/Mac se diagnostican no soportados por este analizador Windows. Adquirir
RAM Linux con AVML/LiME no la convierte en una imagen Windows.

### Timeline

CLI: `[OUTPUT_DIR] [--journal FILE] [--auth FILE] [--syslog FILE] [--dpkg FILE]
[--wtmp FILE] [--tree DIR] [--year YYYY] [--timezone IANA] [--local]`.
Flags de fuentes repetibles, copias independientes. Journal exportado JSON por
línea, auth/syslog/dpkg texto, wtmp explícito mediante `last -f`, árbol sin links
para metadata de modificaciones; nunca consulta host ni `/` en modo offline.
Timestamp UTC con origen, offset completo y precisión ns; sin año/zona se usa
solo lo aportado o queda unresolved separado, no se inventa orden temporal.
Árbol usa mtime_ns observado del original, no creación de copia; snapshots v1
sin metadata temporal quedan unresolved. Productos privados events.jsonl y
timeline_summary.json; conteos/orden de líneas no prueban cronología.
`--local` no se mezcla con fuentes offline: límites históricos fragmentarios
journal24h/100, last20, SSH20, find / modificado24h/20, dpkg10; siempre PARCIAL.

## Disco físico, montaje y recuperación

`disk_forensics.sh IMAGE [--physical] [--mount-copy] [--offset BYTES --length BYTES]`.
Archivo: file/fdisk/blkid sobre copia sin montaje por defecto. Físico requiere
dispositivo explícito, token y root ya disponible: metadata/observación, nunca
staging íntegro ni montaje directo. Identidad física deriva de dev/ino/rdev y
tamaño observado, NO hash del contenido del soporte. No se lee exhaustivamente
un soporte dañado para fingir integridad; tamaño desconocido queda desconocido.

`--mount-copy` requiere root ya disponible, sin escalada sudo, loop propio de
solo lectura y punto privado. ext2 `ro`; ext3/ext4 `ro,noload`; XFS
`ro,norecovery`. Otro filesystem/ambigüedad: NO_EVALUABLE, sin fallback ro
genérico. Disco completo requiere offset y extensión explícitos juntos dentro
del tamaño; no se elige primera partición. Contrasta losetup/findmnt antes de
listar. `ro` por sí solo no neutraliza todo journal. Autopsy permanece manual.
Cleanup idempotente solo de recursos propios verificados: umount, comprobar
ausencia, detach, comprobar ausencia. Error/ambigüedad conserva recursos y
diagnóstico manual privado. Cancelación espera escritores y cleanup opt-in
sincrónico antes de cerrar, registra recibos/hash/rc de limpieza; no desmonta
recursos ajenos ni borra directorios ajenos.

`file_carving.sh FILE [OUTPUT_DIR] [--physical]`: offline conserva Foremost,
Scalpel y ddrescue con copias/destinos separados. Físico requiere token/root y
solo ddrescue lee dispositivo directo, sin copia previa obligatoria. Imagen y
mapfile son NUEVOS. Bloques pendientes/ilegibles: PARCIAL; mapa inválido/ausente
o tamaño físico desconocido impide declarar total. Hash del producto no es
hash del soporte original. Analizar después la imagen con Foremost/Scalpel
requiere selección explícita. Cero productos válidos se distingue de backend
ausente o fallido.

## Acciones locales sensibles y tokens

La barrera del gestor y las confirmaciones de hojas son independientes; no
autocompletar tokens ni pasarlos prefabricados. EOF/negación antes de empezar
retorna2 sin ejecutar la acción. Las hojas piden líneas exactas:

| Acción explícita | Token directo |
|---|---|
| `requirements.sh --install` | `INSTALAR_DEPENDENCIAS` |
| `memory_dump.sh [OUTPUT_DIR] [--method auto|avml|lime|dd]` | `ADQUIRIR_MEMORIA` |
| disco `--physical` | `INSPECCIONAR_FISICO` |
| disco `--mount-copy` | `MONTAR_COPIA` |
| carving `--physical` | `RECUPERAR_FISICO` |
| timeline `--local` | `LOCAL_SI` |
| flujo `--local` | `FLUJO_LOCAL`, después permisos independientes de hojas |
| lectura syslog del flujo local | `LEER_LOG_LOCAL`, después timeline pide `LOCAL_SI` |

Install muestra paquetes históricos volatility/autopsy/foremost/scalpel/tcpdump/
wireshark y conserva instalación confirmada; nunca se ejecuta en estas pruebas,
no instala AVML/LiME ni símbolos automáticamente ni actualiza índices.
Memoria: privilegio root ya disponible o `sudo -n true` tras confirmar, sin
password interactivo; solo backend solicitado con privilegio preparado.
`auto` reconoce AVML o wrapper CLI LiME ya preparado (`lime -o`), NO carga módulo
kernel ni supone CLI de un .ko. No fallback tras adquisición fallida; auto no
elige dd. dd conserva `/dev/mem`, bs1M/count1024 solo explícito, muestra <=1GiB,
PARCIAL/rc1. AVML/LiME exigen RAW regular privado no vacío y metadata
`completitud_memoria=no_verificada`: éxito estructural no prueba RAM íntegra o
consistente. RAW cancelado/fallido puede quedar privado sin referencia utilizable.

Preflight supervisado: límite fijo10s SOLO para ayuda de compatibilidad `--help`,
no adquisición/análisis ni privilegio `sudo -n true` (este sí cancelable).
Timeout/cancelación aborta sin fallback. Otras sondas no adquieren ese deadline.
`step.signal` es cancelación observada por wrapper, no señal terminadora inferida
del rc. Supervisor ancla hijos propios y restaura señales; no cubre escape
deliberado de sesión ni garantiza cleanup frente a SIGKILL. Flujo maneja SIGINT/
SIGTERM sticky, espera hoja/cleanup activos y no inicia nuevas fuentes/prompts;
fallo ordinario de una fuente no impide independientes.

## Flujo, estados, visor y verificador

Flujo: `[--memory FILE] [--log FILE] [--pcap FILE] [--disk FILE]
[--timeline-auth FILE] [--local]`. Offline memory ejecuta strings, disco solo
metadata, sin Volatility Windows/carving/mount implícitos. Fuentes válidas
independientes continúan ante fallos; cuenta ejecutadas/fallidas/omitidas y
propaga parcial. Local valida el ÚNICO producto exacto de su adquisición nueva
con lector/raíces autenticadas antes de strings/log/timeline; RAM denegada o
fallida bloquea dependientes, nunca usa capturas históricas por glob.
Transcript privado `analysis/workflows/flow-XXXXXXXX/workflow.log`, no manifiesto
autoritativo ni evidencia vigente; los runs de hojas sí lo son.

CLI hojas:0 trabajo solicitado completo,1 parcial/fallo/cancelación,2 uso o
precondición antes de empezar. Pasos conservan rc real y cobertura. Estados:
COMPLETADO, PARCIAL, FALLIDO, OMITIDO, NO_EVALUABLE, CANCELADO; sin pasos
solicitados concluidos no hay éxito. COMPLETADO no afirma ausencia de intrusión.

`show_results.sh [--run PATH] [--input SHA256] [--operation OP]` muestra solo
resúmenes/hashes/rc/cobertura, escapa controles y no relee originales. Ordena por
inicio UTC, separa identidades y no revive éxito antiguo ante intento nuevo
fallido/incompleto o metadata inválida. Solo explora raíces propias conocidas;
externos requieren run explícito, no parent externo. Consulta válida puede
devolver0 mostrando FALLIDO: eso no significa análisis exitoso.

`python3 tests/verify_forensics.py RUN_JSON` usa el mismo lector estricto08, sin
importar ejecutores, crear bytecode (también Python normal sin -B), adquirir ni
releer originales físicos/archivos. Valida esquema/sidecars/permisos/confinamiento,
copias y hashes de artefactos privados;0 completo coherente,1 inconsistente o
parcial/fallido/cancelado,2 incompleto/sin datos/uso inválido. Contenedores corruptos
se rechazan sin traceback. No certifica estado actual del original, validez legal
ni éxito operacional del backend. No hay parser ni atribución IP en informes11.

## Pruebas y alcance demostrado

`bash tests/run_forensics.sh` descubre todos `test_forensics_*.py`, copia solo
fuentes allowlist a `/tmp/opencode`, crea config/HOME/PATH/evidencia sintéticos,
sin recorrer evidencia real ni seguir enlaces ajenos. Todos los backends/sudo/
mount/journal/adquisición/install son stubs cerrados, sin fallback. Guardas de
inventario/hash/modo antes/después detectan cambios y ficheros nuevos, conservan
rc real de unittest; copias de diagnóstico se retienen en `/tmp/opencode`.
Los tests del runner usan una fixture representativa, no otra suite anidada.
Prueba adicional: `python3 -B -m unittest discover -s tests -p 'test_forensics_*.py' -v`
solo en copia de fuentes/config sintética, nunca sobre evidencia real.
Regresiones antiguas solo en copia limpia; `run_tests` sigue heredada roja
(374 pasan/11 fallan en cierre06, SSTI intermitente sin causa determinada), no
reejecutada ni debilitada aquí. Stubs no acreditan montaje, adquisición,
recuperación, instalación ni compatibilidad operacional con hardware real.
