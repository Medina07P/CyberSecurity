# Diseño: correcciones funcionales entre módulos y cierre de pendientes

Fecha:2026-11-14. Estado: **PROPUESTO; enfoque elegido, documento pendiente de aprobación**.
Base de trabajo:`00e4bbe4c2a3a380c4ee672072ea488072da561d`.

## 1. Intención y autoridad

El usuario pide corregir todos los fallos investigados, también fuera de09,
conservando capacidades, datos, artefactos y trabajo de otras sesiones. Tras la
investigación eligió expresamente la opción1 para SMB/PSExec/Linpeas: herramientas
estables en sus rutas actuales, ejecución sensible explícita y generación opcional
hacia un archivo nuevo. No se ha aprobado todavía este documento completo.

La investigación es estática. No se han reproducido estos fallos ejecutando
herramientas ni leído configuración, claves, notas o evidencias reales. El60/179
verde de compatibilidad09 no verifica estas hojas ni autoriza otra selección.

### Acordado frente a propuestas del autor

- **Acordado:** corregir los siete frentes y pendientes menores; conservar
  funcionalidades y artefactos; opción1 de herramientas estables; consentimiento
  explícito para limpieza/tráfico; notas previas intactas; pruebas sintéticas.
- **Propuesto aquí:** contratos concretos de modos/confirmación, esquema capturado,
  rutas Labs, validaciónCIDR, orden de bloques y estrategia de verificación.
- Aprobar el diseño autorizará preparar planes. No autoriza auditoría, limpieza,
  descargas, sudo, ejecución fuera de aislamiento ni nuevas excepciones de pruebas.

## 2. Evidencia y punto de partida

Investigación preservada en
`.superpowers/sdd/2026-11-14-cross-module-investigation/`:
`findings.md`, `source-provenance.json`, `burp-cleanup.md`,
`minor-reconciliation.md`, `testing-boundary.md`.
Diagnósticos web y de preservación anteriores enlazados allí siguen vigentes:
12fuentes coinciden con HEAD y con la revisión semántica inicial.

Siete frentes: Burp/S-I1; generadores/S-I2; cleanup/S-I3; rate-limit/S-I5;
request-login/S-I6; notasLabs/S-I7; CIDR/S-M2. S-I4, empaquetado automático11,
ya está corregido: no se vuelve a implementar.

De20IDs menores únicos,18siguen pendientes —dos parcialmente— y2están resueltos.
CIDR está en los siete frentes y en esos18: no contarlo dos veces. Las remisiones
M5/APIkeys yM9/SQLmap no son nuevos defectos.

## 3. Enfoques considerados y elección

1. **Herramientas estables y generación opcional, elegido por el usuario.**
   Conserva rutas públicas y operaciones; elimina la dependencia del estado
   «primera/segunda llamada». Requiere modos/gates explícitos y actualización
   coherente de consumidores, marcas y tests.
2. **Rutas actuales exclusivamente generadoras.** Conserva generación inicial
   pero obliga a operar desde otra ruta; más cambios de descubrimiento y riesgo
   de dejar herramientas generadas fuera de los gates. No elegido.

Se descarta resolverlo solo con documentación, retirar capacidades, ejecutar al
entrar al menú, añadir acciones a99 o reescribir el framework completo.

## 4. Alcance, bloques y exclusiones

El trabajo es transversal y se divide en planes acotados, en este orden propuesto:

1. **Fronteras de consentimiento:** limpieza local y separación GUI/tráficoBurp.
2. **Exactitud web:** cero sondeos previos, composición de request y403.
3. **Preservación local:** notasLabs/CIDR y generadores estables con sus consumidores.
4. **Menores y evidencia de cierre:** contratos documentales, UX y precisión de
   pruebas/recibos pendientes; contraste final de todas las opciones afectadas.

Cada plan incluye sus fuentes de prueba exactas y revisión/gates propios. No se
declara terminado todo al cerrar solo un bloque. Se preserva el método previo de
subagentes, con implementación secuencial por tarea y revisión independiente;
investigaciones de solo lectura independientes pueden ir en paralelo.

No objetivos: nuevas técnicas ofensivas, más volumen/credenciales, automatizar
limpieza desde coordinadores, nuevos perfiles de persistencia, instalar backends,
reabrir SSTI resuelto, modificar autorizaciónscope, garantizar Windows/Docker,
custodia legal o compatibilidad operacional sin evidencia específica.

## 5. Consentimiento: limpieza local

Ruta pública conservada:`06_PostExploitation/cleanup/logs_cleaner.sh`.

- Sin argumentos y `--preview`: presentar únicamente plan local, objetos
  afectados y límites; no crear directorios, leer cuerpos de logs/historial,
  invocar sudo/history/last ni abrir destinos de escritura.
- `--help`: ayuda inerte. Argumentos desconocidos, incluidos antiguos intentos
  `--estado`/`--parar`, se rechazan antes de cualquier efecto; nunca caen al cuerpo.
- Aplicar requiere `--execute` y consentimiento propio de esa ejecución. En TTY,
  confirmación específica que identifica sistema local, usuario e impactos.
  Para CLI no interactiva se propone un flag inequívoco adicional
  `--confirm-local-cleanup`; no sirve un sí genérico ni una variable global.
- El gestor explica destino LOCAL, no la IP de sesión. Su confirmación no elimina
  el gate de la hoja; un adaptador puede pasar los dos indicadores explícitos
  solo después del consentimiento local específico de ese lanzamiento.
- Conservar únicamente las operaciones existentes, sin ampliar objetivos ni
  ámbitos: cuatro ficheros del sistema, historial del shell/usuario y reporte
  de accesos. Aclarar que `history -c` en hijo no borra memoria del shell padre.
- Validar destinos esperados antes de escribir; no seguir enlaces o adoptar
  objetos especiales como logs/historial. No reutilizar `/tmp/last_access.txt`:
  el reporte nuevo es exclusivo/privado en `scans/cleanup/<id>/`. No borrar ni
  migrar archivos preexistentes y no tocar la ruta temporal antigua.
- Errores y rechazos se propagan. Resumen por operación; nunca «limpiado completo»
  cuando falla parte. No esconder stderr con `/dev/null` ni publicar contenido
  de registros. Mantener exclusión de cleanup en `run_all_post` y otros flujos.

**No se ejecutará limpieza real para verificar este arreglo.** La hoja y sus
operaciones se prueban en copia aislada con HOME sintético y privilegios simulados.
No se añade un bypass de producción para «modo test».

## 6. Consentimiento: Burp

Ruta pública y Community/manual se conservan.

- Abrir/configurar GUI no envía ninguna petición al objetivo, aunque exista
  sesión y listener. Se elimina el curl automático del flujo de apertura.
- Verificar captura se conserva como operación separada explícita. Requiere URL
  HTTP(S) completa y puerto proxy seleccionados, informa métodoGET y destino,
  y exige consentimiento propio. Rechazo/EOF no envían nada. No derivar permiso,
  esquema o ruta del objetivo guardado. El plan fijará sintaxisCLI y menú.
- Separar cálculo de rutas de creación. Ayuda/estado no crean salidas, config ni
  PIDfiles y no abren sockets, tampoco `/dev/tcp` como fallback. Estado puede leer
  metadata administrativa de la instancia existente y, para localizar la instancia
  legacy, identificador de sesión; no registra objetivos ni lee evidencias.
- Si falta un mecanismo local de observación, estado informa NO DETERMINADO en
  vez de conectar. Puerto ocupado no acredita que su dueño sea Burp ni que una
  respuestaHTTP venga del origen; no anunciar captura certificada por un código.
- Parar se mantiene como operación con efectos, no como consulta. Solo señaliza
  instancia propia cuya identidad pueda acreditarse; un PIDlegacy ambiguo no
  autoriza señales. Conservar artefactos administrativos necesarios para diagnosis,
  sin señales por nombre, grupos ajenos o supuestas pertenencias no acreditadas.
- Menú03, listado, ayuda e inventario distinguen abrir, consultar, parar y enviar.
  Ni `run_all_scanners` ni99 adquieren nuevas llamadas aBurp.

## 7. Web: esquema y petición exacta

Rutas:`05_Exploitation/web/{rate_limit_probe,web_login_bruteforce}.sh` y helpers
`00_Config/lib/http_request.bash`.

- Construcción/validación y elección de esquema no pueden contactar red. Se
  retiran sondeosHTTPS anteriores al consentimiento en ambas hojas.
- Para `.req` que no contiene esquema inequívoco se requiere selección explícita
  http/https mediante sus interfaces de override/preparación documentadas. Un
  puerto por sí solo no acreditaTLS. No cambiar SQLmap ni otros consumidores
  indirectamente. El modoURLmanual conserva su esquema explícito.
- Conservar métodos, cookies/cabeceras y valores ajenos a campos seleccionados;
  retirar únicamente las cabeceras de transporte ya excluidas. EnJSON se conserva
  significado de valores/tipos ajenos, no se promete formato blanco byte-idéntico.
- En cada intento, partir de captura original y construir target/cuerpo coherentes
  aplicando simultáneamente usuario y candidato, en ubicaciones independientes.
  El cambio de usuario nunca deshace contraseña ni un intento hereda el anterior.
- Form/query deben representar el valor literal, sin introducir pares nuevos ni
  doble codificación. Valores capturados se conservan tal cual si no se cambian;
  overrides literales se codifican una vez. JSON usa serialización real.
- Si un campo seleccionado no tiene identidad única —nombres repetidos, colisión
  usuario/password o rutaJSON no representable de forma inequívoca— rechazar con
  diagnóstico antes de enviar. La nueva composición no altera silenciosamente
  contratos de sustitución individual de otros consumidores del helper.
- Fallo al construir significa cero llamadas de envío, sin puntuar una request
  parcial como intento ni atribuir respuesta a un candidato no transmitido.
- Conservar modosmanual/.req, diccionarios y precedencias existentes, así como sus
  límites actuales; no agregar candidatos, paralelismo ni nuevas técnicas. Los
  mecanismos explícitos actuales de confirmación se documentan por hoja; no se
  instala un nuevo permiso reutilizable o bypass general de entorno.

### Rate-limit

- `wrong-1…wrong-N`, solo contraseña seleccionada, máximo200; mismo criterio
  de retardo y límites configurables, corte al primer freno, sin reintento nuevo.
-403 sin señal explícita de freno: corte inmediato, NO_DETERMINADO y rcnoexitoso.
  No esperar una secuencia lenta para llamarla freno. Conservar precedencia de
  Retry-After literal/cuota agotada,429/503 y sus límites actuales.
- No generalizar esta corrección a otros códigos no investigados sin casos y
  decisión explícita.000 y respuestasaceptadas con falsacredencial siguen ambiguas.
- TSV/contadores/artefactos reflejan exactamente los envíos, no sondeos ocultos.
  Nunca hay un GET extra de autodetección fuera del conteo.

## 8. Herramientas estables y generación opcional

Rutas públicas conservadas: `04_Enumeration/smb/enum_smb.sh`,
`06_PostExploitation/lateral_movement/ps_exec.sh`,
`06_PostExploitation/privilege_escalation/linpeas.sh`.

- Ninguna invocación reemplaza su fuente ni una fuente vecina. Dos llamadas con
  mismos argumentos tienen mismo significado, sin estado oculto de materialización.
- Operar requiere modo explícito —se propone `--execute`— y los consentimientos
  sensibles correspondientes. Invocación sin modo nunca descarga/escanea/eleva:
  muestra ayuda/preview. Conservar argumentosposicionales de las operaciones;
  consumidores/menús se adaptan en el mismo bloque, sin ignorarlos en primeruso.
- Generar requiere modo separado —se propone `--generate DESTINO`—, destino
  explícito NUEVO fuera de fuentes y creación exclusiva. Rechazar destinos
  existentes, enlaces y colisiones. No ejecutar el resultado, descargar, solicitar
  privilegios o incrustar credenciales/objetivo al generar.
- El artefacto generado puede ser un lanzador dependiente del framework, no se
  promete portabilidad autónoma. Debe declarar esa dependencia y recibir raíz del
  framework mediante argumento explícito, sin hardcodearHOME ni interpolar datos
  del operador en código. Conserva gates/mismos contratos de ejecución; no bypass.
- SMB conserva shares, RPC, enum4linux/NSE opcionales y las siete shares comunes;
  no sustituirlo por un alias que pierda estas operaciones.
- PSExec conserva cinco posiciones y comando como un argumento, sin eval, sin
  imprimir contraseña en menú/logs y propagando rc real del backend.
- Linpeas conserva descarga/reutilización explícitas y ejecución seleccionada.
  Añadirlo a la frontera sensible del gestor y no dejar que un coordinador sin
  argumentos lo active. Descarga y sudo no quedan autorizados por generar/preview.
  Errores de descarga y del pipeline son fallos, no éxito de tee. El plan definirá
  salida privada nueva sin sobrescribir fuentes/artefactos antiguos, con binario
  local seleccionado o descarga explícita, sin adoptar a ciegas un fichero delcwd.
- Mantener operaciones de escalada/información existentes, no añadir persistencia
  ni elevar otros privilegios. Los run_all conservadores no obtienen permiso
  implícito para ejecutar estas hojas ni para conceder sus nuevosgates.
- Corregir marcas `[generador]`, `[intrusiva]`, Uso/slots, fuentes y matriz de
  capacidades. La generación opcional no vuelve a marcar falsamente toda operación
  como «solo genera». Mantener ocultación de argumentos sensibles de PSExec.

## 9. Preservación de notasLabs

- Los cinco tipos y secciones de plantilla se conservan. La inicialización solo
  crea README nuevo de forma exclusiva. Si existe un archivo regular, incluso
  vacío, conservar bytes/modo e informar reuso sin reemplazarlo. No añadir plantilla
  por append ni copiar encima. Completar directoriosfaltantes no toca sus contenidos.
- Destino enlace —incluido colgante—, directorio u otro objeto: rechazar sin seguir
  el referente ni anunciar éxito. Erroresmkdir/escritura se propagan.
- Propuesta de rutas: default anclado a la categoría de la hoja, independiente
  delcwd, coherente con listados/editor del menú. Admitir raíz alternativa solo
  si el operador la selecciona explícitamente; jamás migrar/buscar/copiar árboles
  históricos automáticamente. Documentar dónde se creaban antes desdecwd.
- Nombre como un componente, no vacío, sin controles/separadores, ni`.`/`..`.
  Conservar espacios yUnicode válidos; no reinterpretar nombre como ruta u opción.
- Menús/coordinadores no dejan cambios persistentes decwd; mensajes de éxito
  dependen del rc real. Listado/editor apuntan a la raíz/categoría seleccionada.
  No examinar notas reales ni montar antiguosdatos para validar estos cambios.

## 10. ReconCIDR

- Conservar `<red> [rango]`: IPindividual no se convierte en red; prefijo explícito
  de tres octetos yIPv4decuatrooctetos/24 seleccionan la red/24 correspondiente.
  Un CIDR con bitsdehost se normaliza a esa red y se muestra, nunca a otra red.
- Rechazar tresoctetos/24, otros prefijosCIDR no soportados, octetos fuera0–255,
  controles/opciones y cerosiniciales ambiguos. Sin backend ni salida antesvalidar.
- Rangos enterosordenados dentro0–255, máximo256direcciones, default1–254.
 0/255 solo cuando explícitos; no ampliar un rango ni inventar otro por error.
- Mantener ruta/formato de resultados actuales y distinguir resultados de esta
  ejecución de históricos acumulados. Fallo de herramienta no es hostinactivo ni
  cobertura completada. No invocar run_all_recon como smoke ni certificarlo por
  corregir esta hoja.

## 11. Menores pendientes: cobertura exhaustiva sin nuevas capacidades

| IDs de investigación | Tratamiento propuesto |
|---|---|
| S-M1 DNS | Documentar resolución normal y wildcard frente al opt-in de diccionario; no agregar otro gateDNS |
| S-M2 CIDR | Cubierto en§10, no duplicar |
| S-M3 FTP | Distinguir loginanónimo de listado real; no añadir listado para concordar con prosa |
| S-M4 coordinadores05 | Documentar hijos reales, sin AD/descoveryinventados |
| S-M5 plantillas/SSH | Advertir conexiones TCP/NSE/Hydra reales; no llamar inertes a plantillas ni prometer topes09 |
| S-M6 forense | Separar stdoutmetadata de lectura privada para hashes; no quitar verificación ni reabrir originales |
| S-M8 backups | Precisar backupscope y appendtargets; no alterar persistencia ni datosreales |
| S-M9 visor08 | Separar menú sin filtros de CLI con filtros; no ampliar menú por la descripción |
| S-M10 flujo99 | Texto veraz de fases/omisiones; no habilitar cleanup/persistencia/lateral excluidos |
| S-M11 wizard, resto | Documentar defaults y opcionalidad actuales; conservar componentes10/11yaresueltos |
| previousM1 nulltarget | Corregir fixtureYAML para alcanzar validaciónnull y afirmar esa causa, no otro error |
| previousM2 timeout | Readiness sintética acotada antes de timeout; no incrementar sueño para ocultar carrera |
| previousM3 avisos | Capturar/assert de diagnóstico esperado en tests; no suprimir aviso útil del producto |
| previousM4 UX | Mostrar resultado/rc/motivo seguro y rutaderun cuandoexista, también falloprevioastore; no volcar secretos/stderrbackend |
| previousM5 APIkeys | Firmas correctas de estado/pedir, sin leer ni sincronizar clavesreales |
| previousM7 aliasruntime | Mutaciones/identidad de copia y bloqueo con dobles; no nuevos aliases ni ampliación de runtime por comodidad |
| previousM8 reciboterminal | Recibo exclusivo paterno de cancelación cuandoE/Slo permita, sin enmascarar señal/reap ni reemplazar resultado previo; no promesa trasKILL/E/Simposible |
| previousM9 SQLmap | Describir replaycondicional/enum/dumpindependientes por canal; no endurecer ni relajar gatesdelproducto |

S-M7 ypreviousM6 ya resueltos se conservan como tales. El gap de terminal no
reabre clasificaciónFAIL/BLOCKED corregida. La lista de18pendientes abarca las
filas anteriores conCIDRuna sola vez; no declarar18bugsoperacionales.

## 12. Pruebas y autorización

- TDD por defecto: testsprimero, REDobservado de cada fallo corregido y GREEN
  fresco del conjunto autorizado, con rc/fallos/errores/omitidos ySHAexactos.
- Pruebas SOLO en copias allowlist, HOME/sesión/config/wordlists/salidas sintéticos,
  PATHcerrado y dobles obligatorios de backend/red/GUI/sudo. Nada de datosreales,
  sockets/IPdocumental como sondeo, herramientasreales o importsdelrepo en host.
- Mantener Bubblewrap/seccomp/Landlock y contención heredada. Fuentes RO y scratch
  nuevo por caso. Sin fallback, `--unsafe`, suiteglobal ni discoverydeotrosrunners
  por comodidad. No presentar barrera de tests como restricción a auditorías futuras.
- Runtime exacto: añadir solo utilidades ordinarias necesarias, con procedencia
  y cierre estático de dependencias. No instalar ni montar `/usr`/PATH/hostgenéricos,
  ni fingir lógica awk/cut/etc con salidaspreparadas que oculten fallos.
- Nuevoscasos/selección o descartables sintéticos se enumeran en el plan y requieren
  permiso explícito correspondiente; los25IDs actuales no se amplían por aprobar
  este diseño. No usar nombres09 para esconder ejecución de suitesajenas.
- Revisión estática independiente de fuentes/manifiestos/política antes de cada
  combinación nueva; controladorautoriza comandoexacto después. No instalar ni
  probar bwrap/namespace/framework durante redacción del diseño/plan.
- Nunca ejecutar cleanup, descarga/linpeas, PSExec, capturaBurp o loginreal como
  smoke. Sus operaciones se observan mediante dobles y fronteras reales acotadas,
  sin sustituir las funciones de negocio por no-ops que falseen los asertos.
- Preservar fixturesfinales, fuentes, recibos/logs y todos los runsanteriores.
  Fallos/BLOCKED no sonverdes y no autorizan relajar la política.

## 13. Aceptación y cierre

Cada bloque necesita matriz antes/después de capacidades y contratos, pruebas
regresivas concretas, revisión independiente y conciliación de documentación
contra fuentes actuales. Respetar los avances de develop sin refrescar baselines
a ciegas ni reimplementar arreglos resueltos.

El cierre de todoslosbloques incluirá todoslosIDspendientes, erroresparciales,
cancelación/EOF, noefectosantesdeconfirmación, fuente/nota preservadas y listas
completas de opciones afectadas. No confundir cobertura estructural consemántica.

No push ni mergeadevelop sin petición expresa posterior. Conservar worktree,
ramas/logs/artefactos; no cleanupfinal de workspace. No declarar compatibilidad
operacional, Windows/Docker, custodia legal o toda la rama verde por estos tests.

## 14. Delegado al plan y al implementador

Nombres internos de bibliotecas y organización conforme a módulos existentes;
límites numéricos de lectura y esquemas de recibos; sintaxis final coherente de
CLI/menús y matrices exactas de casos/manifiestos. Cualquier cambio de las fronteras
anteriores se registra y revisa; no se retiran métodos ni se conceden efectos
adicionales por completar un formulario o heredar una sesión.

Antes de implementación: revisión de diseño, aprobación del documento por usuario,
planes acotados y permisos específicos de verificación. Aprobación del enfoque
no equivale a aprobación de ejecuciones o de estas propuestas todavía no revisadas.
