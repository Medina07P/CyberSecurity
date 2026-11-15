# Diseño: integración integral de 09_Automation

Fecha: 2026-11-13. Estado: **APROBADO por el usuario para preparar el plan**.

## 1. Intención y decisiones acordadas

Convertir 09 en una entrada fiable para planificar y ejecutar automatizaciones
autorizadas, aprovechando el framework existente y conservando sus entradas y
capacidades. El usuario eligió la integración integral frente a mantenimiento
mínimo o una plataforma nueva. Tras recibir el documento, aprobó su contenido
con «Si, aprobado». El siguiente paso autorizado es preparar el plan; todavía
no se ha elegido método de ejecución ni iniciado implementación.

El problema central no es la falta de herramientas: son ejecuciones implícitas,
argumentos perdidos, errores ocultos, duplicación y declaraciones de éxito sin
evidencia. Se distinguirá ejecución técnica, cobertura y hallazgos.

## 2. Situación comprobada mediante lectura de fuentes de 09

- `run_all_automation.sh` recorre Bash/Python/PowerShell sin argumentos, descarta
  stderr y acaba anunciando éxito. Depende del directorio de trabajo.
- `orchestrator.py` interpola el objetivo en comandos con `shell=True`, no
  propaga correctamente resultados y escribe un JSON con fases supuestamente
  completadas. `--full` encadena también explotación y postexplotación.
- `auto_audit.py` usa `os.system`, construye rutas con el objetivo sin validar y
  trata un selector de fase desconocido como petición de auditoría completa.
- Las hojas Bash repiten tareas, ocultan fallos, reutilizan salidas y deducen
  protocolos o parámetros. `auto_exploit.sh` encadena Hydra, SQLmap y SearchSploit.
- Los YAML son declaraciones que ningún ejecutor interpreta hoy.
- El generador Python ya delega en 11: se conservará esa delegación.
- Compose expone socket Docker, red host y capacidades; su contexto de build no
  corresponde al framework completo. PowerShell escribe en el cwd y no controla
  adecuadamente errores.

No se han ejecutado estas herramientas ni leído reportes, objetivos, claves,
evidencias o logs reales. Los contratos actuales de otros módulos descritos en
AGENTS.md son restricciones, no una verificación operacional nueva.

## 3. Enfoques considerados

1. **Mantenimiento mínimo:** arreglar invocaciones y errores sin unificar. Menos
   trabajo, pero deja duplicación y YAML inertes.
2. **Integración integral, elegida:** catálogo cerrado de acciones, ejecutor común,
   planificación sin efectos y adaptadores compatibles. Un contrato comprobable.
3. **Plataforma nueva:** colas, paralelismo y reanudación. Complejidad injustificada
   antes de estabilizar la ejecución básica.

## 4. Objetivos, exclusiones y límites

Objetivos: navegación segura; argumentos explícitos; workflows utilizables;
resultados por paso; cancelación y límites temporales; compatibilidad documentada;
pruebas aisladas; Docker/PowerShell sin privilegios ni recolección implícitos.

No objetivos: paralelismo, ejecución distribuida, reanudación, nuevas técnicas
ofensivas, modificar internamente 00–08/10–13, reconstruir históricos o certificar
compatibilidad operacional. Un contenedor no se presentará como sandbox de seguridad.

Antióbjetivos: entrar en 09 y lanzar red o recolectar datos; utilizar `99` como
prueba; retirar capacidades sin advertencia; llamar a un run_all sensible por
comodidad; declarar ausencia de vulnerabilidades por rc=0; rescatar resultados
antiguos cuando falla una ejecución nueva.

Se preservan configuración local, evidencias, ledger y logs de 08 y cambios
ajenos. Sin push. No instalaciones, Docker build/up ni herramientas reales para
verificar este trabajo. Las suites antiguas solo podrán correr en copia limpia.

## 5. Arquitectura propuesta (decisiones técnicas del autor)

### 5.1 Un núcleo Python y entradas compatibles

Python 3 será el núcleo, Bash la interfaz local. Se reutilizará PyYAML cuando se
seleccione un workflow; su ausencia dará diagnóstico, nunca instalación automática.
El código compartido no será un nuevo script ejecutable descubierto por el menú.

`orchestrator.py` será la CLI principal. `auto_audit.py` y las tres hojas Bash
serán adaptadores al mismo núcleo, no motores independientes. Se conservarán sus
rutas y argumentos posicionales válidos, con ayuda de migración para cambios de
semántica. Argumentos desconocidos, fases desconocidas o modos incompatibles se
rechazan; jamás activan un flujo completo como alternativa.

Sin argumentos, `run_all_automation.sh` abrirá el menú. En CLI con objetivo pero
sin orden explícita de ejecutar solo mostrará el plan y la forma de confirmarlo.
`--full` pasa a ser una selección del perfil completo, **no autorización**.
El modo ejecución requerirá un indicador explícito y las confirmaciones aplicables.

La conexión de 09 con el gestor debe ser mínima y exclusiva de su despacho y
ayuda; no alterará `99`, otros menús ni los parsers generales. Si la integración
requiere cambiar esos contratos, se detiene para revisar alcance.

### 5.2 Catálogo cerrado y parámetros tipados

Cada acción declara identificador, backend fijo, argumentos requeridos, riesgo,
dependencias, herramientas necesarias, efectos y limitaciones. Se usarán listas
de argumentos y `shell=False`; no `eval`, shell strings ni expansión de YAML.
Hostname, IPv4, puerto, URL HTTP(S), ruta y texto de producto tienen validaciones
distintas; se rechazan controles y opciones disfrazadas. No se inventa TLS,
credenciales, URL, cuenta ni campo de petición a partir de una IP.

Antes de ejecutar se valida el plan completo: acciones, entradas, dependencias,
backend disponible y autorizaciones. `command -v`/resolución de archivos no ejecuta
binarios ni demuestra permisos, hardware o compatibilidad. Planificar no crea
salidas ni lee scans/configuración/credenciales; solo fuentes y YAML seleccionado.

La selección del objetivo será explícita. 09 no registrará objetivos ni modificará
scope/session/targets. La comprobación de alcance existente es orientativa según
AGENTS.md, no una prueba de autorización: el operador debe confirmar que dispone
de autorización antes de cualquier ejecución de red.

### 5.3 Integración y conservación de capacidades

Preferir hojas existentes con contrato explícito, nunca run_all genéricos por
atajo. Durante el plan de implementación se revisarán sus fuentes para concretar
el mapeo; si no hay backend adecuado, se conservará la receta existente en el
catálogo de 09 con ejecución común y límites explícitos, no se simulará integración.

Mapa funcional obligatorio para aceptar la implementación:

| Entrada/capacidad | Destino y condición |
|---|---|
| `auto_recon.sh` | Perfil de reconocimiento; conserva ping, puertos, servicios/NSE y SO como acciones seleccionables. Perfil básico acotado; barrido completo, NSE y SO separados y advertidos. |
| `auto_enum.sh` | SSH, Web, SMB y detección de DB seleccionables; web exige URL explícita; enumeración de usuarios requiere confirmación específica. |
| `auto_exploit.sh` | Catálogo avanzado de SSH/Hydra, SQLmap y búsqueda local de exploits; no cadena automática. Hydra exige cuenta, diccionario local y límites explícitos; SQLmap conserva permisos separados y entrada real requerida por el backend actual. SearchSploit pide producto/versión, no utiliza una IP como producto. |
| `auto_audit.py` | Adaptador de fases recon/scan/enum/web; conserva selección individual y perfil completo planificable. No mantiene otro analizador de puertos por shell. |
| `orchestrator.py` | Conserva selección recon/scan/enum/exploit/post/report; exploit/post son planes avanzados explícitos, nunca llamadas genéricas a sus run_all. |
| `report_generator.py` | Compatibilidad con `--input/--output`, delegación a 11 y explicación de los nombres realmente generados. |
| PowerShell | Recolección local Windows seleccionada expresamente, nunca sustituto de un escaneo remoto ni ejecución automática desde Linux. |

Las operaciones concretas de postexplotación solo se podrán registrar si admiten
entradas y permisos explícitos sin cambiar sus hojas. Si no, el selector post
mostrará una guía al módulo 06 y rechazará ejecución automática con causa clara;
la capacidad sigue accesible en 06, sin prometer automatización no implementada.
Este límite es una propuesta del autor para no ampliar el alcance a 06.

### 5.4 Perfiles y YAML

`quick_scan.yaml` será el perfil básico: reconocimiento y TCP acotado sin NSE,
sin explotación ni POST. `full_audit.yaml` será un plan amplio de diagnóstico
(configuración de solo lectura si se solicita, OSINT con dominio explícito,
reconocimiento, escaneo, enumeración y reporte opcional). No autoriza por nombre
acciones sensibles. Estas se seleccionan aparte y se confirman por acción.

Esquema versionado, con claves permitidas: nombre, versión de esquema, pasos
(id único, acción de catálogo, entradas tipadas, dependencias explícitas) y timeout.
Se rechazan duplicados de claves, tags personalizados, aliases, exceso de tamaño,
acciones desconocidas, ciclos, campos extra, scripts arbitrarios y paralelismo.
Los antiguos `script:` relativos no se ejecutan: ambos YAML del repositorio migran
y un YAML externo antiguo recibe explicación de incompatibilidad.

Sin plantillas, imports, variables de entorno expandibles ni rutas ejecutables
aportadas por YAML. Las rutas de datos se resuelven respecto al YAML y se muestran
en la vista previa; objetivos/URL faltantes se solicitan en menú o se rechazan en
CLI. No se permiten secretos literales en YAML ni argumentos registrados.

## 6. Interacción y permisos

Menú de texto en español: disponibilidad local, guía, plan básico/completo,
acciones avanzadas, ejecución de un plan confirmado y listado de entradas
originales. EOF/0 vuelve sin acciones. Listar entradas no debe permitir eludir el
núcleo ni ejecutar todos los scripts por extensión.

Vista previa: objetivos/URL, pasos y argumentos no secretos, efectos, dependencias,
riesgos, rutas de salida y pasos no ejecutables con motivo. Las confirmaciones
son por ejecución, objetivo y acción; no se guardan como autorización reutilizable.
CLI no interactiva usa opciones explícitas equivalentes; si falta permiso falla,
no acepta un sí genérico por stdin. No se debilitan confirmaciones de las hojas.

Credenciales y peticiones se reciben por rutas locales explícitas o canales
admitidos por el backend, no como secretos nuevos en argv. Los permisos de SQLmap
para probar, enumerar y volcar siguen siendo independientes. Un perfil genérico
no incluye Hydra, SQLmap, persistencia ni limpieza.

## 7. Ejecución, errores y cancelación

Ejecución secuencial. Primer fallo corta la ejecución; dependientes y pasos aún
no iniciados quedan omitidos con causa. Un reporte diagnóstico posterior se pide
aparte; nunca cambia el resultado de la ejecución fallida a exitoso.

Estados de paso: pendiente, ejecutando, completado, fallido, omitido, cancelado.
`completado` significa únicamente que el backend terminó correctamente según su
contrato; no certifica cobertura, hallazgos ni pruebas que el backend no acredita.
Timeout se registra como fallo con motivo específico. Salida del ejecutor: 0 si
todos los pasos seleccionados obligatorios completaron; 1 por fallo/timeout o
paso obligatorio no ejecutable; 2 por entrada/plan/permiso inválido; 130/143 por
interrupción INT/TERM. El adaptador conserva esos códigos.

En Linux cada paso usa sesión/grupo de procesos propio, sin `shell=True`. INT,
TERM o timeout detienen la planificación y señalizan exclusivamente ese grupo;
TERM seguido de KILL tras gracia acotada y espera de reap de hijos directos.
Los procesos que escapan deliberadamente del grupo no tienen garantía de control:
backends que daemonizan quedan fuera del catálogo ejecutable. No se emplean
`pkill`, señales al grupo del gestor ni una promesa de supervisor forense.
La cancelación conserva registros y no elimina evidencias. Los límites numéricos
y pruebas de carreras se fijarán en el plan, incluyendo timeout global del YAML.

## 8. Salidas e informes

`<repo>/scans/automation/<id_aleatorio>/` privado por ejecución (directorio 700,
archivos 600), creado solo al ejecutar tras validación. El objetivo validado se
registra como dato, no determina rutas. Se rechazan destinos inseguros/symlinks.
Registro JSON de plan ejecutado y estados, stdout/stderr por paso y resumen en
español. Escritura atómica del estado; ante error de disco se detiene y no se
anuncia éxito. No se almacenan peticiones o claves en el resumen; no se promete
redacción universal de secretos que las herramientas puedan imprimir en logs.

Estos logs son nuevos registros de 09, no copias ni custodia de todas las salidas
de las hojas. Se documentan las rutas que cada backend produce. Si una hoja usa
salidas compartidas, su aislamiento no se inventa: exclusión mutua entre ejecuciones
09 mientras dura la ejecución y advertencia sobre herramientas lanzadas fuera de
09, que ese bloqueo no controla. No borrar ni renombrar resultados históricos.

El resumen de ejecución no es un informe de seguridad. Para invocar el motor de
11 se exigen objetivo e input explícitos, se advierte que el motor puede leer
históricos y se aplican sus reglas de atribución actuales. No se usará por defecto
todo `scans/` ni se declararán solo resultados frescos por haber terminado un paso.
Si el motor actual no permite atribuir el conjunto elegido, se omite con error
explicado; no se modifica 11 ni se fabrica un informe alternativo.

## 9. Docker y PowerShell

Compose predeterminado sin socket Docker, sin red host y sin capacidades añadidas;
entrada interactiva sin lanzar el framework, y sin montar configuración/evidencias
reales automáticamente. Contexto de build y COPY limitados a código permitido,
con exclusión de configuración privada, scans, logs y credenciales antes de COPY.
Dependencias compatibles con Kali (paquetes o venv, no pip sobre Python del sistema),
lista deduplicada y usuario no root por defecto. Ninguna descarga en pruebas.

Excepciones de red/capacidades se documentan como comandos opcionales razonados,
no se habilitan ni se crea perfil que monte el socket. No se garantiza paridad
de herramientas o hardware sin prueba real independiente.

PowerShell conserva las cinco recolecciones originales. Exige destino explícito
con carpeta única por ejecución, rutas independientes del cwd y tratamiento de
errores por bloque. Un cmdlet ausente no se presenta como resultado vacío válido;
hay resumen y exit no cero cuando una tarea requerida falla. Windows no disponible
implica verificación estática y pruebas de contrato simuladas, no compatibilidad
Windows declarada.

## 10. Verificación y aceptación

Nueva suite aislada de 09 con fuentes copiadas, HOME/configuración sintéticos y
backends falsos. Ningún test lee config/evidencia real, ejecuta herramientas de
red, instala paquetes, invoca Docker real o usa flujo 99. No ejecutar los scripts
de auditoría del checkout para probar ayuda: hacerlo en la copia controlada.

Cobertura exigida:
- Menú/EOF sin procesos ni escrituras, disponibilidad sin ejecutar binarios.
- CLI antigua, modos ambiguos, selector inválido y falta de permisos.
- Inyección de shell/opciones/rutas, YAML inválido/duplicado/cíclico/arbitrario,
  tamaños máximos y vista previa sin efectos.
- Orden/dependencias, rc fallido, ejecutable ausente, salidas vacías, stderr,
  timeout, INT/TERM y ausencia de hijos controlados supervivientes.
- Permisos sensibles separados y no incluidos en perfiles genéricos.
- Identidad de ejecución, logs privados, error de disco, no sobrescritura de
  históricos y exclusión mutua de 09.
- Adaptadores al motor 11 con stub, rechazo de atribución insuficiente y ninguna
  declaración de hallazgos basada solo en el estado del proceso.
- Contratos PowerShell y configuración Docker estáticos; Bash con stderr capturado
  y Python mediante AST sin generar bytecode en el checkout.
- Regresiones afectadas solo en copia limpia y con configuración sintética.

Aceptar exige matriz de capacidades originales antes/después, revisión independiente
de diseño y código, y evidencia de comandos/rc. No declarar toda la rama verde ni
rescatar pruebas históricas de 08. La integración real con herramientas se dejará
como validación operacional pendiente, separada del cierre de implementación.

## 11. Qué queda al implementador

Nombres internos, organización del paquete no ejecutable, API de adaptadores,
límites numéricos razonables, detalles de fixtures y formato visual del menú.
El plan debe fijar una matriz concreta de backends leyendo sus fuentes sin
ejecutarlas. Cualquier capacidad que no pueda conservarse dentro de estos límites
se expone antes de escribir producto; no se retira silenciosamente.

## 12. Seguimiento del diseño

- [x] Leer traspaso, restricciones y fuentes de 09 sin automatizaciones.
- [x] Presentar alternativas y recibir elección de integración integral.
- [x] Redactar diseño y distinguir propuestas técnicas de acuerdos.
- [x] Revisión independiente para detectar decisiones importantes sin resolver.
- [x] Incorporar revisión y preparar documento para presentación al usuario.
- [x] Aprobación del documento por el usuario.
- [x] Invocar writing-plans después de la aprobación; no implementar antes.

Revisión de constructor, sesión `ses_e2a4726aaffeO7WyFM2Wx003hc`: respuesta
`nothing important left`. Esta revisión no implica revisión de código ni
validación operacional. La aprobación posterior del usuario se registra arriba.
