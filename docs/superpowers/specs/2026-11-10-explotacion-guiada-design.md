# Revisión integral de 05_Exploitation sin recortes

Estado: aprobado por el usuario en esta sesión; pendiente de implementación.

## Intención y acuerdos

Mejorar el menú, las herramientas y las automatizaciones existentes de 05,
manteniendo todas sus capacidades y contratos actuales. El usuario declara
que todos los objetivos configurados son de su propiedad y están autorizados.
Solicita validación operacional real con esos datos, no sustituirla por mocks.

Mostrar este aviso informativo en el menú y documentarlo: «Usar exclusivamente
en objetivos autorizados y en un entorno controlado. Estas operaciones pueden
bloquear cuentas, modificar datos o ejecutar código según la herramienta».
El aviso no añade confirmaciones, bloqueos ni restricciones.

No añadir topes de intentos, tasas, diccionarios reducidos, límites de duración
ni otras restricciones nuevas. Conservar los controles ya existentes, incluidos
los permisos independientes de sqlmap, confirmaciones del gestor y frenos HTTP.
No endurecerlos ni eliminarlos aprovechando esta revisión.

## Enfoques considerados

1. Revisión integral: navegación guiada, corrección de hojas y automatizaciones,
   evidencia y documentación coherentes. Mayor trabajo, evita inconsistencias.
2. Revisión por bloques: mismos objetivos, entregas sucesivas por familia;
   facilita entregas parciales, mantiene diferencias entre familias más tiempo.

El usuario eligió la revisión integral, con validación real. Este documento
desarrolla ese enfoque; no es todavía autorización de implementación del diseño.

## Alcance y antiobjetivos

- Conservar cada herramienta, parámetros históricos, payloads, consultas,
  diccionarios, credenciales de prueba y automatizaciones existentes.
- No transformar herramientas activas en simples avisos o guías. Las guías
  actuales de CVE siguen identificadas como guías; no inventar exploits nuevos.
- No ampliar la revisión a 06 ni ejecutar el flujo global 99 como verificación.
- No instalar dependencias ni cambiar privilegios automáticamente. La ausencia
  de una dependencia se informa; no se confunde con un resultado negativo.
- No modificar configuración real, sesión, credenciales ni evidencias previas
  como efecto secundario de una prueba de interfaz o de una suite de regresión.
- No publicar objetivos, claves, respuestas ni credenciales; no hacer push.
- Los commits locales están autorizados por el traspaso, seleccionando fuentes
  explícitamente y dejando scope.yaml fuera; nunca usar git add -A.

## Inventario que debe conservarse

| Familia/entradas | Operaciones conservadas |
|---|---|
| run_all_attacks.sh | Descubrimiento y cadena SSH, web, PostgreSQL, MySQL y Redis |
| run_all_exploits.sh | Descubrimiento, SSH brute force, revisión regreSSHion, SQLi y XSS |
| network/ssh_attack.sh | Enumeración de usuarios NSE y Hydra con listas actuales |
| network/ssh_bruteforce.sh, ftp_bruteforce.sh | Todos los usuarios actuales, diccionario configurable, concurrencia y ejecución Hydra |
| database/mysql_attack.sh | Todas las credenciales actuales, versión, bases y tablas mysql |
| database/postgres_attack.sh | Todas las credenciales actuales, versión, bases, tablas, usuarios y searchsploit |
| database/redis_attack.sh | Acceso sin contraseña, INFO, KEYS * y CONFIG GET * |
| web/web_attack.sh | sqlmap y ffuf con el diccionario actual |
| web/sql_injection.sh | Todos los parámetros y payloads actuales, comparación con baseline y sqlmap |
| web/xss.sh | Todos los parámetros y payloads actuales; distinguir reflexión de ejecución probada |
| web/http_inject.sh | Petición capturada, query/formulario/JSON, sesión, técnicas y clasificación de evidencia actuales |
| web/sqlmap_request.sh | Petición capturada, técnicas disponibles, enumeración y volcado; permisos independientes y opciones actuales, incluido SQLMAP_FILAS=0 |
| web/rate_limit_probe.sh | Prueba de login capturado variando solo contraseña; clasificación y controles actuales |
| web/reverse_shell_php.sh | Generación PHP con LHOST/LPORT, sin desplegarla o ejecutarla implícitamente |
| active_directory/kerberos_attack.sh | Puerto Kerberos y todos los usuarios kinit actuales |
| exploits/cve_2021_4034.sh, cve_2021_44228.sh, cve_2024_6387.sh | Guías/payloads existentes y sondeo SSH donde ya existe, claramente diferenciados de explotación confirmada |
| exploits/reverse_shell.py | Conexión y ejecución de shell existentes; indicar que no es solo un generador |
| wireless/wifi_attack.sh | Comprobación de interfaz y escaneo iwlist actuales |
| custom_exploits/template.sh, template.py | Plantillas y comprobaciones de conexión actuales |
| payloads/ | Conservar muestras y lista de reverse shells, además de payloads generados |

La revisión verificará que las operaciones siguen alcanzables, no solo que sus
nombres aparecen en un menú. No añadir variantes ofensivas nuevas bajo pretexto
de completar títulos que hoy prometen más de lo que implementan.

## Navegación y compatibilidad

Biblioteca dedicada bajo 00_Config/lib/ e integración en module_exploitation.
Entrar en 05 muestra el objetivo y el aviso, pero no ejecuta herramientas.
Ofrecer comprobación de dependencias, web capturada, web por URL/host, SSH/FTP,
bases de datos, Kerberos, CVE, payloads/shell, WiFi, plantillas, ambos flujos
completos, visor de resultados y lista completa original.

Reutilizar execute_script y la navegación existente sin añadir confirmaciones.
Pedir los argumentos correspondientes: fichero HTTP no equivale a host, LHOST
no equivale al objetivo remoto, interfaz WiFi no equivale a IP. Mantener entrada
CLI histórica; añadir URL explícita como alternativa compatible en web para
respetar esquema, puerto, ruta y query, sin retirar heurísticas antiguas.
No insertar el objetivo de sesión en un parámetro con otra semántica.

## Correcciones y evidencia

- Autolocalizar los dos run_all; conservar todas sus fases y puertos actuales.
  Propagar fallos de descubrimiento/hijos, contar ejecutadas/fallidas/omitidas
  y no anunciar éxito si hay fallos o si no se pudo evaluar nada.
- Guardar stderr y código real de cada herramienta, incluidas pipelines;
  distinguir conexión fallida, rechazo de autenticación y evaluación completada.
- MySQL/PostgreSQL: determinar acceso por respuesta del protocolo y resultado
  de la consulta, no por fichero no vacío. No reutilizar credenciales antiguas
  ni aceptar variables/configuración heredadas como prueba del acceso declarado.
- Redis: NOAUTH/errores no son acceso. Conservar INFO/KEYS/CONFIG y reportar
  individualmente éxito, rechazo o fallo de cada operación.
- Web: baseline y comparación que no confundan catch-all, eco, palabras
  preexistentes o errores de transporte con hallazgos. Reflexión no demuestra
  ejecución XSS; banner/versionado no confirma una CVE explotable.
- Mantener los frenos HTTP documentados: 429/503 no puntúan como hallazgo.
  No modificar los controles existentes de http_inject/rate_limit/sqlmap.
- Conservar todas las consultas y listas actuales. Corregir el manejo de
  contraseña vacía de MySQL sin convertir la ejecución en prompt interactivo.
- Resultados nuevos atribuibles a host/puerto o URL y a cada ejecución; las
  ejecuciones fallidas no reemplazan ni reviven éxitos históricos.
- Usar scans.bash y metadatos compatibles con los patrones ya existentes.
  Mantener logs históricos y proteger ficheros sensibles, sin imprimir claves
  de API ni introducir contraseñas en informes generales.
- Visor e informes deben distinguir intento actual, histórico y no atribuible;
  actualizar lectores de forma acotada si cambia una salida reconocida.
- Validar argumentos como datos, evitando inyección de opciones/comandos o
  nombres de fichero inseguros; esto corrige interpretación, no reduce ataques.

## Validación real y preservación de datos

La comprobación operacional usará objetivos y parámetros de la configuración
local, sin copiarlos a documentos versionados. Antes de ejecutarla, el plan
recogerá localmente qué entradas existen, qué servicios corresponden y qué
herramientas/credenciales/peticiones capturadas están disponibles. No inferir
un campo de login, una tabla de volcado o una interfaz a partir de una IP.
Si falta un dato necesario, pedirlo o declarar esa validación pendiente;
no inventarlo ni sustituir un objetivo real por una simulación silenciosa.

Ejecutar herramientas reales para las capacidades aplicables y registrar orden,
argumentos sensibles protegidos, fecha, objetivo, resultado, efectos observados
y ruta de evidencia. Conservar la configuración y evidencia anterior; los
resultados nuevos se almacenan por ejecución sin borrar los previos.
Una capacidad sin servicio/hardware/dependencia no se da por validada.
No crear vulnerabilidades ni desplegar payloads automáticamente para conseguir
un positivo. Generar un payload no prueba que una shell haya conectado.

La validación real no se reemplaza por suites aisladas. Las suites antiguas que
borran árboles compartidos, si se usan para detectar regresiones, se ejecutan
solo en un clon limpio sin datos reales: no son la validación operacional.
Las comprobaciones de sintaxis/diff no ejecutan herramientas. No afirmar éxito
global si solo se comprobó sintaxis, dependencias o una parte de las familias.

## Documentación y criterios de aceptación

Actualizar README de 05, manual del gestor y documento de resultados/límites.
Eliminar instrucciones a ficheros inexistentes sin retirar herramientas reales;
identificar guías, plantillas, generadores y herramientas activas correctamente.

Aceptación: inventario íntegro alcanzable; CLI compatible; navegación correcta;
sin falsas conclusiones por errores/eco/evidencias antiguas; flujos completos
con estados fiables; resultados atribuibles; aviso informativo sin controles
nuevos; validación operacional real documentada, con cobertura y pendientes
explícitos; configuración y evidencia previa preservadas.

## Decisiones del implementador

Nombres y orden de menú, estructura interna de bibliotecas/metadatos, adaptación
acotada de informes y orden de validación se resolverán en el plan siguiendo
los patrones del repositorio. No podrán introducir límites nuevos ni reducir
el inventario. El fallo intermitente SSTI anotado en el traspaso, si reaparece,
requiere conservar evidencia y diagnóstico antes de cambiar código o asertos.
