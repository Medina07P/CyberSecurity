# Revisión de 04_Enumeration sin pérdida de funcionalidad

Estado: aprobado e implementado; verificación final el 2026-11-10, diez suites pasando. Corrección expresa del usuario:
«no quites ninguna funcionalidad».

## Intención y enfoque elegido

Aplicar la revisión, correcciones, automatizaciones y claridad del menú de 03
al módulo 04, conservando TODAS sus capacidades. El operador debe comprender
qué ejecutará, sobre qué objetivo y si una operación se completó o falló.

Se consideraron dos enfoques: corregir exclusivamente hojas (menor cambio,
pero mantiene la navegación técnica), o añadir navegación guiada y corregir
hojas (más cobertura de interacción). Se descarta cualquier versión del segundo
que retire capacidades. La propuesta corregida combina menú guiado con acceso
íntegro a las herramientas existentes; no es una simplificación funcional.

## Restricciones vinculantes

- No quitar, desactivar permanentemente, sustituir por un aviso ni dejar
  inaccesible ninguna capacidad existente. Las confirmaciones son controles
  previos, no la eliminación de una operación.
- No eliminar métodos HTTP, pruebas de acceso anónimo o credenciales por
  defecto, enumeración de usuarios, fuzzing, consultas Redis ni generadores.
- Mantener disponibles los 16 scripts y sus contratos CLI actuales. Añadir
  argumentos opcionales o modos explícitos es posible; no reinterpretar
  silenciosamente los argumentos anteriores.
- Mantener los cambios de 03 y las modificaciones previas de scope.yaml y
  permisos de api_keys.py; no hacer commits, push ni instalaciones.
- Ninguna ejecución contra objetivos reales. Tests de herramientas simuladas
  en PATH cerrado y configuración sintética, sin copiar claves ni evidencias.
- Las suites antiguas solo en clon temporal limpio con los cambios de fuentes
  aplicados; límite suficiente para los fixtures lentos ya conocidos.
- Bash/Python existentes, bibliotecas autolocalizadas, stdout puro para valores,
  interfaz en español, fuentes LF y salidas ignoradas por git.

## Inventario obligatorio de capacidades

| Entrada | Capacidades que deben seguir ejecutables |
|---|---|
| run_all_enum.sh | Descubrimiento de servicios y sus fases actuales SSH, FTP, SMB, LDAP, web y bases de datos; timeout por servicio |
| show_results.sh | Resumen de evidencias, mejorado para seleccionar objetivo sin mezclar otros |
| ssh/enum_ssh.sh | Versión, métodos de autenticación, enumeración de usuarios y algoritmos de intercambio |
| ftp/enum_ftp.sh | Banner, autenticación anónima, listado y scripts NSE FTP |
| ftp/ftp_anonymous.sh | Pruebas anónimas en sus puertos actuales |
| smb/enum_smb_advanced.sh | Null session, usuarios RPC, enum4linux, shares y NSE |
| smb/enum_smb.sh | Generación del script SMB y todas las operaciones de su payload, incluidos shares comunes |
| ldap/enum_ldap.sh | RootDSE, namingContexts y búsqueda de usuarios |
| ldap/ldap_anonymous.sh | Prueba anónima en 389, 636, 3268 y 3269, usando el transporte correspondiente |
| database/enum_mysql.sh | Banner y conexión root sin contraseña con consulta de versión |
| database/enum_postgres.sh | Banner, credenciales por defecto, consulta de versión y listado de bases |
| database/enum_redis.sh | INFO y KEYS *, con advertencia sobre el coste de KEYS |
| web/enum_web.sh | Cabeceras, tecnologías, robots, sitemap y fuzzing con baseline |
| web/enum_web_advanced.sh | Puertos web actuales, cabeceras de seguridad y sondeo de archivos sensibles con baseline |
| web/deepseeenum_web.sh | Generación de enum_web.sh, sincronizada con la hoja corregida |
| api/enum_api.sh | Endpoints, GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD y documentos Swagger/OpenAPI |

Si una orden NSE no existe en la instalación, no se presenta como ejecutada.
Se conserva el objetivo funcional mediante una alternativa verificada si existe;
si no existe, se informa la dependencia/capacidad ausente como NO DETERMINADO,
sin fingir una implementación. No se introduce un diccionario nuevo ni se
amplían los intentos de credenciales que ya contienen los scripts.

## Menú guiado

- Mostrar objetivo de sesión, sin ejecutar automáticamente nada al entrar.
- Comprobación local de herramientas sin invocarlas, sin red ni instalaciones.
- Selección por servicio: SSH, FTP, SMB, LDAP, bases de datos, web y API; pedir
  solamente los datos necesarios y explicar sus operaciones antes de confirmar.
- Acceso al flujo completo existente, resumen de resultados y lista completa
  de herramientas, incluidos los dos generadores identificados como tales.
- Las operaciones activas siguen disponibles. Explicar especialmente métodos
  modificadores HTTP, credenciales por defecto, usuarios, fuzzing, null sessions
  y KEYS *. El flujo completo pide confirmación de las acciones que encadena.
- Respetar objetivo, puerto y esquema introducidos. Añadir entrada por URL
  completa para web/API sin suprimir los modos históricos host/puerto. Cuando
  se use la heurística heredada por puerto, decir que es heurística.
- EOF, cancelación o confirmación negativa no invocan herramientas ni generan
  resultados. No elevar privilegios automáticamente.

## Ejecución y evidencia

- Validar host/puerto/URL antes de lanzar herramientas. Rechazar opciones
  disfrazadas de objetivos y entradas mal formadas, sin perder soporte real.
  IPv6 no se anuncia compatible sin implementación de extremo a extremo.
- Comprobar dependencias, preservar stderr y estados reales. Distinguir entre
  ejecutado, rechazado por autenticación, cerrado, filtrado, omitido y
  NO DETERMINADO. La denegación probada no se confunde con timeout o fallo DNS.
- Salida no vacía o código 0 no demuestran acceso: validar evidencia de cada
  protocolo (por ejemplo Redis NOAUTH no es éxito y FTP requiere respuesta 230).
- No utilizar credenciales del HOME o variables heredadas inadvertidamente
  para atribuir como «anónimo» o «por defecto» un acceso distinto del declarado.
- Rutas de resultados siempre bajo <repo>/scans/<herramienta> mediante las
  bibliotecas. Identificar host y puerto/URL para no pisar objetivos distintos;
  conservar el historial de logs sin presentarlo como diagnóstico actual.
- No consumir resultados antiguos como ejecución nueva ni truncar evidencia
  previa si la nueva orden falla. Publicar resultados solo cuando corresponda.
- show_results selecciona evidencias del objetivo indicado; archivos históricos
  sin atribución se marcan no atribuibles, nunca se asignan por suposición.
- Compatibilidad con informes: conservar formatos reconocidos o actualizar de
  forma acotada descubrimiento/atribución con test de integración. No convertir
  un rechazo o error en un hallazgo ni una ruta antigua en otro objetivo.
- API/web comparan contra baseline para no anunciar catch-all como endpoints
  o archivos reales; un código distinto de 405 no demuestra método permitido.
- Las sondas HTTP respetan el freno 429/503: reintento acotado con Retry-After;
  si persiste, corte sin puntuar, sin seguir enviando métodos.
- El orquestador no transforma fallos de descubrimiento en «cerrado»; cuenta
  ejecutadas/fallidas/omitidas, no afirma completado si falló, ni reutiliza
  gnmap previo. Conservar el timeout configurable y verificar el 8443 en la
  pasada inicial en lugar de depender de un sondeo adicional accidental.
- Los generadores siguen generando sus payloads corregidos; no se ejecutan
  como enumeradores ni se regeneran sobre el checkout real durante tests.

## Verificación y límites

Pruebas primero rojas y después verdes para defectos reproducidos; suite nueva
aislada para navegación, confirmaciones, cada familia y propagación de fallos.
La matriz de capacidades anterior se prueba con registros argv/protocolo: tras
confirmación deben alcanzarse las operaciones correspondientes, no solo aparecer
sus nombres en el menú. Cubrir también negativos, resultados previos, dos
objetivos, puertos no estándar, catch-all, 429/503, timeout y generadores.

Una revisión independiente final y todas las suites en clon limpio preceden a
cualquier afirmación de finalización. Comprobar bash -n con stderr vacío,
sintaxis Python y guardas de configuración/permisos. No afirmar un resultado
de auditoría real ni compatibilidad de una herramienta que no se pudo comprobar.

## Decisiones del implementador

La ubicación de bibliotecas, estructura interna de registros, límites concretos
de tiempo razonables y etiquetas/orden del menú se resolverán en el plan. No
pueden usarse esas decisiones para reducir el inventario, añadir acciones de
ataque distintas o alterar las pruebas reales del usuario.
