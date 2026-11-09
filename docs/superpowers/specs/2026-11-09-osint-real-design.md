# OSINT real, trazable y con APIs

Fecha: 2026-11-09. Estado: aprobado por el usuario el 2026-11-09; pendiente de implementación.

## Intención y acuerdos

Corregir los seis scripts de `01_OSINT`: recopilar información real, no
presentar enlaces construidos como perfiles encontrados ni errores como éxito.
El usuario eligió mantener los scripts del menú con un núcleo compartido y
aprovechar las APIs configuradas. También permite fuerza bruta.

Interpretación propuesta de esta última petición: fuerza bruta **DNS de
subdominios**, no credenciales. Opcional y confirmada, nunca implícita en
`run_all_osint.sh`. Los límites siguientes son propuestas técnicas, no
requisitos expresados por el usuario.

## Alternativas consideradas

1. Parchear cada script: menor cambio inicial, conserva duplicación de consultas
   y criterios de evidencia divergentes.
2. Núcleo compartido y entradas actuales: algo más de trabajo inicial, una sola
   política de fuentes, secretos, errores y validación. Elegida por el usuario.

## Alcance y arquitectura

- Mantener Bash como interfaz del gestor, `Uso:`/`Ejemplo:` en español y
  compatibilidad con los argumentos actuales, incluido directorio de salida.
- Núcleo Python compartido en `00_Config/lib/`, fuera de la lista de scripts
  ejecutables. Biblioteca estándar y PyYAML ya disponible; herramientas externas
  existentes para WHOIS, theHarvester y metadatos cuando aporten valor.
- `run_all_osint.sh` ejecutará una recopilación coordinada sin repetir
  theHarvester, certificados o DNS. Los scripts individuales usarán el mismo
  núcleo. No compartir caché indefinidamente entre ejecuciones.
- Dominio, URL y empresa son entradas distintas: normalización y validación;
  un nombre de empresa sin dominio permite buscar candidatos, no atribuirlos.
  El flujo completo tendrá un nombre de empresa opcional explícito y conservará
  el dominio como referencia; no confundirá la primera etiqueta de un host con
  la empresa. Resolver archivos relativos antes de cambiar de directorio.

## Fuentes y APIs

- Sin claves: sitio oficial si se proporciona dominio, certificados públicos,
  DNS, WHOIS y búsqueda pública de GitHub donde esté disponible. Sin proveedor
  de búsqueda web no se promete cobertura general de todas las redes.
- Adaptadores iniciales directos: Brave Search para búsquedas de empresa y
  perfiles, GitHub para búsqueda pública de cuentas y Hunter para emails del
  dominio. theHarvester complementa con sus fuentes compatibles, seleccionadas
  explícitamente según disponibilidad, en lugar de `-b all` sin límites.
- Leer claves del registro existente y, si faltan allí, de la configuración
  efectiva de theHarvester, respetando su prioridad. No modificar ni sincronizar
  credenciales durante un escaneo. Informar qué fuentes se usaron y cuáles se
  omitieron. No invocar una API solo porque haya una clave: debe servir a la tarea.
- No implementar soporte universal de proveedores ni búsquedas de filtraciones
  o recuperación de credenciales. Las fuentes no integradas se indicarán como
  tales, sin insinuar que fueron consultadas.
- Consultas de solo lectura, límites por fuente, tiempos máximos, sin claves en
  argumentos de procesos, informes o mensajes. Redactar errores del proveedor.

## Qué significa un resultado

- Redes: extraer y normalizar enlaces reales desde la web oficial y búsquedas.
  Guardar plataforma, URL, fuente, fecha y evidencia. Un enlace publicado en el
  sitio oficial es «vinculado desde sitio oficial», no garantía de propiedad.
  Coincidencias por nombre son candidatos. Un HTTP 200 no prueba existencia ni
  pertenencia; no evadir login, CAPTCHA ni bloqueos.
- Emails: direcciones sintácticamente válidas y del dominio solicitado, únicas,
  con procedencia. Cuentas GitHub no son emails. No inferir emails ni afirmar
  que entregan correo sin evidencia.
- Subdominios: nombres normalizados dentro del dominio mediante comparación de
  etiquetas, no regex sin escapar; separar descubiertos y resueltos. DNS no
  equivale a servicio web accesible. Filtrar comodines de certificados.
- WHOIS/tecnologías: conservar salida y estado real; no deducir tecnologías de
  mensajes de error. Consulta web de bajo impacto, sin `whatweb -a 3` implícito.
- Metadatos: comprobar herramienta y resultado; un error del extractor no es
  éxito. No ejecutar archivos ni descargar documentos automáticamente.

## Fuerza bruta DNS y AXFR

- Modo activo explícito en `subdomain_finder.sh`, con confirmación propia para
  que también proteja invocaciones directas; el modo normal permanece pasivo.
- Diccionario local explícito, validado y deduplicado; propuesta inicial de
  máximo 1.000 candidatos, 2 trabajadores y 5 consultas por segundo como techo
  agregado, contando reintentos y consultas de control. Sin diccionario implícito
  enorme ni descarga automática.
- Controles de wildcard con nombres aleatorios antes de enumerar y comparación
  de conjuntos A/AAAA/CNAME. Las coincidencias con wildcard quedan ambiguas y
  no cuentan como descubrimientos confirmados; documentar límites ante DNS
  dinámico, sin prometer detección perfecta.
- Usar resolver configurado por el operador o el del sistema; no fijar 8.8.8.8.
  Detener ante fallos persistentes con progreso y estado parcial explícitos.
- AXFR no se ejecuta automáticamente; queda fuera de esta entrega. No se
  incorporan fuerza bruta de credenciales, persistencia ni explotación.

## Estados, límites y salidas

- Estado por fuente: completada con resultados, completada sin resultados,
  omitida sin configuración/herramienta, bloqueada, fallida o agotó tiempo.
  Omisiones previstas no equivalen a fallos; cobertura siempre visible.
- Propuesta de límites: 15 s por solicitud, 120 s por herramienta y 10 consultas
  por API por ejecución, sin paginación ilimitada. Configuración solo dentro de
  topes documentados; el implementador fijará detalles conservadores.
- HTTP 429/503: un reintento con Retry-After; si no cabe en el presupuesto de
  tiempo, cortar esa fuente sin esperar indefinidamente. Si persiste, cortar la
  fuente sin puntuar respuestas como hallazgos y marcar ejecución parcial.
- Código 0: fuentes ejecutadas terminaron bien, aunque sin resultados; código 1:
  fallo/bloqueo/timeout de alguna fuente intentada o ninguna fuente utilizable;
  código 2: argumentos/configuración inválidos. Sin éxito global ante parcial.
- Resultados JSON estructurados y resumen legible, con objetivo, fecha,
  cobertura, evidencia y errores sin secretos. Mantener salidas dentro de los
  árboles ignorados del módulo por defecto, con objetivo y ejecución en el nombre; no pisar
  ni borrar resultados históricos. Logs de error separados y anunciados.
- Excepción de compatibilidad propuesta: el directorio de salida explícito sigue
  admitiendo rutas externas. Anunciar esa ruta y advertir que puede no estar
  ignorada por git; no agregar archivos al índice ni cambiar `.gitignore`
  automáticamente. Las pruebas usarán siempre un directorio temporal aislado.
- No ampliar el motor de informes en esta entrega: los nuevos datos OSINT no
  deben presentarse como vulnerabilidades confirmadas.

## Pruebas y aceptación

- Pruebas primero con fuentes y herramientas simuladas: descubrimiento real,
  atribución frente a candidatos, API configurada y ausente, secretos redactados,
  JSON/HTML inválido, HTTP 403/429/503, timeout, comandos ausentes y fallidos.
- Cubrir deduplicación, dominio limítrofe ajeno, wildcard DNS, topes y confirmación
  del modo activo, rutas desde cualquier cwd y archivo relativo en run_all.
- Añadir suite OSINT aislada por HOME, credenciales y salida. Reejecutar las seis
  suites existentes y sintaxis Bash capturando stderr; compilar Python sin
  escribir artefactos de prueba en fuentes cuando sea posible.
- No consultar objetivos reales ni consumir cuotas en pruebas automáticas.
  Una prueba de integración real requerirá autorización separada y debe dejar
  claros los proveedores probados y las limitaciones.

## Decisiones delegadas al implementador

Estructura interna de adaptadores, esquema JSON versionado, parsers robustos,
fixtures y distribución en tareas. Consultar documentación vigente de las APIs
antes de implementar; si un proveedor no permite el flujo previsto, comunicar
la limitación sin sustituirlo silenciosamente por scraping frágil.
