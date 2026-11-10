# Revisión de 03_Scanners orientada al menú guiado

Estado: aprobado e implementado el 2026-11-09; nueve suites verificadas en clon limpio.

## Intención

Que el operador pueda elegir un escaneo entendiendo qué va a ejecutar,
qué necesita y cómo distinguir un fallo de un resultado sin hallazgos.
Se mantiene Bash, el gestor existente y el contrato de argumentos de las hojas.

## Evidencia inicial

En una copia temporal de 03 y scans.bash, con nmap/nuclei/nikto/masscan
simulados que salen 7, nmap_smart, nuclei_scan, nikto_scan y run_all_scanners
devuelven 0. Smart anuncia ausencia de puertos; Nuclei, ausencia de
vulnerabilidades; run_all anuncia éxito. La causa es no guardar ni propagar
el estado de cada herramienta y usar la existencia de archivos como éxito.

También se observan por lectura: resultados antiguos consumibles por Smart,
categorías NSE ambiguas, puertos adicionales ignorando la selección del
operador, nombres sin slug en varias hojas y opciones de CLI que necesitan
contraste con la ayuda de la versión instalada (RustScan y Nuclei).

## Enfoques

1. Corregir únicamente las hojas: menor cambio, pero conserva una lista de
   nombres técnicos y una ejecución global excesiva para empezar.
2. **Recomendado: menú específico de 03 y hojas fiables**, reutilizando
   execute_script, sesión y preguntas existentes. Separa uso habitual y
   avanzado sin alterar los otros módulos.
3. Reescribir el gestor entero: mayor riesgo y fuera del alcance solicitado.

La propuesta desarrolla el segundo enfoque, conforme a la petición de
continuar con las mejoras recomendadas. Las decisiones concretas siguientes
son propuestas del implementador, no preferencias expresadas por el usuario.

## Comportamiento propuesto

- Entrar en 03 muestra el objetivo de sesión y opciones con nombres humanos:
  comprobar herramientas (sin red), puertos y servicios básicos,
  análisis de una URL, Burp manual y herramientas avanzadas.
- Las herramientas avanzadas conservan acceso a las diez entradas existentes.
- El análisis básico usa Nmap sobre sus 100 puertos TCP más comunes con
  detección ligera de servicios; no ejecuta NSE, Masscan ni escaneo completo.
- El análisis web pide una URL completa conservando esquema, puerto y ruta;
  permite elegir Nikto o Nuclei. Nunca convierte una URL en objetivo de red.
- El resumen previo muestra objetivo, herramienta e intensidad; ejecutar
  requiere confirmación. Cancelación o EOF no ejecutan nada.
- La comprobación local informa presencia de nmap, masscan, rustscan, nikto,
  nuclei y burpsuite; aclara requisitos de root/interfaz gráfica. No instala,
  descarga plantillas, sincroniza claves ni invoca sudo automáticamente.
- Las hojas propagan fallos y no anuncian ausencia de hallazgos si la orden
  falló. Smart detiene las fases dependientes tras un fallo y solo extrae
  líneas de puertos TCP realmente abiertos de la ejecución actual.
- run_all sigue siendo una opción avanzada explícita, no el inicio recomendado;
  cuenta ejecutados, fallidos y omitidos y sale 1 si falla una tarea requerida.
- URL explícita se usa directamente en las opciones web; el modo heredado de
  descubrimiento por host de run_all conserva 80/443/8080/8443 y explica que
  asignar HTTPS por puerto es una heurística, no detección de TLS.
- Validación de entrada antes de invocar herramientas: host/IP único para
  modos de host, CIDR solo donde se admite, URL HTTP(S) sin credenciales,
  puertos 1–65535, severidades reconocidas; rechazo de valores tipo opción.
- Se conservan prefijos y extensiones que consumen los informes. No se usan
  archivos previos para decidir el resultado de una orden fallida. Los logs
  deben distinguir ejecuciones sin borrar el historial anterior.

## Límites y seguridad

- Ningún escaneo real, instalación, push ni commit automático en esta revisión.
- scope.yaml y el permiso pendiente de api_keys.py permanecen intactos.
- Las pruebas nuevas son autocontenidas; las antiguas solo en clon temporal
  limpio. No se copian evidencias, claves, sesión ni objetivos reales.
- No se altera la política de alcance del proyecto: el registro de sesión
  no sustituye la autorización del operador.
- Burp sigue siendo manual. Esta entrega no rediseña su gestión de procesos.

## Aceptación

Navegación real con entrada canalizada, cancelación y EOF; argv de host/URL
sin deformación; dependencias ausentes; rc distinto de cero en cada hoja;
Smart con resultados antiguos y fallo actual; puertos open frente a
open|filtered; orquestador con fallos parciales y omisiones; HTTP/HTTPS en
puertos no estándar; sintaxis sin advertencias; regresión en copia limpia.
