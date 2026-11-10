# Revisión de 04_Enumeration — 2026-11-09/10

Diseño y plan aprobados: `docs/superpowers/specs/2026-11-09-enumeracion-guiada-design.md`
y `docs/superpowers/plans/2026-11-09-enumeracion-guiada.md`.

## Objetivo vinculante

**No quitar funcionalidades.** Se mantienen las 16 entradas, los accesos
anónimos, credenciales por defecto, usuarios, fuzzing, métodos HTTP,
INFO/KEYS Redis, orquestador y ambos generadores.

## Cambios implementados

- Menú específico de 04: selección por servicio, URL explícita para web/API,
  comprobación local, flujo completo, resultados y lista íntegra de herramientas.
- Resumen y confirmación antes de operaciones activas; cancelación/EOF seguros.
  CLI histórica conservada, sin preguntas interactivas añadidas a hojas.
- Runtime común con capturas nuevas, estados de protocolo y registro de
  último intento, separado de la evidencia anterior conservada.
- Nombres por host/puerto; hash adicional web y límites de nombre para URLs
  largas. Metadatos explícitos para atribución y resultados históricos.
- Clasificación de rechazo autenticado frente a conexión fallida; aislamiento
  de identidad MySQL/Postgres para no usar contraseñas/configuración heredadas.
- LDAPS en sus puertos correctos; todos los puertos auxiliares conservados.
- HTTP con timeout, baseline y freno 429/503; métodos modificadores conservados.
  Un 2xx es una observación, no prueba de modificación ni de vulnerabilidad.
- ffuf conserva diccionario e hilos; stream supervisado para frenos, filtrado
  posterior de baseline y no publicación de hallazgos de tandas bloqueadas.
- Una pasada de descubrimiento con 8443; estados de puerto, errores y timeout
  sin cierre verde incondicional. No consume el gnmap de un intento anterior.
- Los generadores siguen generando, solo se prueban en copia temporal.
- Visor por objetivo e integración de informes SSH/MySQL/API sin atribuir
  resultados antiguos al objetivo de sesión por suposición.

## Verificación registrada hasta ahora

- Baseline acumulado del módulo 03: nueve suites con código 0 en clon limpio
  (`/tmp/opencode/enum-baseline-5vxhkns8`).
- Suite nueva aislada: **35 métodos unittest pasan** antes de revisión final;
  casos rojos observados antes de corregir cada grupo.
- Primera regresión: nueve suites pasan, `run_tests` falla nueve expectativas
  antiguas (slot de esquema, confirmación de fuzzing, dobles curl/ffuf y nombres).
  Se actualizaron tras observar los fallos, sin eliminar esas comprobaciones.
- Segunda regresión: nueve suites pasan; una prueba antigua SSTI de módulo 05
  falla (384/385), sin cambios en ese código. Se repite, sin rebajar el aserto.
- Revisión independiente completada: seis defectos importantes corregidos con
  pruebas rojas/verdes; **39 pruebas nuevas pasan**. HEAD usa modo sin cuerpo;
  SIGTERM limpia el grupo ffuf; metadata inválida no revive resultados;
  sondeo TCP fallido y ffuf ausente invalidan el resultado actual; PostgreSQL
  ignora PGHOSTADDR heredado.
- **Regresión final completada: diez suites con código 0**, incluida
  `run_tests` (385 pasan, 0 fallan) y `run_enumeration` (39 pruebas).
  La prueba SSTI antigua también pasa en esta repetición, sin modificarla.
  Logs: `/tmp/opencode/enum-regression-wfiz8eo7/`. Las 52 fuentes/contratos
  modificados coinciden por SHA-256 con la copia probada.
- Sintaxis: 23 archivos Bash sin stderr y 18 Python compilados en memoria;
  `git diff --check` sin errores. Alcance y permiso pendiente de api_keys intactos.

## Decisiones y límites

- Bibliotecas centralizan lógica; las hojas originales siguen siendo puntos
  de entrada y dependen de ellas.
- El banner PostgreSQL usa Nmap `-sV --version-all`: el script `pg-banner`
  anterior no existe en NSE estándar. Usuarios SSH sigue disponible cuando
  exista su NSE; ausente se informa NO_DETERMINADO, no se sustituye por un ataque.
- ffuf no puede retirar peticiones ya en vuelo; cortar la tanda no es revertirlas.
- No se han ejecutado herramientas contra objetivos reales ni validado una
  vulnerabilidad real. Dependencias ausentes no se instalaron.
- Se preservan cambios de 03, configuración pendiente y evidencias; sin commits ni push.
- Menor pendiente: timeout genérico sin kill-after para herramientas que ignoren
  SIGTERM. La supervivencia concreta de ffuf al timeout sí está corregida y probada.

Guía de navegación y riesgos: `CyberSecurity-Framework/04_Enumeration/README.md`.
