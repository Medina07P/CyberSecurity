# Revisión integral de 06_PostExploitation sin recortes

Estado: borrador para aprobación del usuario.

## Intención y acuerdos

Mejorar el menú, las herramientas y las automatizaciones existentes de 06,
manteniendo todas sus capacidades y contratos actuales. El usuario declara que
todos los objetivos configurados son de su propiedad y están autorizados.
La validación operacional real se hace con esos datos, no con mocks.

Mostrar este aviso informativo en el menú y documentarlo: «Usar exclusivamente
en objetivos autorizados y en un entorno controlado. Estas operaciones pueden
modificar el sistema, crear persistencia o borrar huellas».
El aviso no añade confirmaciones, bloqueos ni restricciones nuevas.

No añadir topes de intentos, tasas, diccionarios reducidos, límites de duración
ni otras restricciones nuevas. Conservar los controles ya existentes, incluidas
las confirmaciones del gestor para scripts intrusivos y los permisos separados.
No endurecerlos ni eliminarlos aprovechando esta revisión.

## Alcance y antiobjetivos

- Conservar cada herramienta, parámetros históricos, payloads, consultas,
  diccionarios, credenciales de prueba y automatizaciones existentes.
- No transformar herramientas activas en simples avisos o guías. Las guías
  actuales (linpeas, template) siguen identificadas como tales.
- No ampliar la revisión a otros módulos ni ejecutar el flujo global 99 como
  verificación.
- No instalar dependencias ni cambiar privilegios automáticamente. La ausencia
  de una dependencia se informa; no se confunde con un resultado negativo.
- No modificar configuración real, sesión, credenciales ni evidencias previas
  como efecto secundario de una prueba de interfaz o de una suite de regresión.
- No publicar objetivos, claves, respuestas ni credenciales; no hacer push.
- Los commits locales están autorizados, seleccionando fuentes explícitamente y
  dejando scope.yaml fuera; nunca usar git add -A.

## Inventario que debe conservarse

| Familia/entradas | Operaciones conservadas |
|---|---|
| run_all_post.sh | Cadena completa de post-explotación |
| privilege_escalation/suid_check.sh | Búsqueda SUID/SGID del sistema |
| privilege_escalation/capabilities_check.sh | Capacidades (getcap) |
| privilege_escalation/cron_check.sh | Tareas programadas del sistema |
| privilege_escalation/linpeas.sh | Descarga y ejecución de linPEAS |
| credential_access/linux_creds.sh | Extracción de credenciales de Linux |
| credential_access/history_parser.sh | Análisis de historiales de comandos |
| loot/file_collector.sh | Recopilación de archivos interesantes |
| loot/screenshot_collector.sh | Captura de pantallas |
| persistence/ssh_backdoor.sh | Puerta trasera SSH en puerto configurable |
| persistence/cron_persistence.sh | Persistencia con cron |
| lateral_movement/ssh_jump.sh | Salto SSH a otro sistema |
| lateral_movement/port_forward.sh | Redirección de puertos con SSH |
| lateral_movement/ps_exec.sh | Movimiento lateral con PSExec |
| cleanup/logs_cleaner.sh | Limpieza de logs y huellas |

## Navegación y compatibilidad

Biblioteca dedicada bajo 00_Config/lib/ e integración en module_postexploitation.
Entrar en 06 muestra el objetivo y el aviso, pero no ejecuta herramientas.
Ofrecer comprobación de dependencias, escalada, credenciales, loot, persistencia,
movimiento lateral, limpieza, flujo completo y visor de evidencia.
Conservar la lista completa de scripts (opción 9+).

La evidencia se atribuye al objetivo de sesión (host:puerto) y se almacena bajo
scans/<herramienta>/, igual que 05, para que el motor de informes la recoja
automáticamente.

## Propiedades del runtime (postexploitation_runtime.bash)

- Funciones: postexploit_init, postexploit_capture, postexploit_publish,
  postexploit_finish (análogas a exploit_* de 05).
- Evidencia por ejecución en scans/<herramienta>/postexploitation_<hash>_<id>/.
- run.json con version, module (06), run_id, host, puerto, url, herramienta,
  started, fecha, estado, rc, complete, steps.
- .meta.json por paso publicado con kind, estado, rc, fecha.
- Clasificación por evidencia real: rc, señales, patrones de denegación.
- Visor (show_results.sh) que lista ejecuciones por host y muestra el último
  intento sin revivir historial como hallazgo actual.

## Comportamiento de run_all_post.sh

- Acepta objetivo posicional (TARGET) y se autolocaliza.
- Ejecuta todos los scripts del módulo que sean seguros de encadenar
  (excluye persistencia y limpieza, que piden confirmación explícita).
- Cuenta ejecutadas/fallidas/omitidas y sale 1 si hay fallos.
- stderr de cada hijo a errores.log del directorio de salida.
- No añade topes ni timeouts.

## Scripts que deben autolocalizarse

port_forward.sh, ps_exec.sh, logs_cleaner.sh, cron_persistence.sh, ssh_jump.sh
y screenshot_collector.sh deben resolver MODULE_DIR desde BASH_SOURCE, no desde
$PWD, y escribir bajo su módulo o scans/ según corresponda.

## Tests aislados

- tests/run_postexploitation.sh: guardas de fuentes/config/sesión + descubrimiento
  de tests/test_postexploitation_*.py.
- tests/test_postexploitation_runtime.py: contrato del runtime (init, capture,
  publish, finish) con comandos inocuos en árbol temporal.
- tests/test_postexploitation_menu.py: navegación del menú con entrada piped.
- tests/test_postexploitation_verify.py: contraste de metadata y rc.

## Integración con informes

- Parser 11_Reports/lib/parsers/postexploitation.py que lee run.json y .meta.json
  de scans/<herramienta>/postexploitation_* y produce ParseResult.
- Registro en sources.py (_PARSER_MODULES).
- Reglas de clasificación: postexploitation.hallazgo, postexploitation.ejecutado,
  postexploitation.denegado.

## Documentación

- docs/POSTEXPLOTACION-GUIADA-YYYY-MM-DD.md con síntomas/causas/fixes/evidencia.
- 06_PostExploitation/README.md actualizado con menú guiado, evidencia y visor.

## Enfoques considerados

1. Revisión integral: biblioteca + runtime + evidencia + menú + tests + informes.
   Mayor trabajo, evita inconsistencias. (Elegido por el usuario.)
2. Revisión por bloques: mismos objetivos, entregas sucesivas. Facilita parciales.

El usuario eligió la revisión integral.

## Lo que queda al builder

- Implementar postexploitation_runtime.bash y postexploitation_evidence.py
  adaptando los de 05 al módulo 06 (MODULE='06', kinds propios de post-explotación).
- Añadir kinds de clasificación apropiados (SUID, capabilities, cron, credenciales,
  loot, etc.) con patrones de evidencia real.
- Adaptar los scripts de 06 para usar el runtime donde tenga sentido.
- Añadir el visor show_results.sh en 06.
- Crear tests aislados.
- Crear parser de informes.
- Actualizar menú, README y documentación.
