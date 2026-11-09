# Configuración usable desde el gestor

Estado: propuesta aprobada por el usuario; menú guiado, ejecución nativa aislada
y commits locales como en los cambios anteriores.

## Problema y solución elegida
El menú descubre api_keys.py pero lo ejecuta sin subcomando. Alternativas:
pedir comandos manuales o reutilizar el menú K. El usuario eligió el menú guiado.
La investigación de las seis entradas también reprodujo éxito falso en run_all,
validadores y parse_targets ante archivos ausentes.

## Diseño corto
- Seleccionar `00_Config/scripts/api_keys.py` en el módulo abre el mismo menú
  guiado de K, con retorno al módulo de configuración. No cambiar su CLI ni
  duplicar lógica de claves; los secretos siguen fuera de argv y salidas.
- «Sin argumentos» se sustituye por una explicación de ejecución directa cuando
  no hacen falta parámetros. Asistente de objetivos conserva preguntas propias;
  parse_targets sigue mostrando el resumen por defecto.
- run_all_config se autolocaliza y ejecuta una lista explícita de tareas de solo
  lectura: validar, verificar, resumen de objetivos y `api_keys.py estado`.
  Nunca asistente, sincronización/importación ni petición de claves automáticos.
- Cada tarea fallida cuenta, se anuncia con su código y no impide ejecutar las
  demás. Stderr queda visible, sin `2>/dev/null` ni log que copie secretos.
  Al final: 0 si todo pasó; 1 si algún paso falló; no éxito global ante parcial.
- validate_config y verify_00_config mantienen verificaciones de existencia y
  devuelven 1 si falta algo. No añadir validación semántica YAML en esta entrega.
- parse_targets mantiene flags y resolución de rutas actuales, pero devuelve 1
  ante archivo ilegible/ausente o exportación fallida, con mensaje sin traceback.
  No cambiar formato de objetivos ni reescribirlo como efecto de lectura.
- Preservar scope.yaml y modo ejecutable local de api_keys.py del checkout
  habitual. No leer ni cambiar claves reales en pruebas ni consultar servicios.

## Verificación
Tests primero con navegación real `00 → 5`, estado, alta guiada de clave sintética,
cancelación/EOF, K, las otras cinco entradas, run_all desde cwd ajeno y con fallos,
validadores y exportaciones. HOME y archivos de configuración temporales.
Ocho suites (nueva config-menu más siete existentes) en worktree/clon limpio;
revisión independiente antes del merge a develop, sin push.
