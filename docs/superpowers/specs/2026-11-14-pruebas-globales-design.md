# Corrección de pruebas globales y SSTI

## Alcance aprobado

El usuario aprobó corregir el runner global y el defecto real de SSTI, sin
retirar capacidades, tocar datos reales, commit ni push. No iniciar otro módulo
ni integrar automáticamente los cambios.

## Enfoques

- Actualizar únicamente expectativas: insuficiente; deja servidores huérfanos,
  borrados entre ejecuciones y el falso negativo intermitente de SSTI.
- **Corrección acotada del runner y SSTI, con regresiones deterministas:**
  recomendado y aprobado. Conservar herramientas, payloads y guardas.
- Reescribir toda la infraestructura de pruebas: fuera del alcance necesario.

## Diseño

Runner: sustituir cifras históricas del inventario por contratos explícitos del
parser; comprobar rutas SQLi con host y puerto y filas diferenciales, no afirmar
inyecciones confirmadas por tamaño. Arrancar servidores desde el shell padre,
validar disponibilidad, detener/reapear solo hijos propios y limpiar únicamente
artefactos de su puerto exacto. Buscar evidencia HTTP en sus subdirectorios por
ejecución, sin exigir el antiguo layout plano. Los asserts sqlmap también deben
limitarse a la ejecución observada: el producto conserva `run_*` independientes,
por lo que no corresponde contar todo el historial ni buscar copias en la raíz.

Duración: medir tandas y separar pausas deliberadas, trabajo y bloqueo. Las
pruebas sintéticas podrán eliminar solo la pausa entre peticiones mediante
HTTP_INJECT_RETARDO=0; conservar sleeps del servidor, umbrales, repeticiones,
frenos y pruebas temporales. No aumentar un timeout sin evidencia.

SSTI: ignorar exclusivamente el token de control reflejado al comprobar si la
línea base contenía 49. Conservar el veto cuando 49 pertenece realmente a la
página. No cambiar expresiones, clasificación, umbrales ni configuración pública.

## Evidencia y límites

Reproducciones iniciales en `/tmp/opencode/global-tests-mvbizw_x` y scripts
`/tmp/opencode/probe-global-{http,ssti}.sh`. El segundo demuestra un confirmado
con RANDOM=1 y cero con RANDOM=5, que genera `zq1849829338`.

Toda ejecución del runner antiguo se hará en copia sintética con HOME/config
propios, PATH allowlist, namespace de red con solo loopback y namespace PID.
No ejecutar escáneres reales: sqlmap real queda fuera del PATH; declarar su caso
opcional omitido, no aprobado. Preservar logs, configuración local y trabajo
ajeno. Una suite aislada verde no acredita compatibilidad operacional ni una
auditoría real. Los fallos adicionales se diagnosticarán antes de corregirlos.
