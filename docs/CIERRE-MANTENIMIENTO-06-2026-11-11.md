# Cierre de mantenimiento de 06 — 2026-11-11

Estado: **cerrado el alcance de mantenimiento aceptado**, con la regresión
general heredada todavía en rojo. No se declara cerrado el plan operacional
integral ni toda la rama libre de fallos.

## Alcance aceptado

El usuario aceptó expresamente cerrar mantenimiento de menú, informes,
validación y pruebas aisladas. Este cierre **no equivale a completar la revisión
operacional integral de 06**. Se conservaron los archivos y capacidades
existentes; no se mejoraron ni ejecutaron operaciones activas.

## Entrega

- Runtime y visor de evidencia por host:puerto:herramienta, metadata validada y
  preservación del último intento, incluidos intentos fallidos o incompletos.
- Códigos de salida conservados por paso incluso al publicar fuera de orden.
- Fechas comparadas como instantes UTC; identidad de host normalizada.
- Menú con acceso correcto al visor y sin imprimir argumentos sensibles de
  PSExec; la exposición de secretos en argv de su CLI histórica permanece.
- Informes sin cuerpos ni credenciales; denegaciones informativas, no una
  vulnerabilidad media por el mero rechazo.
- Verificador de solo lectura: metadata tipada 06 v1 completa y concordante;
  rechazo de módulos ajenos, versiones booleanas y sidecars sin respaldo.
- Compatibilidad de lectura con metadata mínima heredada: solo contrasta
  estado/rc, sin certificar esquema nuevo ni demostrar una vulnerabilidad.
- Diagnósticos de checks de texto sin reproducir contenido sensible.

## Verificación y revisión

Commit previo: `37bdd16` (infraestructura/evidencia y privacidad de menú).
Commit de cierre del mantenimiento: **`1a9b4a6`** (13 rutas explícitas).
Sin push, instalaciones ni pruebas de explotación/post-explotación reales.

La regresión final se ejecuta en copias de fuentes con Git local, configuración
sintética y sin sesión, credenciales, objetivos o evidencia real. Se registran
los resultados definitivos al terminar, incluidos los fallos conocidos; nunca
se interpreta un rc 1 como suite satisfactoria.

Resultados definitivos del bloque en `/tmp/opencode/resume-06-ynom__zl/`:

| Suite | Resultado |
|---|---|
| run_postexploitation | 84 métodos Python, rc 0 |
| run_reports | 78 métodos Python + 28 checks shell, rc 0 |
| run_smoke | 0 fallos, rc 0 |
| run_e2e | 11 comprobaciones, rc 0 |
| run_exploitation | 74 métodos Python, rc 0 |

Sintaxis Bash sin advertencias en stderr y AST Python sin fallos en esa copia.
La tanda complementaria en `/tmp/opencode/resume-06-e1_tmrht/` produjo:

| Suite | Resultado |
|---|---|
| run_wizard | 59 comprobaciones, rc 0 |
| run_keys | 141 comprobaciones, rc 0 |
| run_osint | 69 métodos, rc 0 |
| run_config_menu | 19 métodos, rc 0 |
| run_scanners_menu | 27 métodos, rc 0 |
| run_enumeration | 39 métodos, rc 0 |
| run_tests | 374 pasan, **11 fallan**, rc 1 |

En total, 11 suites pasan y una falla. Esta tanda complementaria empezó antes
de las correcciones finales de sidecars/bytecode; las cinco suites del bloque
se repitieron después de esas correcciones y son las de la primera tabla.

La revisión independiente detectó dos problemas importantes, reproducidos con
tests antes del fix: un sidecar de un paso no concluyente podía declarar un
éxito de otro destino; la importación del validador podía crear `__pycache__`.
Ambos están corregidos y sus tests pasan junto a la suite completa de 06.
También se exige versión estrictamente entera y fecha con zona horaria en
sidecars presentes, y se fortalecieron negativos a partir de fixtures válidas.
La prueba de solo lectura ejecuta el verificador sin `-B` ni variable de
entorno protectora y comprueba tanto evidencia como copias de código.

### Regresión heredada conocida

`run_tests.sh`: **375 comprobaciones pasan y 10 fallan** tanto antes como
después del primer bloque de mantenimiento. El contraste sobre `eb67d1a`
reproduce los mismos asertos; las fuentes de 05 y esta suite no cambiaron.

Fallos conservados, sin debilitar asertos:

1. Recuento fijo de 118 scripts.
2. Detección de diferencia SQLi.
3. Recuento de hallazgos SQLi por objetivo.
4. Existencia de pares `.req`.
5. Existencia de pares `.resp`.
6. Línea de petición en `.req`.
7. Una única cabecera Host en `.req`.
8. Dos logs sqlmap, uno por fichero.
9. Un resumen sqlmap por tanda.
10. Puerto conservado en Host reescrito.

Logs de contraste: `/tmp/opencode/resume-06-zby8frw4/run_tests.sh.log` y
`/tmp/opencode/resume-06-parent-adxhj_dj/run_tests-baseline.log`.
Queda mantenimiento separado de la regresión/contratos de 05; no se afirmó
que todos esos fallos sean defectos de test ni se los corrigió para forzar verde.

En la última tanda reapareció además **`ssti: 49 es CONFIRMADO`**, ya registrado
como intermitente en `RETOMAR-2026-11-10.md`. Log conservado:
`/tmp/opencode/resume-06-e1_tmrht/run_tests.sh.log`. Su causa no se determinó;
no se atribuye a 06 ni se etiqueta como inofensivo. No se modificaron las
fuentes de 05 o su aserto y no se presenta esa suite como aprobada.

## Estado que debe conservarse

Fuera del commit de mantenimiento quedan las modificaciones preexistentes de:

- `CyberSecurity-Framework/00_Config/scope.yaml` (configuración local privada).
- `CyberSecurity-Framework/06_PostExploitation/cleanup/logs_cleaner.sh`.
- `CyberSecurity-Framework/06_PostExploitation/lateral_movement/port_forward.sh`.
- `CyberSecurity-Framework/06_PostExploitation/run_all_post.sh`.

Los diseños/planes integrales de 06 y 07 que ya estaban sin seguimiento no se
borran ni se consideran implementados. No se inició 07 en esta entrega.

## Límites de la entrega

Las 14 hojas y el flujo completo **no se declaran integrados ni verificados
operacionalmente**. No se modificó su comportamiento como parte de este cierre.
Los tests del menú sustituyen las fronteras de ejecución por scripts/funciones
inocuos; no prueban persistencia, acceso a credenciales, movimiento lateral ni
limpieza reales. La suite de 06 no sustituye una auditoría operacional.

Registros locales de trabajo: `.superpowers/sdd/2026-11-11-cierre-mantenimiento-06/`
y `.superpowers/sdd/2026-11-10-postexplotacion-guiada/`; conservarlos.

La comparación SHA-256 de las 13 fuentes de infraestructura con la última
copia probada coincide. Los hashes y modos de scope.yaml y los tres archivos
operacionales pendientes no cambiaron durante este mantenimiento.
