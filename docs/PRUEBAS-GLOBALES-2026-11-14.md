# Corrección de pruebas globales y SSTI — 2026-11-14

## Alcance y ubicación

Trabajo local sin commit, merge ni push, sobre HEAD desacoplado `8435c05`, en el worktree
`/home/kali/.local/share/opencode/worktree/f6569d/fix-global-tests-2026-11-14`.
El checkout develop original y su configuración local no reciben estos fixes.
Plan: `docs/superpowers/plans/2026-11-14-pruebas-globales.md`.
Ledger y pruebas rojas/verdes: `.superpowers/sdd/2026-11-14-pruebas-globales/`.

## Causas y correcciones

- **Inventario:** 118/45 eran cifras históricas; cuatro nuevas entradas y
  cambios de Uso las invalidaron. Ahora se prueban gramáticas literales,
  obligatoriedad/tipos y modos por entrada, conservando los casos concretos.
- **SQLi:** los tests leían nombres sin puerto; el producto escribe host_puerto.
  Los fixtures producen 90 diferenciales fuertes por objetivo (10 parámetros ×
  9 cargas), no confirmaciones de inyección. HTTPS omite :443 en la URL por
  contrato de `webt_url`, pero el nombre conserva `_443`.
- **Procesos:** `HPORT=$(iniciar_servidor_http)` perdía el PID asignado en el
  subshell. La reproducción mostró kill rc1 y servidor aún respondiendo. El
  helper nuevo arranca desde el padre, comprueba disponibilidad y hace kill/wait
  del hijo registrado; EXIT/INT/TERM preservan el estado de salida. La revisión
  encontró además I1: un listener ajeno podía certificar un arranque fallido.
  El fixture ahora recibe puerto0 y solo después de bind/listen publica un
  recibo privado PID/puerto. El helper exige ese recibo del hijo registrado,
  además de HTTP disponible. Sin recibo no anuncia éxito.
- **Cleanup:** rm -f fallaba ante directorios; los comodines entre puertos
  también borraban otros fixtures. Se limpian directorio/txt/tsv exactos del
  puerto propio. Hay regresiones de idempotencia y preservación de otro puerto
  y otro servidor; las señales se prueban con la inicialización real del runner.
- **Layout:** HTTP y sqlmap conservan subdirectorios por ejecución. Los asserts
  buscan pares de evidencia y el run indicado por el recibo de CLI, sin contar
  resultados históricos como si fueran de la tanda actual ni exigir layout plano.
- **SSTI:** el token de control podía contener 49 (semilla5 genera
  `zq1849829338`); su eco hacía creer que la página ya contenía el resultado.
  Se retira solo ese literal al comprobar el baseline. Un 49 real, incluso junto
  al token, sigue vetando la confirmación. No cambian cargas, niveles ni límites.
- **Regresión informes:** el test del shim legacy carecía de sesión propia y
  dependía del entorno. Sin sesión se reprodujo rc1/error de objetivo; con la
  sesión sintética10.0.0.1, rc0. Solo se cambia el fixture y se comprueba su rc;
  no se modifica el motor ni el shim de09.

## Duración

Una tanda /echo idéntica tarda10.383s con pausa0.2 y2.403s con pausa0:
unos8s son pausas deliberadas. La suite llama30 veces a http_inject, aunque
varias llamadas terminan antes de completar una tanda. Por tanto no se atribuye
todo el tiempo a pausas ni se inventa una duración exacta del baseline original.

La suite fija `HTTP_INJECT_RETARDO=0` **solo para sus fixtures sintéticos**;
se conservan los sleeps del servidor, las repeticiones, los frenos y los umbrales.
La ejecución corregida completa terminó en138.422s y la final posfix I1
en133.059s, sin aumentar un timeout.
No se observó bloqueo; el antiguo límite180s no demuestra por sí mismo uno.

## Verificación observada

| Prueba | Resultado | Evidencia |
|---|---|---|
| Global posfix I1 | 520 pasan / 0 fallan, rc0,133.059s | `/tmp/opencode/global-verify-hbt7vqh9/run_tests.sh.log` |
| Runtime HTTP posfix I1 | 7/7, rc0 | `/tmp/opencode/global-verify-hbt7vqh9/test_global_http_runtime.py.log` |
| SSTI determinista | 5 métodos, 7 casos, rc0 | `/tmp/opencode/global-verify-hbt7vqh9/test_ssti_baseline.py.log` |
| e2e | 11/0, rc0 | `/tmp/opencode/global-verify-hbt7vqh9/run_e2e.sh.log` |
| smoke | 0 fallos, rc0 | `/tmp/opencode/global-verify-hbt7vqh9/run_smoke.sh.log` |
| reports | 29 shell + 78 Python, 0 fallos, rc0 | `/tmp/opencode/global-verify-hbt7vqh9/run_reports.sh.log` |
| enumeration | 39/39, rc0 y guardas intactas | `/tmp/opencode/global-verify-hbt7vqh9/run_enumeration.sh.log` |
| scanners_menu | 27/27, rc0 y guardas intactas | `/tmp/opencode/global-verify-hbt7vqh9/run_scanners_menu.sh.log` |
| exploitation | 74/74, rc0 y guardas intactas | `/tmp/opencode/global-verify-hbt7vqh9/run_exploitation.sh.log` |

Baseline inicial:371/12 con xtrace; uno de esos fallos fue contaminación de stderr
por xtrace, no un defecto de Content-Length. Evidencia original conservada en
`/tmp/opencode/global-tests-mvbizw_x`; no confundir sus recuentos con los nuevos.
Primera corrección:518/2 por expectativas nuevas de :443 literal, corregidas tras
leer el contrato. Primera regresión reports:27/1 shell y78 Python correctos;
se conserva ese log rojo en `global-verify-mk7dw6gv`.

Repetición global anterior a I1: **520/0, rc0,133.718s**, en
`/tmp/opencode/global-verify-uol7xl9f/run_tests.sh.log`. Su `overlay.json`
registra los hashes de las fuentes examinadas. Los4 Bash modificados pasan
`bash -n` con stderr vacío; la verificación AST incluye ahora los2 Python nuevos
y el fixture HTTP modificado. `git diff --check`
sin incidencias; hashes/modos de configuración original y ambos HEAD intactos.
La revisión independiente detectó0Critical,1Important(I1),0Minor. I1 fue
reproducido y corregido mediante test RED→GREEN. Global posfix520/0, runtime7/7,
SSTI y las seis regresiones pertinentes: todas rc0. Los7 hashes de
`global-verify-hbt7vqh9/overlay.json` coinciden con las fuentes actuales.
No se solicitó segunda revisión; I1 se cierra por reproducción RED→GREEN y
verificación integrada, no atribuyendo al revisor una aprobación que no emitió.
No quedan hallazgos Critical/Important sin resolver ni menores diferidos.

## Decisiones y límites de revisión

- Sin commits ni eliminación del workspace, por petición del usuario; no hay
  commits nuevos desde los que recuperar estos cambios si se pierden los archivos.
- Copia de HEAD con overlay y paquete de revisión de diff local más archivos
  nuevos, porque no hay commits autorizados. Omitir una fuente invalidaría la
  verificación; cada copia registra la lista y hashes en `overlay.json`.
- El fixture de sesión legacy se corrigió al diagnosticar la regresión obligatoria,
  sin modificar el motor/shim. Para evitar ocultar otra causa se comprueban rc y
  generación real de documentos, además de la reproducción sin/con sesión.
- Las demás limpiezas históricas siguen limitadas a copia sintética: ejecutar
  directamente el runner sobre datos podría perder evidencia.
- sqlmap real y compatibilidad operacional no se certifican: pueden existir
  incompatibilidades no cubiertas por fixtures. No hay menores diferidos.

## Aislamiento y reproducción

Harness de esta sesión: `/tmp/opencode/verify-global-tests.py`.
Ejecutar desde el worktree, por ejemplo:

```bash
python3 /tmp/opencode/verify-global-tests.py run_tests.sh
python3 /tmp/opencode/verify-global-tests.py test_global_http_runtime.py test_ssti_baseline.py
python3 /tmp/opencode/verify-global-tests.py run_e2e.sh run_smoke.sh run_reports.sh run_enumeration.sh run_scanners_menu.sh run_exploitation.sh
```

El harness crea una copia de git HEAD excluyendo scope.yaml/targets.txt, aplica
un overlay explícito de fuentes nuevas/modificadas con hashes en `overlay.json`
y escribe configuración/HOME/sesión sintéticos. PATH tiene una allowlist de
utilidades, sin sqlmap real ni otros escáneres. Cada suite corre en namespaces
de usuario/red/PID, con solo loopback activo; no hay red externa. Los procesos
residuales de fixtures desaparecen al terminar su namespace. Los logs y copias
se conservan; la herramienta de reproducción externa no se añade al producto.

**No ejecutar run_tests.sh sobre un checkout con datos.** Sigue teniendo otras
limpiezas históricas de scans/burp/sqlmap/logs, fuera de esta reparación acotada.
El caso opcional con sqlmap real se omitió deliberadamente: no se declara probado.
Se comparan hash y modo de scope.yaml/targets.txt originales antes/después sin
publicar contenidos. No se usaron objetivos, credenciales ni evidencia reales;
no hubo instalaciones, sudo, adquisiciones ni flujo99.

Estos resultados no acreditan compatibilidad operacional, detección en sistemas
reales, custodia legal ni todas las suites de toda la rama.
