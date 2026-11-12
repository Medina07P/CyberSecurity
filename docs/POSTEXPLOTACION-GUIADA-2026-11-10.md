# Post-explotación guiada (06) — 2026-11-10

## Objetivo

Conservar todas las capacidades de `06_PostExploitation`, registrar su
ejecución y evidencia atribuible por host:puerto, ofrecer menú/visor útil e
integrar resultados fiables en los informes. Sin topes nuevos ni retirada de
funcionalidades.

## Componentes añadidos

- `00_Config/lib/postexploitation_runtime.bash`: `postexploit_init`,
  `postexploit_capture`, `postexploit_publish`, `postexploit_finish`.
- `00_Config/lib/postexploitation_evidence.py`: manifiesto `run.json`,
  sidecars `.meta.json`, clasificación por evidencia real, selección del último
  intento y visor.
- `06_PostExploitation/show_results.sh`: visor de solo lectura por objetivo.
- `06_PostExploitation/run_all_post.sh`: flujo seguro, autolocalizado, con
  conteos y stderr en `errores.log`.
- Parser `11_Reports/lib/parsers/postexploitation.py` y reglas
  `postexploitation.hallazgo`, `postexploitation.ejecutado`,
  `postexploitation.denegado`.
- Suites aisladas `run_postexploitation.sh`, `test_postexploitation_runtime.py`,
  `test_postexploitation_verify.py`, `verify_postexploitation_real.py`.

## Aviso operativo

Usar exclusivamente en objetivos autorizados y en un entorno controlado. Estas
operaciones pueden modificar el sistema, crear persistencia o borrar huellas.

## Evidencia

Cada ejecución vive en `scans/<herramienta>/postexploitation_<hash>_<id>/`
con `run.json`, artefactos y `.meta.json`. El estado sale de la respuesta real
(rc, denegación explícita o patrón probatorio), nunca de la mera existencia de
un fichero. El último intento fallido no revive un éxito histórico.

## Límites

No se ejecutaron operaciones de post-explotación reales como smoke test. La
validación operacional queda pendiente sobre objetivos autorizados del usuario.

## Recuperación del trabajo — 2026-11-11

**Estado: implementación parcial; no dar el módulo por cerrado.** El inventario
anterior describe archivos presentes, no una integración operacional comprobada.
Al retomar tras el apagado, las 40 pruebas iniciales pasaban pero no cubrían
el menú, el parser de informes ni la instrumentación de las hojas.

Defectos reproducidos mediante pruebas nuevas antes de corregirlos:

- La opción 10 del menú abría la lista completa: el patrón de la opción 9
  capturaba también 10. Ahora el visor tiene su propia rama.
- El runtime aceptaba puertos fuera de rango y algunos hosts inválidos;
  también permitía sobrescribir un paso anterior.
- Palabras como `password` y mensajes de éxito impresos por un script se
  convertían en `CONFIRMADO`. Los ecos y el inventario operativo ya no bastan
  para demostrar una vulnerabilidad.
- El parser aceptaba estados sin pasos fiables, sidecars contradictorios o
  ejecuciones incompletas; además, la selección de última fuente ignoraba
  el puerto. Ahora comparte el validador de 06 y conserva host:puerto:herramienta.
- El visor omitía intentos inválidos y podía mostrar un éxito anterior como
  actual; la recuperación incorpora casos sintéticos para impedirlo.

El visor admite `show_results.sh host:puerto`; el puerto filtra de forma exacta.
`POSTEXPLOIT_SCANS_ROOT` permite usar resultados sintéticos sin consultar el
árbol real. Si hay un manifiesto sin identidad fiable, se evita inferir éxitos
actuales en esa carpeta de herramienta: debe revisarse la evidencia privada,
sin borrarla ni repararla automáticamente.

La revisión independiente del bloque detectó además códigos de salida cruzados
entre pasos publicados fuera de orden, fechas comparadas como texto en vez de
instantes, hosts equivalentes no normalizados, estados JSON no textuales y
confirmaciones incompatibles con el tipo de paso. Se añadieron reproducciones
sintéticas y correcciones. También se evita que el gestor imprima los argumentos
de PSExec, que contienen la contraseña; su entrada en el menú no hace eco.
Esto no elimina la exposición inherente a la CLI histórica mediante argumentos
del proceso: no se ha cambiado ese contrato ni se afirma resolver ese límite.

Pendientes conocidos: integración y pruebas aisladas de las 14 hojas,
atribución del flujo completo, propagación de fallos y conservación de su log,
documentación definitiva y cierre de revisión. No comenzar 07 como si estos
pendientes estuvieran resueltos.

Evidencia de la recuperación: ledger local
`.superpowers/sdd/2026-11-10-postexplotacion-guiada/progress.md` y logs en
`/tmp/opencode/resume-06-*/`. Las copias de pruebas excluyen objetivos,
credenciales, sesión y evidencia real; no se ejecutaron herramientas activas
para validar estos cambios.
