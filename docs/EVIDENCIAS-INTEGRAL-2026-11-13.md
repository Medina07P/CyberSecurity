# Módulo 10 — entrega integral de implementación

2026-11-13. **Pendiente de revisión global independiente e integración local.**
No es aprobación futura, rama completa verde, compatibilidad operacional,
autenticidad ni custodia legal. No se ha hecho push ni tocado el checkout original.

## Alcance

Conservadas `evidence_manager.sh`, `auto_capture.sh`, `run_all_evidence.sh`;
núcleo estándar en `00_Config/lib/evidence/`, UI en `evidence_menu.bash` y
conexiones limitadas de gestor/estado/introducción. Las Tasks1–7 llegaron
revisadas por el controlador; Task8 entrega guardas, contratos documentados y
regresiones sintéticas. No cambia 08, 09 ni el motor de informes.

Las CLI y límites exactos están en `10_Evidence/README.md`, `USE.md`, `FLUJO.md`
bajo el framework y en `docs/MANUAL-GESTOR.md`. Puntos incompatibles intencionales:

- Importación de cinco tipos por copia regular, con espacios, sin symlinks ni
  atribución automática. Nuevos registros SHA-256/UUID, legacy MD5 solo lectura.
- Listar no verifica; verificar vacío/error falla. Exportación bloqueada salvo
  inventario completo verificado; paquete privado sin cifrar, no entrega automática.
- Captura/red solo con selección y autorización explícitas; perfiles/deadlines
  documentados, contexto OPERADOR separado, validación PNG/PCAP/Nmap limitada.
- Supervisión Linux de procesos propios y señales, no sandbox de backends hostiles.
- `<TARGET>` antiguo devuelve2 sin adquirir; no se declara reparado el flujo99.
  Entrar al menú no cambia TARGET y fase done significa presencia, no integridad.

## Verificación Task8

Base de Task8: `b790f66`. Logs privados conservados en
`/tmp/opencode/evidence-task8-logs/`; reporte de entrega (con commits/rc/resultados)
en `.superpowers/sdd/2026-11-13-evidence-integral/task-8-report.md`.

RED: seis guardas ejecutadas, cuatro fallos reproducidos: permisos de copia,
documentación ausente de allowlist, guarda de origen ausente y runner que
aceptaba mutación del origen durante la suite. Symlinks y PATH cerrado ya
funcionaban y se conservan como caracterización. GREEN: seis guardas rc0;
suite dedicada: 142 tests rc0 (136 previos más seis guardas).

El runner usa exclusivamente `SOURCES`, una allowlist fija de código/tests/las
tres guías; no descubre ni copia config, credenciales o evidencias del origen.
Solo hashea esos archivos y lstat de sus componentes de ruta (layout permitido),
antes/después de copiar y ejecutar; no inventaría evidencia real para probar
preservación. Raíces de datos/config excluidas se prueban con FIFOs sintéticos
venenosos y enlaces que no se siguen. No es protección ante escritura hostil
concurrente que restaure contenido/modos entre comprobaciones.
Las copias/config nuevas son privadas, HOME/scope/targets/session sintéticos,
PATH cerrado a utilidades mínimas/stubs. También verifica la copia al terminar.

## Regresiones y gates

Las regresiones se ejecutarán desde `git archive` de fuentes versionadas tras
el commit de implementación, no desde este checkout: sin ignorados, sin copiar
scope/targets/credenciales del origen, con config/HOME/sesión sintéticos antes
de ejecutar. Scripts y fixtures inspeccionados previamente.

Seleccionadas: smoke (navegación), e2e (argv con nmap stub), reports (datos y
render sintéticos), config_menu (UI/registro ficticio), module_intro (11 tests,
PATH cerrado interno). `run_forensics.sh` descartada: no se modifica08; añadir
296 pruebas de su runtime sin necesidad amplía la revisión de fixtures, mientras
las conexiones de UI compartidas están en module_intro/dedicada.
`run_tests.sh` completa opcional descartada: fallos heredados conocidos y
eliminación de árboles compartidos, sin beneficio para los contratos de esta
entrega. No se reparan heredados ajenos ni se proclama rama verde.

Los resultados efectivos de regresiones y sintaxis se registrarán después de
ejecutar, no se presuponen. Los pasos7–8 (revisión independiente/integración)
pertenecen al controlador y no quedan aprobados por esta entrega. Conservar
worktree, logs y pendientes históricos/deferred ajenos.
