# 09_Automation — contratos y verificación Task9 (2026-11-13)

Estado: Tasks1–8 implementadas/revisadas según controlador; Task9 implementada,
con auto-revisión y pruebas, **pendiente de revisión independiente**. No es
cierre global, compatibilidad operacional ni declaración de rama completa verde.
Sin merge/push, instalaciones ni Docker build/up. No se ejecutó flujo99.

- [Uso09, flags reales, gates y conservación](../CyberSecurity-Framework/09_Automation/USE.md).
- [Inventario completo00–13, opciones/subopciones y130 hojas](MENU-OPCIONES.md).
- [Manual del gestor](MANUAL-GESTOR.md).

## Cambios acotados

Runner `CyberSecurity-Framework/tests/run_automation.sh`: discovery
`test_automation_*.py`, Python aislado, `PYTHONDONTWRITEBYTECODE=1`, diagnóstico y
rc de unittest. Nuevo contrato estático de rutas versionadas, acciones originales,
opciones de fuentes (incluidos Labs y alias06), flags, matrices con entradas,
efectos/límites y guardas de aislamiento; no assertions solo de encabezados.
La guarda no abre ni hashea configuración para demostrar inmutabilidad: rechaza
acceso a datos del checkout y mutaciones; fixtures copian allowlist de fuentes,
construyen configuración/HOME y ejecutan entradas copiadas con dobles.
La guarda es defensa del harness, **no sandbox para código arbitrario** ni
control heredado por todo hijo. Pruebas negativas tienen stub de respaldo.

README09 se sustituyó por guía preview-first; USE detalla las13 entradas del
árbol original y19 acciones de catálogo. Allowlist Docker añade únicamente
`09_Automation/USE.md` exacto y prueba que no admite `USE-private.md`.
Sin cambios de comportamiento en00–08/10–13, sin pulido de minors anteriores ni
cambios en diseño ajeno de fichas-modulos.

## Evidencia reproducible

Logs locales conservados: `/tmp/opencode/automation-task9/`; reporte/checkpoints:
`.superpowers/sdd/2026-11-13-automation-integral/task-9-report.md`.
Las rutas son de evidencia del desarrollo, no objetivos reales.

| Comando/ámbito | Resultado observado | Logs |
|---|---|---|
| Desde FW/tests: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_contract -v` antes de docs/runner | RED rc1,5tests: README obsoleto y4errores por documentos/runner ausentes | red.log |
| Contratos ampliados antes de guarda | RED rc1 por guarda ausente y contenido de filas | red-inventory-guard.log |
| `python3 /tmp/opencode/task3-supervise.py 300 bash CyberSecurity-Framework/tests/run_automation.sh` | GREEN rc0,113tests,0failures/0errors, live_survivors0; PS dinámico solo con mocks | final-suite.stdout.log / final-suite.stderr.log |
| `python3 /tmp/opencode/task3-supervise.py 240 python3 /tmp/opencode/task3-races.py <workspace>/CyberSecurity-Framework/tests` |20repeticiones ×8casos=160tests rc0, live_survivors0/adopted20 | races20.log |
| Contratos finales directos (mismo comando unittest anterior) |9tests rc0 | contract-verified.log |
| `bash -n` de runner y AST de los cuatro Python modificados |rc0; stderr Bash vacío, sin generar bytecode | syntax.log / bash-n.stderr.log |

Casos de carreras: timeout/INT/TERM, publicación spawn, nieto que ignora TERM,
fallo storage tras spawn, sustitución de ancestro, señal durante estado final,
cancelación antes de spawn y grupo ya reapeado. Supervisor sintético Task3
inspeccionado antes de reutilizar, con pidfd/subreaper; sin mock de PID1.

### Incidencia del harness: no afirmar sesión exclusivamente sintética

Una prueba negativa añadida en Task9 llegó a invocar **Nmap real contra
192.0.2.1**, contra la restricción de no herramientas/red reales. La guarda
confundía el nombre relativo `nmap` con una ruta sintética porque cwd era un
temporal. `contract-final.log` conserva el fallo que lo detectó: la prueba de
backend no fue rechazada; no se interpreta rc0 como auditoría ni se afirma
ausencia de tráfico. Se comunicó al controlador.

Se corrigió solo el harness: backend sintético requiere ejecutable **absoluto**
resuelto bajo fixture; además, la prueba negativa ahora usa PATH con stub nmap
rc97 como segunda barrera y verifica que ni siquiera se alcanza ese stub. La
suite final113tests rc0 incluye el rechazo dinámico de lectura de config y de
backend. La corrección no borra la incidencia histórica ni convierte esta
sesión en validación operacional autorizada.

El primer runner con guarda también produjo fallos falsos al clasificar
operaciones relativas a dir_fd como relativas al checkout; se preservan
`suite.*` y la corrección del harness, sin tocar runtime de Tasks1–8. CPython
no incluye dir_fd en evento open: la guarda conserva ese contexto sin alterar
las rutas/syscalls del producto. `suite2.*` registra112tests rc0 previos al
último contrato dinámico.

## Regresiones heredadas, solo copia sintética

Inspeccionados wrappers y fixtures antes de ejecutar. Copia en
`/tmp/opencode/automation-task9/legacy-clean/`: solo fuentes permitidas,
config/wordlists/HOME sintéticos, sin copiar scans/evidencias/reportes existentes.
Backends externos de respaldo denegados; fixtures internos usan sus stubs.
Scripts de preparación/comandos en `legacy-copy.py`, `legacy-run.py` del mismo
directorio de logs. Las guardas antiguas que leen/hasean config solo vieron
config sintética de la copia, nunca la del workspace original.

| Suite en copia limpia | Resultado final | Evidencia |
|---|---|---|
| `bash tests/run_config_menu.sh` |19tests rc0 | legacy-config_menu.* |
| `bash tests/run_scanners_menu.sh` |27tests rc0 | legacy-fixed-scanners_menu.* |
| `bash tests/run_enumeration.sh` |39tests rc0 | legacy-fixed-enumeration.* |
| `bash tests/run_reports.sh` |28shell checks y78tests Python rc0 | legacy-reports.* |
| `bash tests/run_e2e.sh` |11asserts,0fallos,rc0 | legacy-fixed-e2e.* |
| unittest discover `test_exploitation_runtime.py` |16tests rc0 | legacy-exploitation_no_network.* |
| unittest discover `test_exploitation_databases.py` |14tests rc0,clientes stub | legacy-exploitation_databases.* |
| unittest discover `test_exploitation_verify.py` |24tests rc0,manifiestos sintéticos | legacy-exploitation_verify.* |
| Smoke subconjunto sin99 |23checks,0fallos,rc0 | legacy-fixed-smoke_no99_subset.* |

La primera copia omitió por error el archivo fuente `dangerous.txt` por su
extensión: scanners1fallo,enumeration6fallos,e2e4fallos y smoke2fallos (este
último incluso rc0 heredado). Se conservan logs originales; se repitió tras
copiar ese **archivo fuente**, sin cambiar tests para ocultar fallos.

**Bloqueos/límites:** no se ejecutó `run_exploitation.sh` completo porque su
fixture web abre sockets loopback y la instrucción vigente prohíbe red. Se
ejecutaron54tests sin red, no se declara toda explotación verde. Smoke original
introduce99 aun sin objetivo: se omitió explícitamente solo esa línea en un
harness temporal, no en fuentes; el resultado es subconjunto, no suite completa.
`run_tests.sh`/SSTI heredado no ejecutados: no se atribuye ni resuelve su fallo
histórico. La publicación shim exige mismo filesystem Linux renameat2; EXDEV
falla conservando originales. Docker es estático/no sandbox; PowerShell requiere
padre controlado, no garantía anti-TOCTOU ni compatibilidad Windows probada.
