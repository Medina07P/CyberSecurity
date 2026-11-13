# Revisión integral de 08_Forensics — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development para ejecutar una tarea por implementador, con revisión de tarea y revisión final. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Conservar las diez entradas de 08, proteger originales y resultados, corregir estados/errores e integrar análisis offline y adquisición explícita en un menú guiado.

**Architecture:** Bash conserva CLI y herramientas; una biblioteca exclusiva de 08 coordina copias privadas, procesos y rc. Python estándar valida manifiestos, integridad y selección de intentos sin ejecutar herramientas. No añadir atribución a IP de sesión ni parser global de vulnerabilidades.

**Tech Stack:** Bash/Kali, Python 3 stdlib/unittest, herramientas forenses existentes; tests con fuentes copiadas y PATH cerrado en /tmp/opencode.

**Spec:** `docs/superpowers/specs/2026-11-11-forensics-integral-design.md` (aprobado).

## Global Constraints

- «Conservar las diez entradas originales y sus métodos»; mantener posiciones válidas de argumentos existentes y documentar los cambios expresamente aprobados de defaults sensibles.
- «No se toma `/dev/sda1`, `/dev/mem`, logs del sistema o capturas encontradas por glob como defecto de una prueba offline».
- «Cada analizador obtiene una copia independiente desde el original elegido; no comparte una copia mutable con otros analizadores».
- «No exigir una copia íntegra previa a ddrescue cuando el origen esté dañado»; soporte físico solo en modo explícito de metadata/adquisición/recuperación, nunca montaje directo del original.
- Directorios 700 y archivos 600 desde creación; resultados únicos, sin truncar symlinks o resultados previos. No imprimir cuerpos, credenciales ni argv completos en consola/visor/manifiesto.
- «No se descargan símbolos ni se consulta red en modo offline»; no instalar, cargar módulos de kernel, montar o adquirir como efecto de entrar al menú o comprobar dependencias.
- «No añadir parser al motor global de vulnerabilidades de 11 en esta entrega»; no usar IP de sesión como identidad forense.
- CLI: 0 trabajo solicitado completo; 1 fallo/parcial/cancelación; 2 uso inválido o precondición incumplida antes de empezar. rc/señal de herramientas intactos en pasos.
- Tests: fuentes/HOME/PATH/config/evidencia sintéticos en /tmp/opencode; TODOS los backends, sudo, mount/umount/losetup, journal y adquisición son stubs, sin fallback al sistema. No leer evidencia real.
- Suites antiguas solo en copia limpia sin datos reales. run_tests heredada sigue roja (último cierre06: 374/11, SSTI intermitente sin causa determinada); no debilitarla ni atribuir causas no probadas.
- Preservar scope.yaml y pendientes de 06 fuera de commits; sin limpieza masiva, instalaciones ni push. Commits locales solo de rutas explícitas, conservar logs/revisiones.

## Review Focus

1. Cambio del original/copia durante análisis, symlink u output solapado: no éxito ni ejecución dependiente, nunca restaurar/escribir el original (Tasks 1–2).
2. rc de captura publicado fuera de orden y metadata parcialmente escrita: no cruzar rc, no revivir éxito histórico ni generar bytecode al visualizar (Tasks 1–2/8).
3. SIGINT/SIGTERM con montaje o hijo vivo: detener solo recursos propios, verificar desmontaje y conservar evidencia parcial (Tasks 2/5).
4. PCAP/imagen vacía/corrupta, símbolos ausentes o ddrescue con sectores pendientes: distinguir cobertura parcial, vacío válido y fallo (Tasks 3–6).
5. Flujo offline con fuentes ausentes y menú/lista genérica: nunca sustituir por datos del host ni omitir confirmaciones de acciones sensibles (Tasks 6–8).

## Preparación

- Leer AGENTS y documentos de rutas referenciados; preservar fuentes/cambios previos mediante hashes/modos, sin exponer configuración real.
- El usuario ha pedido subagentes. Implementadores NO despachan otros implementadores/revisores; controlador coordina revisión y commits por tarea.
- Aislar pruebas mediante copia de fuentes/config sintética como en 07; la suite vieja no corre sobre el checkout real. Usar `PYTHONDONTWRITEBYTECODE=1` salvo test que demuestra lectura sin protección externa.
- Invocaciones unittest siguientes desde `CyberSecurity-Framework` en copia aislada. Toda salida extensa se guarda en ledger/workspace propio del plan y se compara con Expected.
- Nombres nuevos: `00_Config/lib/forensics_{evidence.py,runtime.bash,menu.bash}`, `08_Forensics/show_results.sh`; tests prefijo `test_forensics_`. Los helpers de test se concentran en `tests/forensics_fixture.py`.

---

### Task 1: Almacén de evidencia, copias e integridad de 08

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/forensics_evidence.py`
- Create: `CyberSecurity-Framework/tests/forensics_fixture.py`
- Create: `CyberSecurity-Framework/tests/test_forensics_evidence.py`

**Interfaces:**
- `start_run(root: Path, operation: str, mode: str, inputs: list[dict]) -> Path`; modo `offline|local|physical`, sin datos reales durante tests. Operaciones fijas: `strings|logs|timeline|pcap|volatility|disk|carving|memory|workflow|dependencies`.
- `stage_input(run_dir: Path, source: Path, kind: str = 'file') -> dict`: registra entrada y devuelve `input_id`, `work_path`, `sha256`, `size`, `mode`; árbol explícito soportado como `kind='tree'` con inventario/digest determinista de rutas relativas, modos y contenido, sin seguir symlinks. Entradas no regulares se rechazan salvo modo físico explícito y nunca se copian como archivo ordinario.
- `check_integrity(run_dir: Path) -> bool`: compara originales y copias, sin escribir originales. Cambios => evidencia no confiable, estado FALLIDO y dependientes bloqueados; no ocultar fallo bajo rc0.
- `read_run(path: Path, *, verify_artifacts: bool = True) -> dict`: valida version1/module08, tipos estrictos (bool no entero), estados, identidad, timestamps conscientes de zona horaria, steps/sidecars/rc/hashes/roots confinados en TODOS los estados presentes. JSON inválido => ValueError, nunca traceback por contenedores no hashables.
- `record_step(run_dir, name, rc, state, coverage, artifacts, *, tool='internal', signal=None)`, `finish_run(run_dir) -> dict`, `select_runs(root, filters) -> list[dict]`, `show_results(root, filters)`: sin cuerpos. coverage es objeto `{code: identificador_fijo, complete: bool, requested: bool}`; sin texto sensible/argv. Orden por inicio convertido a instanteUTC; último intento fallido/incompleto/ilegible no revive anterior como actual.
- Esquema mínimo run: version,module,run_id,operation,mode,inputs,started,finished,state,complete,rc,steps,artifact_roots. Paso: name,tool,rc,signal,state,coverage,artifact references. Archivo de paso privado con mismo contenido de control que manifiesto. Sin argv ni contenido sensible. Identidad offline por digest/tipo, no por nombre o IP.
- CLI Python interna: `init|stage|step|finish|validate|list|integrity`; JSON por stdout para resultados, diagnósticos seguros por stderr. Los writers retornan fallo si no pueden persistir metadata.

- [ ] **Step 1: Pruebas rojas.** Unicidad, permisos desde creación, copia independiente/árbol, espacios y archivos vacíos; falta/ilegible/dispositivo/pipe, outputs solapados/symlinks/colisiones, original o copia mutados, ENOSPC simulado. Validador corrupto/contradictorio/incompleto, identidad distinta, fechas UTC equivalentes, último inválido e histórico, secretos ausentes en metadata/visor. `assert run['module']=='08'`, `assert original_bytes==before`, `assert mode(run_dir)==0o700`; lectura normal sin -B no crea archivos en código/evidencia.
- [ ] **Step 2: RED.** `python3 -B -m unittest discover -s tests -p test_forensics_evidence.py -v`; Expected FAIL por biblioteca/interfaces ausentes, no acceso a datos/herramientas reales.
- [ ] **Step 3: Implementar.** JSON atómico en raíz privada, SHA-256 streaming, validación sin convertir entradas corruptas a éxito. OUTPUT_DIR explícito externo conserva raíz elegida; subdir único sin alterar padre, rechazar rutas symlink/solapadas y advertir sensibilidad/gitignore. Referencias externas únicamente de raíces creadas para ese run; no recorrer raíces externas al listar sin selección explícita de manifiesto.
- [ ] **Step 4: GREEN.** Repetir comando; Expected OK. AST Python sin bytecode y guardas de entradas/código intactos. Estados exactos del spec; run sin pasos nunca COMPLETADO.
- [ ] **Step 5: Commit.** Solo las tres rutas: `feat(08): add private evidence store and integrity checks`.

### Task 2: Runtime Bash, pasos y procesos propios

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/forensics_runtime.bash`
- Create: `CyberSecurity-Framework/tests/test_forensics_runtime.py`
- Modify: `CyberSecurity-Framework/00_Config/lib/forensics_evidence.py`, `CyberSecurity-Framework/tests/forensics_fixture.py`

**Interfaces:**
- `forensics_begin OPERATION MODE [OUTPUT_ROOT]` deja `FORENSICS_RUN_DIR`; default `<module>/analysis/runs`. `FORENSICS_ANALYSIS_ROOT`, `FORENSICS_RECOVERED_ROOT`, `FORENSICS_MEMORY_ROOT` para tests, defaults del spec.
- `forensics_stage SOURCE [file|tree]` devuelve ruta de copia SOLO por stdout; deja entrada registrada. `forensics_capture NAME TOOL [ARGS...]` captura streams y rc real, deja `FORENSICS_STEP_RC`, `FORENSICS_STEP_OUT`, `FORENSICS_STEP_ERR`; rc de cada paso se persiste por nombre, nunca se toma último global al publicar.
- `forensics_complete_step NAME STATE COVERAGE` conserva rc/streams registrados; COVERAGE es identificador fijo, no texto de secretos. `forensics_finish` valida integridad/pasos/artifacts y sale0/1 según contrato. `forensics_require TOOL` diagnóstico sin invocar herramienta; `forensics_skip NAME COVERAGE` registra omisión solicitada sin fingir ejecución.
- `forensics_capture` admite funciones Bash ya definidas para pipelines con `pipefail`, sin `eval`. Logs privados por run, no `2>/dev/null` para errores de herramientas. Señales => CANCELADO, preservar parcial, esperar hijos/grupo propio y no tocar procesos ajenos.

- [ ] **Step 1: Pruebas rojas.** Captura de stdout/stderr, rc7/127/143, publicación demorada de dos pasos con rc distintos, sin pasos, stderr con rc0, fallo de metadata, pipeline cuyo productor falla, señales con centinela ajeno, privacidad desde creación y doble finalización. `assert failed_step['rc']==7`; `assert unrelated.poll() is None`; no timeout operativo añadido.
- [ ] **Step 2: RED.** `python3 -B -m unittest discover -s tests -p test_forensics_runtime.py -v`; Expected FAIL por runtime inexistente.
- [ ] **Step 3: Implementar.** Source self-locating `${BASH_SOURCE[0]:-$0}`, umask077, procesos/traps propios y registro de cancelación. Etapas dependientes comprueban fallo/integridad antes de ejecutar; una falla de publicación es operativa aunque comando rc0.
- [ ] **Step 4: GREEN.** Tasks1–2 (`-p 'test_forensics_*.py'`) y bash-n runtime con stderr vacío; Expected rc0 y guardas sin cambios.
- [ ] **Step 5: Commit.** Solo cuatro rutas de esta tarea: `feat(08): capture tool results with trustworthy process state`.

### Task 3: Strings, logs y timeline offline/local explícita

**Files:**
- Modify: `CyberSecurity-Framework/08_Forensics/memory/strings_analysis.sh`
- Modify: `CyberSecurity-Framework/08_Forensics/logs/log_analyzer.sh`
- Modify: `CyberSecurity-Framework/08_Forensics/timeline/timeline_creator.sh`
- Create: `CyberSecurity-Framework/tests/test_forensics_text.py`
- Create: `CyberSecurity-Framework/00_Config/lib/forensics_timeline.py`
- Modify: `CyberSecurity-Framework/00_Config/lib/forensics_evidence.py`, `CyberSecurity-Framework/tests/test_forensics_evidence.py` solo para metadata temporal original de árboles (ruling de integración Task3).

**Interfaces:**
- Strings/logs mantienen `<FILE>`; todos sus productos dentro de run privado, sin imprimir coincidencias sensibles. Un grep0/1 se distingue de grep>1/error de lectura.
- Timeline conserva `[OUTPUT_DIR]` y añade flags `--journal FILE`, `--auth FILE`, `--syslog FILE`, `--dpkg FILE`, `--wtmp FILE`, `--tree DIR`, `--year YYYY`, `--timezone IANA`, `--local`. Sin fuentes/--local: ayuda/selección, EOF no ejecuta. Local usa fuentes históricas y límites históricos del script, con cobertura explícita, nunca implícito desde flujo offline.
- `forensics_timeline.py` consume fuentes de trabajo tipadas, produce `events.jsonl` y resumen privado. Journal JSONL; logs/auth/dpkg texto; wtmp mediante stub/last-f; árbol privado sin escapes. TimestampUTC cuando resuelto; fuentes sin año/zona y sin parámetros quedan en sección unresolved sin orden inventado. Toda transformación preserva origen y limita alcance, no afirma cronología probada.
- Árbol: staging registra mtime_ns original por entrada como metadata observada, con validación/procedencia e integridad; timeline no usa mtime de copia. Snapshots heredadas sin esa metadata no inventan fechas (cobertura temporal no evaluable). Todos los symlinks provocan rechazo explícito del árbol entero, no omisión silenciosa.

- [ ] **Step 1: Pruebas rojas.** Entradas con espacios/duplicado de basename/dos runs, vacíos válidos y grep sin hits; error de strings/lectura no limpio; filtros históricos preservados y conteos sin secretos. Timeline con mezcla formatos/zonas, sin año, líneas ilegibles, sección de archivos modificados y symlinks fuera del árbol; offline nunca invoca journalctl/last-host/find-/; --local solo datos simulados y cobertura fragmentaria. `assert source_hash_after==before`, `assert secret not in public_output`.
- [ ] **Step 2: RED.** `python3 -B -m unittest discover -s tests -p test_forensics_text.py -v`; Expected FAIL por contratos anteriores de salida/CLI.
- [ ] **Step 3: Integrar.** Copias independientes por fuente, preservar patrones existentes; llamar solo paths de trabajo. Seleccionar modo antes de fuentes locales. Si falla una fuente requerida: PARCIAL si otra concluyó, FALLIDO si ninguna; selección vacía NO_EVALUABLE con rc2 antes de empezar.
- [ ] **Step 4: GREEN.** Suite forensics completa + sintaxis tres hojas/AST helper; Expected rc0, originales/código inalterados.
- [ ] **Step 5: Commit.** Solo siete rutas de esta tarea, incluidas las dos de metadata temporal autorizadas por integración: `fix(08): isolate text analysis and build attributable timelines`.

### Task 4: PCAP y Volatility offline sin falsos éxitos

**Files:**
- Modify: `CyberSecurity-Framework/08_Forensics/pcaps/pcap_analyzer.sh`
- Modify: `CyberSecurity-Framework/08_Forensics/memory/volatility_analysis.sh`
- Create: `CyberSecurity-Framework/tests/test_forensics_pcap_memory.py`
- Create: `CyberSecurity-Framework/00_Config/lib/forensics_volatility.bash`

**Interfaces:**
- PCAP `<PCAP_FILE>` conserva análisis capinfos, protocolos, conversaciones TCP/UDP, DNS, HTTP, indicadores sensibles y archivos transferidos. Todas lecturas con `-r` a copia, sin captura live. `tshark -n` evita resolución externa; compatibilidad de estadísticas se determina por ayuda/version reconocida, no cero silencioso.
- Volatility `<MEMORY_FILE> [--backend auto|v2|v3] [--profile PROFILE] [--symbols DIR]`. Backend se detecta por versión/ayuda reconocible de candidatos `volatility`, `vol`, `vol.py`; no ejecutar plugins para adivinar sobre original. V2 mantiene imageinfo y pslist/pstree/netscan/dlllist/cmdscan/consoles, perfil proporcionado o detección válida. V3 Windows ejecuta equivalentes disponibles con `--offline` y símbolos locales, nunca --profile; sin cmdscan/consoles se registra cobertura no soportada, no eliminar esas capacidades de v2.
- Biblioteca `forensics_volatility_detect [requested]` devuelve familia/comando validado; `forensics_volatility_run NAME PLUGIN` utiliza runtime y copia. Sin versión/OS soportado/símbolos/plugins: no inventar datos ni sustituir por backend incompatible; diagnóstico por paso.

- [ ] **Step 1: Pruebas rojas.** capinfos/tshark corruptos/ausentes y fallo en productor antes de sort/grep; vacío válido distinto de PCAP truncado, todos argumentos -r correctos, secretos no públicos. v2/v3 con fixtures de ayuda/version/plugin, --profile jamás en v3, offline obligado, símbolos ausentes/error/pluginunsupported y Linux no reinterpretado Windows. Instrumentar stubs de red para exigir cero llamadas.
- [ ] **Step 2: RED.** `python3 -B -m unittest discover -s tests -p test_forensics_pcap_memory.py -v`; Expected FAIL por estados/salidas/backend no implementados.
- [ ] **Step 3: Integrar.** Capturas completas privadas antes de resumen, propagación de rc e integridad; cero coincidencias no = fallo. Backend desconocido NO_EVALUABLE; no pip/apt/download. Mantener todos productos actuales por ejecución sin sobrescritura.
- [ ] **Step 4: GREEN.** Suite forensics + bash-n de hojas/biblioteca; Expected rc0 y ninguna llamada fuera de stubs.
- [ ] **Step 5: Commit.** Solo cuatro rutas: `fix(08): preserve offline pcap and volatility analysis coverage`.

### Task 5: Disco, montaje de copia y recuperación física explícita

**Files:**
- Modify: `CyberSecurity-Framework/08_Forensics/disk/disk_forensics.sh`
- Modify: `CyberSecurity-Framework/08_Forensics/disk/file_carving.sh`
- Create: `CyberSecurity-Framework/00_Config/lib/forensics_disk.bash`
- Create: `CyberSecurity-Framework/tests/test_forensics_disk.py`
- Modify: `CyberSecurity-Framework/00_Config/lib/forensics_evidence.py`, `CyberSecurity-Framework/00_Config/lib/forensics_runtime.bash`, `CyberSecurity-Framework/tests/test_forensics_evidence.py` solo para registro y validación de raíces privadas de artefactos recovered/captures (ruling de integración Task5).

**Interfaces:**
- Disco `<DISK_IMAGE> [--physical] [--mount-copy] [--offset BYTES --length BYTES]`. Archivo regular por defecto: file/fdisk/blkid sobre copia. Dispositivo exige --physical y solo metadata; --mount-copy de físico rechazado. Imágenes filesystem ext2/ext3/ext4/XFS, loopro propio y opciones del spec; disco completo requiere partición/offset/length seleccionados explícitos y dentro del tamaño. Filesystem desconocido no monta.
- Carving `<FILE> [OUTPUT_DIR] [--physical]`. Archivo regular: Foremost/Scalpel/ddrescue conservados en destinos nuevos separados. --physical solo ddrescue lee dispositivo directo hacia NUEVA imagen/mapa privado, nunca hash/copia exhaustiva previos ni escribir origen. Productos en recovered/runid, referencias desde manifiesto08.
- `forensics_disk_mount COPY [OFFSET LENGTH]` y `forensics_disk_release`: loop/mountpoint privados, control de propietario y verificación real antes de listar; traps idempotentes esperan procesos propios. Fallo de unmount => no retirar loop/mountpoint ni afirmar cleanup completo; conservar diagnóstico de recuperación manual. Ningún rm-rf de punto ambiguo.
- Parser ddrescue interpreta estados del mapfile; cualquier pendiente/bad => PARCIAL, desconocido/mapa ausente => NO_EVALUABLE/FALLIDO, no concluir por rc0 o imagen no vacía solamente.
- Integración de raíces: ampliar la API común con registro explícito de destinos privados nuevos por run para recovered y adquisición posterior, sin confiar en rutas arbitrarias del JSON ni seguir symlinks. Preservar compatibilidad de runs v1 con solo analysis, confinamiento por raíz, hashes, permisos y lectura del visor sin reabrir originales. Overrides externos son explícitos y se validan con la misma política; Task6 reutiliza esta interfaz.

- [ ] **Step 1: Pruebas rojas.** Stubs montajes ext3/4 noload/XFS norecovery/ext2ro, flags de loopro, offsets inválidos/partición ambigua, filesystem no soportado, fallos intermedios y señales; punto/loop ajenos intactos. `assert mounted_source != original`; `assert original_writes == []`. Carving con backend ausente/error/cero recuperado, dos runs no colisionan, dispositivos solo explícitos; ddrescue mapa con sectores malos/parciales, sin hashlectura física previa; --physical jamás llama foremost/scalpel. Mapas/imagen anteriores inmutables.
- [ ] **Step 2: RED.** `python3 -B -m unittest discover -s tests -p test_forensics_disk.py -v`; Expected FAIL por montaje original/default/salidas compartidas/errores ocultos.
- [ ] **Step 3: Integrar.** Usar runtime y lectura sobre copia; permisos privados, validar destinos contra identidad del origen. Mantener recuperación física separada de análisis; no ejecutar ningún comando sudo/mount real en tests ni comprobarlo con dispositivo local.
- [ ] **Step 4: GREEN.** Suite forensics + sintaxis tres Bash; Expected rc0 y todos recursos de fixture liberados o estado fallido documentado, centinelas ajenos intactos.
- [ ] **Step 5: Commit.** Solo siete rutas autorizadas, incluidas las tres de integración de raíces: `fix(08): protect disk sources and track recovery completeness`.

### Task 6: Adquisición de memoria y dependencias explícitas

**Files:**
- Modify: `CyberSecurity-Framework/08_Forensics/memory/memory_dump.sh`
- Modify: `CyberSecurity-Framework/08_Forensics/requirements.sh`
- Modify: `CyberSecurity-Framework/00_Config/lib/dangerous.txt`
- Create: `CyberSecurity-Framework/tests/test_forensics_acquisition.py`

**Interfaces:**
- Memoria `[OUTPUT_DIR] [--method auto|avml|lime|dd]`; invocación explícita/adquisición confirmada. Auto solo AVML reconocido o LiME CLI compatible ya preparado; dd histórico accesible por método explícito, muestra1GiB/PARCIAL, no fallback silencioso por presencia ubicua de dd. Sin backend válido/precondición => rc2, sin falsa memoria guardada.
- Privilegios: preservar uso privilegiado histórico dentro de acción explícita, no instalar herramientas/cargar módulos. Backend no compatible NO_EVALUABLE. Información sistema histórica privada, separada del artefacto RAM; ningún uname exitoso convierte adquisición fallida en éxito. Campos cobertura `completitud_memoria=no_verificada`, método y bytes, no RAM completa asegurada.
- Requirements sin args/`--check`: command-v solo; `--install`: lista de paquetes histórica visible, confirmación directa y del gestor, ejecución explícita manteniendo rc de apt; versiones/paquetes ausentes se diagnostican, sin cambiar de método/install en un análisis. No ejecutar apt real en implementación.
- Añadir dangerous para memory_dump, requirements (incluido listado genérico), disk_forensics, file_carving, timeline y run_all por sus modos sensibles; no retirar confirmaciones actuales. Hojas directas también confirman acciones físicas/locales/install/mount antes de efectos, con EOF/cancelación sin ejecutar.

- [ ] **Step 1: Pruebas rojas.** AVML rc/error/archivoausente/vacío; dd exacto histórico con bound1GiB y PARCIAL; LiME no asumir CLI de módulo; outputdir externo privado/colisión; falta privilegios o confirmación/EOF cero acción. --check no sudo/apt/version invocations; --install denied/EOF/success/fail con stubs y rc correcto. Gestor/listado mantienen dangerous por todas las rutas sensibles.
- [ ] **Step 2: RED.** `python3 -B -m unittest discover -s tests -p test_forensics_acquisition.py -v`; Expected FAIL por instalación/adquisición implícitas y falsos éxitos.
- [ ] **Step 3: Integrar.** Solo métodos explícitos/seleccionados, no descartar capacidad por dependencia ausente; mostrar disponibilidad/cobertura. Capturas en captures/memory/runid y manifiesto en analysis/runs. Alias backend preparado requiere ayuda reconocida; desconocido no se ejecuta a ciegas.
- [ ] **Step 4: GREEN.** Suite forensics + sintaxis dos hojas/guardas dangerous; Expected rc0 y ningún proceso sistema real invocado.
- [ ] **Step 5: Commit.** Solo cuatro rutas: `fix(08): separate explicit acquisition from dependency checks`.

### Task 7: Menú, visor y flujo por fuentes elegidas

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/forensics_menu.bash`
- Create: `CyberSecurity-Framework/08_Forensics/show_results.sh`
- Modify: `CyberSecurity-Framework/08_Forensics/run_all_forensics.sh`
- Modify: `CyberSecurity-Framework/cyber_framework.sh`
- Modify: `CyberSecurity-Framework/00_Config/lib/params.bash`
- Create: `CyberSecurity-Framework/tests/test_forensics_menu_flow.py`

**Interfaces:**
- `forensics_menu` usa execute_script/run_module_scripts sin capturar UI como valores. Opciones:1 dependencias;2 strings;3 logs;4 PCAP;5 Volatility;6 disco/recuperación;7 timeline offline;8 adquisición/local explícitos;9 flujooffline;10 visor;11 lista original;0volver. Cada categoría selecciona una acción, no lanza todas sus hojas.
- Preparar rutas explícitas sin IP sesión/defaults de adquisición. Tipos de slots: ampliar params_type_of para DISK_IMAGE/MEMORY_FILE/LOG_FILE/PCAP_FILE como FICHERO sin alterar otros contratos. Menú cancela con0/! y EOF, paths con espacios como un argumento.
- Flujo CLI `run_all_forensics.sh [--memory FILE] [--log FILE] [--pcap FILE] [--disk FILE] [--timeline-auth FILE] [--local]`; sin fuentes muestra selección/ayuda y no ejecuta en EOF. --local conserva adquisición/logs/timeline históricos explícitos, pasa archivo RAM exacto validado, nunca glob histórico. Adquisición y lectura sistema claramente separadas de offline.
- Flujo ejecuta hojas aplicables por rutas absolutas, resume ejecutadas/fallidas/omitidas y rc0/1/2 real. Puede usar run padre operationworkflow con pasos referenciando runshijos validados; herramientas se ejecutan una vez, no se recaptura secreto en consola. Dependencia fallida bloquea solo dependientes; no error stderr descartado ni instalación.
- `show_results.sh [--run PATH] [--input SHA256] [--operation OP]`: solo lectura; identidad propia, actuales/historial separados y sin cuerpos. Raíces externas únicamente run explícito. Sin metadata fiable, diagnósticos y no revivir previos como hallazgos.

- [ ] **Step 1: Pruebas rojas.** Gestor copiado source/cwd externo, menúentrar/EOF/cancelar/accióninválida no herramientas; 1solo check, 10visor y11lista diferenciados; parámetros files no IP; confirmaciones de hojas sensibles vigentes también listado. Flujo offline no acquisition/journal/hostlogs, dos fuentes exactas y pathsespacios, fallo independiente continúa, dependiente bloqueado, nada seleccionado rc2 sin runfalso. Local RAMrutaexacta (no histórico), conteos/rc/logprivado, visor inválidos ypuertos/IPnoatribución.
- [ ] **Step 2: RED.** `python3 -B -m unittest discover -s tests -p test_forensics_menu_flow.py -v`; Expected FAIL por menú/flujo/visor/tipos no implementados.
- [ ] **Step 3: Implementar.** Integración mínima de module_forensics y source; no alterar menús de03–07. Mantener lista de las diez entradas más visor, sin presentar biblioteca .bash como herramienta.
- [ ] **Step 4: GREEN.** Suite forensics y sintaxis gestor/biblioteca/hojas; Expected rc0, guardas fuentes/configsintética intactas.
- [ ] **Step 5: Commit.** Solo seis rutas: `feat(08): integrate evidence-aware forensics menu and selected-source flow`.

### Task 8: Verificación, suite aislada, documentación y entrega

**Files:**
- Create: `CyberSecurity-Framework/tests/run_forensics.sh`
- Create: `CyberSecurity-Framework/tests/verify_forensics.py`
- Create: `CyberSecurity-Framework/tests/test_forensics_verify.py`
- Modify: `CyberSecurity-Framework/08_Forensics/README.md`
- Create: `CyberSecurity-Framework/08_Forensics/USE.md`
- Modify: `docs/MANUAL-GESTOR.md`, `AGENTS.md`
- Create: `docs/FORENSE-INTEGRAL-2026-11-11.md`
- Modify: `.gitignore` solo si pruebas demuestran salida nueva no ignorada.

**Interfaces:**
- `verify_forensics.py RUN_JSON`: solo lectura, códigos0válido completo/1inconsistente o parcialfallido/2incompleto-nodatos; utiliza validador08, no importa ejecutores ni crea bytecode. No vuelve a leer origen físico/adquirir; comprueba artifacts privados hash/metadata, no certificar integridad legal.
- `run_forensics.sh`: descubre todos test_forensics_*.py, rc verdadero y guardas antes/después de fuentes/config/evidencia SINTÉTICAS. Nunca snapshots recursivos de evidencia real ni symlinks ajenos; lista de fuentes allowlist. Runner detecta ficheros nuevos/cambiados indebidos.

- [ ] **Step 1: Pruebas rojas.** Verificador válido/discrepante/esquema/versionbool/móduloajeno/sidecarrc/hash/nombresfuera de raíz/incompleto; normal sin -B no escrituras código/evidencia; entradas de contenedores corruptos sin traceback. Runner respeta rc de fallo y detecta violación de guardas sin ejecutar backends reales.
- [ ] **Step 2: RED.** `python3 -B -m unittest discover -s tests -p test_forensics_verify.py -v`; Expected FAIL por verificador/runner ausentes.
- [ ] **Step 3: Implementar y documentar.** Diez entradas conservadas, cambiosde defaults aprobados, adquisiciones/montajes explícitos, copias/verificación/costoatime/espacio, sistemas/backendsoportados, estados/cobertura, outputs externos, privacidad y límites de stubs. Registrar síntomas/causas/fixes/evidencia real de pruebas, no prometer auditoría operacional ni cadena de custodia.
- [ ] **Step 4: GREEN y regresión.** run_forensics + unittest completo, bash-n de todo08/bibliotecas/gestor con stderr vacío, ASTPython. En copia de solo fuentes correr reports,smoke,e2e,postexploitation,wireless_maintenance,config_menu,scanners_menu,enumeration; logs/rc explícitos hasta900s/suite. No forzar run_tests verde; informar el estado heredado si no se reejecuta. Comparar hashes de fuentes entregadas con copia probada y guardas de pendientes ajenos.
- [ ] **Step 5: Revisión/cierre.** Controlador coordina revisión de tarea y global, importantes RED→GREEN en una pasada según skill. Commits explícitos de fuentes/tests/docs/diseño/plan aprobado, sin scope ni datosreales, sin push; conservar ledger/logs. Cierre solo cuando requerimientos del plan y tests nuevos pasan, con fallos heredados/compatibilidad operacional no comprobada declarados.

## Self-review del plan

- Protección/privacidad/identidad/estados: Tasks1–2; backendsemántica no se decide por match de palabras o archivoexistente.
- Ocho hojas por familia y requirements/flujo conservados: Tasks3–7; visor nuevo y bibliotecas fuera del inventario original no eliminan entradas.
- Modofísico y memoria no simulan copia completa: Tasks5–6; tests sin dispositivos/sudo reales.
- Integración/CLIconfirmaciones/tiposslots/espacios: Tasks6–7; outputs y validador son interfaces compartidas definidas antes del consumo.
- Timeline formatos/año/zona/árbol y Volatility realv3 offline: Tasks3–4; no se dejan como guías.
- Cierre evidenciaprobada/testread-only: Task8. No reporte global atribuido a IP ni nueva API innecesaria de vulnerabilidades.
