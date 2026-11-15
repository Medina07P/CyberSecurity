# Aislador exclusivo de pruebas de 09 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reanudar la verificación sintética de 09 mediante aislamiento Linux heredado por hijos y nietos, sin restringir auditorías operacionales autorizadas ni borrar archivos conservados.

**Architecture:** Preparador host de fuentes/runtime explícitos, lanzador Bubblewrap con raíz privada, namespaces y filtro seccomp, y controlador de probes dentro de esa frontera antes de discovery. La infraestructura de pruebas nunca modifica el ejecutor operacional; la indisponibilidad de cualquier requisito bloquea la ejecución sin fallback.

**Tech Stack:** Python 3.13 / biblioteca estándar en el host Kali inspeccionado; Bash; Bubblewrap existente; Linux x86_64, ELF64 little-endian y seccomp BPF. No paquetes nuevos ni ejecución Docker.

**Spec:** `docs/superpowers/specs/2026-11-13-automation-test-isolation-design.md` (aprobado).

## Global Constraints

- «Mantener intactas las entradas y capacidades operacionales de 09 y otros módulos.»
- «Este diseño no autoriza ninguna auditoría ni amplía el alcance de una existente.»
- «No borrar logs, evidencias, archivos ni workspaces, tampoco los de prueba.»
- «No instalaciones, sudo, Docker build/up, VM ni nuevas dependencias descargadas.»
- «Sin bypass `--unsafe`, entorno que desactive protección ni fallback al host.»
- «Antes de cualquier ejecución, una revisión estática independiente debe aprobar el lanzador, manifiesto runtime, validación y probes.»
- «Los tests y backends se importan/ejecutan exclusivamente dentro del sandbox.»
- «No usar `ldd` sobre archivos arbitrarios»; runtime inspeccionado como datos, no ejecutado para descubrir dependencias.
- «No cambiar sus suites a SKIP general ni eliminarlas para conseguir verde.»
- Conservar incidente y ledgers anteriores. No merge/push, ni limpieza de worktrees. Modelo de subagentes elegido previamente por usuario, sin overrides de modelo no solicitados.
- Tasks1–8 del plan09 no se repiten. No tocar sus módulos de producto ni incorporar aislamiento al uso operacional con Internet/datos autorizados.

### Identidad de user namespace anidado (enmienda autorizada)

`uid_map` se interpreta en el padre inmediato, no directamente en el host: una
entrada única de longitud1 para el UID interior no root requiere composición
VFS, no aceptar parent0 por sí solo. Host crea exclusivamente un canary sintético
nuevo400 en work, fija descriptor/metadatos (dev/ino/mode/size/owner/nlink/times),
y conserva su recibo. Interior exige mismo archivo y propietario traducido a su
UID no root, userns distinto y capacidades cero; declara scope
`immediate-parent-user-namespace`.
El interior debe abrir para lectura el canary400 sin leer su contenido: igualdad
numérica de UID traducido/overflow por stat sola no es prueba de propietario.
Host relee descriptor y nombre originales sin seguir enlaces al aceptar la
prueba; alias/cambio/ambigüedad => BLOCKED. Hijos,
nietos y cancelación heredan256 sin normalización y observan la misma prueba.
No cambia privilegios ni acredita pids.max/ucounts; revisión enfocada y permiso
explícito antes de retry siguen obligatorios.

## Review Focus

1. Descriptor de host, entorno o enlace heredado permite a un nieto leer fuera de la raíz: cierre de fd, canonicalización y mounts mínimos (Tasks1–3).
2. Runtime Python carga `.pth`, sitecustomize o un ELF con dependencia no inventariada: staging cerrado, ningún import host de framework ni ejecución del ELF inspeccionado (Task1).
3. Ausencia de seccomp/namespaces produce fallback silencioso o un probe fuera de aislamiento: fallo rc2 y suites no iniciadas (Task2).
4. Fixture/atexit/test conserva TemporaryDirectory o unlink de evidencia: desactivar limpieza y bloquear casos destructivos hasta tener política compatible, sin afirmar suite completa verde (Tasks3–4).
5. Suite anidada vuelve a ejecutar el lanzador, trunca registros o reusa un test-run antiguo: fases separadas, IDs nuevos y resultados explícitos (Tasks2–4).

---

## Estado, comprobación estática y secuencia de seguridad

Base documental: commit797460f más aprobación registrada con este plan; worktree aislado existente, HEAD detached administrado por harness (no cambiar/mezclar rama). El preparador debe usar su raíz derivada de `__file__`, no variables de entorno para elegir otro checkout.

Solo se inspeccionaron fuentes y metadatos runtime: `/usr/bin/python3` resuelve a `/usr/bin/python3.13`, stdlib `/usr/lib/python3.13`, libs `/usr/lib/x86_64-linux-gnu`, Bash y bwrap en `/usr/bin`, PyYAML en `/usr/lib/python3/dist-packages/yaml`. **No** se ha ejecutado bwrap ni acreditado disponibilidad de namespaces/seccomp.

Nuevo ledger propio: `.superpowers/sdd/2026-11-13-automation-test-isolation/progress.md`; enlazar desde ledger09 sin borrar nada. Desde ahora las Tasks1–3 se escriben y revisan **estáticamente** antes de ejecutar cualquier test del framework o probe. No fabricar RED histórico: las pruebas se escriben antes del código y su primer RED/GREEN se ejecuta dentro de la barrera solo después del gate estático. Fuera de ella solo AST como datos, `bash -n` con stderr, lecturas de fuentes/runtime explícito, git diff/commit. Nunca unittest/import de módulos de tests/producto en host para «comprobar rápido».

## Mapa de archivos y contratos

Todas las rutas `T/` siguientes significan `CyberSecurity-Framework/tests/`.

| Archivo | Responsabilidad |
|---|---|
| `T/automation_sandbox_manifest.json` | Runtime, utilidades y fuentes exactas permitidas, sin configuración/datos |
| `T/automation_sandbox_sources.json` | Inventario exacto de fuentes/documentos/hojas necesario para contratos; reemplaza necesidad de git en sandbox |
| `T/automation_sandbox_prepare.py` | Preparación host sin imports de tests/producto; staging regular, sin symlinks |
| `T/automation_sandbox_elf.py` | Lector ELF64 estático: intérprete, DT_NEEDED, RPATH/RUNPATH y dependencias |
| `T/automation_sandbox_policy.py` | Política BPF y argumentos Bubblewrap puros |
| `T/automation_sandbox_launch.py` | Gate host, fd, límites, logs y un único hijo Bubblewrap |
| `T/automation_sandbox_inside.py` | Probes luego discovery/races dentro de la frontera, nunca host |
| `T/test_automation_sandbox_{prepare,policy,boundary}.py` | Contratos nuevos; solo correr dentro del aislador |
| `T/{run_automation.sh,automation_fixture.py,automation_test_guard.py,test_automation_isolation.py,test_automation_contract.py}` | Integración, preservación y adaptación a copia sin `.git` |
| `docs/AUTOMATION-TEST-ISOLATION-2026-11-13.md`, `09_Automation/USE.md` | Uso, límites y pruebas vs operación; no certificación operacional |

Dataclasses frozen en prepare.py: `RuntimeFile(source: Path, destination: str, category: str)`; `PreparedRun(root: Path, source_root: Path, runtime_root: Path, work: Path, evidence: Path, manifest: tuple[RuntimeFile,...])`. `IsolationBlocked(RuntimeError)`. Fuentes/runtime por fd no-follow: si se descubre symlink en fuente de repo se rechaza; alias runtime fijos `/bin`/loader pueden resolverse durante preparación a archivos canónicos y copiarse como archivos normales, registrando origen/destino. No aceptar rutas aportadas por YAML/CLI o manifiestos externos.

APIs: `prepare(repo: Path) -> PreparedRun`, `read_elf(path: Path) -> ElfInfo`, `resolve_runtime(entries: tuple[RuntimeFile,...]) -> tuple[RuntimeFile,...]`, `seccomp_program() -> bytes`, `bubblewrap_argv(run: PreparedRun, seccomp_fd: int) -> tuple[str,...]`, `launch() -> int`, `inside_main(argv: Sequence[str]) -> int`. ElfInfo frozen: interpreter str|None, needed tuple[str,...], rpaths tuple[str,...]. Nombres/tipos idénticos en consumidores.

### Manifiesto inicial exacto y política

- Intérpretes expuestos en sandbox: `/usr/bin/python3` y `/usr/bin/python3.13` (copias del mismo ELF), `/bin/bash` y `/usr/bin/bash`; `/bin/sh` como Bash invocado con ese basename. No intérpretes recibidos por argumentos.
- Utilidades: nombres exactos `basename,cat,chmod,cp,date,dirname,env,find,grep,head,mkdir,mktemp,mv,od,printf,readlink,sed,sort,stat,tail,timeout,tr,wc`. Cada uno desde `/usr/bin/<nombre>`, archivo canónico fijado en manifiesto efectivo, proyectado `/usr/bin/<nombre>` y alias `/bin/<nombre>` solo si los tests lo requieren. No `rm,rmdir,git,sudo,curl,wget,nmap,hydra,sqlmap,pwsh` reales.
- Stdlib: enumerar como datos los `.py` regulares de `/usr/lib/python3.13`, excluyendo `site-packages`, `dist-packages`, `__pycache__`, sitecustomize/usercustomize y archivos `.pth`; extensiones exactas `.so` de `lib-dynload` se incluyen en manifiesto efectivo con sus ELF-deps. No copiar un directorio stdlib entero ciegamente ni bytecode preexistente. Mantener `site.py` estándar, sin archivos de arranque externos.
- PyYAML: solo `.py` regulares en paquete `/usr/lib/python3/dist-packages/yaml`; excluir extensión C y usar implementación Python. Copiar al único directorio site permitido `/usr/lib/python3.13/site-packages/yaml`, sin `.pth` ni otros paquetes. No importar PyYAML en host para inspeccionarlo.
- ELF: aceptar solo ELF64 x86_64 little-endian. Resolver nombres DT_NEEDED sin `/` en `/usr/lib/x86_64-linux-gnu` con copias individuales; intérprete aprobado `/lib64/ld-linux-x86-64.so.2` se materializa desde ruta canónica. RPATH/RUNPATH fuera de esos directorios y `$ORIGIN` no contenido se rechazan, no se ejecutan. Falta de dependencia bloquea. No bind de todos los `.so` del directorio.
- Runtime bloqueado después de staging: manifest efectivo de archivos exactos, modos e identidades. No conservar referencias de ejecución a paths host; solo copia read-only del runtime en raíz privada.
- Socket syscall bloqueada siempre, no solo connect: BPF seccomp x86_64 verifica AUDIT_ARCH_X86_64=0xc000003e, rechaza x32 (bit0x40000000); `socket(41)`, `socketpair(53)` e `io_uring_setup/enter/register(425,426,427)` devuelven EPERM. Arquitectura ajena se termina antes de ejecutar payload. Otros syscalls permitidos bajo namespaces/cap_drop; no seccomp «falla abierto».
- Bubblewrap usa `--unshare-all --new-session --die-with-parent --cap-drop ALL --clearenv`; no `--share-net`, no `--unshare-user-try`. Raíz nueva; mounts del runtime/source staging solo lectura por rutas exactas, work/evidence únicos read-write; `/proc` propio y `/dev` mínimo nuevo, no hostproc/dev/run. Ningún hostroot/HOME/config/bin-directory bind.
- Entorno fijo `PATH=/usr/bin:/bin`, HOME privado, TMPDIR privado, LANG=C.UTF-8, PYTHONDONTWRITEBYTECODE=1. Entrypoint Python `-I -B` script inside fijo. No forward de argv de shell/env/targets; launcher solo selector cerrado `--probes`, `--suite`, `--races`, default suite. Probes siempre antes de suite/races.
- Tiempo host900s, suite600s, races240s, probe10s; RLIMIT_AS=2GiB, CPU=600s, NOFILE=256, FSIZE=64MiB antes de exec. Enmienda NPROC autorizada por controlador: bootstrap Bubblewrap confiable hereda soft/hard host sin elevarlos; workload impone y relee soft=hard256 en el primer entrypoint interior, antes de probes/forks/imports de tests/producto. Recibos registran límites, UID no root, mapping único, capacidades nulas y snapshot de hilos por UID; ausencia/ambigüedad => BLOCKED. Hijos/nietos verifican herencia. NPROC es contabilidad UID/userns jerárquica, no pids.max ni cuota independiente por árbol; overhead consume plazas y ancestros pueden agotar antes. Tradeoff: bootstrap confiable no está limitado a256; no hay presupuesto agregado256 host+bootstrap+workload. No matar procesos host por nombre; Bubblewrap PID namespace/parent-death y espera de hijo fijado. Límite insuficiente genera fallo explícito, no se incrementa silenciosamente. Ningún retry autorizado por esta enmienda sin revisión estática enfocada y permiso del controlador.
- Persistencia host `/tmp/opencode/automation-isolated-<uuid>/`700: source, runtime, work, evidence; mismos nombres visibles solo dentro del sandbox. Directorios/ficheros nuevos 700/600 excepto código runtime que requiere exec500. No reutilizar, limpiar o borrar al salir. Artefactos fallidos también se conservan.

### Task 1: Preparación de fuentes y runtime sin ejecución

**Files:** Create `T/automation_sandbox_{manifest.json,sources.json,prepare.py,elf.py}`, `T/test_automation_sandbox_prepare.py`.

**Interfaces:** Produce PreparedRun/RuntimeFile/IsolationBlocked/read_elf/resolve_runtime/prepare como arriba; solo biblioteca estándar y lectura de fuentes/runtime permitidos. Inventario sources creado estáticamente a partir de nombres versionados de fuente, no `.git` en sandbox.

- [ ] **1. Escribir pruebas antes del código:** `test_source_symlink_rejected`, `test_no_config_or_generated_input`, `test_runtime_dependencies_closed`, `test_no_cleanup_or_reuse`. ELF fixture de bytes sintéticos, nada ejecutable real para test negativo.
  ```python
  self.assertNotIn('00_Config/scope.yaml', source_names)
  with self.assertRaises(IsolationBlocked): read_elf(synthetic_elf32)
  self.assertEqual(len({entry.destination for entry in runtime}), len(runtime))
  ```
- [ ] **2. Implementar** las APIs en archivos asignados: copia por fd con identidad antes/después, O_EXCL/O_NOFOLLOW, fuentes exactas; ELF reader bounded32MiB y máximo1024 dependencias transitivas/64 niveles; JSON máximo1MiB y claves cerradas. Guardar manifest/estado inicial por archivo nuevo sin sobrescribir. Guardar espacio disponible como diagnóstico, ENOSPC bloquea sin limpieza. No crear un `TemporaryDirectory` con finalizer.
- [ ] **3. Verificación estática solamente:** AST de fuentes nuevas como datos; `git diff --check`; revisar inventario de runtime/sources línea por línea. Pruebas se marcan NOT RUN hasta Task3 gate; no invocar `prepare()` en host aún para «ver si funciona».
- [ ] **4. Commit acotado** `test: prepare allowlisted runtime and sources for isolation`; revisión estática independiente del preparador. Mantener run_automation bloqueado.

### Task 2: Lanzador y política heredada

**Files:** Create `T/automation_sandbox_{policy.py,launch.py,inside.py}`, `T/test_automation_sandbox_policy.py`.

**Interfaces:** Consume PreparedRun; produce seccomp_program/bubblewrap_argv/launch/inside_main. Inside inicialmente ejecuta solo probes-placeholder con resultado BLOCKED (jamás suite sin probes implementados). launch retorna2 blocked,1 test/probe failure,0 todo seleccionado pasó,130/143 por señales.

- [ ] **1. Escribir pruebas estáticas y unitarias de argv/BPF:** `test_no_host_mounts`, `test_bpf_blocks_network_and_x32`, `test_missing_prerequisite_stops_before_payload`, `test_environment_and_fd_closure`. Interpretar BPF como datos en un test, sin instalarlo en host.
  ```python
  self.assertIn('--unshare-all', argv)
  self.assertNotIn('--share-net', argv)
  self.assertEqual(evaluate_bpf(seccomp_program(), 41, 0xc000003e), errno.EPERM)
  ```
  `evaluate_bpf` es helper **de prueba** en test_policy: interpretar solo instrucciones utilizadas y comparar decisión seccomp RET_ERRNO|EPERM, no confundir errno puro con retorno kernel.
- [ ] **2. Implementar** policy/launch: bwrap fuente fijo `/usr/bin/bwrap`, validar inode/owner no setuid y revisión versión por lectura documental/manifiesto (no `bwrap --version` previo). seccomp por memfd cerrado a escritura/sellado, único fd pasado a bwrap y no a test. stdout/stderr host redirigidos a archivos nuevos700/600. Cerrar fds no indispensables y limpiar entorno ANTES exec bwrap; ningún test ejecutado como fallback cuando falla bwrap. No aceptar comando libre desde CLI ni reentrar launcher desde inside. Descriptor stdout/stderr solo archivos de evidencia, stdin DEVNULL.
- [ ] **3. Verificación estática:** AST/bpf bytes razonados por lectura, bash-n si aplica; revisión independiente de argumentos, montaje/fds/env, límites y señalización. No probes aún. Commit `test: add fail-closed isolated launcher and network policy`.

### Task 3: Probes sintéticos y gate de primera ejecución

**Files:** Modify inside.py; Create `T/test_automation_sandbox_boundary.py`; tests anteriores se incluyen por allowlist en sources; Modify `T/automation_test_guard.py` para que diagnóstico no bloquee Popen legítimo DENTRO de barrera validada, sin convertirse en autorización de host.

**Interfaces:** `run_probes(run_id: str) -> dict[str,object]` dentro inside.py, esquema version1 con lista id/result/reason; `inside_main` ejecuta probes antes del selector. Host verifica resultado/rc de bwrap, no confía en variable `SANDBOX=1` ni archivo viejo como prueba. Probes cruzan hijos/nietos Python/Bash del runtime privado.

- [ ] **1. Escribir negativos sin ejecutarlos:** `test_child_and_grandchild_cannot_read_outside`, `test_no_real_backend_fallback`, `test_sockets_denied`, `test_namespace_identity_and_cancel`. Canary externo nuevo sintético fuera del conjunto de mounts, permitido interno nuevo; doble de herramienta externo marcador, jamás Nmap real ni destino documental.
  ```python
  self.assertTrue(result['inside_canary_read'])
  self.assertFalse(result['outside_canary_read'])
  self.assertEqual(result['socket_errno'], errno.EPERM)
  self.assertFalse(external_stub_marker.exists())
  ```
- [ ] **2. Completar probes:** socket(AF_INET/AF_INET6) debe fallar al CREAR, sin connect/bind/send; si inesperadamente se crea, cerrar descriptor y fallar inmediatamente, nunca transmitir. Probar errno en hijo/nieto y ausencia archivos/binarios host; fd/proc namespace corroborado con ids sintéticos capturados antes del lanzamiento, sin leer procesos ajenos/datos. Probe global no supera10s.
- [ ] **3. Gate independiente:** entregar diff completo Tasks1–3 y manifest efectivo previsto a revisor estático nuevo. Debe aprobar construcción antes de primer prepare/launch/probe. Si no aprueba o detecta ruta host accesible, fijar fallos sin ejecutar. Guardar aprobación en ledger; token/env/archivo en código no sustituye revisión.
- [ ] **4. Primera ejecución autorizada SOLO tras gate y aceptación del plan:** `python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --probes`. Único proceso no-estándar de host permitido es bwrap; nunca framework o doble en host. Ausencia herramienta/namespace/runtime/política: BLOCKED rc2, conservar evidencia y no reintentar relajando mounts/política. Probes failed rc1 mantienen suites bloqueadas.
- [ ] **5. TDD diferido dentro sandbox:** correr tests prepare/policy/boundary mediante selector interno fijo tras probes aprobados, registrar RED con variantes sintéticas de entradas (no cambiar barrera a versión insegura para obtener RED), GREEN con fuentes finales. No afirmar RED previo de implementación si no existió. Cancelación/timeout confirman que nadie fuera del namespace recibe señal y descendientes propios no siguen ejecutando.
- [ ] **6. Commit** `test: verify isolation boundary with synthetic descendant probes`; revisión de evidencia y diff. Gate I1 todavía no cierra si faltan adaptación de suite y preservación Task4.

### Task 4: Integración de suite sin pérdida de artefactos y cierre

**Files:** Modify `T/{run_automation.sh,automation_fixture.py,test_automation_contract.py,test_automation_isolation.py,automation_test_guard.py}`, manifest/source allowlists y tests nuevos; Create `docs/AUTOMATION-TEST-ISOLATION-2026-11-13.md`; Modify `CyberSecurity-Framework/09_Automation/USE.md`, `AGENTS.md` solo estado verificado. No código operacional.

**Interfaces:** run_automation llama launcher fijo con selector cerrado; inside discovery `test_automation_*.py` solo después probes por ejecución, nunca llama run_automation recursivamente. tests del lanzador usan funciones puras o lanzador en fase host permitida de gate, no ejecutan bwrap anidado ni simulan aislamiento con env.

- [ ] **1. Escribir regresiones** `test_fixture_close_preserves_tree`, `test_sources_manifest_replaces_git`, `test_launcher_reentry_is_rejected`, `test_operational_entrypoints_unchanged`. Tests de fuentes usan source_paths JSON explícito en vez de git ls-files. Cambios de opciones/hojas requieren actualizar manifiesto fuente y documentación con pruebas de mutación; no desactivar cobertura actual.
  ```python
  fixture.close()
  self.assertEqual(sentinel.read_bytes(), original)
  self.assertEqual(fixture.repo.stat().st_mode & 0o777, 0o700)
  ```
- [ ] **2. Adaptar fixtures y casos sin cleanup:** mkdtemp con persistencia, close solo libera descriptores propios; reemplazar test-only unlink/rmdir/cleanup por renombrado único a archivo de conservación cuando no cambia la aserción. No monkeypatch de funciones del producto para esconder errores o alterar sus semánticas. No exponer rm real; preservación previa a una sustitución de archivos debe quedar explícita en evidencia.

  **Frontera conservadora de «no borrar nada»:** algunos tests de producto ejercitan replace/unlink/cleanup deliberados sobre datos sintéticos. Si no pueden conservar íntegramente sus objetos mediante renombrados/archivos nuevos sin cambiar lo que prueban, NO ejecutarlos bajo esta autorización. Se mantienen fuentes y funcionalidad, se reportan como BLOCKED-preservation con nombres concretos, no pasan a green ni se borran tests. Pedir al usuario autorización específica para operaciones sobre descartables sintéticos antes de ampliar esa frontera. No usar este plan como autorización tácita de borrados. Los tests completos y I1 operacionalmente verificado siguen pendientes si esa frontera impide la suite requerida.
- [ ] **3. Ejecutar prueba focalizada dentro sandbox** tras probes; RED/GREEN de fixture/doc manifest, sin limpiar previos. `bash CyberSecurity-Framework/tests/run_automation.sh` solo después adaptar sus regresiones recursivas. Selector races usa casos internos específicos con contador20, no scripts anteriores externos bajo /tmp. Guardar resultados de cada repetición y SKIP dinámico PowerShell por ausencia runtime, no herramientas instaladas al vuelo.
- [ ] **4. Documentar** separación pruebas/operación; Internet/datos reales siguen disponibles únicamente en auditorías autorizadas, sin convertir el runner en modo operacional. Uso, espacio ocupado, BLOCKED, prerequisitos/manifest, limitaciones Linux/Python, versiones observadas, incidentes y logs. No borrar historias; enlace al ledger09 para retomar Task9 y minor findings diferidos.
- [ ] **5. Revisión independiente global de este aislador y controlador:** comprobar código/fuentes operacionales intactos mediante diff de rutas versionadas, sin hashes de configuración/evidencia. Integración con Task9 requiere completar su verificación de cobertura/doc y review global09, no marcarlo terminado solo por sandbox verde. Cuando suite completa no se pudo ejecutar, informe detallado de pendientes y bloqueo real.
- [ ] **6. Commit** `test: integrate isolated automation verification with preserved artifacts`; conservar worktree/artefactos incluso tras aprobar. Sin merge/push.

## Auto-revisión y handoff

- [x] Spec cubierto: separación/operación en constraints+Task4, runtime/staging en1, barrera en2, probes/gates en3, preservación y verificación en4.
- [x] Interfaces compartidas consistentes; gate estático previo a primera ejecución explícito. No pruebas host para acreditar aislamiento; no afirmaciones de tests futuros.
- [x] Review Focus con caso propietario y controles; no fallback ni eliminación de capacidades para obtener verde.
- [x] Fuentes existentes con cleanup identificadas por lectura; frontera de no-borrado explicitada sin reinterpretar permiso del usuario.
- [ ] Usuario revisa este plan antes de implementación, manteniendo método por subagentes.

Plan no ejecutado. La existencia estática de bwrap no acredita que este host permita sus namespaces. Si el gate o cualquier requisito falla, el resultado correcto es BLOCKED con fuentes/logs conservados, no relajar protección ni alterar operación de auditorías.
