# Integración integral de 09_Automation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hacer de 09 una entrada planificable, explícita y verificable para automatización autorizada sin éxitos ficticios ni pérdida de capacidades.

**Architecture:** Paquete Python no ejecutable en `00_Config/lib/automation/`, CLI y adaptadores bajo 09, ejecución secuencial con catálogo cerrado. El menú comparte la CLI y el gestor solo cambia su despacho 09. Se reutilizan hojas compatibles y se conservan recetas directas cuando las hojas existentes tienen efectos adicionales no seleccionables.

**Tech Stack:** Python 3.10+ y biblioteca estándar; PyYAML opcional para workflows; Bash; PowerShell y Docker comprobados estáticamente, sin instalaciones.

**Spec:** `docs/superpowers/specs/2026-11-13-automation-integral-design.md` (aprobado).

## Global Constraints

- «Sin push.» Preservar cambios ajenos y registros históricos; no añadir configuración real a commits.
- «No instalaciones, Docker build/up ni herramientas reales para verificar este trabajo.»
- «Las suites antiguas solo podrán correr en copia limpia.»
- «Planificar no crea salidas ni lee scans/configuración/credenciales; solo fuentes y YAML seleccionado.»
- «Se usarán listas de argumentos y `shell=False`; no `eval`, shell strings ni expansión de YAML.»
- «09 no registrará objetivos ni modificará scope/session/targets.»
- «Ejecución secuencial. Primer fallo corta la ejecución»; dependientes y pasos restantes se omiten con causa.
- «Un perfil genérico no incluye Hydra, SQLmap, persistencia ni limpieza.»
- «No se debilitan confirmaciones de las hojas.» El catálogo aplica además los gates de `dangerous.txt` para las hojas que reutiliza.
- «Un contenedor no se presentará como sandbox de seguridad.» No declarar compatibilidad operacional ni rama completa verde.
- «No ejecutar los scripts de auditoría del checkout para probar ayuda: hacerlo en la copia controlada.»
- Cambios de producto permitidos: 09, paquete y puente de menú nuevos en 00/lib, despacho exclusivo de 09 en gestor y tests/documentación correspondientes. Otros módulos se leen como contratos, no se modifican.

## Review Focus

1. Entorno heredado con `SQLMAP_*`, `BASH_ENV` o `PYTHONPATH`: no debe autorizar acciones, alterar el destino ni cargar código ajeno (Tasks 1, 4, 5).
2. URL y objetivo válidos pero distintos: ningún backend debe contactar un host que no figura en el plan y sus permisos (Tasks 1, 4).
3. SIGTERM justo antes/después de crear un hijo y nieto que ignora TERM: no iniciar el siguiente paso ni dejar procesos controlados vivos (Task 3).
4. Backend rc=0 sin datos o rc=3 del motor 11: no fabricar cobertura/hallazgos ni anunciar informe evaluable (Tasks 3, 5).
5. Ruta con espacios, enlace simbólico o ancestro sustituido: no escapar del destino privado ni seguir un destino cambiado (Tasks 2, 3, 8).

---

## Preparación, estado y estructura de archivos

No implementar al leer este plan: solicitar revisión y método de ejecución. Al ejecutar, cargar using-git-worktrees y mantener el checkout actual intacto. Si se usa worktree limpio, partir del commit documental del plan: los cambios locales de scope/targets no se copian. Registrar tareas/revisiones en `.superpowers/sdd/2026-11-13-automation-integral/progress.md`; evidencia sintética en `/tmp/opencode/automation-<id>/`. Nunca copiar árboles de evidencia o credenciales al worktree.

Convenciones en las tareas: `FW=CyberSecurity-Framework`; todas las rutas de archivo son relativas al repo. Todos los tests nuevos están en `FW/tests/` y sus comandos parten de ese directorio en el workspace de implementación. Cada suite usa `automation_fixture.py`: copia allowlist de fuentes a un temporal bajo `/tmp/opencode`, crea config/HOME sintéticos y backends falsos. El módulo unittest puede cargarse desde fuentes, pero solo invoca entradas del framework copiadas. No hashear ni abrir config real como guarda: comprobar inmutabilidad del checkout mediante inventario de rutas/modos/metadatos y git diff limitado a fuentes; aislamiento por construcción para contenido sensible.

| Archivos | Responsabilidad |
|---|---|
| `FW/00_Config/lib/automation/{__init__,model,validation,catalog}.py` | Tipos, entradas válidas, catálogo de acciones fijas y permisos |
| `FW/00_Config/lib/automation/{planner,workflows}.py` | Planes inmutables, dependencias y YAML estricto |
| `FW/00_Config/lib/automation/{storage,runner}.py` | Directorios privados, lock, manifiesto y procesos |
| `FW/00_Config/lib/automation/{adapters,reporting,cli}.py` | Backends, motor 11 y CLI/menú común |
| `FW/00_Config/lib/automation_menu.bash` | Puente del gestor; no contiene ejecución propia |
| `FW/09_Automation/python/{orchestrator,auto_audit,report_generator}.py` | Entradas compatibles; solo inicializan import seguro y delegan |
| `FW/09_Automation/bash/auto_{recon,enum,exploit}.sh`, `run_all_automation.sh` | Adaptadores Bash autolocalizados, exit propagado |
| `FW/09_Automation/workflows/{quick_scan,full_audit}.yaml` | Perfiles del esquema v1 |
| `FW/09_Automation/powershell/auto_enum.ps1` | Cinco recolecciones locales con destino explícito |
| `FW/09_Automation/docker/{Dockerfile,docker-compose.yml,Dockerfile.dockerignore}` | Build por allowlist de fuentes y ejecución sin privilegios |
| `FW/tests/automation_fixture.py`, `test_automation_*.py`, `run_automation.sh` | Pruebas sintéticas y runner aislado |
| `FW/09_Automation/{README,USE}.md`, `docs/AUTOMATION-2026-11-13.md` | Contratos de uso, matriz y evidencia de cierre |

## Contratos compartidos fijados por este plan

En `model.py`, dataclasses frozen (sin estructuras mutables compartidas):
- `ActionSpec(id: str, input_types: Mapping[str,str], required: tuple[str,...], gates: tuple[str,...], tools: tuple[str,...], network: bool, effects: str, limitations: str)`.
- `Step(id: str, action: str, inputs: Mapping[str,object], depends_on: tuple[str,...])`.
- `Plan(name: str, steps: tuple[Step,...], timeout: int)`.
- `Command(argv: tuple[str,...], cwd: Path, env: Mapping[str,str], timeout: int)`.
- `StepResult(id: str, state: str, rc: int | None, reason: str)` y `RunResult(rc: int, run_dir: Path | None, steps: tuple[StepResult,...])`.
- `Permissions(targets: frozenset[str], grants: frozenset[tuple[str,str]])`: grants son `(step_id, gate)`, nunca datos persistidos para autorizar otra ejecución.
- `PlanError(ValueError)` y `PreflightError(RuntimeError)`: CLI los traduce a 2 y 1 respectivamente. `render_plan` puede listar errores sin ejecutar; CLI devuelve 2 para inputs ausentes y 1 para backend ausente.

`RuntimeContext(framework: Path, repo: Path, python: Path, path: str)` en `model.py`: todas las rutas se derivan del archivo de entrada, no de cwd. Producción no acepta root/output/executable overrides desde YAML o entorno. Tests inyectan contexto temporal por API interna, no por flags de producción.

Límites: YAML UTF-8 máximo 64 KiB, profundidad máxima 12, máximo 64 pasos; id `[a-z][a-z0-9_]{0,47}`; timeout global entero 1–86400 s (default quick 600, full 3600), paso 300 s por defecto, SQLmap 900, nunca mayor al presupuesto global restante; gracia TERM 2 s, sondeo 50 ms, deadline medido con reloj monotónico. Rechazar bool donde se exige entero. No se ofrece flag de timeout por paso en v1.

### Matriz concreta de backends (lectura de fuentes, no validación operacional)

| Action id | Backend fijo y entradas | Gates además de autorización de red |
|---|---|---|
| `ping` | receta `ping -c 1 <target>` | ninguno |
| `scan_basic` | Bash `03_Scanners/network_scanners/nmap/nmap_smart.sh <target> basico` | `scanner` (hoja en dangerous.txt) |
| `ports_full` | receta Nmap TCP completo, XML dentro del run privado | `full_ports` |
| `services` | receta Nmap `-Pn -sV -p <ports> <target>`; ports explícitos | ninguno |
| `nse_services` | receta `-Pn -sV -sC -p <ports> <target>` | `nse` |
| `os_detect` | receta `nmap -Pn -O <target>`; no sudo automático | `os` |
| `scan_vuln` | receta `nmap -Pn -sV --script vuln -p <ports> <target>` | `nse_vuln` |
| `ssh_enum` | Bash `04_Enumeration/ssh/enum_ssh.sh <target> <port>` | `users` (incluye usuarios y auth) |
| `smb_shares` | receta `smbclient -L //<target> -N`; no hoja avanzada con RPC adicional | `anonymous_access` |
| `db_versions` | receta `nmap -Pn -sV -p 3306,5432,6379 <target>` | ninguno; no prueba contraseñas/consultas |
| `web_tech` | receta `whatweb <url> -a 3` | ninguno |
| `web_scan` | Bash `03_Scanners/web_scanners/nikto/nikto_scan.sh <url>` | `web_scan` |
| `smb_audit` | Bash `04_Enumeration/smb/enum_smb_advanced.sh <target>` | `smb_users` (opt-in adicional, no sustituye shares) |
| `osint_domains` | Bash `01_OSINT/scripts/osint_harvester.sh <domain> <run>/osint` | `osint` |
| `config_check` | Bash `00_Config/scripts/validate_config.sh`, solo al incluirlo | `config_read` (lee wordlists; no planificación) |
| `ssh_attempts` | receta Hydra de la entrada original de 09, una cuenta explícita y diccionario acotado | `credential_attempts` |
| `sqlmap_request` | Bash `05_Exploitation/web/sqlmap_request.sh <request_file> <target>` | `sqlmap_probe`; gates adicionales `sqlmap_replay`, `sqlmap_enum`, `sqlmap_dump` |
| `exploit_lookup` | receta SearchSploit con texto producto/versión validado | ninguno, consulta local |
| `report` | Python `11_Reports/report_engine.py` con objetivo/input/salida explícitos | `report_read` |

Las recetas de puertos no hacen parsing de salidas antiguas: `services`/NSE/scan_vuln exigen lista explícita; se conserva la capacidad, no el encadenamiento ciego. Puertos TCP válidos, listas/rangos sin duplicados expandidos hasta 65535; catálogo muestra volumen. XML por receta Nmap en run privado. `scan_basic` mantiene rutas compartidas de 03 y requiere lock de 09. No usar fingerprint de 02: oculta fallos, mezcla SO con pruebas web y adivina esquema. No usar ssh_bruteforce de 05: impone root/admin/user/test. No usar hojas DB de 04 para simple versión: incluyen accesos o KEYS. No añadir fuzzing de 04 a la fase web original de 09: esta conserva WhatWeb y Nikto; la hoja de 04 añade ffuf en otra sesión y requeriría revisar otro contrato de cancelación. `post` será guía no ejecutable a 06; su run_all es local y mezcla escalada, credenciales y loot. No registrar persistencia/cleanup.

Perfiles: quick = `ping`, `scan_basic` dependiente de ping; full base = quick + `db_versions` después de scan. `--domain` añade `osint_domains` al inicio; `--url` añade `web_tech`; `--include-config` antepone `config_check`; `--report-input` añade report al final con `report_read`, sin ejecutar si falla algo anterior. Enum = ssh_enum, smb_shares, db_versions y web_tech solo con URL; muestra gates users/anonymous_access; enum4linux original sigue accesible mediante smb_audit opt-in. Recon = ping + scan_basic. Scan = scan_basic; scan_vuln opt-in con puertos. Web de auto_audit = web_tech + web_scan. Exploit no selecciona nada implícitamente: exige `--action`. Post siempre guía (preview 0 con aviso, execute 2). Report requiere input y target. `--full` no añade acciones sensibles fuera de lo expresamente seleccionado. Se documenta que los perfiles generales son conservadores: puertos completos, NSE, SO, SSH/SMB y Nikto se seleccionan mediante sus acciones explícitas.

Entradas de catálogo: target obligatorio en acciones de host; port default 22 solo para SSH (siempre visible); services/nse_services/scan_vuln requieren además ports; acciones web requieren url y target concordante; osint_domains exige domain, usando ese dominio como destino declarado; config_check no recibe target; exploit_lookup exige product y es local. ssh_attempts y sqlmap_request usan los campos de Task 4; SQLmap database/table son opcionales pero table requiere database o formato base.tabla. report exige target y report_input. No se aceptan otras claves, secretos literales ni env en inputs. Acciones host no usan IPv6. Cada step generado tiene id igual a action salvo sufijo numérico para repetición; YAML declara sus ids. Perfiles YAML base son autocontenidos en orden/acciones pero requieren --target como default si no lo incluyen; no contienen marcadores de plantilla.

Herramientas requeridas: recetas usan su binario homónimo; hojas Bash requieren bash y python3; scan_basic añade nmap; SSH nmap+timeout; smb_audit nmap+timeout+rpcclient+smbclient (enum4linux opcional, omisión visible); web_scan nikto; SQLmap sqlmap+timeout y utilidades estándar de la hoja; report Python estándar. OSINT requiere Python estándar, con whois/whatweb/dig opcionales que conservan su cobertura omitida. No ejecutar --script-help ni importar backends al comprobar disponibilidad. Dependencias internas adicionales de una hoja se contrastan con su fuente y se reflejan en el test de disponibilidad, sin instalar.

### Task 1: Catálogo tipado, validación y fixture segura

**Files:** Create `FW/00_Config/lib/automation/{__init__,model,validation,catalog}.py`, `FW/tests/{automation_fixture,test_automation_catalog}.py`.

**Interfaces:** Produces los tipos anteriores; `validate(kind: str, value: object) -> object`, `get_action(id: str) -> ActionSpec`, `availability(ctx: RuntimeContext) -> Mapping[str,bool]`. Sin procesos ni lectura de datos para estas funciones.

- [ ] **1. Escribir pruebas rojas** `test_typed_inputs`, `test_catalog_preserves_capabilities`, `test_availability_does_not_execute`: asserts para IPv4/dominio normalizado (lowercase, sin punto final), IPv4 inválida/IPv6/CIDR/`-oX` rechazados; ports 1 y 65535 válidos, 0/65536/bool inválidos; URL HTTP(S) sin usuario/password, fragmento ni controles; texto producto con espacios permitido pero sin controles, prefijo `-` o metacaracteres shell. Rutas con espacios admitidas como datos. Cada fila de matriz existe y su gate coincide.

  ```python
  self.assertEqual(validate('target', 'EXAMPLE.COM.'), 'example.com')
  with self.assertRaises(PlanError): validate('port', True)
  self.assertEqual(get_action('ssh_enum').gates, ('users',))
  ```
- [ ] **2. Ejecutar** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_catalog -v`; debe fallar por paquete inexistente, nunca por falta de herramienta real.
- [ ] **3. Implementar tipos/validación/catálogo.** La fixture usa `TemporaryDirectory(dir='/tmp/opencode')`, copia solo fuentes identificadas, crea falsos ejecutables que registran argv y simula datos. `availability` usa resolución PATH, no `--version`. No importar scripts de entrada para inspeccionar disponibilidad. Tests revisan cero registros de procesos y cero scans creados.
- [ ] **4. Ejecutar el mismo comando**, esperar todos los casos PASS, sin writes al checkout.
- [ ] **5. Commit acotado** de los archivos de esta tarea: `feat: add typed automation action catalog`.

### Task 2: Planificador y workflows estrictos sin efectos

**Files:** Create `FW/00_Config/lib/automation/{planner,workflows}.py`, `FW/tests/test_automation_plans.py`; Modify ambos YAML de 09.

**Interfaces:** Consumes ActionSpec/Step/Plan/RuntimeContext y validate. Produces `build_plan(selector: str, inputs: Mapping[str,object]) -> Plan`, `load_workflow(path: Path, defaults: Mapping[str,object]) -> Plan`, `validate_plan(plan: Plan) -> Plan`, `render_plan(plan: Plan, ctx: RuntimeContext) -> str`. Orden topológico estable por orden declarado; resolver defaults solo para claves admitidas ausentes, nunca sustituir valores explícitos.

- [ ] **1. Pruebas rojas** `test_profiles_exact_actions`, `test_strict_yaml`, `test_plan_has_no_data_reads`, `test_paths_relative_to_yaml`: assert quick/full exactos según matriz; gates sin ejecutar; `script:`, campo extra, ciclo, id duplicado, clave duplicada, tag, alias, 65537 bytes, 65 pasos, profundidad 13, bool timeout y paralelo rechazados. Sin PyYAML: solo workflow falla con diagnóstico; perfil built-in funciona. Ruta `dir con espacios/a.req` se resuelve junto al YAML, no al cwd; symlink se deja marcado inválido para preflight, no se abre su contenido.

  ```python
  plan = build_plan('quick', {'target': '192.0.2.1'})
  self.assertEqual(tuple(s.action for s in plan.steps), ('ping', 'scan_basic'))
  self.assertEqual(plan.timeout, 600)
  with self.assertRaises(PlanError): load_workflow(oversized_yaml, {})
  ```
- [ ] **2. Ejecutar** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_plans -v`; esperar fallo por APIs ausentes.
- [ ] **3. Implementar planner/workflows.** Esquema exacto `{name, version: 1, timeout, steps:[{id, action, inputs, depends_on}]}`; no otras claves. Claves mínimas por step id/action; inputs/depends_on default vacíos. `safe_load` con loader limitado que rechaza duplicados/aliases/tags, y límite de profundidad antes de construir objetos. Validar también claves de inputs contra catálogo. Nunca cargar credenciales/peticiones/scans para renderizar. YAML no acepta permisos. Entradas compartidas CLI se inyectan como defaults tipados, no plantillas.
- [ ] **4. Repetir suite**, además comparar árbol temporal antes/después del preview (sin archivos nuevos).
- [ ] **5. Commit** `feat: add effect-free automation plans and strict workflows`.

### Task 3: Almacenamiento privado y ejecución secuencial cancelable

**Files:** Create `FW/00_Config/lib/automation/{storage,runner}.py`, `FW/tests/test_automation_runner.py`.

**Interfaces:** Consumes Plan, Command, Permissions, RuntimeContext, StepResult, RunResult. Produces `RunStore.create(repo: Path) -> RunStore`, `RunStore.write_state(data: Mapping[str,object]) -> None`, `RunStore.open_log(step_id: str, stream: str) -> BinaryIO`, `run_plan(plan: Plan, ctx: RuntimeContext, permissions: Permissions, compile_step: Callable[[Step,Path],tuple[Command,...]]) -> RunResult`. Almacenamiento expone `path: Path`; lock flock no bloqueante retenido durante todo run. Tarea 4 aporta compilador/preflight; aquí stub sintético.

- [ ] **1. Pruebas rojas** `test_stop_on_failure`, `test_private_atomic_logs`, `test_storage_errors`, `test_lock_contention`, `test_timeout_and_signals`: asserts estados/rc exactos; rc=0 vacío no declara hallazgos; rc=7 queda raw rc=7 y run rc=1; pasos siguientes omitidos. Permisos 700/600 aun con umask 000. Symlink en scans/automation o archivos, ancestro sustituido, ENOSPC y EACCES: ningún hijo posterior y sin éxito. Doble ejecución 09 falla con causa, sin borrar lock de otro proceso. INT/TERM antes de spawn y tras spawn, nieto que ignora TERM, fin simultáneo y timeout: 130/143/1, ningún siguiente paso; esperar PID de hijos controlados muertos sin sleeps arbitrarios (handshake por pipes/archivos sintéticos y deadline de test).

  ```python
  result = run_plan(plan, ctx, permissions, compile_first_exit7)
  self.assertEqual(result.rc, 1)
  self.assertEqual(result.steps[0].rc, 7)
  self.assertEqual(result.steps[1].state, 'omitido')
  self.assertEqual(result.run_dir.stat().st_mode & 0o777, 0o700)
  ```
- [ ] **2. Ejecutar** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_runner -v`; confirmar rojo controlado.
- [ ] **3. Implementar storage.** `scans/automation/<uuid4hex>/`, root y subdirectorios abiertos por fd con `O_DIRECTORY|O_NOFOLLOW`, creación relativa al fd; archivos `O_EXCL|O_NOFOLLOW`. No chmod de directorios ajenos, no seguir symlinks. Estado `run.json` con schema_version=1, run_id, plan no secreto, timestamps, raw rc y motivos. Reemplazo atómico relativo al fd y fsync; UUID no contiene objetivo. Lock `.lock` bajo root seguro, no persistir autorizaciones.
- [ ] **4. Implementar runner.** Popen con `start_new_session=True`, stdout/stderr ficheros abiertos, stdin DEVNULL; handlers solo marcan cancelación. Proteger ventana check/spawn/publicación del proceso contra señales. Deadline monotónico global y por comando; finalizar grupo propio TERM, gracia 2 s, KILL a miembros restantes aun si líder salió; reap de hijo directo. No reapear/liberar identidad del líder antes de terminar la limpieza pendiente del grupo (en Linux, waitid con WNOWAIT permite observar salida sin liberar PID); jamás señalizar un PGID liberado que pueda haberse reutilizado. Error de almacenamiento posterior a spawn cancela/reapea antes de retornar 1. No `communicate` con buffers ilimitados ni `pkill`; no lanzar backends daemonizantes. Restaurar handlers/lock al salir.
- [ ] **5. Repetir suite** y repetir 20 veces los casos de carrera; esperar cero supervivientes y rc esperados.
- [ ] **6. Commit** `feat: execute automation plans with private logs and cancellation`.

### Task 4: Adaptadores de catálogo y permisos por acción/destino

**Files:** Create `FW/00_Config/lib/automation/adapters.py`, `FW/tests/test_automation_adapters.py`.

**Interfaces:** Consumes APIs 1–3. Produces `preflight(plan: Plan, ctx: RuntimeContext, permissions: Permissions) -> None`, `compile_step(step: Step, run_dir: Path, ctx: RuntimeContext, permissions: Permissions) -> tuple[Command,...]`, `child_env(ctx: RuntimeContext, run_dir: Path) -> Mapping[str,str]`. El wrapper de runner cierra sobre contexto/permisos. Preflight de todos los pasos termina antes de crear run o lanzar red.

- [ ] **1. Pruebas rojas** `test_exact_argv_for_every_action`, `test_permissions_are_step_and_target_bound`, `test_env_cannot_grant_permissions`, `test_request_destination_matches`, `test_dictionary_bound`, `test_backend_missing`: fakes registran argv/env/cwd, assert no run_all, sudo ni shell. `SQLMAP_TABLA` y `SQLMAP_ENUMERAR` heredados no autorizan; gate para id distinto no sirve. URL example.org con target example.com falla. Host de petición, puerto y esquema/contexto diferentes fallan antes de ejecutar cualquier paso; no reescribir Host silenciosamente. Sin herramientas/hoja es PreflightError/1; permiso ausente PlanError/2.

  ```python
  with self.assertRaises(PlanError): preflight(sqlmap_plan, ctx, Permissions(frozenset({'192.0.2.1'}), frozenset()))
  env = child_env(ctx, run_dir)
  self.assertNotIn('SQLMAP_TABLA', env)
  self.assertNotIn('BASH_ENV', env)
  ```
- [ ] **2. Ejecutar** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_adapters -v`; rojo por adaptador ausente.
- [ ] **3. Implementar mapping fijo de matriz.** Catálogo nunca toma executable/cwd/env desde inputs. Nmap recetas `-sT -Pn -p- -T4` para ports_full (sin min-rate), `-oX <run>/<step>.xml`; servicios no leen scans anteriores. URL y target normalizados deben coincidir; host de URL se añade a destinos autorizados, no implícitamente al scope. Tool availability de cada hoja enumera dependencias que usa, con herramientas opcionales marcadas como tales, sin ejecutarlas.
- [ ] **4. Implementar controles sensibles.** `ssh_attempts`: inputs target/port/account/wordlist/max_attempts/max_seconds; cuenta `[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}`, intentos 1–200, segundos 1–300, concurrencia 1; exigir wordlist regular local sin symlink, no abrir en preview. En ejecución copiar solo primeros N candidatos a archivo 600 privado; Hydra una cuenta con `-t 1 -f`, timeout min(max_seconds, presupuesto); sin imprimir candidatos. `exploit_lookup` usa texto validado como argumento único. SQLmap exige un .req regular explícito, esquema http/https y target; no admite directorio ni stdin desde 09. Preflight de ejecución valida autoridad real y contexto sin incluir contenido en mensajes, no muta original. Contexto adyacente conflictivo se rechaza porque la hoja lo prioriza al entorno. Replay requiere gate separado cuando el método no es GET/HEAD; enum y tabla requieren sus gates propios. Inyectar SQLMAP_SI/ENUMERAR/TABLA solo desde permisos y parámetros tipados, FILAS=50, MAX_SEG acotado; sin dump sin gate, enum no concede dump. No leer petición durante preview.
- [ ] **5. Implementar entorno mínimo.** Conservar PATH controlado, locale, HOME de ejecución privado y variables de plataforma imprescindibles; borrar BASH_ENV/ENV/PYTHONPATH/PYTHONHOME/LD_*/permisos SQLMAP y overrides SESSION/REPORT/ENUM heredados. OSINT recibe KEYS_FILE privado vacío y KEYS_HARVESTER_DIRS apuntando a directorio privado vacío, para no caer en rutas /etc o credenciales locales. No agregar lector/sincronizador de claves ni selección de APIs nuevas en 09; informar fuentes API omitidas, que siguen configurables en 01. Adjuntar dependencias de la matriz al catálogo y su test. Nikto rechaza comas literales en url antes de invocar su hoja, conservando la defensa de 03.
- [ ] **6. Repetir suite**, comprobar preservación de las confirmaciones de las hojas mediante mapping de dangerous.txt en fixture, no import de configuración real.
- [ ] **7. Commit** `feat: bind automation backends to explicit inputs and permissions`.

### Task 5: Informes sin atribución implícita y compatibilidad Python

**Files:** Create `FW/00_Config/lib/automation/reporting.py`, `FW/tests/test_automation_reports.py`; Modify `FW/09_Automation/python/report_generator.py`.

**Interfaces:** `report_command(step: Step, run_dir: Path, ctx: RuntimeContext) -> Command`; consumido mediante import diferido por compile_step para action=report. Extender shim con objetivo explícito y validación compartida; `main(argv: Sequence[str] | None = None) -> int`, entrypoint `sys.exit(main())`. El shim construye Plan de report y usa preflight/run_plan; no depende todavía de cli.py. Mantiene raw rc del motor solo en esta entrada histórica, frente al rc de ejecución agregado del orquestador.

- [ ] **1. Pruebas rojas** `test_report_requires_target_input`, `test_no_implicit_session_or_all_targets`, `test_report_engine_rc3`, `test_legacy_output_names`: stub de 11 exige `--objetivo`, `--scans`, `--salida`, `--tipo ambos`, `--cliente`, `--auditor`, ausencia de `--todos`/`--incluir-sin-objetivo`/`--abrir`. rc=3 no evaluable => run 1; shim conserva raw rc=3. Missing target => 2 sin leer sesión. No resumir éxito por existir report antiguo. `--output /dir/report.html` sigue indicando directorio `/dir` pero explica nombres `findings.json`, `informe_tecnico.*`, `informe_cliente.*`.

  ```python
  command = report_command(report_step, run_dir, ctx)
  self.assertIn('--objetivo', command.argv)
  self.assertNotIn('--todos', command.argv)
  self.assertIn('--scans', command.argv)
  ```
- [ ] **2. Ejecutar** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_reports -v`; esperar rojo por comportamiento heredado.
- [ ] **3. Implementar integración.** Motor 11 admite objetivo y filtro de atribución; no cambiar su código. Ejecutar desde 09 solo con directorio input explícito (estructura scans admitida por 11), objetivo/gate report_read y advertencia de históricos. Report de workflow escribe en `<run>/reports`; shim conserva `--input/--output`, añade `--target`, `--execute` y `--allow report:report_read` (sin esos últimos solo preview). Su destino explícito nunca sobreescribe informes existentes sin selección explícita de directorio nuevo; el permiso de destino externo es exclusivo del shim, no YAML ni otros perfiles. REPORT_PROFILE apunta a archivo privado vacío, cliente/auditor explícitos evitan datos locales; objetivo explícito evita fallback de sesión. No interpretar stdout como hallazgo. No fabricar `status: completed` con fases no ejecutadas.
- [ ] **4. Repetir suite** con motor stub y un test adicional del motor real copiado y configuración sintética; el stub no acredita reglas reales de atribución. Revisar pruebas heredadas de shim y migrarlas solo si cambió el contrato aprobado, sin relajar atribución.
- [ ] **5. Commit** `fix: make automation reports explicit and attributable`.

### Task 6: CLI, adaptadores históricos y menú 09 integrado

**Files:** Create `FW/00_Config/lib/automation/cli.py`, `FW/00_Config/lib/automation_menu.bash`, `FW/tests/test_automation_cli.py`; Modify `FW/09_Automation/python/{orchestrator,auto_audit}.py`, tres hojas Bash, `run_all_automation.sh`, `FW/cyber_framework.sh` (solo source y module_automation).

**Interfaces:** `cli.main(argv: Sequence[str] | None = None) -> int`, `cli.menu(ctx: RuntimeContext) -> int`; Bash `automation_menu()` invoca `run_all_automation.sh` sin target de sesión. Wrappers insertan el lib propio en sys.path antes de importar; Bash usa `exec python3 <orchestrator> ...`, sin eval ni array construido por split de texto.

- [ ] **1. Pruebas rojas** `test_menu_eof_is_inert`, `test_manager_dispatch_09`, `test_legacy_adapters_plan_only`, `test_cli_rejects_ambiguity`, `test_confirmation_is_not_stdin_yes`: desde cwd distinto, EOF/0 no crean run ni invocan backend; selector auto_audit desconocido =>2 no full; --phase junto a --full/workflow/action =>2. stdin `yes` nunca autoriza CLI. Árbol original completo de 09 listado sin ejecución por extensión. Un --execute válido propaga 0/1/2/130/143.

  ```python
  self.assertEqual(cli.main(['--target', '192.0.2.1', '--full', '--phase', 'scan']), 2)
  self.assertEqual(cli.main(['--target', '192.0.2.1', '--phase', 'post', '--execute']), 2)
  ```
- [ ] **2. Ejecutar** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_cli -v`; rojo por interfaz no integrada.
- [ ] **3. Implementar CLI.** Flags: selector exclusivo `--phase`, `--full`, `--workflow`, `--action`; defaults target sin selector = quick. `--menu` es modo exclusivo sin selector/ejecución: run_all sin argumentos lo utiliza para abrir menú; orchestrator sin argumentos solo ayuda. Entradas `--target`, `--url`, `--domain`, `--ports`, `--port`, `--request-file`, `--scheme`, `--account`, `--wordlist`, `--max-attempts`, `--max-seconds`, `--product`, `--database`, `--table`, `--report-input`, `--include-config`. Campos de acciones de YAML se tipan igual; flags que no aplican se rechazan. `--execute` nunca implica permiso; `--authorized-target <host>` repetible para cada host, `--allow <step_id>:<gate>` repetible para gates exactos. Rechazar grants huérfanos/desconocidos, no persistirlos. No almacenar tokens, passwords o bodies como flags. Sin flags ejecutar no crea archivos. `--help`/`--list`/`--check` no consultan datos. argparse no debe escapar con SystemExit desde main: errores de uso se traducen a return2 para conservar contrato de API.
- [ ] **4. Implementar adaptadores y menú.** `auto_audit.py <target> [recon|scan|enum|web]` sin fase selecciona full como preview; hojas Bash mantienen `<target>` y forward de flags separados. `auto_exploit.sh <target>` muestra catálogo avanzado; exige --action al ejecutar. Menú 1 disponibilidad, 2 guía, 3 quick, 4 full, 5 avanzadas, 6 workflow, 11 lista original, 0 volver. Primero mostrar plan; ejecutar solo tras confirmación de objetivo y cada gate. No reutilizar autorizaciones al volver. EOF durante cualquier prompt cancela sin ejecutar. Pausas/UI no se capturan como argumentos. No cambiar run_all_99 ni parsers genéricos.
- [ ] **5. Repetir suite**, navegación real del gestor copiado con config sintética y herramientas trampa en PATH; Bash -n con stderr vacío y AST de Python. Si import/env del gestor puede disparar fuera de 09, aislarlo con stubs de módulos existentes, no ejecutarlos como smoke test.
- [ ] **6. Commit** `feat: expose automation plans through compatible CLI and safe menu`.

### Task 7: Recolección PowerShell explícita y con errores visibles

**Files:** Modify `FW/09_Automation/powershell/auto_enum.ps1`; Create `FW/tests/test_automation_powershell.py` y `FW/tests/fixtures/automation/powershell_contract.ps1`.

**Interfaces:** Script `param([string]$OutputDirectory, [switch]$Execute)`; sin ambos solo ayuda/plan sin recolectar; destino padre explícito, run GUID creado tras validación. Resumen con estado/raw exit/reason de cinco bloques; códigos 0/1/2. No recibe objetivo remoto.

- [ ] **1. Pruebas rojas** `test_ps_no_implicit_collection`, `test_ps_five_blocks_and_paths`, `test_ps_failure_contract`: aserciones estáticas de params, Join-Path, ErrorAction Stop por cmdlet, LASTEXITCODE para netstat, nombres originales y salida no cero. Fixture PowerShell define mocks de las cinco fuentes y Out-File, inyecta fallo en cada bloque y asegura resumen con fallo, no éxito global.

  ```python
  self.assertIn('$OutputDirectory', source)
  self.assertIn('$Execute', source)
  for name in ('system_info.txt', 'local_users.txt', 'top_processes.txt', 'connections.txt', 'scheduled_tasks.txt'):
      self.assertIn(name, source)
  ```
- [ ] **2. Ejecutar** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_powershell -v`; rojo por ausencia del contrato. Detectar pwsh solo por PATH; si no existe, registrar SKIP de prueba dinámica.
- [ ] **3. Implementar bloque por fuente:** Get-ComputerInfo, Get-LocalUser, Get-Process top20 CPU, netstat -ano y Get-ScheduledTask; mantener sus nombres de archivo originales bajo run GUID, sin sobrescribir ni seguir destino symlink/reparse point. Validar destino antes de cualquier recolección. Capturar fallo sin convertirlo en archivo vacío válido, resumen final y exit1 si alguno falla.
- [ ] **4. Repetir suite.** Si pwsh existe, ejecutar únicamente script copiado con mocks aislados; nunca recolección real. Sin Windows no declarar compatibilidad aunque mocks pasen.
- [ ] **5. Commit** `fix: make PowerShell collection explicit and failure-aware`.

### Task 8: Contenedor por fuentes permitidas y sin privilegios implícitos

**Files:** Modify `FW/09_Automation/docker/{Dockerfile,docker-compose.yml}`; Create `FW/09_Automation/docker/Dockerfile.dockerignore`, `FW/tests/test_automation_docker.py`.

**Interfaces:** Compose context `../..` (framework), dockerfile `09_Automation/docker/Dockerfile`. Dockerfile-specific ignore: denegar todo y permitir directorios ancestros y nombres exactos de fuentes versionadas necesarias (no glob recursivo de extensiones), los dos YAML de workflows y documentación necesaria; config local, wordlists, `.session`, perfil report, claves, report.json/html, scans, logs y bytecode nunca en contexto. Se puede obtener la lista de nombres desde git ls-files de fuentes, sin abrir datos ni incluir ficheros de configuración versionados. Test enumera candidatos desde un árbol sintético, no desde datos reales.

- [ ] **1. Pruebas rojas** `test_compose_minimum_privileges`, `test_context_allowlist`, `test_nonroot_and_dependencies`: assert sin socket/host network/cap_add/privileged/bind de fuentes; usuario no root; entrypoint Bash inerte; patrones de ignore excluyen señuelos secretos incluso con sufijo .py/.sh dentro de loot/scans/credentials/analysis. Rutas context/dockerfile/ignore coherentes. Sin `COPY . .` de contexto sin filtro, pip del sistema ni Hydra duplicado. Detectar volúmenes/override que oculten el código o monten repo en default.

  ```python
  service = compose['services']['ctf-toolkit']
  self.assertNotIn('volumes', service)
  self.assertNotIn('cap_add', service)
  self.assertNotEqual(service.get('network_mode'), 'host')
  ```
- [ ] **2. Ejecutar** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_docker -v`; rojo por defaults heredados.
- [ ] **3. Implementar Docker/Compose.** Mantener Kali rolling y shell interactiva; paquetes apt Python y dependencias previas deduplicadas (`netcat-openbsd` en vez del virtual netcat, `python3-yaml/requests/bs4/scapy/shodan` en vez de pip global), usuario toolkit con home privado, `COPY --chown` de allowlist; sin apt/pip en runtime. Sin montajes predeterminados; datos nuevos en capa de contenedor y advertencia de persistencia. No prometer que todo backend está instalado. Documentar que BuildKit con Dockerfile-specific ignore es requisito y no usar builder antiguo que omita el filtro. Si hace falta ajustar lista apt, solo lectura documental, nada de build para esta tarea.
- [ ] **4. Repetir suite**, parser YAML seguro y chequeos estáticos; no `docker compose config`, build ni up sobre el checkout.
- [ ] **5. Commit** `fix: remove implicit Docker host access and private build inputs`.

### Task 9: Runner aislado, matriz de conservación y cierre verificable

**Files:** Create `FW/tests/run_automation.sh`, `FW/tests/test_automation_contract.py`, `FW/09_Automation/USE.md`, `docs/AUTOMATION-2026-11-13.md`; Modify `FW/09_Automation/README.md` y `AGENTS.md` solo con estado comprobado de 09.

**Interfaces:** `bash FW/tests/run_automation.sh` corre discovery `test_automation_*.py`, PYTHONDONTWRITEBYTECODE=1, rc real y diagnóstico; no usa tests/run_tests.sh directamente ni lee config real como guarda. Reporte registra fuentes, comandos, rc y límites, no objetivos reales.

- [ ] **1. Pruebas rojas** `test_no_legacy_success_or_shell_execution`, `test_complete_capability_matrix`, `test_docs_use_real_flags`, `test_suite_isolated`: todos los archivos/acciones originales aparecen en matriz, no quedan os.system/shell=True ni éxito incondicional; ejemplos usan opciones reales y separan permisos; suite falla si intenta leer config real o invocar backend fuera de copia. Ningún test usa mkdir/rm en scans real ni copia reportes generados existentes.

  ```python
  self.assertIn('post', use_doc)
  self.assertIn('--authorized-target', use_doc)
  self.assertIn('--allow', use_doc)
  self.assertIn('PYTHONDONTWRITEBYTECODE', runner_source)
  ```
- [ ] **2. Ejecutar** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_contract -v`; confirmar rojo antes de escribir documentación/runner.
- [ ] **3. Implementar runner y docs.** Ejemplos con 192.0.2.1/example.com, primero preview y luego flags de ejecución separados; explicar cambios incompatibles aprobados, gates, post guía, límites de procesos, compartición de salidas, logs sensibles, Docker no sandbox, PowerShell no probado en Windows e informes con históricos. Matriz de capacidades por entrada original y sus condiciones; no confundir selección de perfil con permiso.
- [ ] **4. Ejecutar** `bash CyberSecurity-Framework/tests/run_automation.sh` desde raíz del workspace de implementación y capturar stdout/stderr/rc en `/tmp/opencode/automation-<id>/`; Bash -n de fuentes modificadas con stderr vacío y AST de Python. Repetir casos de cancelación 20 veces. Publicar conteos reales, no predichos por este plan.
- [ ] **5. Regresiones seguras.** En clon/worktree temporal limpio con fuentes finales y config sintética ejecutar suites afectadas: config menu, scanners menu, enumeration, exploitation, reports, smoke/e2e; inspeccionar primero fixtures y guardas de cada suite. Si pueden tocar configuración/evidencias fuera del temporal, ajustar únicamente aislamiento del harness o marcar bloqueado con motivo; no ejecutar flujo 99. No cambiar tests antiguos para ocultar fallos. SSTI heredado se reporta con su resultado observado, no se atribuye sin investigar.
- [ ] **6. Revisión independiente** de especificación/código y correcciones con pruebas rojas/verdes; evidencias y ledger conservados. Revisar explícitamente Review Focus, ventanas de spawn/cancelación y copia Docker. Si aparece desviación de alcance, parar para aprobación.
- [ ] **7. Commit** `test: verify and document integral automation contracts`; actualizar AGENTS solo tras comprobación. Sin push. Cierre distingue implementación revisada de validación operacional pendiente y de suites heredadas no verdes.

## Auto-revisión del plan y handoff

- [x] Cobertura del diseño: secciones 1–4 en restricciones/matriz; 5 en Tasks 1,2,4,6; 6 en 4,6; 7–8 en 3,5; 9 en 7,8; 10 en 1–9; 11 decisiones fijadas en contratos. No se delegan backends a un TBD.
- [x] APIs y tipos compartidos nombrados; compilador entrega tupla de Command, runner consume callable con Step/run_dir; report usa el mismo Command; cada paso de pruebas tiene comando y resultado verificable.
- [x] Los cinco Review Focus tienen pruebas en su tarea propietaria. No implementar antes de revisión del usuario y elección de método.
- [x] Auto-revisión, no revisión de código: este plan no acredita éxito de pruebas futuras.
- [ ] Usuario revisa plan y elige ejecución por subagentes o nativa.
- [ ] Cargar skill de ejecución elegida y using-git-worktrees antes de producto.

Recomendación: ejecución por subagentes, tarea a tarea con revisión fresca. Las fronteras de catálogo, permisos, supervisor y adaptadores son comprobables por separado y un error puede ejecutar acciones contra un destino distinto o dejar procesos activos. No es una autorización para paralelizar cambios de interfaces dependientes.
