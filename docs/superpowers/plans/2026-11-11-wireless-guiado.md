# Wireless guiado (07) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mejorar las diez entradas originales de 07, conservar sus capacidades y ofrecer el menú aprobado con evidencia fiable, restauración de adaptador e informes atribuibles.

**Architecture:** Bash mantiene las CLI y los comandos de herramientas; bibliotecas exclusivas de 07 centralizan interfaz, procesos y captura. Python estándar valida manifiestos, clasifica evidencia y selecciona el último intento. La integración con informes añade identidad inalámbrica tipada sin pasar MAC por normalización IP ni alterar las fuentes existentes.

**Tech Stack:** Bash en Kali, Python 3 stdlib/unittest, herramientas inalámbricas ya usadas por el módulo; pruebas con PATH cerrado y fuentes copiadas a temporal.

**Spec:** `docs/superpowers/specs/2026-11-10-wireless-guiado-design.md` (aprobado 2026-11-11).

## Global Constraints

- «Mejorar sin quitar ninguna funcionalidad»: conservar nueve hojas y `run_all_wireless.sh`, sus CLI válidas, herramientas, diccionarios y controles existentes.
- «No añadir topes de intentos, tasas, diccionarios reducidos, límites de duración ni otras restricciones nuevas».
- «No instalar dependencias ni cambiar privilegios automáticamente»; conservar las invocaciones privilegiadas existentes, sin instalaciones ni escalada añadida.
- Menú aprobado: opciones 1–11 y 0; lista completa en 11; guía/captura/verificación en el submenú de handshake.
- Aviso: «Usar exclusivamente en objetivos autorizados y en un entorno controlado. Estas operaciones pueden modificar el estado del adaptador, capturar tráfico o interrumpir conexiones».
- Manifiestos solo en `<repo>/scans/wireless/wireless_<hash>_<id>/`; binarios nuevos en `CyberSecurity-Framework/07_Wireless/captures/runs/<run_id>/`; directorios 700 y archivos 600 desde creación.
- No revelar claves, paquetes ni argumentos sensibles en metadata, gestor, visor o informes; no escribir en `scope.yaml`, `targets.txt`, `.session` ni evidencia previa.
- «Ninguna herramienta real de radio, sudo, interfaz, historial o servicio se ejecuta en estas pruebas»; no probar el flujo 99 ni ejecutar una auditoría real.
- Suites antiguas exclusivamente en clon limpio, sin evidencia, sesión, claves o configuración real; usar `/tmp/opencode` para temporales.
- No push, limpieza masiva, `git add -A` ni descarte de trabajo ajeno. Commits locales de tareas solo con las rutas explícitas enumeradas, tras revisión de diff y pruebas.

## Review Focus

1. Adaptador renombrado/retirado o fallo a mitad de transición: no tocar otro dispositivo ni anunciar recuperación falsa (Task 2).
2. SIGINT/SIGTERM, hijo persistente y dos operaciones sobre el mismo PHY: detener únicamente procesos propios y no perder el bloqueo durante restauración (Task 2/5).
3. Captura multirred, truncada o diccionario ausente: selección explícita, diagnóstico exacto y ningún falso handshake/clave (Task 4).
4. SSID con escapes, rutas con espacios, symlinks o secretos en stdout: datos inertes, evidencia confinada y ninguna fuga pública (Task 1/4/6).
5. Manifest posterior corrupto o incompleto tras un éxito y MAC parecida a objetivo legado: no revivir historial ni mezclar informes de clientes (Task 1/7).

## Preparación y estructura

- Antes de implementar, usar `using-git-worktrees` para aislamiento. El checkout actual tiene cambios de 06 y de informes sin commit: inventariarlos, no asumir que 06 está completo ni incluirlos en commits de 07. Si el worktree no contiene esas fuentes, acordar cómo trasladar solo la base necesaria sin descartar nada.
- Leer AGENTS.md y los documentos de rutas/limpieza que referencia; no copiar evidencia/configuración al entorno de pruebas.
- Nombres de archivos de producción nuevos:
  - `00_Config/lib/wireless_evidence.py`: esquema, identidad, clasificación, integridad, último intento y visor.
  - `00_Config/lib/wireless_runtime.bash`: run/capture/publish/finish y procesos propios.
  - `00_Config/lib/wireless_interface.bash`: inspección, exclusión por adaptador, transiciones y restauración.
  - `00_Config/lib/wireless_menu.bash`: navegación y contexto volátil, no una nueva sesión en disco.
  - `07_Wireless/show_results.sh`: visor CLI de solo lectura.
  - `11_Reports/lib/parsers/wireless.py`: traducción de evidencia validada a `ParseResult`.
- `tests/wireless_fixture.py` construye fuente/config/HOME/PATH sintéticos; solo enlaza utilidades de archivos inocuas. `sudo`, `ip`, `iw`, herramientas WiFi/BT y procesos persistentes son stubs, nunca fallback al sistema.
- Todos los comandos unittest de este plan se ejecutan desde `CyberSecurity-Framework`, con `PYTHONDONTWRITEBYTECODE=1`. El timeout de un test limita su stub, no introduce límites a las operaciones de producto.

---

### Task 1: Identidad y evidencia exclusiva de 07

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/wireless_evidence.py`
- Create: `CyberSecurity-Framework/00_Config/lib/wireless_runtime.bash`
- Create: `CyberSecurity-Framework/tests/wireless_fixture.py`
- Create: `CyberSecurity-Framework/tests/test_wireless_runtime.py`

**Interfaces:**
- `canonical_target(kind: str, value: str) -> str`: MAC en minúsculas con dos puntos; SHA-256 de 64 hex; tipos restantes con identificador local explícito, no IP de sesión.
- `read_run(path: Path, *, verify_artifacts: bool = True) -> dict`, `classify(kind: str, output: str, error: str, rc: int) -> dict`, `latest(root: Path, filters: dict) -> list[dict]`; inválidos levantan ValueError y no se convierten en éxito.
- `wireless_init TOOL OPERATION TARGET_TYPE TARGET_ID [INTERFACE] [CONTROLLER] [BSSID]` deja `WIRELESS_RUN_DIR`, `WIRELESS_CAPTURE_DIR`; `wireless_capture NAME CMD [ARGS...]` deja `WIRELESS_RC` y devuelve rc real; `wireless_publish NAME KIND`; `wireless_finish` devuelve 0 solo para conclusión completa sin fallo operativo/restauración.
- Overrides de pruebas `WIRELESS_SCANS_ROOT`, `WIRELESS_CAPTURES_ROOT`, `WIRELESS_LOCK_ROOT`; por defecto resolver desde `scans_root()` y ubicación del módulo.
- Manifest/sidecars version 1, módulo `07`, campos y vocabulario del spec. Python CLI interna `init|step|publish|finish|list|validate`; no almacenar argv completos.

- [ ] **Step 1: Escribir pruebas rojas.** Inicialización única/privada, identidad canónica, null offline, captura fiel de stdout/stderr/rc/señal, herramienta ausente, cero pasos, kind desconocido, echo no probatorio, operación sin hallazgos, denegación, metadata sin secretos y escritura atómica. Validar version/module/tipos/steps/sidecars/hashes y nombres de paso fijos sin traversal. Cubrir symlink de salida y ficheros existentes sin alterar entradas ajenas. En la fixture, este contrato debe cumplirse:

  ```python
  assert run['module'] == '07'
  assert run['target_id'] == '02:00:00:00:00:01'
  assert run['complete'] is False
  assert 'CLAVE-SINTETICA' not in public_output
  ```

- [ ] **Step 2: Verificar rojo.** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_wireless_runtime.py' -v`; debe fallar por bibliotecas ausentes/contrato no implementado, no por una herramienta real.
- [ ] **Step 3: Implementar las interfaces.** Usar mktemp/atomic replace, nombres seguros, umask privada, timestamps UTC de inicio y resumen estructurado separado del cuerpo. Hash de destino determinista + id aleatorio; distinguir rc de pasos y resultado de finish. `classify` solo reconoce kinds definidos por hojas de Tasks 3–5 con fixtures probatorios, no patrones genéricos como «✅» o «password». Los indicadores de evidencia son distintos del estado operativo y cobertura.
- [ ] **Step 4: Verificar verde.** Repetir unittest; `bash -n 00_Config/lib/wireless_runtime.bash` con stderr vacío; validar AST Python sin generar bytecode. Esperado: código 0, permisos 700/600 y ningún cambio fuera del temporal.
- [ ] **Step 5: Commit explícito.** Solo los cuatro archivos de Task 1, después de inspeccionar diff: `feat(07): add private typed wireless evidence runtime`.

### Task 2: Adaptadores, bloqueos, procesos y restauración

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/wireless_interface.bash`
- Modify: `CyberSecurity-Framework/00_Config/lib/wireless_runtime.bash`
- Modify: `CyberSecurity-Framework/00_Config/lib/wireless_evidence.py`
- Modify: `CyberSecurity-Framework/tests/wireless_fixture.py`
- Create: `CyberSecurity-Framework/tests/test_wireless_processes.py`

**Interfaces:**
- `wireless_inspect INTERFACE` imprime JSON con identidad local (ifindex/PHY), modo, up/down, frecuencia/canal y capacidades observables; sin cambios ni transmisión.
- `wireless_begin_interface INTERFACE temporary|persistent`: toma bloqueo del PHY, guarda estado privado antes de cambiarlo y registra dueño de restauración.
- `wireless_set_mode MODE`, `wireless_set_channel CHANNEL`, `wireless_restore`: usan identidad inspeccionada, rc real y verificación posterior; restore idempotente no libera bloqueo hasta acabar.
- `wireless_capture` puede ejecutar hijos en grupo propio y espera al hijo; `wireless_stop_owned` termina solo ese grupo. El runtime conserva traps anteriores y registra `cancelled`/señal y `restore` por separado.
- Dueño de flujo puede prestar bloqueo a hijos propios mediante token privado heredado; el hijo valida dueño, PHY y recurso, no restaura/libera el bloqueo prestado. El proceso padre hace una única restauración final.

- [ ] **Step 1: Escribir pruebas rojas.** Simular iw/ip/rfkill, down→fallo→recuperación, modo persistente exitoso que no se deshace, temporal que sí vuelve al estado previo, canal desconocido sin inventarlo, interfaz retirada/renombrada y fallo de restore. Dos interfaces del mismo PHY compiten por el mismo bloqueo; heredero propio puede usarlo, proceso ajeno no. SIGINT/SIGTERM esperan hijos propios, preservan proceso centinela ajeno y registran interrupción. Repetir cleanup no duplica operaciones:

  ```python
  assert final_state == initial_observed_state
  assert unrelated_process.poll() is None
  assert result['restore']['estado'] == 'fallido'  # caso de recuperación fallida
  ```

- [ ] **Step 2: Verificar rojo.** Unittest discover con patrón `test_wireless_processes.py`; FAIL por interfaces ausentes, sin ejecutar sudo/ip/iw reales.
- [ ] **Step 3: Implementar las interfaces.** Validación de capacidades/canales/regulación sin modificar dominio regulatorio, servicios ni rfkill. Bloqueo local con propietario verificable y recuperación de bloqueo huérfano solo tras comprobar que su dueño ya no existe; los snapshots tras apagado se muestran para recuperación manual, no se aplican al abrir menú. No reinterpretar un rc interrumpido como éxito aunque exista una captura parcial.
- [ ] **Step 4: Verificar verde.** Repetir tests de Tasks 1–2; inspeccionar que el centinela ajeno sigue vivo, los stubs propios terminan y el bloqueo no queda activo. `bash -n` de ambas bibliotecas con stderr vacío.
- [ ] **Step 5: Commit explícito.** Solo los cinco archivos enumerados en Task 2: `feat(07): restore adapter state and manage owned processes`.

### Task 3: Escaneo WiFi, monitor, canales y desautenticación existentes

**Files:**
- Modify: `CyberSecurity-Framework/07_Wireless/wifi/wifi_scan.sh`
- Modify: `CyberSecurity-Framework/07_Wireless/wifi/wifi_monitor.sh`
- Modify: `CyberSecurity-Framework/07_Wireless/wifi/wifi_deauth.sh`
- Modify: `CyberSecurity-Framework/07_Wireless/scripts/interface_manager.sh`
- Modify: `CyberSecurity-Framework/07_Wireless/scripts/channel_hopper.sh`
- Create: `CyberSecurity-Framework/tests/test_wireless_leaves.py`
- Modify: `CyberSecurity-Framework/00_Config/lib/wireless_evidence.py`

**Interfaces:**
- Mantener los posicionales históricos de las cinco hojas y `list|monitor|managed`; `interface_manager list` es inspección local.
- Kinds: `wifi_inventory`, `interface_mode`, `channel_change`, `deauth_transmission`. Escaneo/monitor/transmisión son inventario u operación, no vulnerabilidad ni desconexión probada.
- `wifi_scan` usa modo compatible con iw scan y restaura cambios temporales; órdenes explícitas monitor/managed son persistentes tras éxito.

- [ ] **Step 1: Escribir pruebas rojas.** Invocación desde cwd externo, argumentos exactos de herramientas simuladas, scan inicial managed/monitor, fallo de preparación que impide operación dependiente, inventario vacío válido frente a fallo de iw y monitor anunciado solo tras comprobación. Canales derivados del adaptador, intervalo de salto histórico, cancelación limpia. Desautenticación conserva operación/argumentos existentes sin añadir automatismos. Prueba crítica:

  ```python
  assert scan_mode_seen_by_stub == 'managed'
  assert deauth_stub_calls == []  # falla preparar canal
  assert transmission_result['estado'] != 'CONFIRMADO'
  ```

- [ ] **Step 2: Verificar rojo.** Discover `test_wireless_leaves.py`; FAIL por rutas/rc/clasificación anteriores, nunca llamar herramientas reales.
- [ ] **Step 3: Integrar hojas.** Autolocalizar, delegar transición y evidencia, conservar salida privada completa antes de filtrar y rc reales. Identificar operaciones con target tipado; no sobrescribir logs por fecha ni alterar capturas históricas. Registrar cambios de interfaz sin tratar nombres como objetivo IP.
- [ ] **Step 4: Verificar verde.** Tasks 1–3, sintaxis Bash con stderr de las cinco hojas y `git diff --check`. Esperado: todos los tests en 0; el listado original conserva sus cinco entradas.
- [ ] **Step 5: Commit explícito.** Los siete archivos de Task 3: `fix(07): preserve wifi operations with verified state and evidence`.

### Task 4: Guía, captura/verificación opcional y análisis offline

**Files:**
- Modify: `CyberSecurity-Framework/07_Wireless/wifi/wifi_handshake.sh`
- Modify: `CyberSecurity-Framework/07_Wireless/wifi/wifi_crack.sh`
- Modify: `CyberSecurity-Framework/00_Config/lib/wireless_evidence.py`
- Modify: `CyberSecurity-Framework/tests/test_wireless_leaves.py`
- Create: `CyberSecurity-Framework/tests/test_wireless_offline.py`

**Interfaces:**
- `wifi_handshake.sh <INTERFACE>` guía sin captura; `<INTERFACE> --capture <BSSID> <CHANNEL>` captura explícita; `--verify <CAPTURE> [BSSID]` verificación offline.
- `wifi_crack.sh <HANDSHAKE_FILE> [WORDLIST] [--bssid BSSID]` conserva dos posicionales y diccionario por defecto al omitirlo; sin fallback ante diccionario explícito inválido.
- Kinds `handshake_capture`, `handshake_validation`, `dictionary_analysis`; indicadores `handshake_validated`, `key_recovered`, cobertura, motivo estructurado. Archivo existente o texto de guía no confirma nada.
- BSSID múltiple requiere elección del menú o diagnóstico CLI (no elección silenciosa); artefactos referenciados por ruta confinada + SHA-256. No contraseña en argv/metadata/salidas públicas.

- [ ] **Step 1: Escribir pruebas rojas.** Guía sin ejecutar airodump, capture sin deauth automático, cancelación con parcial privado, verificación estructural positiva y negativa por BSSID. Captura truncada/multirred/formato desconocido, diccionario ausente y ruta con espacios. Stub aircrack valida que el archivo es posicional y `-b` recibe solo BSSID; recuperación inequívoca/diccionario agotado/fallo operativo distintos. Inyectar clave sintética en stdout crudo y comprobar su ausencia en metadata, visor y resumen:

  ```python
  assert capture_path in aircrack_args
  assert bssid == aircrack_args[aircrack_args.index('-b') + 1]
  assert key_marker not in public_output
  assert partial_run['cancelled'] is True
  ```

- [ ] **Step 2: Verificar rojo.** Discover `test_wireless_offline.py`; FAIL por modos inexistentes y uso incorrecto de `-b`.
- [ ] **Step 3: Implementar CLI y análisis probatorio.** Mantener interactividad de herramientas donde proceda sin retransmitir salida sensible; el menú recibe solo progreso/resumen seguro. Fixtures de versiones de herramientas deben probar cada formato reconocido; desconocido→no determinado. Clave recuperada no dispara conexión ni autenticación posterior. Captura parcial verificable produce un run offline separado, no reescritura del run interrumpido.
- [ ] **Step 4: Verificar verde.** Repetir Tasks 1–4, sintaxis de dos hojas y clasificación; confirmar hash/modo de la captura y diccionario de entrada intactos, y que no se ha recortado el diccionario ni añadido límites.
- [ ] **Step 5: Commit explícito.** Los cinco archivos de Task 4: `feat(07): add optional handshake capture and fix offline analysis`.

### Task 5: Bluetooth por backend/controlador y ciclo de descubrimiento

**Files:**
- Modify: `CyberSecurity-Framework/07_Wireless/bluetooth/bt_scan.sh`
- Modify: `CyberSecurity-Framework/07_Wireless/bluetooth/bt_discover.sh`
- Modify: `CyberSecurity-Framework/00_Config/lib/wireless_evidence.py`
- Modify: `CyberSecurity-Framework/00_Config/lib/wireless_interface.bash`
- Modify: `CyberSecurity-Framework/tests/test_wireless_processes.py`
- Create: `CyberSecurity-Framework/tests/test_wireless_bluetooth.py`

**Interfaces:**
- CLI históricas `bt_scan.sh`, `bt_discover.sh <MAC>`; añadir `--controller HCI` opcional a ambas sin cambiar el primer posicional MAC.
- Scan sin controlador explícito usa el predeterminado observable y lo registra; menú pide elegir si hay varios.
- Kinds `bluetooth_inventory`, `bluetooth_info`, `bluetooth_sdp`, `bluetooth_gatt`; estados/rc por backend y cobertura diferenciada Classic/LE.

- [ ] **Step 1: Escribir pruebas rojas.** Ausencia de hcitool con bluetoothctl disponible y viceversa, ausencia de todos los backends, permisos/rfkill, varias controladoras, MAC inválida, dirección aleatoria sin fusión por nombre y consulta SDP/GATT parcial. En sesión bluetoothctl propia, salida/cancelación termina solo el descubrimiento iniciado por ese run; si ya estaba activo, no envía scan off. Asersiones principales:

  ```python
  assert run['controller'] == 'hci1'
  assert run['steps'][0]['rc'] == 7  # fallo simulado de un backend
  assert 'scan off' not in external_discovery_session_commands
  ```

- [ ] **Step 2: Verificar rojo.** Discover `test_wireless_bluetooth.py` y tests nuevos de procesos; FAIL por pérdida de rc/cobertura/controlador.
- [ ] **Step 3: Integrar backends.** Conservar hcitool/info, bluetoothctl, SDP y características GATT. Capturar resultados completos privadamente sin head como terminador. Sesión/controlador propios y gestión de estado previo; dependencia ausente es paso no disponible, no motivo para eliminar otros métodos. Cobertura parcial explícita; sin controlador/backends utilizables, fallo operativo.
- [ ] **Step 4: Verificar verde.** Tasks 1–5, comprobación de hijos/centinelas y sintaxis de las dos hojas. Ninguna sesión externa queda detenida por tests.
- [ ] **Step 5: Commit explícito.** Los seis archivos de Task 5: `fix(07): retain bluetooth backends with attributable coverage`.

### Task 6: Menú aprobado, visor y flujo existente

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/wireless_menu.bash`
- Create: `CyberSecurity-Framework/07_Wireless/show_results.sh`
- Modify: `CyberSecurity-Framework/07_Wireless/run_all_wireless.sh`
- Modify: `CyberSecurity-Framework/cyber_framework.sh`
- Modify: `CyberSecurity-Framework/00_Config/lib/wireless_evidence.py`
- Create: `CyberSecurity-Framework/tests/test_wireless_menu.py`

**Interfaces:**
- `wireless_menu` sustituye solo la llamada genérica de `module_wireless`; reutiliza `execute_script` y confirmaciones existentes.
- Contexto volátil WiFi/BSSID/controlador/captura; no escribir sesión global ni scope. Pasar argv preparados sin eval ni desdoblamiento de rutas.
- `show_results.sh [--target TYPE:ID] [--interface IFACE] [--operation OP]`: filtra y muestra solo resumen validado; carpeta vacía e inválidos son diagnósticos, no crashes.
- `run_all_wireless.sh <INTERFACE>` conserva las tres etapas WiFi scan→monitor temporal→BT, con conteo y rc final. El dueño de restauración es el flujo, no cada hijo.

- [ ] **Step 1: Escribir pruebas rojas.** Las once opciones coinciden con spec; 11 muestra las diez entradas originales además del nuevo visor. Categorías no ejecutan todas las hojas; submenú handshake conserva guía/captura/verificación. Entrar/EOF/0/cancelar no ejecuta; opción 1 solo inspección sin transmisión/cambios. Revisar escapes terminal de SSID, rutas con espacios y no imprimir secretos en el gestor. Run_all desde cwd externo: éxito, dependencia ausente, fallo de scan que omite monitor, BT independiente, restauración tras fallo BT, conteos reales y stderr privado.

  ```python
  assert tool_transmissions == []  # entrar y comprobar herramientas
  assert '11. Lista completa de scripts' in menu_output
  assert run_all_result.returncode == 1  # falta hardware requerido
  assert final_adapter_state == initial_adapter_state
  ```

- [ ] **Step 2: Verificar rojo.** Discover `test_wireless_menu.py`; FAIL por menú/visor nuevos y run_all heredado, en gestor copiado a temporal.
- [ ] **Step 3: Implementar navegación, visor y flujo.** Mantener opciones visibles con explicación de dependencias ausentes; corregir entrada inválida en contexto. Renderizar campos no confiables como texto seguro. Visor agrupa por clave de último intento y mantiene historial separado. Corrupto no atribuible bloquea éxito actual de su conjunto potencial (misma raíz wireless; no fuentes 03–06), explicando que exige revisar evidencia. No introducir deauth/craqueo automático en cadena que antes no lo tenía; sus opciones 5/6 permanecen operativas.
- [ ] **Step 4: Verificar verde.** Tests de Tasks 1–6; `bash -n` de gestor/biblioteca/visor/run_all con stderr vacío; inventario y diff. No afirmar escaneo ni handshake real por resultados de stubs.
- [ ] **Step 5: Commit explícito.** Solo los seis archivos de Task 6: `feat(07): integrate approved guided menu and reliable run flow`.

### Task 7: Informes inalámbricos tipados sin regresión de atribución

**Files:**
- Create: `CyberSecurity-Framework/11_Reports/lib/parsers/wireless.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/sources.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/attribution.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/engine.py`
- Modify: `CyberSecurity-Framework/11_Reports/lib/catalog.py`
- Modify: `CyberSecurity-Framework/11_Reports/report_engine.py`
- Create: `CyberSecurity-Framework/tests/test_wireless_reports.py`

**Interfaces:**
- `wireless_target(raw: str) -> tuple[str, str]` y `wireless_belongs_to(activo: str, selector: str) -> bool` en attribution; prefijos completos `wifi_bssid:`, `bluetooth_mac:`, `capture_sha256:`, `local_interface:`, `discovery:`. No modificar `normalize_host` para interpretar MAC.
- Añadir `wireless_target: str | None = None` como parámetro keyword-only de `collect`, conservando los cinco argumentos existentes; report CLI `--wireless-target TYPE:ID` excluye `--objetivo` explícito y desactiva fallback a IP de sesión. `--todos` incluye fuentes con identidad propia; no asociación IP↔MAC implícita ni API de asociación nueva en este alcance.
- `wireless.parse(path, repo_root) -> ParseResult` reutiliza validación de evidencia de Task 1 por carga explícita aislada; no importar el paquete `lib` del gestor como si fuera el `lib` de informes.
- Reglas `wireless.inventario`, `wireless.handshake`, `wireless.key_recovered`, `wireless.ejecutado`, `wireless.denegado`. Severidad info salvo key_recovered=media, confianza confirmado solo con prueba; texto contextual, no gravedad universal.

- [ ] **Step 1: Escribir pruebas rojas.** Mezclar fuentes 03–06 y 07 sintéticas con dos MAC/operaciones/controladores y dos capturas; selector exacto y --todos conservan identidad. Informe por IP no incluye WiFi cercano, incluso con sesión activa e incluir-sin-objetivo. Parser rechaza version/module/complete/steps/rc/sidecars/hashes inválidos; latest por inicio, incluyendo fallido/incompleto, y manifest corrupto no revive histórico. JSON→render roundtrip conserva identidad sin cambios de model innecesarios. No filtrar por fecha de finalización tardía:

  ```python
  assert all(f.activo.startswith('wifi_bssid:') for f in wifi_result.findings)
  assert not any(f.rule.startswith('wireless.') for f in ip_result.findings)
  assert corrupted_latest_result.findings == []
  assert key_marker not in generated_json_and_reports
  ```

- [ ] **Step 2: Verificar rojo.** Discover `test_wireless_reports.py`; FAIL por selector/parser ausente, no por datos reales.
- [ ] **Step 3: Implementar integración mínima.** Descubrir solo manifiestos canónicos y excluir sus logs del parser genérico para que no se atribuyan por nombre. Añadir rama tipada también para activos, objetivos e incidencias (no solo findings). `Source` puede añadir campos opcionales tipados sin romper construcción posicional existente. Conservar selección/semántica de fuentes 03–06. Paths de salida del selector son seguros y separados de informes IP. Render usa identidad textual tipada existente; si requiere ajuste de render, primero añadir prueba y limitarlo a identidad, sin rediseñarlo.
- [ ] **Step 4: Verificar verde.** Discover nuevo y `bash tests/run_reports.sh` exclusivamente en clon temporal limpio de la fuente bajo prueba, sin scope/sesión/credenciales/evidencia reales. Repetir selectores, mutual exclusion, --desde-json y fallback legado; guardar logs y códigos finales.
- [ ] **Step 5: Commit explícito.** Solo los siete archivos de Task 7; cualquier ajuste de render demostrado se enumera y revisa aparte: `feat(reports): add typed wireless evidence without host attribution leaks`.

### Task 8: Verificador, suite con guardas, documentación y entrega

**Files:**
- Create: `CyberSecurity-Framework/tests/verify_wireless_real.py`
- Create: `CyberSecurity-Framework/tests/test_wireless_verify.py`
- Create: `CyberSecurity-Framework/tests/run_wireless.sh`
- Modify: `CyberSecurity-Framework/07_Wireless/README.md`
- Modify: `CyberSecurity-Framework/07_Wireless/USE.md`
- Modify: `docs/MANUAL-GESTOR.md`
- Create: `docs/WIRELESS-GUIADO-2026-11-11.md`

**Interfaces:**
- `verify_wireless_real.py MANIFEST --case NAME`: solo lectura, códigos 0 coincide / 1 discrepancia / 2 falta evidencia. Manifest `version=1`, `cases` con name, capability, evidence, expected_state, actual_state, rc, checks; checks path/contains/not_contains/sha256 relativos al manifest. Validar evidencia mediante Task 1, sin fabricar conclusión a partir de rc=0.
- `bash tests/run_wireless.sh` descubre `test_wireless_*.py`, captura exit code real y verifica guardas de configuración/sesión/fuentes/evidencia previa (hash+modo+conjunto de rutas). No seguir symlinks ajenos durante snapshots.

- [ ] **Step 1: Escribir pruebas rojas.** Caso satisfecho, discrepancia de rc/estado/identidad/hash, casos duplicados/desconocidos, schema inválido, evidencia ausente, path relativo desde cwd externo y snapshot antes/después del verificador sin escrituras. Suite detecta cambios y ficheros nuevos indebidos, no toma un pipeline tail como código de prueba:

  ```python
  assert verifier_result.returncode == 2  # datos insuficientes
  assert before == after
  assert failing_child_suite_result.returncode != 0
  ```

- [ ] **Step 2: Verificar rojo.** Discover `test_wireless_verify.py`; FAIL por verificador inexistente. Pruebas de runner se hacen sobre copias sintéticas, nunca mutando evidencia real para probar guardas.
- [ ] **Step 3: Implementar verificador/suite y guías.** Documentar menú exacto, todas las CLI, identificación BT/WiFi/offline, cobertura, diccionarios, estado temporal/persistente, señales/apagado, restauración fallida y privacidad. Distinguir versión de herramienta respaldada por fixture de versión comprobada con hardware. Validar que `.gitignore` ya cubre scans/captures y generated; no modificarlo si no hay ruta nueva fuera de esos árboles. Registrar pruebas realmente ejecutadas y validación física pendiente.
- [ ] **Step 4: Verificar verde y regresión aislada.** Suite wireless y tests reportes en copia limpia; sintaxis de todos los Bash de 07/bibliotecas nuevas capturando stderr y AST de Python nuevo/modificado sin bytecode. Regresión de suites existentes solo en clon limpio con datos sintéticos; si reaparece un fallo previo, conservar logs y diagnosticar, no debilitar asertos. Inventario: diez entradas originales + visor; guardas intactas, ningún secreto o objetivo real en diff, `git diff --check` sin errores. Registrar cada suite y rc, sin decir «todas pasan» con solo sintaxis.
- [ ] **Step 5: Commit explícito.** Solo siete archivos de Task 8: `docs(07): add guarded verification suite and wireless usage guide`.

## Checklist de autorrevisión del plan

- [x] Spec completo: menú/compatibilidad (Task 6), evidencia (1), interfaz/restauración/procesos (2), WiFi/canales/deauth (3), handshake/offline (4), Bluetooth (5), informes (7), verificador/guías/pruebas (8).
- [x] Interfaces compartidas y ubicaciones canónicas consistentes; no reutilizar IP de sesión como target wireless.
- [x] Cinco riesgos de Review Focus asignados a pruebas concretas; fallos, interrupciones y privacidad no dependen de pruebas de hardware.
- [x] Cada tarea tiene rojo→implementación→verde→commit explícito; ningún paso autoriza operaciones reales.
- [x] Cambios previos de 06 e informes son base ajena pendiente, no entregables ni evidencia de calidad de 07.

## Entrega y decisión de ejecución

Este documento es un plan, no una implementación. Tras revisión del usuario,
elegir ejecución nativa o por subagentes; no implementar antes de esa decisión.
La revisión final debe contrastar capacidades conservadas, pruebas y diff de la
rama completa. Nunca hacer push. Validación operacional física queda pendiente
de hardware y autorización explícita, fuera del smoke test.
