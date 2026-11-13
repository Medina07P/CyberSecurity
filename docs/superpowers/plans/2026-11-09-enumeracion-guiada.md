# Enumeración guiada sin pérdida de funcionalidad — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Corregir 04_Enumeration y mejorar su menú conservando las 16 entradas y todas sus operaciones.

**Architecture:** Hojas Bash y CLI existentes, con bibliotecas compartidas de ejecución/evidencia y sondas HTTP. Menú específico de 04 integrado en el gestor sin cambiar el menú 03. Reportes y visor leen resultados atribuibles con estados explícitos, manteniendo lectura de formatos históricos.

**Tech Stack:** Bash, Python 3 estándar, unittest, herramientas simuladas en PATH cerrado.

**Spec:** `docs/superpowers/specs/2026-11-09-enumeracion-guiada-design.md` (aprobado).

## Global Constraints

- No quitar, desactivar permanentemente, sustituir por un aviso ni dejar inaccesible ninguna capacidad existente.
- Mantener disponibles los 16 scripts y sus contratos CLI actuales.
- No eliminar métodos HTTP, pruebas de acceso anónimo o credenciales por defecto, enumeración de usuarios, fuzzing, consultas Redis ni generadores.
- Mantener los cambios de 03 y las modificaciones previas de scope.yaml y permisos de api_keys.py; no hacer commits, push ni instalaciones.
- Ninguna ejecución contra objetivos reales. Tests de herramientas simuladas en PATH cerrado y configuración sintética, sin copiar claves ni evidencias.
- Las suites antiguas solo en clon temporal limpio con los cambios de fuentes aplicados.
- Bash/Python existentes, bibliotecas autolocalizadas, stdout puro para valores, interfaz en español, fuentes LF y salidas ignoradas por git.

## Review Focus

- Una salida de error no vacía, rc=0 ambiguo o autenticación rechazada no prueba acceso; cubrir cada protocolo en Task 2.
- HOME, .netrc, opciones de cliente y variables de credenciales no pueden cambiar silenciosamente la identidad probada; fixtures contaminadas en Task 2.
- URL con ruta/query, redirección o catch-all no amplía objetivos ni demuestra endpoints/métodos; Task 3.
- Fallo o timeout actual con evidencia previa debe dejarla intacta y no reutilizarla como éxito; Tasks 1, 4 y 5.
- Cancelación/EOF y generadores desde menú no deben ejecutar herramientas ni sobrescribir fuentes sin confirmación; Task 6.

---

### Task 1: Infraestructura aislada, evidencia y reproducción de fallos

**Files:** crear `CyberSecurity-Framework/tests/run_enumeration.sh`, `tests/test_enumeration_runtime.py`, `tests/enumeration_fixture.py`, `tests/fixtures/enumeration_tools.py`, `00_Config/lib/enumeration_runtime.bash`, `00_Config/lib/enumeration_evidence.py`.

**Interfaces:**
- `enum_init <servicio> <host> <puerto>` valida sin red, prepara directorio y globals `ENUM_DIR`, `ENUM_ID`, `ENUM_LOG`; el host no puede ser una opción ni URL en modo red.
- `enum_capture <nombre> <orden...>` conserva stdout/stderr nuevos separados; no publica el archivo final antes de verificarlo. `enum_publish <nombre> <estado>` publica respuesta verificada y sidecar `<archivo>.meta.json` con versión 1, host, puerto, herramienta, estado, fecha y rc. Estados: `EJECUTADO`, `CONFIRMADO`, `DENEGADO`, `CERRADO`, `FILTRADO`, `OMITIDO`, `NO_DETERMINADO`.
- Nombres nuevos `<prefijo>_<slug-host>_<puerto>.<ext>`. Los identificadores web incluyen además hash corto de esquema/ruta/query para evitar colisiones; autoridad completa en metadata. Nombres limitados a 240 bytes por componente con fallback hash y metadata, sin truncar la URL usada en red.
- `enumeration_evidence.py` proporciona validación/serialización y selección por host exacto para el visor; no realiza peticiones.

- [ ] Guardar snapshot del estado inicial y ledger propio; no reutilizar ni borrar el ledger de 03. Preparar baseline aislado con cambios 03 incluidos y configuración sintética.
- [ ] Crear fixtures copiando solo fuentes necesarias a `/tmp/opencode`, con HOME y entorno sintéticos; las herramientas falsas registran argv/stdin, simulan salidas reales y nunca delegan en binarios del sistema.
- [ ] Escribir tests que fallen: salida anterior intacta tras fallo, dos objetivos/puertos no colisionan, URL larga no rompe nombres, stdout de funciones sin UI y comandos no invocados ante entrada inválida.
- [ ] Ejecutar `bash CyberSecurity-Framework/tests/run_enumeration.sh`; esperar fallos por infraestructura/comportamiento ausente antes de implementar.
- [ ] Implementar interfaces, publicación de metadata y logs acumulados fechados. Reutilizar rutas/validadores útiles de 03 sin modificar su contrato. Los temporales que fallan no se descubren como resultados válidos de informes.
- [ ] Reejecutar suite: todos los casos de runtime verdes; runner verifica hashes/permisos de configuración, sesión y fuentes preexistentes relevantes.

### Task 2: Servicios de red y bases de datos, conservando todas las operaciones

**Files:** modificar `04_Enumeration/ssh/enum_ssh.sh`, `ftp/enum_ftp.sh`, `ftp/ftp_anonymous.sh`, `smb/enum_smb_advanced.sh`, `ldap/enum_ldap.sh`, `ldap/ldap_anonymous.sh`, `database/enum_mysql.sh`, `database/enum_postgres.sh`, `database/enum_redis.sh`; crear `tests/test_enumeration_services.py`.

**Interfaces:** consumir runtime de Task 1; conservar argumentos actuales. Hoja: 0 si operaciones requeridas evaluadas (incluido rechazo demostrado), 1 ante fallo/no determinado; omisiones de dependencias auxiliares explícitas, nunca éxito fingido.

- [ ] Escribir matriz de tests de capacidades de estas nueve hojas: demostrar en argv/stdin versión/auth/usuarios/algoritmos SSH; banner/anónimo/listado/NSE FTP; RPC/enum4linux/shares/NSE SMB; RootDSE/contexts/usuarios LDAP; consultas actuales MySQL/Postgres; INFO y KEYS Redis.
- [ ] Añadir negativos por protocolo: DNS/timeout, FTP sin 230, LDAP result no-success, SMB ACCESS_DENIED/LOGON_FAILURE, DB errores frente a salida válida, Redis NOAUTH/ERR frente a respuesta INFO/array. Sembrar evidencia vieja antes del fallo.
- [ ] Añadir HOME/config/env contaminados: la prueba root sin contraseña no puede usar MYSQL_PWD/login-path; Postgres debe probar exclusivamente postgres/postgres sin .pgpass, servicio ni psqlrc. Los clientes no pueden pedir contraseña por stdin ni colgar el menú.
- [ ] Ejecutar suite y comprobar los fallos esperados antes de tocar hojas.
- [ ] Migrar cada hoja a validación, timeout acotado, captura y clasificación por evidencia. Mantener los NSE actuales (incluido ftp-*), con patrones entre comillas y sin expansión del shell; comprobar disponibilidad de scripts consultando instalación local sin escanear. No instalar alternativas.
- [ ] Mantener enumeración de usuarios SSH; si el script/plugin no existe, informar capacidad no disponible, no fingir ni quitar su ruta de ejecución cuando sí existe. Mantener la condición histórica de localhost.
- [ ] Corregir LDAPS en 636/3269, respetar puertos; mantener todos los puertos históricos de los auxiliares FTP/LDAP. Acotar búsquedas LDAP con límite informado, sin eliminar la búsqueda de usuarios.
- [ ] Reejecutar suite por hoja y completa; verificar que clientes fallidos no se presentan como acceso denegado demostrado ni como acceso confirmado.

### Task 3: Web/API completos y controles HTTP

**Files:** crear `00_Config/lib/enumeration_http.py`, `tests/test_enumeration_http.py`; modificar `04_Enumeration/web/enum_web.sh`, `web/enum_web_advanced.sh`, `api/enum_api.sh`.

**Interfaces:** `enumeration_http.py request --url U --method M --output D` produce cuerpo/cabeceras/metadata nuevos, con rc 0 respuesta evaluable, 1 error/bloqueo. `enum_web.sh <IP> [PUERTO]` y `enum_api.sh <IP> [PUERTO]` mantienen modo histórico y añaden opcional `esquema`; nueva modalidad explícita `--url <URL>` no mezcla URL con host/puerto. `enum_web_advanced.sh <IP>` conserva sus siete puertos.

- [ ] Escribir tests que fallen: conservar cabeceras/whatweb/robots/sitemap/ffuf, todos los puertos avanzados y archivos sensibles, doce endpoints API, siete métodos HTTP y Swagger/OpenAPI.
- [ ] Añadir URL HTTPS en puerto no estándar y con ruta/query, 000, 401/403/405, 404, catch-all 200 y 403, redirección a otro host y documento que solo refleja «swagger». Un método no se declara permitido solo por no recibir 405.
- [ ] Añadir 429/503 con Retry-After segundos/fecha y persistente: un reintento, luego corte y ningún método siguiente ni hallazgo puntuado. Si la espera supera el presupuesto disponible, abortar explícitamente en lugar de dormir menos y reintentar antes de tiempo.
- [ ] Ejecutar suite y comprobar rojo antes de implementar helper y hojas.
- [ ] Implementar peticiones con timeout de conexión 5 s, total 15 s por intento, sin seguir redirects fuera del objetivo ni usar credenciales/proxy heredados inadvertidamente; TLS/esquema conservados. Mantener baseline de código/tamaño/cuerpo para diferenciar catch-all de evidencia.
- [ ] Mantener ffuf y su diccionario actual: observar streaming JSON con códigos 429/503 incluidos, cortar su grupo de proceso ante freno y no publicar hallazgos de la tanda incompleta. Filtrar catch-all sin ocultar códigos de freno; conservar salida JSON `results` reconocida por informes. Limitar la garantía a cortar nuevas tareas: las peticiones ya en vuelo no son reversibles. Verificar argv y parser con fixtures del formato real de ffuf, sin lanzarlo contra red.
- [ ] Mantener todos los métodos HTTP con sus riesgos visibles y evidencias por método. Guardar registros TSV nuevos con URL, método, código, clasificación y referencia de respuesta; estados catch-all/denegado/bloqueado no se etiquetan como métodos permitidos.
- [ ] Reejecutar suite verde, incluidos corte de fuzzing, preservación de resultados antiguos y todas las capacidades afirmativas.

### Task 4: Orquestador y generadores íntegros

**Files:** modificar `04_Enumeration/run_all_enum.sh`, `smb/enum_smb.sh`, `web/deepseeenum_web.sh`; crear `tests/test_enumeration_orchestrator.py`.

**Interfaces:** `run_all_enum.sh <TARGET>`, `ENUM_TIMEOUT` entero positivo (60 s por defecto), resumen ejecutadas/fallidas/omitidas y rc 0/1. Generadores conservan destino y todas las capacidades de su payload; nunca son enumeradores automáticos.

- [ ] Escribir tests que fallen: descubrimiento actual fallido con gnmap antiguo, estados open/closed/filtered/open|filtered, 8443 incluido en primera pasada, timeout, hijo ausente/no ejecutable/fallido, ejecución desde otro cwd y todos los hijos heredados con argv correcto.
- [ ] Añadir tests de ambos generadores en sandbox: antes/tras generar, destino correcto, payload válido, operaciones conservadas y ausencia de escrituras fuera de sandbox. El generado web debe coincidir con la hoja corregida.
- [ ] Ejecutar rojo; corregir descubrimiento validando rc y evidencia nueva, conservar timeout configurable, distinguir estados de puerto y no ocultar stderr. No añadir fases nuevas al run_all bajo el pretexto de que el nombre diga «all».
- [ ] Sin eliminar wrappers, sincronizar payloads con comportamiento corregido y dependencias de biblioteca localizables. No ejecutar generadores sobre las fuentes reales para producir la sincronización.
- [ ] Reejecutar suite verde y comprobar que cada una de las 16 entradas sigue disponible, contando los generadores una vez cada uno.

### Task 5: Resultados atribuibles e informes compatibles

**Files:** modificar `04_Enumeration/show_results.sh`, `11_Reports/lib/sources.py`, `11_Reports/lib/parsers/host_sources.py`; crear `tests/test_enumeration_reports.py`. Ampliar `enumeration_evidence.py` solo si es necesario para seleccionar resultados.

**Interfaces:** `show_results.sh [objetivo]` conserva invocación sin argumentos y añade filtro explícito; nuevos archivos reconocidos `ssh/auth_methods_*.txt`, `database/anon_*.txt`, `api/methods_*.tsv`, además de históricos. Metadata de Task 1 manda para nuevas evidencias, nunca se atribuye un archivo histórico por su carpeta o sesión actual.

- [ ] Escribir tests que fallen: dos hosts y dos puertos separados; evidencias sin atribución; una ejecución fallida tras otra correcta; nombres largos con metadata; visor sin tocar archivos ni ejecutar red.
- [ ] Añadir integración real con collect: nuevo SSH atribuible, MySQL root sin contraseña solo con estado CONFIRMADO y consulta verificada, API 2xx como observación baja (no prueba de vulnerabilidad), catch-all/errores descartados. Mantener tests de formatos históricos con su política previa de no atribución.
- [ ] Ejecutar rojo; implementar selección y parsers acotados. No convertir automáticamente salidas no vacías de clientes fallidos en hallazgos ni fusionar métodos de hosts distintos bajo una misma clave.
- [ ] Reejecutar suite nueva y `run_reports.sh` solamente en copia limpia; comprobar que el informe no pierde la compatibilidad de 03.

### Task 6: Menú guiado con acceso a las 16 entradas

**Files:** crear `00_Config/lib/enumeration_menu.bash`, `tests/test_enumeration_menu.py`; modificar `cyber_framework.sh` (carga y `module_enumeration`), `00_Config/lib/dangerous.txt`.

**Interfaces:** `enumeration_menu` reutiliza sesión, execute_script, prepared argv y confirmación existentes, sin cambiar la excepción básica de 03. Opciones: comprobar localmente, SSH, FTP, SMB, LDAP, bases de datos, web, API, flujo completo, resultados y lista completa/generadores.

- [ ] Escribir tests de navegación real, disponibilidad local sin invocar herramientas, objetivo de sesión/no sesión, puertos, URL explícita y retorno; todas las operaciones siguen seleccionables.
- [ ] Añadir cancelación/EOF en cada prompt, selección inválida, confirmación negativa de métodos modificadores/pruebas de acceso/fuzzing/flujo completo y de los dos generadores: cero ejecución o modificación. Tras confirmación afirmativa, verificar operaciones reales mediante stubs, no solo texto del menú.
- [ ] Ejecutar rojo; implementar nombres humanos y resumen previo con host/puerto/URL, operaciones e intensidad. La lista completa conserva las 16 entradas. Marcar entradas activas/intrusivas/generadores con confirmación del gestor antes de ejecutar.
- [ ] Mantener CLI directa como invocación explícita por el operador, con advertencias, dependencias y límites; no introducir prompts interactivos inesperados que rompan automatizaciones existentes. Las nuevas confirmaciones pertenecen al menú.
- [ ] Reejecutar suite verde: stdout no contiene preguntas como argumentos, ningún dato se procesa con eval y no se modifica el comportamiento de 03.

### Task 7: Documentación, regresión aislada y revisión final

**Files:** modificar `04_Enumeration/README.md`, `docs/MANUAL-GESTOR.md`, `AGENTS.md`; crear `docs/ENUMERACION-2026-11-09.md`. Ajustar tests antiguos únicamente donde contratos corregidos/nuevas confirmaciones cambien expectativas documentadas.

- [ ] Documentar todas las capacidades, navegación, riesgos, requisitos, límites, estados, atribución y generadores; no presentar flujo completo como prueba inicial de instalación.
- [ ] Actualizar expectativas antiguas después de observar su fallo real, sin debilitar controles aprobados ni borrar casos que revelen un defecto.
- [ ] Ejecutar suite nueva en checkout real con guardas y fuentes temporales; no ejecutar suites antiguas allí.
- [ ] Crear clon limpio con baseline acumulado 03+04, excluyendo alcance real, permiso pendiente de api_keys.py, credenciales, sesión y evidencias. Ejecutar secuencialmente las diez suites con límite 900 s, logs separados y grupos de proceso propios.
- [ ] Ejecutar bash -n con stderr vacío sobre todos los Bash modificados; Python compile en memoria y diff --check. Comparar fuentes probadas con checkout para no atribuir resultados a otra versión.
- [ ] Solicitar una revisión independiente de la entrega 04, distinguiendo cambios previos de 03. Corregir hallazgos importantes con rojo→verde y repetir regresión; registrar menores explícitamente, sin eliminaciones funcionales encubiertas.
- [ ] Cerrar ledger/checklist con evidencias y dejar cambios sin commit ni push. Mantener logs porque no hay commits para recuperar el registro.

## Handoff

Implementación y verificación completadas el 2026-11-10. Registro por tarea en
`.superpowers/sdd/2026-11-09-enumeracion-guiada/progress.md`; resultados, ajustes
y límites en `docs/ENUMERACION-2026-11-09.md`. Las siete tareas están completas,
con diez suites finales pasando, revisión independiente y correcciones probadas.

Propuesta: ejecución nativa en esta sesión como en 03, sin agentes de implementación; una revisión independiente al final. El diseño fue aprobado, el plan se entrega para confirmar antes de tocar código de producto. Decisiones concretas del plan (formatos, límites, menús) son propuestas del implementador y están sujetas a esa confirmación.
