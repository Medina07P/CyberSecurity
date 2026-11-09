# OSINT real Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sustituir resultados ficticios y éxitos silenciosos de todo `01_OSINT` por recopilación trazable con APIs opcionales y enumeración DNS activa acotada.

**Architecture:** Entradas Bash compatibles delegan en un paquete Python común. Una sesión coordina las fuentes y comparte sus resultados únicamente durante esa ejecución. Transporte, secretos, evidencias y estados tienen contratos comunes.

**Tech Stack:** Bash, Python 3, biblioteca estándar, PyYAML existente, herramientas externas instaladas y `unittest`; sin instalaciones automáticas.

**Spec:** `docs/superpowers/specs/2026-11-09-osint-real-design.md`

## Global Constraints

- No tocar el cambio previo del usuario en `CyberSecurity-Framework/00_Config/scope.yaml` ni datos generados existentes.
- Interfaces y mensajes en español; conservar nombres y argumentos actuales, incluido segundo argumento de salida de scripts individuales.
- Máximo 15 s por solicitud, 120 s por herramienta y 10 consultas por API por ejecución, incluidos reintentos; sin `-b all` ni `whatweb -a 3` implícitos.
- Fuerza bruta DNS solo explícita y confirmada: máximo 1.000 candidatos, 2 trabajadores y 5 consultas por segundo agregadas, incluidos controles y reintentos.
- AXFR, ataques de contraseñas, filtraciones y explotación fuera de alcance.
- Registro de claves solo de lectura, sin secretos en stdout/stderr, argumentos de procesos ni artefactos.
- Salidas por defecto en árboles ignorados del módulo; directorio explícito externo admitido con advertencia. Objetivo y ejecución única en los nombres; conservar datos históricos.
- Código 0: fuentes intentadas completadas; 1: alguna fallida/bloqueada/timeout o ninguna utilizable; 2: entrada/configuración inválida. Las omisiones previstas no fallan por sí solas.
- Pruebas completamente aisladas, sin tráfico externo ni cuotas. No afirmar integración real si solo se probaron fixtures.
- Checkpoints de cada tarea: revisar diff, registrar resultados y crear commits locales pequeños (autorizados por el usuario para recuperarse de cortes eléctricos). Merge a develop tras verificar; no publicar.

## Review Focus

1. Enlace con host parecido a una red, redirección o ruta de búsqueda: no atribuir un perfil falso (tarea 3).
2. Registro YAML corrupto o error que refleja una clave: fallo seguro sin divulgar secretos ni escribir configuración (tarea 2).
3. DNS NXDOMAIN frente a SERVFAIL y wildcard rotatorio: separar ausencia, fallo y ambigüedad sin inflar resultados (tarea 4).
4. Archivo relativo y directorio de salida con espacios desde otro cwd: conservar destino y argumentos sin shell interpolation (tarea 5).
5. Dos ejecuciones consecutivas y reporte parcialmente fallido: no mezclar ni sobrescribir evidencia ni declarar éxito global (tareas 1 y 5).

## File map

Crear paquete `CyberSecurity-Framework/00_Config/lib/osint/`:
- `__init__.py`: exportación mínima, sin efectos al importar.
- `model.py`: evidencias, resultados y límites.
- `runtime.py`: transporte HTTP, procesos, presupuestos, redacción y escritura.
- `credentials.py`: lectura efectiva de claves compatibles.
- `sources.py`: sitio oficial, certificados, WHOIS, theHarvester y tecnologías.
- `discovery.py`: Brave, GitHub, Hunter y parsers de perfiles/emails.
- `dns.py`: resolución y enumeración DNS acotada.
- `cli.py`: argumentos, coordinación, metadatos y resumen.

Modificar las seis entradas actuales de `01_OSINT` para delegar al paquete. Crear `tests/test_osint.py`, `tests/run_osint.sh` y fixtures exclusivamente sintéticos en `tests/fixtures/osint/`. Actualizar `tests/run_tests.sh`, README de OSINT y `docs/MANUAL-GESTOR.md` con el contrato nuevo; no alterar el motor de informes.

---

### Task 1: Estados, ejecución acotada y evidencia

**Files:** crear `osint/{__init__,model,runtime}.py` en el paquete anterior y `tests/test_osint.py`.

**Interfaces:**
- `Limits(request_seconds=15, tool_seconds=120, api_calls=10, dns_candidates=1000, dns_workers=2, dns_qps=5)`; no admitir aumentos por encima de topes.
- `Evidence(kind: str, value: str, source: str, attribution: str, detail: str)`.
- `SourceResult(source: str, status: str, evidence: list[Evidence], error: str = '')`; estados internos `ok`, `empty`, `skipped`, `blocked`, `failed`, `timeout`.
- `Run(target: str, output: Path, limits: Limits)` mantiene timestamp UTC, ID único, resultados y caché solo en memoria.
- `HttpClient.request(source: str, url: str, headers: dict | None = None) -> HttpResponse`; respuesta con `status`, `headers`, `body`, `final_url`. Dependencias de reloj, espera y opener inyectables.
- `run_tool(argv: list[str], timeout: float) -> CompletedProcess`; nunca `shell=True`.
- `exit_code(results: list[SourceResult]) -> int`; `write_run(run: Run) -> Path` escribe JSON versión 1, resumen y errores redactados en subdirectorio exclusivo.

- [ ] Escribir pruebas `test_failed_sources_exit_one`, `test_only_skipped_exit_one`, `test_empty_success_exits_zero`, `test_runs_do_not_overwrite`: códigos 1/1/0 y rutas diferentes con dos ejecuciones.
- [ ] Añadir pruebas de 403, JSON no esperado, timeout, proceso ausente, salida no cero, límite 10 incluyendo reintentos, 429/503 persistente y Retry-After en segundos/fecha. Si la espera excede presupuesto, no dormir ni emitir otra solicitud.
- [ ] Ejecutar `python3 -m unittest discover -s CyberSecurity-Framework/tests -p test_osint.py -v`; comprobar fallo por módulos/contratos ausentes.
- [ ] Implementar contratos. Limitar cuerpo HTTP a 2 MiB y saltos de redirección a 5; no reenviar autorización entre hosts. Prohibir respuestas de error como evidencia y redactar tokens registrados antes de persistir.
- [ ] Repetir comando y comprobar todos los casos de esta tarea; revisar diff y registrar checkpoint.

### Task 2: Configuración de fuentes y recopilación compartida

**Files:** crear `osint/{credentials,sources}.py`; ampliar `tests/test_osint.py` y fixtures.

**Interfaces:**
- Consume `Run`, `Limits`, `HttpClient`, `SourceResult`, `Evidence`, `run_tool` de tarea 1.
- `load_credentials(registry: Path, harvester_dirs: list[Path]) -> dict[str, str]`: claves lógicas `brave`, `github`, `hunter`; precedencia por campo: registro `theharvester.<proveedor>.key`, después primer archivo efectivo de theHarvester. No fusionar directorios ignorados por la herramienta.
- `collect_site(run: Run, client: HttpClient, url: str) -> SourceResult` conserva URL final y HTML limitado en caché para parsers.
- `collect_certificates(run: Run, client: HttpClient, domain: str) -> SourceResult` normaliza entradas multilínea y distingue wildcard de host concreto.
- `collect_tool(run: Run, tool: str, domain: str) -> SourceResult` para WHOIS, tecnologías de bajo impacto y theHarvester.

- [ ] Añadir `test_registry_precedence_without_writes`, `test_missing_keys_skip`, `test_corrupt_yaml_no_secret_leak`, `test_provider_error_redacted`: claves sintéticas nunca aparecen en artefactos, argv ni salidas; hashes de configuración intactos.
- [ ] Añadir `test_crtsh_invalid_json_fails`, `test_certificate_scope_boundary`, `test_harvester_selected_sources`, `test_shared_collection_once`: un solo acceso por fuente compartida durante run_all, dominio ajeno rechazado, sin `-b all` ni fuentes imposibles.
- [ ] Ejecutar suite, verificar que fallen estos tests antes de implementar.
- [ ] Consultar documentación vigente y ayuda local de theHarvester para formatos/extensiones y fuentes disponibles; anotar contratos comprobados en comentarios/fixtures sin claves reales. Si no permite limitar consultas de una fuente, no habilitarla bajo el presupuesto prometido: informar incompatibilidad.
- [ ] Implementar adaptadores sin modificar archivos de claves, con selección explícita y lectura estructurada de resultados de theHarvester. No usar conteo de `@dominio` en HTML como número de emails.
- [ ] Ejecutar suite y verificar checkpoint, incluida ausencia total de red real mediante mock que rechaza sockets no simulados.

### Task 3: Descubrimiento real de perfiles y emails

**Files:** crear `osint/discovery.py`; ampliar pruebas y fixtures HTML/JSON.

**Interfaces:**
- Consume transporte y caché de tareas 1–2.
- `extract_profiles(html: str, page_url: str, official: bool) -> list[Evidence]`.
- `extract_emails(text: str, domain: str, source: str) -> list[Evidence]`.
- `discover_social(run: Run, client: HttpClient, company: str, domain: str | None, keys: dict[str, str]) -> list[SourceResult]`.
- `discover_emails(run: Run, client: HttpClient, domain: str, keys: dict[str, str]) -> list[SourceResult]`.

- [ ] Añadir `test_no_generated_profile_urls`, `test_official_link_not_ownership`, `test_name_match_is_candidate`: únicamente enlaces observados; atribuciones `vinculado_desde_sitio` o `candidato`, nunca propiedad confirmada.
- [ ] Añadir `test_social_host_and_route_validation`: rechazar `github.com.attacker.test`, URLs de compartir/búsqueda/login, enlaces `javascript:` y redirecciones que dejan de ser perfil; aceptar perfiles reales de LinkedIn, X/Twitter, GitHub, Instagram, Facebook y TikTok según rutas documentadas.
- [ ] Añadir `test_github_login_not_email`, `test_mailto_normalized`, `test_email_domain_boundary`, `test_api_missing_coverage_visible`: deduplicar emails, rechazar dominio sufijado ajeno y exponer cobertura incompleta.
- [ ] Ejecutar suite y comprobar fallos nuevos.
- [ ] Consultar documentación actual de Brave Search, GitHub Search Users y Hunter Domain Search; implementar consultas escapadas y presupuestadas, sin scraping de redes autenticadas. Hunter lleva clave en transporte API según su contrato, pero URL con secreto nunca se registra. No mandar clave de un proveedor a otro host.
- [ ] Implementar parsers con `HTMLParser` y `urllib.parse`, sin aceptar contenido de errores como resultados. Sin claves, extraer enlaces desde dominio proporcionado y consultar GitHub público donde funcione; declarar búsqueda web general omitida si no hay Brave.
- [ ] Ejecutar suite, comprobar criterios y checkpoint.

### Task 4: DNS descubierto, resuelto y fuerza bruta confirmada

**Files:** crear `osint/dns.py`; ampliar pruebas.

**Interfaces:**
- `normalize_domain(value: str) -> str` valida IDNA, etiquetas y longitudes; rechaza IP/puerto/ruta cuando se espera dominio.
- `DnsAnswer(name: str, status: str, records: dict[str, list[str]])`; estados `resolved`, `absent`, `failed`, `timeout`.
- `resolve_name(name: str, resolver: str | None, limiter: DnsLimiter) -> DnsAnswer`; ejecutar `dig` con argv y parsear status DNS, no solo `+short`.
- `DnsLimiter(qps: float = 5)` usa reloj monotónico y espera inyectables; comparte cada llamada A/AAAA/CNAME, incluidos controles/reintentos.
- `enumerate_dns(run: Run, domain: str, wordlist: Path, resolver: str | None, confirmed: bool) -> SourceResult`.
- `resolve_discovered(run: Run, domain: str, names: list[str], resolver: str | None) -> SourceResult` comparte presupuesto DNS; no inicia diccionario.

- [ ] Añadir `test_active_requires_confirmation`, `test_wordlist_limit_1000`, `test_wordlist_deduplicates_and_rejects_invalid`: rechazar entrada excesiva antes de consultas, sin truncar silenciosamente.
- [ ] Añadir `test_dns_nxdomain_not_failure`, `test_dns_servfail_not_absence`, `test_wildcard_ambiguous`, `test_rotating_wildcard_not_confirmed`, `test_global_qps_includes_controls`: registros normalizados como conjuntos y controles aleatorios en al menos tres nombres; no confirmar coincidencias ambiguas.
- [ ] Añadir `test_dns_workers_at_most_two`, `test_persistent_failures_stop`: máximo 2 trabajadores, detener tras 3 nombres consecutivos fallidos, retener progreso como parcial sin contar fallos como nombres ausentes.
- [ ] Ejecutar suite y observar fallos antes de implementar.
- [ ] Implementar normalización, resolución y enumeración. Resolver de sistema por defecto, opcional explícito validado; sin AXFR ni `dnsrecon -t brt` fuera del modo activo. Consultas DNS presupuestadas globalmente, sin reintentos opacos de `dig`.
- [ ] Ejecutar suite y verificar límites mediante reloj falso, sin dormir ni resolver dominios reales; checkpoint.

### Task 5: Integración de las seis entradas, metadatos, documentación y regresión

**Files:** crear `osint/cli.py`, `tests/run_osint.sh`; modificar `01_OSINT/run_all_osint.sh`, sus cinco `scripts/*.sh`, `tests/run_tests.sh`, `01_OSINT/README.md`, `docs/MANUAL-GESTOR.md` y este plan con resultados.

**Interfaces:**
- `main(argv: list[str] | None = None) -> int`; arranque con `PYTHONPATH` apuntando a `00_Config/lib` y `python3 -m osint.cli` desde wrappers autolocalizados.
- Subcomandos internos `social`, `emails`, `domains`, `subdomains`, `metadata`, `all`; preservan posicionales de wrappers actuales.
- `social_media_search.sh <empresa> [directorio_salida] [dominio]`: tercer argumento nuevo permite referencia oficial; sin dominio, solo candidatos.
- `run_all_osint.sh <dominio> [archivo] [empresa]`: tres slots, archivo opcional y sin ejemplo que autocomplemente un archivo ficticio. Una ejecución coordinada reutiliza sitio/certificados/theHarvester/DNS.
- `subdomain_finder.sh <dominio> [directorio_salida] [diccionario] [resolver]`: diccionario no vacío activa confirmación por stdin de la frase exacta `DNS_SI`; EOF/rechazo cancela antes de consultar. Sin diccionario no hay fuerza bruta. Sin flags en primera línea Uso para conservar slots del gestor.
- `collect_metadata(run: Run, file: Path) -> SourceResult` comprueba archivo y usa detección MIME/formatos, subprocess sin shell y timeouts; fallo del extractor se propaga.

- [ ] Añadir tests de wrappers mediante subprocess, stubs locales y HOME/KEYS_FILE/KEYS_HARVESTER_DIRS temporales: empresa con espacios, salida externa, cwd ajeno, documento relativo y dos ejecuciones sin pisar resultados.
- [ ] Añadir `test_all_partial_is_not_success`, `test_metadata_extractor_failure`, `test_all_does_not_bruteforce`, `test_menu_slots_and_confirm`: códigos y mensajes correspondientes; ninguna acción activa sin confirmación.
- [ ] Reemplazar tests antiguos de run_all que asumían cinco hijos invocados por pruebas del nuevo contrato coordinado; conservar comprobaciones de parámetros, stderr y no alterar archivos reales. Probar entrada inválida con código 2 en lugar del contrato antiguo de 1.
- [ ] Ejecutar nuevas pruebas y comprobar fallos antes de cambiar wrappers.
- [ ] Implementar CLI, wrappers y metadatos; mostrar resumen por fuente, cobertura y ruta real. Al cancelar modo activo no ejecutar otras fuentes ni escribir falso éxito. Sin herramientas opcionales disponibles, informar omisión, no instalar.
- [ ] Crear `run_osint.sh` aislado con guardas de integridad de configuración real y red externa prohibida; actualizar guías con argumentos, claves compatibles en K, presupuestos, estados, fuerza bruta DNS, wildcard y limitaciones. No dar por hecho que una API configurada es válida.
- [ ] Ejecutar `bash CyberSecurity-Framework/tests/run_osint.sh`; exigir todos los tests pasando y ninguna modificación real.
- [ ] Ejecutar individualmente `bash CyberSecurity-Framework/tests/run_tests.sh`, `run_e2e.sh`, `run_smoke.sh`, `run_wizard.sh`, `run_reports.sh`, `run_keys.sh` con sus rutas completas. Investigar cualquier fallo sin rebajar assertions para ocultarlo.
- [ ] Ejecutar `bash -n` sobre `.sh` y `.bash`, guardando stderr y rechazando warnings de heredoc; compilar `.py` con caché dirigida a temporal. Comprobar `git diff --check` y `git status --short`; scope original intacto y ningún dato real nuevo versionado.
- [ ] Revisar contra el diseño y documentar evidencia y fuentes no probadas en vivo; no declarar OSINT de un objetivo que no se consultó. Hacer revisión de código antes de ofrecer integración; no commit/publicación automáticos.

## Handoff

### Progreso persistente (recuperación tras cortes)

- Tarea 1: implementada, 12 tests RED→GREEN; commit `b408bb5`.
- Tarea 2: implementada, suite acumulada 20 tests RED→GREEN; commit `f4a53a7`.
- Tarea 3: implementada, suite acumulada 31 tests RED→GREEN.
- Tarea 4: implementada, suite acumulada 42 tests RED→GREEN. DNS usa un
  trabajador (dentro del máximo de dos), ritmo agregado y presupuesto de 120 s;
  diccionarios grandes pueden quedar parciales, anunciado explícitamente.
- Línea base: seis suites originales pasando, incluida run_tests 388/388.
- Tarea 5: núcleo conectado a las seis entradas, documentación y suite aislada;
  50 tests pasando. Regresión completa en curso antes de revisión/merge.
- Corrección necesaria en prompt.bash: conserva opcionales vacíos intermedios
  (empresa sin documento, diccionario sin salida explícita); solo recorta vacíos
  finales. Test observado RED→GREEN; se revisa compatibilidad con gestor.
- Sintaxis provisional: 132 Bash sin errores/avisos; 39 Python compilados con
  caché temporal. Ningún archivo de configuración real fue modificado.
- Decisión técnica: theHarvester se anuncia omitido; las implementaciones locales
  inspeccionadas hacen reintentos opacos y ocultan errores. Se reemplazan sus
  fuentes integradas por adaptadores directos; otras fuentes no se consultan.
- Hunter permite autenticación por `X-API-KEY` según documentación vigente;
  se usa cabecera, no query con clave. Documentación Brave contrastada con su
  repositorio oficial porque su portal devolvió 403 al lector.
- Worktree: rama `feat/osint-real`. No se ha consultado un objetivo real ni
  utilizado credenciales reales durante la implementación.

- [x] Diseño aprobado y contratos existentes inspeccionados.
- [x] Plan contrastado con diseño: fuentes, compatibilidad, secretos, fuerza bruta DNS, estados, salidas y pruebas cubiertos por tareas 1–5.
- [x] Usuario aprueba ejecución nativa, worktree aislado, commits de progreso y merge posterior a develop.
- [ ] Implementar tareas 1–5 siguiendo pruebas primero y registrar resultados.
