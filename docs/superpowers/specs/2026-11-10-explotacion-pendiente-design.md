# Módulo 05: trabajo pendiente y cobertura no verificada

**Fecha:** 2026-11-10
**Estado:** borrador (trabajo futuro)
**Contexto:** continuación de `docs/superpowers/specs/2026-11-10-explotacion-guiada-design.md` y del ledger `.superpowers/sdd/2026-11-10-explotacion-guiada/progress.md`. Las tareas 1–8 del plan se declararon completas en código; este documento recoge lo que quedó sin acreditar o sin implementar.

## Objetivo

Cerrar las brechas de cobertura y las integraciones diferidas del módulo 05 sin ampliar su superficie, preservando las capacidades existentes y sin inventar datos, objetivos ni credenciales.

## Alcance y límites

- No se añaden topes de intentos, tasas, diccionarios ni límites de duración.
- No se instalan dependencias ni se cambian privilegios automáticamente.
- No se versionan payloads generados, credenciales ni evidencia real.
- `scope.yaml` permanece fuera de los commits.
- La validación real no se sustituye por suites aisladas.

## Trabajo pendiente

### P1. Validación positiva de detección con sqlmap

- **Situación:** no existe un objetivo inyectable autorizado disponible; solo se validó el caso negativo (NO INYECTABLE) y la compuerta de permisos.
- **Necesario:** un endpoint autorizado con parámetro inyectable para ejecutar `sqlmap_request.sh` con `SQLMAP_SI=1` y confirmar el veredicto INYECTABLE, la enumeración (`SQLMAP_ENUMERAR=1`) y el volcado acotado (50 filas) (`SQLMAP_TABLA`).
- **Aceptación:** caso en el manifiesto con estado CONFIRMADO y verificador en verde; hashes de evidencia registrados.

### P2. Recuperación o reemplazo de la petición capturada de producción

- **Situación:** el incidente del 2026-11-10 destruyó `scans/web/login.req` (POST /api/auth/login, host `sgcrc.myconnectfibraoptica.com`), los resultados `rate_limit_sgcrc…`, `ffuf_*`, `headers_*`, `robots_*`, `sitemap_*`, `security_headers_*`, `sqli_findings.txt`, `errores.log` y las sesiones sqlmap de `127.0.0.1` y `sgcrc…`. No hay copia.
- **Opciones:** recuperación ext4 solo con autorización explícita del usuario; o, si el operador dispone de la petición original, reimportarla bajo el árbol de evidencia privada y añadir casos al manifiesto.
- **Prohibido:** reconstruir la petición por conjetura o inventar parámetros.

### P3. Integración de 05 con el motor de informes (11_Reports) — COMPLETADO

- **Implementado:** `11_Reports/lib/parsers/exploitation.py` (ParseResult para runs de 05), registrado en `sources.py` (`_PARSER_MODULES`), reglas de clasificación para `run.json` de explotación y priorización del último run por host/herramienta. El parser oculta secretos y filas volcadas, y distingue hallazgo, diferencial, reflexión, guía y no evaluado.
- **Reglas añadidas al catálogo:** `exploitation.hallazgo`, `exploitation.diferencial`, `exploitation.reflexion`, `exploitation.guia`.
- **Aceptación:** `tests/run_reports.sh` en verde (28/28); parser probado con fixture de dos runs (prioriza el último).

### P4. Documentación final (Task 8) — COMPLETADO

- **Implementado:** creado `docs/EXPLOTACION-2026-11-10.md` con la matriz inventario → entrada CLI → operación → ejecución real → evidencia → resultado, marcando como no validado lo que falte por dato/servicio/hardware. Actualizado `docs/MANUAL-GESTOR.md` con el menú de 05.

### P5. Validación real de las familias no cubiertas por datos

- **Situación:** no se ejecutó fuerza bruta real (sin objetivo autorizado), ni Kerberos real, ni sondeo de CVE real, ni WiFi (sin interfaz).
- **Necesario:** cuando exista un objetivo autorizado e interfaz identificada, ejecutar las capacidades ya disponibles (`ssh_attack.sh`, `kerberos_attack.sh`, `cve_2024_6387.sh`, `wifi_attack.sh`) y registrar casos en el manifiesto.
- **Aceptación:** casos con estado observado y hashes; sin desplegar payloads ni reconfigurar hardware.

### P6. Menú de 05 y pruebas de navegación

- **Situación:** el menú se cargó y navegó en smoke, pero no se validó una elección real desde el menú contra un objetivo.
- **Necesario:** ejecutar una opción real aplicable con la configuración del usuario y verificar argumentos y destino en la evidencia.
- **Aceptación:** evidencia atribuible al run iniciado desde el menú; sin tráfico en las rutas de cancelación/EOF.

## Orden sugerido

1. P2 (si hay autorización de recuperación o petición disponible).
2. P1 (requiere objetivo inyectable autorizado).
3. P3 (integración con informes).
4. P4 (documentación).
5. P5 y P6 (validación real cuando haya datos).

## Criterios de cierre

- Cada caso del manifiesto pasa `verify_exploitation_real.py` con `RESULTADO: SATISFECHO`.
- `bash -n` sin salida en stderr para todos los `.sh` tocados.
- `python -m py_compile` fuera del árbol de fuentes.
- `git diff --check` sin salida.
- `scope.yaml` fuera de los commits; sin push.
