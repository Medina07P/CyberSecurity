# Módulo 05: explotación guiada — trabajo pendiente y cobertura

**Fecha:** 2026-11-10
**Estado:** borrador (trabajo futuro; ver `docs/superpowers/specs/2026-11-10-explotacion-pendiente-design.md`)
**Contexto:** continuación de `docs/superpowers/specs/2026-11-10-explotacion-guiada-design.md` y del ledger `.superpowers/sdd/2026-11-10-explotacion-guiada/progress.md`.

## Objetivo

Cerrar las brechas de cobertura y las integraciones diferidas del módulo 05 sin ampliar su superficie, preservando las capacidades existentes y sin inventar datos, objetivos ni credenciales.

## Alcance y límites

- No se añaden topes de intentos, tasas, diccionarios ni límites de duración.
- No se instalan dependencias ni se cambian privilegios automáticamente.
- No se versionan payloads generados, credenciales ni evidencia real.
- `scope.yaml` permanece fuera de los commits.
- La validación real no se sustituye por suites aisladas.

## Matriz inventario → entrada CLI → operación → ejecución real → evidencia → resultado

| Capacidad | Entrada CLI | Operación | Ejecución real | Evidencia | Resultado |
|---|---|---|---|---|---|
| Petición capturada (http_inject) | `http_inject.sh <fichero> [objetivo]` | Inyección en query/form/JSON con sesión, eco y catch-all | Validado en loopback (http_target.py) | `scans/web/http_inject_*` | CONFIRMADO/FUERTE/DÉBIL |
| Petición capturada (sqlmap) | `sqlmap_request.sh <fichero> [objetivo]` | Tres fases: detección, enumeración, volcado (50 filas) | Validado en loopback; host real no inyectable | `scans/sqlmap/<host>_<puerto>/run_*` | INYECTABLE/NO INYECTABLE/NO DETERMINADO |
| Rate limit probe | `rate_limit_probe.sh <fichero> [objetivo]` | N intentos variando solo contraseña | No ejecutado contra host real (sin petición válida) | `scans/web/rate_limit_*` | FRENADO/SIN FRENO/NO DETERMINADO |
| Fuerza bruta SSH/FTP | `ssh_attack.sh`, `ftp_bruteforce.sh` | hydra con usuarios/wordlists | No ejecutado (sin objetivo autorizado) | `scans/.../exploitation_*` | CONFIRMADO/DENEGADO/NO DETERMINADO |
| Kerberos | `kerberos_attack.sh` | kinit con tickets aislados | No ejecutado (sin objetivo autorizado) | `scans/.../exploitation_*` | CONFIRMADO/DENEGADO/NO DETERMINADO |
| CVE 2024-6387 | `cve_2024_6387.sh` | Sonda de versión (sin payload) | No ejecutado (sin objetivo autorizado) | `scans/.../exploitation_*` | Candidato/no confirmado |
| WiFi | `wifi_attack.sh` | Escaneo con iwlist | No ejecutado (sin interfaz) | `scans/.../exploitation_*` | NO DETERMINADO sin interfaz |
| Payloads/shells | `reverse_shell_php.sh`, `template.sh/py` | Generación de payload | Generación verificada (archivo creado y limpiado) | Archivo temporal | EJECUTADO |
| Visor de evidencia | `show_results.sh [host]` | Lista runs por host/herramienta | Validado | stdout | Resumen |

## Estado de las tareas pendientes

### P1. Validación positiva de detección con sqlmap — NO COMPLETADO

- **Situación:** el endpoint `/api/auth/login` del host autorizado devuelve 401 incluso con credenciales válidas; sqlmap concluye que no es inyectable. No se dispone de un endpoint inyectable autorizado.
- **Necesario:** un endpoint autorizado con parámetro inyectable.
- **Aceptación:** pendiente.

### P2. Recuperación de la petición capturada de producción — NO COMPLETADO

- **Situación:** el incidente del 2026-11-10 destruyó `scans/web/login.req` y los resultados asociados. La recuperación ext4 no tuvo éxito (solo 2 inodos borrados antiguos; ninguno correspondía al archivo).
- **Opciones restantes:** si el operador dispone de la petición original, reimportarla bajo el árbol de evidencia privada.
- **Prohibido:** reconstruir la petición por conjetura.

### P3. Integración de 05 con el motor de informes — COMPLETADO

- **Implementado:** `11_Reports/lib/parsers/exploitation.py` (ParseResult para runs de 05), registrado en `sources.py` (`_PARSER_MODULES`), reglas de clasificación para `run.json` de explotación y priorización del último run por host/herramienta.
- **Reglas añadidas al catálogo:** `exploitation.hallazgo`, `exploitation.diferencial`, `exploitation.reflexion`, `exploitation.guia`.
- **Aceptación:** `tests/run_reports.sh` en verde (28/28); parser oculta secretos y filas volcadas; distingue hallazgo, diferencial, reflexión, guía y no evaluado.

### P4. Documentación final — EN CURSO

- Este documento y la actualización de `docs/MANUAL-GESTOR.md` (menú de 05).

### P5. Validación real de familias no cubiertas — NO COMPLETADO

- **Situación:** no se ejecutó fuerza bruta real, Kerberos real, sondeo de CVE real ni WiFi (sin interfaz).
- **Necesario:** objetivo autorizado e interfaz identificada.

### P6. Menú de 05 y pruebas de navegación — VALIDADO PARCIALMENTE

- **Situación:** el menú se cargó y navegó en smoke; no se validó una elección real desde el menú contra un objetivo.
- **Necesario:** ejecutar una opción real aplicable con la configuración del usuario.

## Menú de 05

El módulo 05 dispone de un menú guiado (`05_Exploitation/...`):

1. Herramientas (fuerza bruta, Kerberos, CVE, WiFi, payloads)
2. Web capturada (http_inject, sqlmap_request, rate_limit_probe)
3. Web por URL/host (xss, sqli, fuzzing)
4. SSH/FTP
5. Bases de datos
6. Kerberos
7. CVE
8. Payload/shell
9. WiFi
10. Plantillas
11. Flujos completos (run_all_attacks, run_all_exploits)
12. Resultados (visor de evidencia)
13. Lista completa (todas las entradas)
14. Volver

El submenú 13 reutiliza `run_module_scripts`, así que ninguna entrada se suprime.

EOF
echo "Creado docs/EXPLOTACION-2026-11-10.md"