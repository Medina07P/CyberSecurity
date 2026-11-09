# crt.sh exact-first Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Conservar descubrimiento de certificados y resolución DNS ante fallo parcial de crt.sh.
**Architecture:** Dos consultas independientes con estados separados y un presupuesto HTTP compartido; unión única para DNS. Misma CLI y formatos de artefactos.
**Tech Stack:** Python 3 estándar, unittest y Bash existentes.
**Spec:** `docs/superpowers/specs/2026-11-09-crtsh-exact-first-design.md`

## Global Constraints
- 15 s absolutos/solicitud, 120 s/fuente, 10 solicitudes API totales incluidos reintentos.
- No continuar tras bloqueo del proveedor; ni falsear un parcial como éxito.
- No escribir objetivos reales, claves ni resultados en git; no tocar scope.yaml.
- Ejecutar pruebas en worktree/clon aislado; commits locales pequeños, sin push.

## Review Focus
- Timeout/502 exacto seguido por éxito ampliado: conservar nombres sin reiniciar presupuesto.
- Exacto correcto y ampliado fallido: DNS debe ejecutarse y salida seguir siendo 1.
- 429/503 persistente: no hacer la otra consulta como evasión.
- Duplicados o nombres inválidos: no duplicar DNS ni abortar por un SAN ajeno.
- Nuevas carpetas de ejecución: ignorar JSON/logs sin ignorar código o documentación.

### Task 1: Consultas independientes y regresiones

**Files:** modificar `CyberSecurity-Framework/00_Config/lib/osint/{runtime,sources,cli}.py`,
`CyberSecurity-Framework/tests/test_osint.py`, `CyberSecurity-Framework/tests/fixtures/osint/osint_http_fixture.py`,
`.gitignore`, `CyberSecurity-Framework/01_OSINT/README.md`.

**Interfaces:** `HttpClient.request(source, url, headers=None, *, independent_query=False)`
mantiene frenos globales y permite solo aislar failed/timeout entre consultas;
`collect_certificates(run, client, domain) -> SourceResult` conserva firma, cachea
unión y registra resultados individuales `crtsh_exact`/`crtsh_wildcard`;
CLI resuelve evidencia aunque la unión sea parcial.

- [ ] Añadir tests de consultas exacta/ampliada en orden, nombres únicos y cacheados;
  ambos órdenes de fallo/éxito; 403/429/503 sin segunda consulta; límite API global;
  SAN ajeno/inválido; JSON inválido parcial; CLI parcial con DNS y sin falso éxito.
- [ ] Ejecutar `bash CyberSecurity-Framework/tests/run_osint.sh`; observar fallos RED.
- [ ] Implementar aislamiento opt-in de failed/timeout, jamás blocked; parser de
  nombres válidos y resultados separados; unión en caché sin tercera fila duplicada.
- [ ] Cambiar condición de CLI para resolver nombres conservados tras error parcial.
- [ ] Añadir prueba `git check-ignore` para resultados de las cinco categorías,
  comprobar RED y añadir regla exclusiva de carpetas `osint_*`.
- [ ] Actualizar README sobre dos consultas, estados y límites sin aumentar plazos.
- [ ] Verificar suite OSINT GREEN y guardar commit de implementación.
- [ ] Ejecutar las siete suites en worktree limpio; sintaxis Python/Bash y diff check.
- [ ] Revisión independiente única; corregir importantes con tests RED→GREEN.
- [ ] Commit final, merge local a develop sin tocar trabajo ajeno y verificación
  integrada en clon limpio. Conservar pruebas y registro de progreso para cortes.

## Progreso
- [x] Diseño corto aprobado; ejecución nativa y worktree aislado heredados.
- [ ] Task 1 completa.
- [ ] Revisión y merge verificados.
