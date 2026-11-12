# Cierre de mantenimiento de 06 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cerrar únicamente mantenimiento de menú, informes, validación y pruebas aisladas, alcance aceptado expresamente por el usuario en esta conversación.

**Architecture:** Conservar Bash/Python existentes. Correcciones pequeñas con pruebas primero, sin tocar operaciones activas, sus automatizaciones ni sus archivos pendientes.

**Tech Stack:** Bash, Python estándar, unittest y Git local; sin dependencias nuevas.

**Spec:** Este documento concreta el cierre reducido aceptado por el usuario; sustituye para esta entrega la integración de hojas/flujo del plan integral `2026-11-10-postexplotacion-guiada.md`, no declara ese plan completo.

## Global Constraints

- No modificar ni ejecutar operaciones de persistencia, credenciales, movimiento lateral o limpieza.
- No retirar archivos/capacidades existentes; preservar los cambios pendientes de hojas, run_all y scope.yaml fuera de los commits de mantenimiento.
- No ejecutar suites antiguas sobre el checkout real; copias de fuentes con Git local y configuración sintética en /tmp/opencode.
- Conservar los diez fallos de run_tests reproducidos en eb67d1a; no debilitar asertos para obtener verde.
- Commits locales con rutas explícitas; sin push ni instalaciones.

## Review Focus

1. Una denegación no implica vulnerabilidad: severidad informativa.
2. Un diagnóstico de check no debe imprimir el secreto que estaba buscando.
3. Metadata tipada de otro módulo/versión o incompleta no acredita una verificación.
4. La compatibilidad con metadata mínima heredada no valida automáticamente datos tipados nuevos.
5. Menú de comprobación local y navegación probados sin ejecutar herramientas activas.

### Task 1: Informes y verificación de solo lectura

**Files:** `CyberSecurity-Framework/11_Reports/lib/catalog.py`, `tests/verify_postexploitation_real.py`, `tests/test_postexploitation_{reports,verify}.py`.

**Interfaces:** `parse(path, repo_root)` conserva ParseResult; `verificar(manifest,nombre)` mantiene códigos 0/1/2 y lectura sin escritura. Metadata mínima heredada se contrasta como antes; metadata que declara módulo/versión debe ser 06 v1 válida.

- [x] Escribir pruebas para denegación informativa, redacción de checks, versión booleana, módulo ajeno y manifiesto tipado incompleto.
- [x] Ejecutar unittest y observar rojo por los contratos que faltan.
- [x] Corregir únicamente severidad, mensajes y validación de lectura, reutilizando validador 06 cuando corresponda.
- [x] Ejecutar suite 06 y run_reports en copia aislada; código 0.

### Task 2: Cobertura de navegación y cierre documental

**Files:** `tests/test_postexploitation_menu.py`, `tests/run_postexploitation.sh`, README 06 y documentos de cierre/traspaso.

**Interfaces:** llamadas del menú sustituidas por frontera inocua; ningún test dispara hojas reales. Entrar/salir/EOF/comprobación local/lista/visor deben ser concluyentes sin operaciones activas.

- [x] Añadir pruebas de comprobación local, EOF y navegación con fronteras simuladas; distinguir pruebas nuevas de caracterización de fixes RED→GREEN.
- [x] Corregir referencias documentales erróneas a 05 y documentar limitaciones reales.
- [x] Ejecutar regresiones pertinentes aisladas, sintaxis con stderr, AST Python, git diff --check y hashes de fuentes. Once suites pasan, run_tests sigue rojo: diez fallos reproducidos en padre y un SSTI intermitente de causa no determinada.
- [x] Revisión independiente exclusiva de mantenimiento; corregir problemas importantes con pruebas.
- [ ] Commit local de rutas explícitas y traspaso: mantenimiento cerrado; revisión operacional integral fuera del alcance y no implementada; 07 no iniciado.
