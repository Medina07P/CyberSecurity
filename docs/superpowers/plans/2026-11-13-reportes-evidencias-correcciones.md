# Informes desde evidencias existentes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generar informes fieles a las evidencias de ejecuciones anteriores, con atribución, cobertura y confianza explícitas, sin acciones operacionales.

**Architecture:** Conservar el motor Python determinista y sus renderizadores. Corregir primero los lectores y lanzadores existentes; añadir cobertura de fuentes anteriores mediante adaptadores explícitos de metadata, no búsqueda de palabras ni ejecución de herramientas.

**Tech Stack:** Python estándar, Bash, unittest y fixtures sintéticas; sin dependencias nuevas.

**Spec:** `docs/superpowers/specs/2026-11-05-informes-automatizados-design.md`, con la petición del usuario de 2026-11-13: informes desde evidencias de módulos anteriores; revisar y corregir defectos. Ampliación aprobada por el usuario para ejecución inline sin subagentes.

## Global Constraints

- No red, adquisiciones, sudo, instalaciones ni ejecución de módulos previos.
- No leer configuración, perfiles, credenciales ni evidencias reales para las pruebas.
- Preservar cambios locales de `00_Config/scope.yaml` y `targets.txt`.
- Pruebas antiguas únicamente en copia limpia, con HOME, configuración y sesión sintéticos.
- Un objetivo por informe salvo `--todos` explícito; metadata sin atribución no se etiqueta con la sesión.
- Un archivo, una captura, una cadena CVE o un estado de ejecución no prueban por sí solos una vulnerabilidad.
- Sin push ni integración automática; no declarar compatibilidad operacional ni custodia legal.

## Enfoques

1. **Corrección puntual:** reparar CLI, aislamiento y falsos positivos, manteniendo la cobertura actual. Menor trabajo, pero no resuelve la omisión de evidencias anteriores.
2. **Integración conservadora (elegido y aprobado):** lo anterior más cobertura explícita y adaptadores de metadata de módulos anteriores. Contexto OSINT/recon y referencias forenses/evidencias no se elevan a vulnerabilidades.
3. Reescribir el motor: descartado como propuesta; existen parsers y pruebas reutilizables y aumentaría el riesgo sin necesidad acreditada.

## Review Focus

- Una sesión ausente o un JSON de otro objetivo no debe ampliar silenciosamente el alcance.
- Un último intento fallido, incompleto o con identidad inválida no debe resucitar éxitos históricos.
- Metadata y referencias de evidencias privadas no autorizan lectura de cuerpos ni exposición de secretos.
- Fuentes no soportadas, dañadas o vacías no deben convertirse en conclusiones de cobertura total.
- Un fallo al generar no debe presentar ni abrir un informe anterior como recién generado.

## Evidencia del diagnóstico inicial

Base: copia de `HEAD` en `/tmp/opencode/reports-audit-jb9pcz94/repo`, con configuración, sesión y HOME sintéticos. Suite Python existente: **78 tests, rc 0**; log `baseline.log` en la raíz de ese sandbox. Reproducciones independientes: `reproduce.py` en esa misma raíz.

Defectos reproducidos:

1. CLI sin objetivo ni sesión activa `todos` y publica hallazgos de cualquier host con rc0.
2. `--desde-json` con `--objetivo 192.0.2.99` publica sin rechazo hallazgos de `192.0.2.10`.
3. `report_generator.sh --cliente cliente ...` consume el valor como tipo y falla por argumento ausente.
4. Parser de 05 admite paso CONFIRMADO/rc1 de un run NO_DETERMINADO, sin sidecar, como confirmado evaluable.
5. Dos manifiestos de 05 con cuerpo `[]` causan AttributeError en descubrimiento.
6. Nmap convierte una referencia documental CVE en hallazgo confirmado sin prueba de vulnerabilidad.
7. Masscan JSON queda ignorado sin cobertura/no_evaluable mientras una fuente Nmap permite evaluación positiva.
8. `run_all_reports.sh` solicita `--package` sin selección explícita; acreditado mediante stub, sin empaquetar datos.

Inspección adicional: OSINT escribe fuera de scans y documenta que 11 aún no lo consume; recon y forense también tienen árboles propios; 10 conserva inventario independiente. Esta revisión inicial no equivale a auditoría exhaustiva ni a corrección entregada.

### Task 1: Aislamiento de objetivo, CLI y relanzado desde JSON

**Files:** `CyberSecurity-Framework/11_Reports/report_engine.py`, `report_generator.sh`; crear `CyberSecurity-Framework/tests/test_reports_evidence_contract.py`.

**Interfaces:** conservar `run(argv) -> int`; usar `SESSION_FILE` para aislamiento y compatibilidad con el gestor; el modo agregado requiere `--todos` explícito. JSON debe validar estructura y concordancia de objetivo antes de escribir.

- [ ] Añadir pruebas: falta de objetivo falla sin archivos; SESSION_FILE sintético manda; JSON de otro objetivo se rechaza sin publicar; listas/tipos inválidos producen diagnóstico sin traceback; valores `cliente`, `tecnico` y `ambos` dentro de opciones se conservan.
- [ ] Ejecutar las pruebas y conservar fallos antes de implementar.
- [ ] Corregir resolución de sesión/alcance, validación previa y consumo de argumentos: solo el primer argumento posicional representa el tipo.
- [ ] Reejecutar pruebas y suite existente en copia aislada; comprobar compatibilidad de flags existentes.

### Task 2: Confianza y selección de evidencias existentes

**Files:** `CyberSecurity-Framework/11_Reports/lib/{sources,engine,model}.py`, `lib/parsers/{exploitation,nmap}.py`, `lib/catalog.py`; tests de Task1 y `test_report_engine.py`.

**Interfaces:** conservar `discover(scans_dir) -> list[Source]` y `parse(path, repo_root) -> ParseResult`. Contrastar contratos reales de 05/06 antes de reutilizar validadores; no ejecutar sus acciones.

- [ ] Escribir y ejecutar pruebas de las reproducciones 4–6 y de último intento fallido, manifiesto sin identidad, puertos distintos y mezcla de fuentes/hosts.
- [ ] Validar tipos, identidad, finalización y coherencia de estados/códigos de 05 con su productor; reportar metadatos insuficientes como no evaluables.
- [ ] Seleccionar históricos con identidad completa y orden publicado, sin atribuir manifiestos dañados por conjetura.
- [ ] Tratar referencias CVE de Nmap como candidatos, no explotación confirmada; elevar confianza solo con un formato de veredicto explícito y probado. Ajustar deduplicación para no aumentar confianza por asociación.
- [ ] Reejecutar pruebas y regresiones de informes, enumeración y postexplotación en sandbox; documentar cambios intencionales de confianza.

### Task 3: Cobertura de módulos anteriores y trazabilidad

**Files:** `CyberSecurity-Framework/11_Reports/lib/{sources,engine,render}.py`; nuevos `lib/coverage.py` y `lib/parsers/prior_modules.py`; pruebas sintéticas en `tests/test_reports_evidence_contract.py`.

**Interfaces propuestas:** añadir `cobertura: list[dict]` a `Collected`, con default vacío para compatibilidad. Cada entrada registra `modulo`, `fuente`, `objetivo`, `estado`, `motivo`; estados `evaluada`, `contexto`, `no_evaluable`, `no_soportada`. Serializar y reconstruir con default para JSON heredado.

- [ ] Inventariar contratos de productores 01–10 a partir de código y fixtures versionadas, no datos reales. Registrar qué módulos producen evidencia y cuáles solo configuran/orquestan.
- [ ] Escribir pruebas rojas de cobertura parcial, fuente desconocida, cero resultados válido, otro objetivo, corrupción, symlinks y metadata sin objetivo.
- [ ] Incorporar OSINT/recon como contexto atribuible; resultados estructurados compatibles como observaciones. Para artefactos ambiguos o no soportados, mostrar limitación, no extraer hallazgos por palabras clave.
- [ ] Referenciar metadata de 08/10 sin releer originales, cuerpos privados ni capturas. Declarar los límites de esa lectura: no equivale a verificar integridad ni autenticidad. No inferir objetivo forense ni vulnerabilidad desde etiquetas libres.
- [ ] Mostrar cobertura en Markdown/HTML técnicos y limitaciones agregadas sin rutas privadas en cliente; sustituir afirmaciones universales de pruebas completadas por afirmaciones limitadas a fuentes evaluadas.
- [ ] Verificar roundtrip de JSON antiguo/nuevo, paridad Markdown/HTML y ausencia de secretos con marcadores sintéticos.

### Task 4: Integración del gestor, ejecución de fase y documentación

**Files:** `CyberSecurity-Framework/11_Reports/run_all_reports.sh`, `CyberSecurity-Framework/cyber_framework.sh` (`quick_report`), `11_Reports/{README,FLUJO}.md`, nuevo `11_Reports/USE.md`, `docs/MANUAL-GESTOR.md`; nuevo `CyberSecurity-Framework/tests/run_reports_evidence.sh`.

**Interfaces:** generación exclusivamente offline; empaquetado se conserva como acción explícita de 10, no efecto lateral de informes. El resultado del motor debe identificar los archivos escritos para que el gestor no adivine rutas ni abra históricos.

- [ ] Probar con stubs que generar informes nunca invoca evidence_manager ni herramientas de los módulos; fallo de generación no lista/abre históricos; salida personalizada se respeta; EOF cancela sin actividad.
- [ ] Quitar empaquetado implícito y propagar rc; listar solo archivos de esta generación y respetar tipo solicitado/salida efectiva en fase y acceso R.
- [ ] Crear runner aislado con fuentes permitidas, configuración/HOME sintéticos y guardas sin leer evidencia real.
- [ ] Documentar fuentes soportadas, contexto/no evaluable, confianza y trazabilidad; actualizar instrucciones contradictorias de 01/11 si corresponde.
- [ ] Ejecutar suite dedicada y regresiones pertinentes solo en copia limpia; revisar Bash capturando stderr, AST Python y `git diff --check`.
- [ ] Registrar resultados, límites y pendientes; revisar diff completo antes de proponer integración. Sin commit ni push automáticos.

## Estado

- [x] Investigación inicial y reproducciones sintéticas.
- [x] Plan y revisión de coherencia: las cinco clases de Review Focus tienen casos en Tasks1–4.
- [x] Aprobación de alcance/enfoque por el usuario.
- [x] Implementación de Tasks1–4 y pruebas dedicadas.
- [x] Regresiones pertinentes y revisión propia final: suite144/GUARD OK y cinco regresiones rc0; entrega en `docs/INFORMES-EVIDENCIAS-2026-11-13.md`.
- [ ] Gate global verde: run_tests heredada alcanzó timeout180 con cuatro fallos observados. No integrar automáticamente.
