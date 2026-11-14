# Pruebas globales y SSTI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reparar las regresiones del runner global y el falso negativo SSTI por colisión del token.

**Architecture:** Cambios acotados a pruebas y a la comprobación de baseline SSTI. Un helper de pruebas concentra el ciclo de vida de servidores HTTP y su limpieza exacta. Verificación sobre copias sintéticas, nunca sobre datos del checkout.

**Tech Stack:** Bash, Python unittest, fixtures HTTP locales, namespaces Linux existentes; sin instalaciones.

**Spec:** `docs/superpowers/specs/2026-11-14-pruebas-globales-design.md` (alcance aprobado por el usuario).

## Global Constraints

- Sin retirar capacidades, tocar datos reales, commit ni push.
- No iniciar otro módulo ni integrar automáticamente los cambios.
- HOME/config sintéticos, PATH allowlist, namespace de red con solo loopback y namespace PID.
- No ejecutar escáneres reales; declarar el caso opcional sqlmap real omitido.
- Conservar sleeps del servidor, umbrales, repeticiones, frenos y pruebas temporales.
- No aumentar un timeout sin evidencia.

## Review Focus

- Token que contiene 49 junto a un 49 real: sigue sin confirmar SSTI (Task 2).
- Servidor que no arranca: el helper falla y reapéa su hijo, sin convertir fallo en éxito (Task 1).
- Interrupción del runner: detener hijos propios sin afectar otro servidor (Task 1).
- Dos puertos simultáneos: limpiar uno conserva íntegros los artefactos del otro (Task 1).
- Evidencia anidada: afirmar pares reales y su contenido, no pasar por un glob vacío (Task 1).

---

### Task 1: Reparar contratos y recursos del runner

**Files:**
- Modify: `CyberSecurity-Framework/tests/run_tests.sh`.
- Create: `CyberSecurity-Framework/tests/fixtures/global_http_runtime.bash`.
- Create: `CyberSecurity-Framework/tests/test_global_http_runtime.py`.
- Modify: `CyberSecurity-Framework/tests/fixtures/http_target.py`, recibo opcional PID/puerto postbind para cerrar I1 de la revisión final.

**Interfaces:**
- Consume: `FW`, ruta del framework sintético; fixture `tests/fixtures/http_target.py`.
- Produce: `iniciar_servidor_http()` retorna 0 solo tras disponibilidad y asigna `HPORT`, `HTTP_SRV_PID` al shell padre.
- Produce: `detener_servidor_http()` detiene/reapéa el hijo propio registrado y limpia sus variables; operación repetible.
- Produce: `limpiar_evidencia_http()` elimina solo el directorio y resúmenes `.txt`/`.tsv` del `HPORT` registrado.
- El runner instala cleanup EXIT/INT/TERM sin perder el código de salida; las pruebas importan el helper sin ejecutar la suite.

- [ ] Registrar la reproducción completa original; distinguir fallos reales de contaminación por `bash -x` en stderr capturado. Para medir, poner PS4 dentro del proceso y usar BASH_XTRACEFD separado, o registrar tiempos por sección sin xtrace.
- [ ] Añadir regresiones del helper: PID visible al padre, disponibilidad real, stop/reap, fallo de arranque, cleanup repetible, otro servidor y otro puerto intactos; comprobar interrupción en subproceso aislado. Ejecutar antes del helper: debe fallar por la interfaz ausente. Conservar también la reproducción roja del helper antiguo ya obtenida.
- [ ] Implementar el helper con PID obtenido de `$!`, readiness acotada con curl `--max-time`, kill/wait de ese hijo y rutas exactas, sin comodines entre puertos. Conectar las seis tandas del runner y sus traps.
- [ ] Sustituir recuentos históricos por fixtures literales de gramática (sin parámetros, uno obligatorio, uno opcional, varios y modo manual); recorrer las entradas para comprobar modos válidos y slots no vacíos cuando el modo sea slots. Mantener los casos concretos existentes; no regenerar expectativas desde el parser bajo prueba.
- [ ] Corregir rutas SQLi a `sqli_findings_192.0.2.1_443.txt` y `sqli_findings_192.0.2.2_443.txt`. Afirmar 90 filas fuertes por objetivo, URL/puerto correctos y cero confirmados con el stub sqlmap sin veredicto; catch-all cero filas. Comprobar códigos de salida.
- [ ] Corregir lecturas de evidencia a los subdirectorios `run_*`: encontrar pares `.req`/`.resp` y validar contenido no vacío, cabecera y límite de tamaño. Mantener los asserts de contexto y resumen.
- [ ] Reproducir los asserts sqlmap de historial/layout sin xtrace: dos llamadas previas no deben contaminar el recuento de la tercera. Inspeccionar `sqlmap_request.sh:208,281,304–305`; localizar el directorio de la ejecución observada y exigir sus dos logs y un resumen, sin borrar historial para forzar el resultado. Buscar la copia de Host reescrito en ese run, no en el layout plano antiguo.
- [ ] Medir las pausas con y sin `HTTP_INJECT_RETARDO=0` en el fixture; si explican la duración, fijar ese valor solo para la suite sintética. No tocar el default del producto ni sleeps temporales del fixture.
- [ ] Ejecutar `python3 -m unittest discover -s tests -p 'test_global_http_runtime.py' -v` en sandbox: todos pasan; verificar stderr y que no quedan procesos del helper. No commit.

### Task 2: Corregir SSTI sin ocultar contenido real de baseline

**Files:**
- Modify: `CyberSecurity-Framework/05_Exploitation/web/http_inject.sh`, `probar_ssti()`.
- Create: `CyberSecurity-Framework/tests/test_ssti_baseline.py`.

**Interfaces:**
- Consume: fixture HTTP local y runner con `bash -c 'RANDOM=$1; shift; source "$@"'` para semillas controladas, sin añadir una opción pública al producto.
- Produce: mismo TSV/evidencia/clasificación; el token reflejado ya no cuenta como 49 preexistente.

- [ ] Añadir casos de integración: `/ssti` con semillas 1 y 5 produce exactamente un `CONFIRMADO/ssti`; `/mostrar49` con ambas produce cero; `/echo` con token que contiene 49 produce cero. Usar HOME/config y salida aislados; `HTTP_INJECT_RETARDO=0`.
- [ ] Ejecutarlos antes del fix: semilla 5 en `/ssti` falla (reproducción previa: 0 frente a 1). Mantener el caso con 49 real como testigo negativo.
- [ ] En `probar_ssti()`, comprobar presencia previa de 49 después de retirar únicamente la cadena literal TOKEN del cuerpo de baseline. No normalizar otros números ni suprimir 49 genuino; no cambiar las otras clases.
- [ ] Ejecutar `python3 -m unittest discover -s tests -p 'test_ssti_baseline.py' -v` en sandbox: todos pasan, varias repeticiones sin depender de suerte. No commit.

### Task 3: Verificación integrada y entrega

**Files:**
- Create: `docs/PRUEBAS-GLOBALES-2026-11-14.md`.
- Modify: `CyberSecurity-Framework/tests/run_reports.sh`, solo fixture de sesión legacy descubierto en la regresión (ruling en ledger).
- Update: notas de reanudación/AGENTS solo para registrar el estado alcanzado, preservando contenido ajeno.

**Interfaces:**
- Consume: fixes Tasks 1–2 y evidencia roja/verde.
- Produce: informe con comandos, resultados completos, omisiones y recursos preservados.

- [ ] Repetir `tests/run_tests.sh` completo sobre fuentes corregidas, copia git sintética y aislamiento descrito; guardar duración por bloque, rc y resumen. Diagnosticar cualquier fallo adicional antes de modificarlo.
- [ ] Ejecutar regresiones pertinentes: `run_e2e.sh`, `run_smoke.sh`, `run_reports.sh`, `run_enumeration.sh`, `run_scanners_menu.sh`, `run_exploitation.sh` si existe; comprobar sus requisitos y aislamiento antes de lanzarlas. Registrar por nombre suites omitidas o fallidas.
- [ ] Verificar Bash con rc y stderr vacío, Python por AST sin bytecode en el checkout y `git diff --check`.
- [ ] Revisar diff contra alcance y hacer revisión final independiente solo si el usuario elige una modalidad que la autorice; de otro modo declarar revisión propia.
- [ ] Confirmar hash/modo intactos de scope.yaml/targets.txt locales sin leer sus contenidos; conservar logs y workspaces. Documentar que sqlmap real no se probó, sin declarar compatibilidad operacional ni toda la rama verde sin evidencia.
- [ ] Entregar archivos modificados, resultados y límites. Sin commit, merge ni push.

## Autorrevisión del plan

Scope cubierto por Tasks 1–3. Las cinco condiciones de Review Focus tienen
pruebas asignadas. No se modifica ningún módulo nuevo ni una herramienta ajena
al defecto SSTI. El detalle de duración queda condicionado a mediciones, no a
una hipótesis tratada como hecho.

Baseline completado: 371 pasan / 12 fallan. Uno (aviso Content-Length contado
diez veces) está contaminado por xtrace en stderr y necesita repetición sin esa
instrumentación. Los restantes corresponden a recuentos/rutas SQLi y layouts
históricos HTTP/sqlmap. El caso opcional de sqlmap real fue omitido por PATH.
