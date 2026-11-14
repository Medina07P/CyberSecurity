# Exactitud y consentimiento de peticiones web — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Corregir S-I5/S-I6: petición transmitida coherente, cero sondeos previos al consentimiento y403 indeterminado sin señal explícita.

**Architecture:** Añadir composición pura de campos sin alterar los helpers de sustitución individual; integrar las dos hojas existentes. Usar el aislador y fixture del plan de consentimiento con una selección web fija nueva, no el runner heredado de explotación.

**Tech Stack:** Bash/Python3 estándar, urllib.parse/json, unittest, curl doble obligatorio.

**Spec:** `docs/superpowers/specs/2026-11-14-cross-module-corrections-design.md` §7,12–14.
**Prerequisite:** `2026-11-14-cross-module-consent.md` implementado/revisado; interfaces `CrossModuleFixture`, `group_cases/group_grants`, `validated_selection` y permiso por selección disponibles. No ejecutar este plan antes de cerrar ese gate.

## Global Constraints

- «No push ni mergeadevelop sin petición expresa posterior.»
- «Pruebas SOLO en copias allowlist, HOME/sesión/config/wordlists/salidas sintéticos, PATHcerrado y dobles obligatorios de backend/red/GUI/sudo.»
- «Preservar fixturesfinales, fuentes, recibos/logs y todos los runsanteriores.»
- «Sin fallback, `--unsafe`, suiteglobal ni discoverydeotrosrunners por comodidad.»
- Conservar `wrong-1…wrong-N` y máximo200 de la sonda; login conserva sus límites200/default y1000/tope duro, sin nuevas técnicas/candidatos/paralelismo.
- Mecanismos de consentimiento específicos actuales se conservan; no instalar permiso global ni leer config/evidencia real para verificar.
- Runtime/probes/tests/imports del repo solo dentro de selección revisada y comando exacto autorizado. Ningún curl/socket/backend real, ni siquiera loopback/IP documental.

## Review Focus

- Usuario y contraseña en ubicaciones distintas o nombres repetidos: no cambiar un campo ajeno ni enviar parcialmente; Tasks1–2.
- `&`, `+`, `%`, Unicode y espacios: valor lógico literal una vez, no nuevos parámetros; Task1.
- Usuario capturado percent-encoded sin override: no doble codificarlo al sustituir contraseña; Task2.
-403 rápido/lento con/sin Retry-After/cuota: precedencia y corte correctos; Task3.
- Esquema ausente/inválido, EOF o diccionarioURL cancelado: cero transporte; Tasks2–3.

## Archivos e interfaces

Rutas relativas al framework:
- Crear `00_Config/lib/http_fields.py`: `FieldChange(location: str, name: str, value: str)` inmutable y `compose_request(target: str, body: str, content_type: str, changes: tuple[FieldChange, ...]) -> tuple[str, str]`.
- Extender `00_Config/lib/http_request.bash`: `hr_request_pair` y `hr_pair_part`, conservando `hr_target_with`, `hr_body_with`, `hr_params` y sus contratos existentes.
- Modificar `05_Exploitation/web/{web_login_bruteforce,rate_limit_probe}.sh`.
- Crear `tests/test_cross_web.py`; ampliar solo mapas/fuentes exactos del fixture y selección del plan previo.
- Actualizar guías05, `docs/RATE-LIMIT-2026-10-31.md`, `docs/MENU-OPCIONES.md`, contrato de fuentes y equivalentes de regresiones heredadas afectados.

Nuevo selector fijo: `--cross-web`. Comando previsto: `python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --cross-web`. Gate estático y autorización del controlador por SHA; regresión09/consentimiento con sus selectores también autorizados por separado, no anidados.

## IDs y solicitud específica de descartables

Prefijo `test_cross_web.WebTests.`. Dos métodos puros sin permiso destructivo:
`test_pair_composes_locations_and_literals`, `test_pair_rejects_ambiguity`.

Permiso NUEVO propuesto, pendiente de confirmación explícita, solo scratch nuevo/ABIverificado para:
- `test_login_req_transmits_each_candidate`
- `test_login_has_no_preconsent_transport`
- `test_rate_has_no_scheme_probe`
- `test_rate_403_and_existing_verdicts`
- `test_web_inputs_and_previous_runs_are_preserved`

Los cinco pueden observar código antiguo que reemplaza temporales nuevos; no cubren datos/credenciales reales ni logs/evidencia/fixtures de otras ejecuciones. El inventario25 de09 sigue intacto y no se concede permiso por prefijo.

### Task 1: Composición pura y adaptador Bash

**Files:** http_fields.py/http_request.bash, dos casos puros y mapas/fuentes de selección.
**Interfaces:** `hr_request_pair <loc> <name> <literal> [<loc> <name> <literal>]` devuelve un único JSON `{target, body}` por stdout. `hr_pair_part target|body` consume ese JSON por stdin e imprime solo el valor. Datos al helperPython por stdin delimitadoNUL, no interpolación de shell ni argv con nuevas copias de secretos. Máximo1MiB de entrada total y dos cambios; error se propaga antes de enviar.

- [ ] Escribir primero `test_pair_composes_locations_and_literals`: form/form, query/query, form/query, JSON/query y JSON anidado/lista; valores `a&b=+%`, comillas, barra, espacio yUnicode. Verificar valores lógicos con decodificador independiente, método/campos ajenos preservados y dos composiciones que parten del original.
- [ ] `test_pair_rejects_ambiguity`: nombre seleccionado duplicado o alias percent-encoded, usuario/password mismo campo, JSON con claves duplicadas/ruta no inequívoca, ubicación inválida, más de dos cambios y entrada mayor1MiB. No mutar entrada ni fabricar petición parcial.
- [ ] Escribir también los cinco métodos de Tasks2–3 antes del primer RED, con imports nuevos dentro de métodos. Añadir selección cerrada/web con los sieteIDs exactos y fuentes de tests/helper existentes; permisos de los dos métodos puros son falsos. Revisión estática de la ampliación y autorización exacta antes del RED; helper ausente debe fallar dentro de los casos, no romper discovery.
- [ ] Implementar `compose_request`. Para form/query conservar pares crudos ajenos; identificar el nombre crudo seleccionado de `hr_params`, rechazar ambigüedad al decodificar nombres y codificar solo el override literal una vez. ParaJSON conservar significado/tipos ajenos y serializar mediante json real.
- [ ] Implementar adaptador de protocolo NUL por stdin y extracción JSON; nunca eval/exec ni separar datos por una línea/pipe que pueda estar en un valor. Los errores de cada proceso deben llegar al consumidor.
- [ ] Revisión+gate y `--cross-web` autorizado. Expected: los dos casos puros GREEN; demás casos presentes y resultados explícitos, todavía RED cuando dependen de producción no implementada. Nunca omitirlos para aparentar cierre.
- [ ] Commit e informe, preservando la regresión de consumidores antiguos del helper en fuentes copiadas.

### Task 2: Login .req realmente transmite el candidato y esquema explícito

**Files:** web_login_bruteforce.sh, tres casos login/preservación y mapas exactos.
**Consumes:** API de composición Task1. `BRUTE_ESQUEMA=http|https` explícito cuando `.req` no contiene esquema inequívoco; el modoURLmanual conserva su esquema. `BRUTE_SI` mantiene su mecanismo específico documentado, sin nuevas concesiones globales.

- [ ] Escribir `test_login_req_transmits_each_candidate`: dos candidatos sintéticos distintos llegan a curl doble en form,JSON,query y ubicaciones cruzadas. Usuario no sobreescrito queda intacto; override de entorno/tercerargumento se aplica una vez en su ubicación. Comparar argv/cuerpos reales del doble, no el TSV del producto.
- [ ] `test_login_has_no_preconsent_transport`: esquema ausente/inválido incluso conpuerto443, campo ambiguo/entrada inválida, falta consentimiento y EOF: cero curl, incluidas descargas de diccionario. Los cambios manuales de modo siguen explícitos.
- [ ] `test_web_inputs_and_previous_runs_are_preserved`: fuentes/.req/diccionario y artefacto anterior intactos; dos ejecuciones crean nuevos directorios. No leer config ni historial real.
- [ ] Staticreview+autorización exacta y RED observado antes de modificar enviar/esquema. No reemplazar transporte del producto por una función vacía: solo curl es doble con respuestas/cuerpos locales programados.
- [ ] En `enviar`, construir par desde captura original, aplicar password y solo usuario realmente sobreescrito, comprobar todos los rc y formar URL usando target resultante. No reutilizar `hr_url` con HR_TARGET original ni acumular estado entre intentos.
- [ ] Sustituir autodetecciónHTTPS por selección puramente local: override `BRUTE_ESQUEMA` válido, o esquemaHTTP(S) inequívoco de captura; faltar ambos o override inválido retorna error sin tráfico. Puerto no es esquema. Mantener método/cookies/filtrado actual de cabeceras, topes y modo manual; no añadir nuevos intentos.
- [ ] Revisar+autorizar selector y observar GREEN de casos login. Expected: cada candidato correlaciona con respuesta programada, capturaoriginal nunca sustituye al candidato por accidente; advertir que diferencial no certifica por sí solo credencial válida.
- [ ] Commit y reporte de casos/resultados reales, sin credenciales reales.

### Task 3: Rate-limit sin sondeos previos y403 no determinado

**Files:** rate_limit_probe.sh, dos casos rate y registro exacto.
**Consumes:** validación de ubicación/ambigüedad de Task1 sin romper sustitución de un único password; `RATE_LIMIT_ESQUEMA=http|https` obligatorio cuando la captura carece de esquema inequívoco.

- [ ] `test_rate_has_no_scheme_probe`: con permiso y esquema explícito se registran exactamente Npeticiones de login, nunca GETextra. Sin esquema/permiso, input/rango inválido o EOF:0curl. Probar443/8443/8080 yHost sinpuerto sin inferirTLS.
- [ ] `test_rate_403_and_existing_verdicts`: tabla literal:401estable→SIN_FRENO;403sinsenalrápido/lento→NO_DETERMINADO/rc1/1envío;403conRetry-After o cuota0→FRENADO/1envío;429/503→FRENADO;000y2xx/3xx ambiguos→NO_DETERMINADO;401→403 corta sin siguienteintento. Mantener retardo de401 y mínimo10muestras con tiempos sintéticos, sin dormir para obtener el resultado.
- [ ] Revisión/gate+RED del selector antes del arreglo.
- [ ] Eliminar detección activa de esquema y validar override antes del transporte. Añadir corte403sinseñal después de comprobar frenos explícitos, con causa propia, sin simular cambio de código ni permitir que retardo convierta403enfreno.
- [ ] Conservar tope200, `wrong-N`, cambio exclusivo de password y señalRetry-Afterliteral; TSV/refuerzo de contador muestran exactamente llamadas del doble. Ningún reintento nuevo ni interpretación de códigos no investigados.
- [ ] Revisión/gate y GREEN del selector, todos los casos web ya presentes; commit e informe.

### Task 4: Documentación de contrato y regresión del conjunto

**Files:** guías05/rate/manual/MENU y contratos correspondientes; sin ampliar backends.

- [ ] Documentar esquema explícito y migración de autodetección, campos/ambigüedad, límites y clasificación403; distinguir candidatos de éxito acreditado. No imprimir secretos en ejemplos/versionado.
- [ ] Adaptar regresiones heredadas equivalentes a curl doble y entradaesquemaexplícita, sin ejecutar run_exploitation/run_tests ni sus servidores. Mantener las aserciones de otros consumidores de http_request.
- [ ] Revisar fuentes/selección/runtime/grants y capacidades antes/después. No tocar el empaquetado11 ya corregido ni gatesSQLmap independientes.
- [ ] Autorizar por separado `--cross-web`, `--cross-consent` y `--suite` tras revisión de este SHA. Expected: selecciones completas sin fallos/errores/bloqueados y omisiones explícitas; todos los logs/fixtures conservados.
- [ ] Revisión independiente final del bloque, commit documental y cierre acotado. No inferir auditoría real ni cierre global por estos resultados.

## Self-review / handoff

Esquema/consentimiento→Tasks2–3; composición/escape/ambigüedad→Tasks1–2; clasificación→Task3; cinco riesgos de revisión tienen métodos concretos. Interfaces de Task1 coinciden con consumidores deTask2. El plan conserva topes/modos, no inventa login masivo ni otras técnicas. Confirmar plan y la solicitud precisa de descartables antes de ejecutar; método subagentes retenido.
