# Task4 — INITIAL: tests/docs/source contracts

**Estado: DONE_WITH_CONCERNS; runtime NOT RUN.** Base `95d260f`.
Cambios de contenido: `e503d23` (`test(web): strengthen manual wire oracles and document current contracts`).
Este informe se entrega en un commit documental posterior. No cierra Task4,
Task9/global09 ni el bloque web. No hay arreglo de producción WM1 en esta fase.

## Alcance y fuentes de autoridad

Se leyeron primero `task-4-brief.md`, `task-1-context.md` (Global Constraints y
contratos), el diseño aprobado §7/12–14 y las restricciones AGENTS suministradas.
Las APIs/fuentes aceptadas de Tasks1–3 fueron la autoridad, no el pseudocódigo
del plan: `http_fields.py`, `http_request.bash` y ambas hojas web actuales.
No se ejecutó ni importó ningún módulo del repo para inspeccionarlo.

## Entregables exactos

| Archivo | Cambio |
|---|---|
| `CyberSecurity-Framework/05_Exploitation/README.md` | Contrato vigente de ambas hojas: esquema local obligatorio/override/autoridad absoluta literal; campos e identidades ambiguas; codificación literal una vez; precedencias; presupuestos reales; modo manual crudo y WM1 abierto; topes, tiempos, veredictos, privacidad y límites heurísticos. También cierra un fence Markdown previo al menú |
| `docs/RATE-LIMIT-2026-10-31.md` | Migra ejemplos/tabla de esquema sin sondeo,403 sin señal y precedencias; rutas run únicas; distingue verificación histórica de la fase actual NOT RUN |
| `docs/MANUAL-GESTOR.md` | Resumen operativo web, consentimientos específicos, esquema/autoridad, campos, WM1 y candidato no probado |
| `docs/MENU-OPCIONES.md` | Actualiza solo las dos filas web existentes, sin agregar/quitar hojas o submenús |
| `docs/EXPLOTACION-2026-11-10.md` | Corrige `[objetivo]` por la posición real `[intentos]` de rate |
| `CyberSecurity-Framework/tests/test_cross_web.py` | Refuerza oráculos dentro de los siete métodos existentes, sin nuevos IDs ni omisiones |
| `CyberSecurity-Framework/tests/test_automation_contract.py` | Dentro de `Contracts.test_every_leaf_explained`, exige18 tokens concretos en las dos filas web y uso del compositor/sin detección legacy en sus fuentes; no nuevos IDs |

No se refrescaron baselines ni se modificaron manifiestos, fixture, doble curl,
runtime, selección, permisos, sandbox, fuentes productivas o configuración del
operador. Los cambios nuevos de contratos09 también requieren gate posterior
del controlador; no fueron ejecutados como sustituto de revisión independiente.

## WM1: procedencia real, no un GREEN nuevo

Se inspeccionaron como **datos sintéticos retenidos** estos archivos:

```
/tmp/opencode/automation-isolated-3bf6247d45e542b3879e6033b16b42b9/work/fixtures/case-ye8t1mc4/fixtures/cross-web-mapxvhju/harness-output/curl-records.jsonl
/tmp/opencode/automation-isolated-3bf6247d45e542b3879e6033b16b42b9/work/fixtures/case-ye8t1mc4/fixtures/cross-web-mapxvhju/harness-output/curl-result-643c9dee67684ea0b648fb35d0fdfb1d.json
```

El recibo terminal tiene SHA256
`4092b43570a0b9118d5ec6f4ed20ed314f59d6a7ffe8538f0a2c2eb6bbc7909f`.
Su body y argv registran literalmente `password=a{password}b=+%`, con URL
`http://example.test:8080/login`; no el candidato `a&b=+%` intacto.
No se modificaron ni recrearon recibos/fixtures. Los valores aquí son sintéticos.

Inspección de fuente: `enviar_manual`, líneas246–247 de la fuente inalterada,
usa RHS sin comillas internas en sustituciones Bash. La expansión de `&` por
`patsub_replacement` explica el marcador observado. Además las dos sustituciones
sucesivas pueden reinterpretar un candidato con aspecto de `{usuario}`; este
riesgo se cubre por separado, no se presenta como una reproducción ya ejecutada.

Oráculos escritos, **sin observar todavía RED**:

- `test_login_req_transmits_each_candidate`: ocho subcasos manuales con cuerpos
  esperados literales independientes de Bash/compositor. Varía por separado
  candidato y usuario: `&` (con `=+%`), barra inversa, `{password}` y `{usuario}`.
  Cada fixture nuevo contiene solo dos candidatos sintéticos y conserva el modo
  manual real: cuerpo crudo `text/plain`, método PATCH, URL HTTP explícita8080,
  cabecera ajena, segundo intento y ausencia de estado heredado. No se exige
  codificación form/JSON al modo manual ni se sustituye negocio por un no-op.
  Un marcador introducido como dato debe permanecer literal, no expandirse otra vez.
- `test_login_has_no_preconsent_transport`: conserva el smoke manual positivo
  existente de URL/conteo y añade comparación exacta de ambos cuerpos, incluido
  `password=a&b=+%`. El smoke ya no puede pasar ignorando el cuerpo erróneo.
- Ambos IDs login pueden presentar fallos WM1 en el próximo run; no se fija de
  antemano un número de fallos/subcasos ni se oculta ninguno con skip/xfail.

El65units+7PASS de `95d260f` en
`/tmp/opencode/automation-isolated-98870a222a804df89504b477b934015b/` es el
resultado anterior comunicado por el controlador, no una ejecución de esta fase
ni acreditación de estos oráculos nuevos. El antiguo éxito de URL/conteo no
valida el cuerpo. Producción WM1 queda **sin tocar** hasta revisión estática y
RED del comando exacto autorizado `--cross-web`; después se requiere reanudación
explícita para el arreglo mínimo y un nuevo gate/GREEN.

## Equivalentes heredados y cobertura preservada

No se ejecutaron `run_tests.sh`, `run_exploitation.sh`,
`test_exploitation_web.py` ni `fixtures/http_target.py`; tampoco se importaron o
levantaron sus servidores. No se cambiaron sus aserciones ni las de otros
consumidores de `http_request.bash`. Esos entrypoints antiguos NO quedan
certificados/migrados íntegramente por este trabajo.

Los equivalentes afectados se escribieron en los IDs web ya autorizados para
futura revisión; todo transporte de estos métodos usa el doble obligatorio del
fixture existente, sin nuevas fuentes/runtime:

| Contrato heredado | Equivalente dentro de la selección actual |
|---|---|
| Arranque: Uso, petición ausente/sin Host/sin password,500 rechazado,08 decimal y0310=310 | Añadidos a `test_rate_has_no_scheme_probe`, con esquema explícito, diagnóstico y cero recibos curl |
| Segundo nombre distinto que parece password | Mismo ID: aviso conservado y cuerpo literal `password=wrong-1&password2=untouched`, sin tocar el segundo |
|20×401 sin freno y429 al cuarto sin quinto, Retry-After7 literal | Añadidos a la tabla de `test_rate_403_and_existing_verdicts`; conteo de recibos y TSV correlacionados |
|429/503 inicial, cuota agotada, fecha Retry-After,403,200/302,000, retardo≥10 y no evaluado con<10 | Tabla existente conservada; añade verificación exacta de ms, respuesta inicial guardada, respuesta de freno y anuncio del siguiente solo cuando realmente se cortó antes del tope |
| Redacción del password query en informe | Añadida al caso query del ID rate sin sondeo: cuerpo ajeno intacto, informe sin valor capturado y con `password=***` |
| Runs distintos y respuesta inicial por tanda de `test_exploitation_web` | `test_web_inputs_and_previous_runs_are_preserved` conserva bytes/modos/identidad de fuentes/inputs/runs previos; añade existencia de respuesta inicial en ambos runs rate |
| Contrato de helpers individuales consumidos por http_inject/SQLmap | Aserciones previas de `hr_target_with`, `hr_body_with`, `hr_params` y JSON anidado permanecen intactas en el método puro; ninguna API legacy modificada |
| Inventario/finalidad de las dos hojas | Contrato documental09 reforzado dentro de su ID existente; ninguna hoja ni capacidad retirada |

No se afirma equivalencia de toda la suite legacy: sus checks de slots/dangerous
y avisos scope quedan preservados en sus fuentes originales, no portados ni
ejecutados aquí. No se añadió `params.bash` ni otra fuente a la selección web
para ejecutar esos checks por comodidad.

## Matriz de preservación antes/después

- Los mismos siete IDs web en el mismo orden, cinco grants preexistentes y dos
  puros sin grant. Sin nuevos selectores, aliases, IDs, skip, xfail o filtros.
- API pública/capacidades intactas: `.req`/manual, diccionario local/URL,
  método/cookies/cabeceras, ubicaciones query/form/JSON, usuario env/argumento,
  login200/default y1000/tope, rate20/default y200/tope, `wrong-N`, delay/timeouts,
  clasificación y artefactos existentes. Ningún candidato/técnica nueva de producto.
- Sin modificación de los tres gates SQLmap, otros consumidores HTTP ni
  empaquetado11. Los datos/artefactos históricos y todas las fuentes se conservan.
- La documentación distingue salida «credencial válida» del producto de prueba
  real de autenticación: solo heurística de candidato, no identidad acreditada.

## Comprobación estática realizada

Todos los comandos siguientes retornaron0; no hubo pruebas, imports del repo,
helpers, launcher, doble curl ni producto ejecutados:

1. `git status --short` (inicial vacío), `git rev-parse --short HEAD` → `95d260f`.
2. Lecturas/grep de fuentes y de los dos recibos sintéticos citados; solo datos.
3. `git diff --check` → sin salida (repetido tras edición).
4. `bash -n CyberSecurity-Framework/05_Exploitation/web/web_login_bruteforce.sh CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh CyberSecurity-Framework/00_Config/lib/http_request.bash 2>&1`
   → sin stdout/stderr, rc0; fuentes productivas inalteradas.
5. `python3 -I -B -c` con biblioteca estándar exclusivamente
   (`ast,json,pathlib,subprocess`): `ast.parse` de los dos tests modificados;
   comparación con texto de `git show 95d260f:<archivo>` → mismos siete IDs web
   en orden y mismos IDs del contrato09. `json.loads` del inventario existente
   → siete casos/cinco grants. No se ejecutó el AST ni se importó el repo.
6. Otro `python3 -I -B -c`, solo `ast,hashlib,json,pathlib,subprocess`:
   allowlist exacta del diff de siete archivos tests/docs, sin producto/runtime;
   `ast.literal_eval` de las constantes de tokens del nuevo contrato y búsqueda
   textual en MENU →18 tokens presentes/dos filas de cuatro celdas; SHA256 y
   `json.loads` del recibo WM1 → cuerpo erróneo histórico confirmado como datos.
7. `git diff --stat` y lectura completa del diff de ambos tests para self-review.

Estos checks no son65units/7tests nuevos ni RED/GREEN. Tampoco son revisión
independiente o prueba de sandbox/hostil/compatibilidad operacional.

## Pendientes y gate de devolución

1. Revisión estática independiente del SHA combinado, incluidos estos nuevos
   oráculos, el contrato09 y todos los casos/rutas fuente conservados.
2. Autorización exacta del controlador para `--cross-web` y observación del RED
   WM1 con recibos frescos. Ninguna autorización se deriva de este informe.
3. Reanudación para arreglo mínimo de producción manual, nueva revisión/gate,
   GREEN fresco del conjunto completo. No reinterpretar recibos antiguos como GREEN.
4. Regresiones `--cross-consent` y `--suite` por separado siguen pendientes de
   revisión/autorización; toda combinación nueva necesita gate nuevo.
5. Revisiones finales y cierre acotado siguen pendientes. No se afirma validez
   de credenciales, auditoría real, compatibilidad universal, custodia legal ni
   cierre global. No push/merge/limpieza/descartes ni cambios de configuración.

## Phase2 WM1 — implementación estática tras RED real (2026-11-14)

**Entrega de código: implementado, revisión independiente/nuevo GREEN pendientes.**
Base autorizada `18cb1f2`. Esta sección actualiza el estado; la entrega INITIAL
anterior permanece como historia exacta de aquella fase. No se ejecutó runtime
nuevo en esta reanudación. El commit de esta fase contiene esta sección, el
arreglo manual y tres actualizaciones documentales; su SHA se comunica al devolver.

### RED del controlador inspeccionado como datos

Raíz conservada:
`/tmp/opencode/automation-isolated-41fb611a6a694e69a279dd09570cab8b/`.
Se leyeron `evidence/host-wait.json`, `cross-web.json`,
`cross-web-sandbox-units.json`, `cross-web-selection.json`, los stderr de casos3/4
y metadata `launch.json`; manifiesto y tres fuentes staged solo para procedencia.

- `host-wait.json`: EXIT/rc1.65units PASS.7casos web,4 fallos de aserción,
  0errores/0skips/0BLOCKED. Puros, `.req`, rate y preservación sin fallo observado.
- Caso3: tres subcasos manuales fallaron. Candidato `a&b=+%` produjo
  `a{password}b=+%`; candidato literal `{usuario}` se convirtió en `plain-user`;
  usuario `a&b=+%` produjo `a{usuario}b=+%`. Los restantes subcasos no figuran
  fallidos. Son diferencias de body del doble obligatorio, no fallos de política.
- Caso4: cuarto fallo, smoke manual: cuerpo `password=a{password}b=+%` en vez
  de `password=a&b=+%`. El segundo cuerpo con comilla/Unicode coincidió.
- Esto acredita el RED de las expectativas fortalecidas, **no** el nuevo GREEN.
  Ninguna evidencia anterior se modifica ni se atribuye a la fuente nueva.

SHA256 de recibos leídos:

| Archivo bajo evidence | SHA256 |
|---|---|
| `cross-web.json` | `44168c52a86527feb7dca4247589525cc59af109c385c6f9b433730265d841cf` |
| `cross-web-sandbox-units.json` | `97e00e885f2ef975cf586cce6d4231a9f23c77e31e11f9b22665ebba7cfbf14a` |
| `case-00003.stderr.log` | `4d9b40bec6dad081d3f67ef1daafdba99494b469022f549f1d28b54ea2439535` |
| `case-00004.stderr.log` | `f5ab2f538429ff091628f77c23cd4d0198edf3e2c2ad8b43e5bf094efdb63333` |

Se compararon SHA256 del manifiesto, bytes staged y `git show 18cb1f2:<ruta>`:

| Fuente | SHA256 del RED/base |
|---|---|
| `05_Exploitation/web/web_login_bruteforce.sh` | `5141da17f9714193b10ad060dfb117ced0e92202ab410086a134fc7b249d4503` |
| `tests/test_cross_web.py` | `1acaf4b8d5cd0820bdd00c042961f415aa00810db6f9443243ab051decb70b8e` |
| `tests/test_automation_contract.py` | `cf088c2b184a0e8dfa38b89f211768b7b4fd52dd6509be087e604dd6421dc2c0` |

Las rutas son relativas a `CyberSecurity-Framework/`. Ambos tests siguen
byte-idénticos al RED; ninguna aserción debilitada o expectativa regenerada.

### Implementación e interfaces exactas

Solo cambia la construcción de `cuerpo` dentro de `enviar_manual`:
`plantilla` local toma `BRUTE_CUERPO` original, un índice local avanza1/9/10
caracteres y un `case` de hasta10 caracteres reconoce `{usuario}`/`{password}`.
Añade el usuario/candidato con asignación append entrecomillada, o un carácter
original. Solo recorre la plantilla, nunca el resultado/valores insertados.
No usa RHS de sustitución Bash, `eval`, regex de sustitución, subprocess,
intérprete, archivo/helper nuevo, datos en código/argv de un helper ni stdout
intermedio. No recodifica, escapa o serializa el cuerpo manual crudo, ni pierde
saltos finales por command substitution. La fuente original/variables de entrada
no se mutan. No depende de `patsub_replacement` ni cambia opciones del shell.

No cambian firma, CLI, precedencias de usuario/diccionario, gates, caps, candidatos,
método, URL, cabeceras, transporte, clasificación o artefactos. Todo lo anterior
a la antigua asignación de cuerpo y todo lo posterior a `local -a args=(-skS`
se comparó byte a byte con base: idéntico. `.req`, compositor y rate intactos.
SHA256 de la hoja nueva:
`4a5411b0290a3f88672b36c01f6650883e4efafbe111a323ac9aa3dd18d9098c`.

README05/manual/MENU ahora describen RED observado y arreglo implementado,
revisión/GREEN pendientes. M1 de `task-4-static-review.md` reconciliado en README:
rc0 de login puede ser candidato heurístico **o cancelación genuina sin intentos**,
no acreditación de autenticación. No se reescribe el review histórico.

### Verificación estática y límites de esta fase

- `git status --short` inicial vacío; `git rev-parse --short HEAD` → `18cb1f2`.
- `bash -n CyberSecurity-Framework/05_Exploitation/web/web_login_bruteforce.sh 2>&1`
  → rc0, sin salida ni warnings; no ejecuta el cuerpo.
- `git diff --check` → rc0, sin salida. Diff de producción leído completo:
  único hunk local de sustitución manual; self-review de offsets y datos literales.
- `python3 -I -B -c` solo con `ast,hashlib,json,pathlib,subprocess` estándar:
  comparación de prefijo/sufijo inalterados de hoja; procedencia manifiesto/
  staged/base de las tres fuentes; AST y bytes inalterados de ambos tests;
  JSON de recibos con conteos exactos; hashes anteriores; allowlist de cuatro
  archivos de código/docs antes de anexar este informe. Todo rc0, sin imports
  del repo ni ejecución de helpers/producto/tests. Solo se usó subprocess para
  lecturas Git de texto/bytes, no para Bash/producto.
- Las fuentes runtime/fixture/doble/manifiestos/selectores y7IDs/5grants no
  cambian. Sin baselines refrescados, nuevas concesiones, skips u omisiones.

**Runtime de la fuente nueva NOT RUN.** Falta revisión independiente de este
SHA combinado y nueva autorización exacta del controlador para `--cross-web`
completo. Solo ese run podrá acreditar GREEN; el RED retenido no lo sustituye.
`--cross-consent`, `--suite`, revisiones finales y cierre acotado siguen pendientes.
No hay cierre global ni claim de credencial válida/compatibilidad operacional.
Sin subagentes, red, configuración del operador, instalaciones, limpieza,
eliminación de artefactos, push, merge o reset.

## WHOLE WEB single fix wave — INITIAL TESTS FIRST, base467020f

**Estado: tests/doble escritos; producción intencionadamente sin corregir;
runtime NOT RUN.** Esta fase no afirma RED observado de I1/I2, GREEN ni cierre.
Se leyó completo `final-static-review.md` antes de modificar archivos.
Los findings se conservan literalmente con estos títulos del review:

> Important I1 — curl URL globbing can multiply transfers behind one receipt/TSV row

> Important I2 — a literal manual body beginning with `@` is still a file reference

> Minor M1 — source-level login exit-code contract remains misleading

I1 señala que comillas del shell no desactivan expansión curl `{one,two}`/`[1-3]`,
por lo que una invocación puede ocultar varios envíos bajo una fila. I2 señala
que `--data-binary "$cuerpo"` adopta un cuerpo con `@` inicial como fichero,
no como texto crudo. M1 pide alinear cabecera rc0 del login con candidato
heurístico o cancelación, sin cambiar clasificación/gates. M1 y producción
I1/I2 quedan para reanudación explícita tras revisión y RED autorizado.

### Cambios exactos y oráculos independientes

- `tests/cross_web_curl_double.py`: única modificación, aceptar `--globoff`
  como opción sin valor. No implementa expansión de URL, simulación de varias
  peticiones ni defensa ficticia de negocio. Recibos raw/terminal, body base64,
  errores, semántica `--data-binary @file` y lectura de fichero se conservan.
- `test_cross_web.WebTests.test_login_req_transmits_each_candidate`: conserva
  todos los oráculos previos. Añade dos subtests I1 separados (capturada/manual):
  path `/login/{one,two}/[1-3]`, query `view={a,b}&range=[4-6]`, URL completa
  esperada literal por modo (HTTPS8443 capturada/HTTP8080 manual), exactamente
  dos invocaciones/recibos y los dos candidatos sintéticos ya existentes.
  Compara password lógico capturado o cuerpo crudo manual y exige `--globoff`
  en argv real del recibo. El doble no convierte ausencia del flag en múltiples
  respuestas: la aserción explícita expone esa ausencia sin red real.
- Dentro del mismo ID, un subtest I2 **independiente de I1** crea exclusivamente
  `readable-synthetic-body.txt` nuevo bajo su fixture y un diccionario sintético
  de una línea con esa ruta. Plantilla manual `@{password}` exige literalmente
  `@` + ruta, no los contenidos conocidos del fichero. Revisa conteo1, estadoDONE,
  URL/métodoPATCH/cabeceras, fichero conservado y body exacto/base64 UTF-8 distinto
  del contenido. Sin exigir una representación de transporte de producción
  concreta ni añadir modo de adopción de ficheros. En fuente actual se espera
  exponer la lectura del fichero por el doble existente, no un fallo artificial.
- `test_cross_web.WebTests.test_rate_has_no_scheme_probe`: un subtest I1 exige
  la misma sintaxis path/query literal con URL HTTPS8443 completa, exactamente
  dos invocaciones/recibos, `wrong-1`/`wrong-2`, usuario capturado intacto y
  `--globoff` en argv. Al ser subtest, su fallo no omite el resto del método.

Los subtests nuevos son escenarios sintéticos en IDs/grants existentes, no
nuevos casos de discovery, técnicas ni candidatos de producto. No cambia
`WEB_CASES`,7IDs/5grants, runtime, fixture, manifiestos, selección, baselines,
fuentes productivas o configuración del operador. El arreglo WM1 previo y todos
los artefactos/recibos/runs se conservan. SQLmap y empaquetado11 intactos.

### Checks estáticos realizados

- `git status --short` inicial vacío; `git rev-parse --short HEAD` → `467020f`.
- Lectura del review completo, doble y secciones de test; solo fuente/datos.
- `python3 -I -B -c` con stdlib `ast,json,pathlib,subprocess`: AST de ambos
  archivos; comparación con `git show 467020f:<ruta>` de mismos7IDs/orden;
  **cada statement AST original de cada método conservado en orden**, sin
  debilitar oráculos antiguos; igualdad exacta del doble salvo añadir opción
  `--globoff`; inventario JSON7IDs/5grants; allowlist exacta del diff de esos dos
  archivos antes del informe. rc0, sin importar/ejecutar AST o repo; subprocess
  solo para lecturas Git.
- `git diff --check` y revisión textual del diff antes del commit: sin incidencias
  (rc0). No Bash de producto alterado ni necesario para esta fase.

**No se ejecutó** repo import/helper/test/probe/launcher/producto/doble/curl/rm/
backend, tampoco dentro de sandbox. Sin red/GUI/sudo/install/download, subagentes,
cleanup/eliminación/archivo de artefactos, push/merge/reset o datos del operador.
Falta revisión estática independiente del nuevo SHA y comando exacto autorizado
del controlador para observar RED I1/I2. Solo después se reanudará el arreglo
mínimo de producción y M1, seguido de nueva revisión/gate y GREEN completo.
No se anticipan conteos de fallos ni se reutiliza un GREEN previo para esta ola.

## WHOLE WEB final fix wave — producción tras RED, baseb76757e

**Implementación estática entregada; revisión/nuevo GREEN pendientes. Runtime
de esta combinación NOT RUN.** Actualiza la sección tests-first anterior sin
reescribir sus resultados históricos. No es cierre Task4/WEB/Task9/global09.

### RED real y procedencia (lectura como datos, sin ejecución)

Raíz retenida del controlador:
`/tmp/opencode/automation-isolated-d95a3225a5e64a66803f63d260c12dce/`.
`evidence/host-wait.json`: EXIT/rc1. `cross-web-sandbox-units.json`:65units PASS.
`cross-web.json`:7casos/4fallos de aserción/0errores/0skips/0BLOCKED.
Se leyeron completos los stderr de casos3/5:

- Caso3 login: falta `--globoff` en capturada y manual (dos aserciones);
  cuerpo manual `@{password}` produjo `SYNTHETIC FILE CONTENTS, NOT THE REQUEST BODY\n`
  en vez del `@`+ruta esperado (tercer fallo).
- Caso5 rate: falta `--globoff` (cuarto fallo).
- Son los fallos esperados del transporte/oráculo fortalecido, no errores de
  infraestructura ni un RED supuesto. Los otros casos no registran fallos.

SHA256 de recibos:

| Archivo bajo evidence | SHA256 |
|---|---|
| `cross-web.json` | `551674523b4b73a9503fb8cbb4561714fea2e0325ad78cb738cd7d6b23d4ab26` |
| `case-00003.stderr.log` | `d6dcc6ce6c7794073b8c1a6d35dc8c4fe7ddc4e42848e0f8a9af0d8cc50fe2b6` |
| `case-00005.stderr.log` | `147b037d9c51651878270df417b3681656e67039fa994d18e03e7f74ca176dcd` |

Manifiesto del run, bytes staged y `git show b76757e:<ruta>` coinciden para las
cuatro fuentes relevantes (rutas relativas a `CyberSecurity-Framework/`):

| Fuente | SHA256 RED/base |
|---|---|
| `05_Exploitation/web/web_login_bruteforce.sh` | `4a5411b0290a3f88672b36c01f6650883e4efafbe111a323ac9aa3dd18d9098c` |
| `05_Exploitation/web/rate_limit_probe.sh` | `51e154a725aaccf32cb1db6272e6e45e23510ddf2627b0d5e24d20049a079b37` |
| `tests/test_cross_web.py` | `d187b7167870bdc76b99a1cb58ef64578f5b2b8a88ae49dab433eaa73b0db606` |
| `tests/cross_web_curl_double.py` | `939fda21ef199bf378b7068091823abc78c2193898a0c3309838740d450650aa` |

Ningún recibo/fixture anterior se modifica, borra o representa como GREEN nuevo.

### I1/I2/M1: cambio mínimo de producción y doble

- **I1:** las tres ramas de envíos de login/rate añaden `--globoff` a sus arrays
  curl. Path/query con llaves/corchetes dejan de ser instrucciones de expansión
  para curl, sin rechazarlas ni alterar target. No cambia método, URL, esquema,
  cap, conteo ni el flag-oracle independiente. Las descargas opcionales de
  diccionario no se refactorizan; esta corrección abarca las tres ramas de
  intentos identificadas en el review.
- **I2:** los tres cuerpos no vacíos usan `--data-binary @-`; un builtin
  `printf '%s' "$cuerpo"` alimenta stdin por pipe. No añade newline, no hace
  escape form/JSON, no cambia el cuerpo ni reinterpreta un `@` inicial.
  Cuerpo vacío conserva ausencia de opción data, sin convertirlo en POST nuevo.
  No fichero temporal, adopción de fichero del operador, datos en código,
  nuevo intérprete/helper o utilidad runtime. El rc del pipeline sigue siendo
  el del curl final; el chequeo de rc en `.req` se conserva. No se aprovecha
  esta ola para refactorizar clasificación o manejo legacy de errores manual/rate.
- Se comprobó la misma frontera de cuerpo `@` en capturada/rate: una petición
  con password en query puede llevar cuerpo `text/plain` opaco que no cambia al
  componer. Por eso ambos transportes reciben la misma defensa stdin, no solo
  manual. La composición, extracción, filtros de cabeceras, consentimiento y
  mecanismo original de una pasada WM1 permanecen intactos.
- **Doble obligatorio:** solo añade reconocimiento de valor exacto `@-` para
  leer `sys.stdin.buffer.read()`; otros `@ruta` siguen leyendo ese fichero,
  argumento literal sigue `os.fsencode`. Se conserva orden del recibo raw antes
  de programa/opciones/body, semántica de fallo/file, respuesta y base64 real.
  No se fuerza cuerpo esperado ni se sustituye negocio del producto.
- **M1:** cabecera fuente de login ahora dice rc0 candidato heurístico o
  cancelación sin intentos; rc1 sin candidato o error, no prueba de autenticación.
  Clasificador y gates no cambian. README05 documenta únicamente este transporte
  literal implementado, RED previo y revisión/GREEN pendientes.

SHA256 nuevos de producción/doble:

| Fuente | SHA256 nuevo |
|---|---|
| login | `0088b958fb84bfaa7e95b68683f04632e557dbe5dbe2bb329a5c44091f4634e5` |
| rate | `86cd5547c80791c090e527002f98b1c18abd09a332ef7324bc4d1dc78b98d90d` |
| doble | `fc0e972082e9618f413a70abe2c999d66db4f11c7ee56cf31375394de664eef2` |

### Pruebas escritas adicionales y cobertura preservada

Todos los oráculos del RED permanecen; ningún ID/grant nuevo o skip.
Dentro de `test_login_req_transmits_each_candidate`, añade cuerpo opaco
capturado `@`+ruta sintética legible con password query, y un cuerpo manual
`@` inicial con CRLF, Unicode, barra inversa, `&+%`, marcador insertado y dos
newlines finales. Expectativas literales de URL/body/base64, sin usar composición
de producto para calcularlas. Fichero sintético sigue intacto.
En `test_rate_has_no_scheme_probe`, cubre cuerpo opaco `@`+ruta con query
`wrong-1`/`wrong-2` y las dos URLs literales independientes, cuerpo/base64/fichero.
Estas ampliaciones están **escritas NOT RUN**, no son RED observado adicional.
En `test_login_has_no_preconsent_transport`, dos comprobaciones directas del
doble para stdin vacío y texto con `@`/CRLF/Unicode/newlines: recibos raw y bytes
base64 frente al literal. No socket, backend o sustitución de lógica de negocio.
El mecanismo de entrada de la fixture actual se reutiliza sin ampliarlo.

### Verificación estática y self-review

- `git status --short` inicial vacío; `git rev-parse --short HEAD` → `b76757e`.
- `bash -n CyberSecurity-Framework/05_Exploitation/web/web_login_bruteforce.sh CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh 2>&1`
  → rc0, sin salida/stderr. Ningún cuerpo Bash ejecutado.
- `git diff --check` → rc0 vacío; `git diff --stat` y lectura de diffs de hojas,
  doble y tests para comprobar cambios acotados y expectativas independientes.
- `python3 -I -B -c` stdlib `ast,hashlib,json,pathlib,subprocess` únicamente:
  AST de tests/doble sin ejecución; siete IDs/orden iguales; cada statement AST
  original de cada método de test retenido en orden; JSON7IDs/5grants; validación
  de conteos RED y SHA256 manifiesto/staged/base de cuatro fuentes; hashes nuevos
  anteriores y hashes de recibos; allowlist exacta de cinco archivos antes de
  anexar informe. rc0. subprocess solo para lecturas Git, no producto/helpers.
- Check final adicional `python3 -I -B -c` (`ast,pathlib,subprocess` estándar):
  reconstrucción textual independiente del diff permitido sobre `git show
  b76757e` y comparación exacta de ambas hojas: únicamente3flags globoff,
  3opciones data stdin/3pipes printf, cabecera M1 y comentario de transporte.
  AST final de tests/doble válido y statements previos íntegros. rc0.
- No se altera fixture, runtime, manifiestos, selectores, grants, SQLmap,
  empaquetado11, API del compositor, caps, diccionarios de producto o técnica.
  No refresh de baselines ni supresión de casos/errores para obtener verde.

No ejecución nueva de repoimports/helpers/tests/probes/launcher/producto/doble/
curl/rm/backend, ni dentro de sandbox. Sin subagentes/red/GUI/sudo/install/
download/cleanup/eliminación/push/merge/reset/configuración del operador.
Se entrega para revisión estática independiente y nuevo comando exacto autorizado
del controlador; GREEN fresco completo, regresiones separadas y revisión final
siguen pendientes. No afirmar cierre global, credenciales válidas ni operación
real verificada a partir de este código/checks estáticos.

## Load-bearing residual I3 — continuation base602e707

**Source/test delivery only; new runtime NOT RUN.** Se leyó completo
`final-static-rereview.md`. Su finding literal es:

> Important I3 — new stdin producer failure is masked by pipeline status

El review considera I1/I2/M1 estáticamente atendidos, pero encuentra que
`printf | curl` devolvía solo rc del consumidor y que manual/rate tampoco
comprobaban ese rc. Un productor puede escribir un prefijo, fallar y dejar al
consumidor devolver una respuesta aparentemente válida. No equivale a cero
transporte. **I3 sigue siendo hallazgo estático, no RED observado**; los recibos
RED I1/I2 anteriores no acreditan I3 ni esta combinación nueva.

### Reparación acotada de fuente

- Login manual, login capturado y rate ejecutan el pipeline dentro del command
  substitution con `set -o pipefail` local: fallo del productor **o** curl hace
  fallar el transporte completo, sin cambiar opciones del shell llamador.
- Todos conservan incremento `N_ENVIOS` inmediatamente después de intentar el
  pipeline; después comprueban status antes de parsear código/tamaño/tiempo.
  El status llamado `rc_curl` en capturada ahora recoge el pipeline completo;
  el chequeo existente se conserva. Manual/rate añaden chequeo equivalente.
- Manual añade `return 0` explícito tras éxito: el test aritmético de «primer
  envío» al final de la función ya no puede confundirse con rc de transporte
  al comprobarlo desde el caller en envíos posteriores.
- Los callers manual/rate ahora cortan con rc1 antes de evaluar respuesta,
  candidato, freno, retardo o veredicto. Capturada conserva su corte y recibe
  el mismo recibo parcial. No se crea una fila TSV como respuesta evaluada,
  no se sigue con siguiente candidato/intento y no se cambia el clasificador.
- En el run nuevo, el corte conserva `transporte_fallido.txt` con
  `Intentos de transporte: N`/`Estado: ERROR`, copia la respuesta disponible a
  `transporte_fallido.resp` y guarda `rc=1` antes de salir. Errores de copia van
  al log existente y no convierten el corte en éxito. Recibos del doble, logs,
  runs previos y tabla parcial se conservan. Si falló construcción antes de
  invocar transporte en capturada, N puede ser0; si se invocó el consumidor,
  debe figurar el intento, no una falsa garantía de ausencia de red.

No se cambia composición/request, plantilla original WM1, flags globoff/stdin,
cabeceras, consentimiento, caps, gates, candidatos, retries o técnica. Ningún
entorno/flag/bypass de prueba se introduce en producción. Runtime, guard,
fixtures, manifiestos, selección, grants, doble, SQLmap y11 intactos.

### Oráculos enfocados dentro de los IDs/grants existentes

`test_login_has_no_preconsent_transport` añade manual/capturada × dos fallos;
`test_rate_has_no_scheme_probe` añade los dos fallos rate. Se usan las hojas
reales completas, el curl doble obligatorio existente y dos candidatos/intentos
ya habituales para comprobar que se corta después del primero:

1. **Productor parcial rc73 + consumidor rc0 aparentemente exitoso:** login
   programa HTTP200/body`SUCCESS` y `BRUTE_EXITO_PATRON=SUCCESS`; rate programa
   HTTP429/Retry-After7. Exige rc1, una invocación real registrada, bytes de
   prefijo independientes (`pas` manual, `use` capturada/rate), sin candidato
   ni veredicto, tabla solo cabecera, recibo N=1/rc1 y respuesta parcial guardada.
2. **Productor real + consumidor rc7 con la misma respuesta aparente:** invoca
   la fuente original sin driver, compara cuerpo real completo, mantiene una
   invocación y exige idéntico corte/preservación. Así ni un patrón de éxito ni
   una señal de freno permite puntuar un transporte fallido.

Helper test-only `producer_failure_driver` crea un driver nuevo exclusivo en
el mismo directorio sintético de la hoja para conservar su autolocalización.
Parte del texto real staged completo. Sustituye **únicamente** el token productor
exacto `printf '%s' "$cuerpo" | LC_ALL=C curl` por `i3_producer` (comprobando2
ocurrencias login/1rate); antepone una función fija que valida sus dos argumentos,
escribe los3primeros caracteres mediante `builtin printf` y retorna73.
No redefine `printf` globalmente, no interfiere con fixture/compositor/URL ni
reemplaza función de negocio, caller, curl o clasificador. No usa valores del
operador/candidato como código, eval, nuevos módulos o herramientas. Tanto
driver como fuente original permanecen retenidos, sin editar el original.
Este es el driver estrecho de fuente/transport producer permitido por el
controlador para inyectar fallo sin bypass de producción.

Helper de aserción comprueba recibo real/base64 del doble y artifacts de fallo,
incluido cuerpo parcial de respuesta, sin no-op de negocio. Todos los statements
previos de métodos y sus oráculos de wire/JSON/caps/consentimiento/preservación
se conservan en orden. Siete IDs/cinco grants, sin skips nuevos.

### Comandos estáticos/resultados y gate pendiente

- `git status --short` inicialmente vacío; `git rev-parse --short HEAD` →602e707.
- `bash -n CyberSecurity-Framework/05_Exploitation/web/web_login_bruteforce.sh CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh 2>&1`
  → rc0, stdout/stderr vacíos, sin ejecutar funciones.
- `git diff --check` → rc0 vacío; lectura del diff completo y `git diff --stat`.
- `python3 -I -B -c` stdlib `ast,json,pathlib,subprocess`: parsea test nuevo y
  texto base de `git show 602e707`; mismos7IDs/orden y todos los statements
  anteriores retenidos en orden. Lee inventario JSON7IDs/5grants. Del AST solo
  extrae la constante de función productor, reconstruye textualmente ambos
  drivers e invoca exclusivamente `/bin/bash -n` con ese texto en stdin: ambos
  rc0/sin salida ni warnings. **No ejecuta driver ni función del repo**.
  Comprueba2/1 productores y2/1 pipefail locales y allowlist exacta de dos hojas
  y test antes de anexar informe; rc0. subprocess restante solo lee Git.

Sin import/ejecución de repo/tests/helpers/probes/launcher/producto/doble/rm/
backend, incluso sandbox; sin subagentes/red/GUI/sudo/install/download/cleanup/
push/merge/reset/configuración del operador/eliminación de artefactos.
Faltan revisión estática independiente del SHA y autorización exacta nueva del
controlador. No afirmar RED I3 observado, GREEN nuevo, credencial acreditada,
compatibilidad operacional, cierre WEB/Task9/global o ampliación de permisos.
