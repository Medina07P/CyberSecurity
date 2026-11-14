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
