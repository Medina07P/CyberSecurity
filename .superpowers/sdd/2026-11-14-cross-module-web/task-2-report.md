# WEB Task2 — entrega STATIC NOT RUN

Base inspeccionada: `76fd530`; árbol inicialmente limpio. Alcance: login `.req`
y ampliaciones dentro de los dos IDs login existentes de `test_cross_web.py`.
No se ejecutaron imports del repo, producto, helpers, dobles, launcher, pruebas,
probes, red, descargas ni limpieza. GREEN nuevo **PENDIENTE**, no cierre Task2.

## Comportamiento escrito

- Cada `enviar` consume `hr_request_pair` desde HR_TARGET/HR_BODY originales en
  memoria, con password y, únicamente si existe override no vacío, usuario.
  Precedencia existente: entorno no vacío, tercer argumento, captura. Sin override
  el usuario capturado no se recodifica. Query/body salen del mismo par; hr_url
  recibe el target compuesto mediante asignación local, sin mutación acumulativa.
- Validación local previa a consentimiento/descarga: esquema, Host/puerto,
  target, parseo de parámetros, campos seleccionados, homónimos entre ubicaciones,
  colisión usuario/password y ambigüedades rechazadas por Task1. Un override de
  usuario sin campo representable se rechaza, no se anuncia como aplicado.
- `.req`: BRUTE_ESQUEMA presente debe ser exactamente http/https (vacío también
  inválido); si ausente, se acepta URL absoluta HTTP(S) cuyo authority coincide
  exactamente con Host. Se normaliza su ruta en memoria. Sin ambos, error; nunca
  sondeo HTTPS ni inferencia por puerto. Host no representable por el contrato
  actual host/puerto se rechaza, no se añade soporte IPv6 ni otro transporte.
- rc del compositor, productores/extractores, hr_url y curl se comprueba. Un
  fallo de construcción no llama curl ni añade fila/candidato evaluado; fallo de
  curl corta sin evaluar respuesta aunque parezca éxito. Ambos dejan rc1 privado.
  Se conservan saltos finales del cuerpo durante extracción Bash.
- Se mantienen consentimiento propio BRUTE_SI/TTY, cookies, método, filtrado de
  cabeceras, rutas, scope/session, precedencias de diccionario, manual, límites
  200/default y1000/hard, candidatos y ejecución secuencial. No nuevos permisos.
  Una respuesta diferencial sigue siendo heurística: no certifica credencial válida.

## TDD: evidencia previa realmente leída

Recibo del controlador (no ejecución de este implementador):
`/tmp/opencode/automation-isolated-41db60ea3c8d4472a641c881c9fdaad4/evidence/`.
Se leyeron `case-00003.stderr.log` y `case-00004.stderr.log` como datos antes
del parche. Caso3:18 fallos, password observado `captured` frente a `a&b=+%`,
en seis combinaciones de ubicaciones × tres modos de usuario. Caso4:6 fallos:
sondeo sin esquema/consentimiento, puerto443 inferido, override ftp con descarga,
password alias duplicado y colisión usuario/password enviadas. Sin errores.
Resumen comunicado por controlador:65units PASS,7casos/31fallos/0errores;
puros y preservación PASS; rate5+2 pendientes. No atribuir este RED a cambios nuevos.
El recibo `automation-isolated-a9e7eca5cdb34a399d8ff3195dc07766` de65+179/1SKIP
pwsh es histórico y no verifica esta modificación.

## Pruebas escritas, NO ejecutadas

Se mantienen las comprobaciones originales de18 combinaciones de envío real
al curl obligatorio, cookie, cabeceras, nonce, dos candidatos, respuestas y TSV.
Ampliaciones dentro de los mismos IDs:

- Captura absoluta HTTPS y override HTTP sobre8443 con URL literal esperada.
- Precedencia entorno sobre tercer argumento y tokens JSON ajenos exactos
  `1e-400` y decimal de alta precisión inspeccionados en cuerpo real.
- Esquema vacío, alias ambiguo con diccionario remoto y campo usuario ausente:
  recibos crudos de invocación vacíos, no solo resultados del doble.
- Candidato mayor al presupuesto del compositor: cero invocaciones y TSV solo
  cabecera; fallo curl rc7 con respuesta/patrón200: un envío, cero filas evaluadas.
- El caso de preservación existente queda intacto (fuentes/.req/diccionario,
  artefactos previos y dos directorios nuevos). Sin nuevos IDs ni grants.

Los mapas de fuentes existentes ya enumeran las dos rutas; no contienen hashes
que refrescar. No se modifican infraestructura, Task1, rate/Task3, documentación
pública/Task4 ni baselines ajenos. Los nuevos subcasos necesitan revisión estática
independiente y autorización exacta del controlador antes de cualquier ejecución.

## Verificación estática fresca

Mediante `python3 -I -B -c` exclusivamente stdlib, sin imports del repo:
`subprocess.run(['bash','-n',login], capture_output=True, text=True)`:
rc0, stdout `''`, stderr `''`.
`ast.parse(Path(test).read_text(), filename=test)`: AST OK.
`subprocess.run(['git','diff','--check'], capture_output=True, text=True)`:
rc0, stdout `''`, stderr `''`. Diff completo leído para autorrevisión; no review
independiente, no compatibilidad operacional ni suite global verde.

SHA256 de fuentes tras parche:

| Ruta bajo framework | SHA256 |
|---|---|
|05_Exploitation/web/web_login_bruteforce.sh|5141da17f9714193b10ad060dfb117ced0e92202ab410086a134fc7b249d4503|
|tests/test_cross_web.py|88b27570c30a6c9ee5a658cf34a3840ad41027bedb578cbf071ee740487afcce|
|00_Config/lib/http_request.bash (intacto)|88dc9621daf3840c04206a8da4bfb85dcbe4b415937374c72918cbf7d81fec09|
|00_Config/lib/http_fields.py (intacto)|68ca23e9a22df046ca2825cf97b22d7a2504f8d1d177c6922d3a283114dc8975|

## Límites / pendientes

GREEN de login/preservación y regresiones no ejecutado ni autorizado por esta
entrega. Rate y documentación pública posteriores permanecen explícitamente
pendientes. No se cambia el clasificador histórico de credenciales ni el envío
manual, ni contratos de sustitución individuales. La coincidencia authority/Host
es conservadora exacta; capturas equivalentes pero no idénticas se rechazan antes
de tráfico, sin adivinar. No se detectó conflicto que requiera ampliar capacidades.
Conservar worktree, fuentes, fixtures, logs y todos los recibos previos; sin merge,
push, reset, instalaciones, limpieza ni operaciones sobre configuración real.

## Refinamiento M1 — STATIC NOT RUN sobre bcc6b29

Se leyó íntegramente `task-2-static-review.md`: spec APPROVED STATIC, quality con
un único menor M1. La tabla existente de cero transporte ahora declara rc exacto
por fila y lo comprueba junto con cero recibos RAW. Diez filas de entrada inválida
exigen rc1 (esquema ausente/inválido/vacío, incluso puerto443, ambigüedad/colisión,
campo usuario ausente y límite1001); la fila con esquema válido pero sin
consentimiento exige rc0. Esquema ausente más EOF sigue siendo error rc1 previo
al gate de consentimiento, no se rebaja a cancelación. No cambian las once filas,
el producto, los dobles, los IDs, grants ni contratos de esquemas/topes/campos.

Verificación fresca permitida:

```text
python3 -I -B -c 'import ast,pathlib; p="CyberSecurity-Framework/tests/test_cross_web.py"; ast.parse(pathlib.Path(p).read_text(),filename=p); print("AST OK: "+p)'
rc0; stdout: AST OK: CyberSecurity-Framework/tests/test_cross_web.py; stderr vacío.
git diff --check
rc0; stdout/stderr vacíos.
```

Autorrevisión del diff acotado: expectativas explícitas, ninguna aserción RAW
retirada ni validación de producto relajada. No imports del repo, pruebas,
helpers, probes, launcher, producto, doble ni runtime ejecutados. Re-review
independiente y autorización exacta del controlador siguen siendo gates antes
de runtime; GREEN nuevo sigue PENDIENTE. Los hashes de la tabla anterior describen
la entrega bcc6b29, no esta revisión del test. Rate/Task3 y docs siguen pendientes.
