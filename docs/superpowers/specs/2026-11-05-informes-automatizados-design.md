# Diseño — Informes automatizados (técnico y cliente) desde el gestor

- **Fecha:** 2026-11-05
- **Estado:** aprobado (2026-11-05)
- **Origen:** petición del partner: «desde el interactivo de `cyber_framework.sh` poder generar
  reportes más avanzados, añadir automatizaciones efectivas, y que haya un instructivo de uso»,
  acotado a dos entregables: uno técnico y otro como si fuera para un cliente real, **deducidos
  automáticamente** de lo ya escaneado, con precisión.

## Intención y por qué

Hoy `11_Reports/report_generator.sh` escribe un esqueleto con huecos `[ASÍ]` y lo marca como
PLANTILLA: no lee ni una línea de `scans/`. El único generador que lee archivos,
`09_Automation/python/report_generator.py`, busca palabras (`password`, `inject`, `CVE-…`) y las
llama hallazgos; eso es exactamente el defecto que el repo ya documentó (herramientas que
reportan su propio eco) y no se puede entregar a un cliente.

El framework, en cambio, ya calcula veredictos honestos y los deja en disco: `sqlmap_request.sh`
distingue `INYECTABLE` / `NO INYECTABLE` / `NO DETERMINADO`, `http_inject.sh` clasifica
`CONFIRMADO` / `FUERTE` / `DEBIL` con guardas contra el eco, `rate_limit_probe.sh` emite
`FRENADO` / `SIN FRENO` / `NO DETERMINADO`, `sql_injection.sh` guarda solo respuestas distintas
de la línea base, `ffuf` se lanza con `-fs` y `nmap` deja XML. Falta **leer esos veredictos, no
reinterpretarlos**, y redactar dos documentos distintos con la misma base.

## Objetivos

1. Un motor determinista que convierta lo evaluable de `scans/` en un registro canónico
   `findings.json`, sin red, sin LLM y sin palabras clave.
2. Dos informes desde ese registro, generados desde el menú:
   - **técnico**: hallazgos con severidad, activo, técnica, evidencia (`archivo:línea`),
     reproducción, recomendación y referencias;
   - **cliente**: resumen ejecutivo, riesgo de negocio, plan de acción, sin payloads ni rutas
     internas.
3. Que «0 hallazgos» nunca signifique «el parser no entendió nada»: todo lo ilegible va a un
   apéndice de **no evaluable**.
4. Un instructivo de uso del interactivo (`docs/MANUAL-GESTOR.md`) enlazado desde el `?` del menú
   y el README.

## No-objetivos

- Verificación activa en red de los candidatos (queda como bandera futura `--verificar`).
- PDF con dependencias pesadas: se genera HTML autocontenido listo para imprimir; si hay
  `pandoc` o `wkhtmltopdf`, se produce PDF como extra.
- Cambiar los escáneres. El motor se adapta a lo que ya escriben.
- Un registro con confirmación manual obligatoria: el partner pidió deducción automática.

## Anti-objetivos (cómo se vería un éxito falso)

1. Un archivo con la palabra «password» (banner, README, log) convertido en hallazgo.
2. Un `200` de una SPA que responde a todo contado como directorio encontrado, o un directorio
   encontrado contado como vulnerabilidad.
3. Un `429`/`503`/timeout contado como vulnerabilidad o como «sin hallazgos».
4. Un `NO INYECTABLE` de sqlmap leído como `INYECTABLE` por buscar la subcadena.
5. Un `NO DETERMINADO` presentado al cliente como «sin riesgo».
6. Un archivo de otro objetivo (o de un laboratorio) colado en el informe de un cliente.
7. Dos ejecuciones sobre los mismos datos produciendo informes distintos.

## Enfoques considerados

| Enfoque | Qué es | Veredicto |
|---|---|---|
| **A. Motor determinista por herramienta** | Parser por fuente, reglas duras, registro canónico, dos renderizadores | **Elegido** |
| B. A + verificación activa | Re-comprobar candidatos débiles contra el objetivo | Se deja como `--verificar` futuro: repite peticiones, exige red y objetivo vivo |
| C. Resumen con LLM | Pasar el texto crudo a un modelo | Descartado: no determinista, no auditable, puede inventar; choca con «preciso» |

## Precisión: reglas duras del motor

1. **Solo señales que la herramienta emite.** Nada de `grep` de palabras: se parsea la estructura
   (XML, JSON, TSV, líneas con formato conocido) o el veredicto ya calculado.
2. **Sin evidencia no hay hallazgo.** Cada hallazgo guarda `archivo`, `linea` (cuando aplica) y
   `extracto`; si el archivo no existe o no se puede leer, el hallazgo no se emite.
3. **Cuatro estados, no dos.**
   - `confirmado`: la herramienta demostró explotación o un diferencial concluyente
     (`sqlmap` inyectable, `http_inject` confirmado, `SIN FRENO`, acceso anónimo, CVE de nuclei).
   - `candidato`: diferencial reproducible que aún no prueba explotación (`http_inject` fuerte,
     `sqli_findings`).
   - `observacion`: configuración observada directamente, sin explotar (puerto abierto, cabecera
     ausente, auth por contraseña, recurso accesible).
   - `descartado`: eco, catch-all, `429`, timeout. Se cuenta y se explica, no se publica.
4. **`NO DETERMINADO` no es un resultado.** Va a `no_evaluable`, nunca a hallazgo ni a «limpio».
5. **Dedupe estable** por `(cve)` o `(host, parámetro, clase)` o
   `(herramienta, regla, activo normalizado, ruta)`; se fusionan evidencias y gana la confianza y
   severidad mayores. Un `INYECTABLE` de sqlmap absorbe el `CONFIRMADO` de `http_inject` y el
   `candidato` de `sqli_findings` sobre el mismo parámetro.
6. **Id estable**: `sha1` de la clave de dedupe. Dos ejecuciones idénticas producen el mismo JSON
   salvo `generado_en`.
7. **Línea base obligatoria** en fuzzing: un hit de `ffuf` sin `-fs` recuperable de su
   `commandline` no es hallazgo, es `no_evaluable`.
8. **Ausencia de evidencia ≠ evidencia de ausencia.** Un `security_headers_*.txt` vacío no
   significa «faltan cabeceras»: hace falta el `headers_*.txt` pareado con un 2xx/3xx del mismo
   objetivo. Si no está, `no_evaluable`.
9. **Un objetivo por informe.** Un archivo entra solo si se puede atribuir al objetivo pedido. Lo
   que no se puede atribuir no se cuela: va a `no_evaluable` con motivo «sin objetivo atribuible»
   (o se incluye con `--incluir-sin-objetivo`, marcado).

## Atribución de archivos al objetivo

El objetivo de sesión es un host (`127.0.0.1`, `example.com`). Los nombres de archivo usan tres
convenciones y algunas fuentes no llevan objetivo. Reglas, por orden:

1. **El propio registro manda cuando lo trae**: `<address addr>` del XML de nmap, `matched-at` de
   nuclei, `host`/`-u` de ffuf, `- Objetivo:` de `rate_limit` y `sqlmap`, URL de
   `sqli_findings`. Si el host no coincide, el archivo no entra aunque el nombre lo sugiera.
2. **Si no lo trae, el nombre**: se busca el host como token completo en el basename, con
   fronteras (`127.0.0.1` no casa con `127.0.0.10`), admitiendo las formas `host`, `host_puerto`
   y `esquema_host_puerto` que produce `scans_slug`.
3. **Sin objetivo en el nombre ni en el contenido** (`api/methods.txt`, `ssh/auth_methods.txt`,
   `database/anon.txt`, nombres legados como `ffuf_8080.json` o `smart_ports.xml`) → no
   atribuible. Por defecto queda fuera del informe y aparece en el apéndice; con
   `--incluir-sin-objetivo` entra marcado como tal.
4. `--todos` agrega todo lo que haya en `scans/` en un informe multiobjetivo, con la lista de
   objetivos en portada. Es la única forma de mezclar objetivos.
5. Si no hay `--objetivo` ni objetivo de sesión, el motor avisa y se comporta como `--todos`.

## Fuentes, parser y confianza

Todo se lee de `<repo>/scans/`. Solo se abren los patrones con significado de evidencia; un
`robots.txt`, un `sitemap` o un par `.req/.resp` no son «no evaluable», simplemente no son fuente
de hallazgos.

| Fuente | Qué se parsea | Resultado | Confianza / severidad |
|---|---|---|---|
| `scans/nmap/*.xml` | `<port state="open">`, `<service>`, `<script>` | activo/puerto/servicio; CVE dentro de un `<script>` | puerto abierto → **observacion** info; CVE → **confirmado** (severidad de `vulners` si está, si no `media` + «CVSS no consultado») |
| `scans/nuclei/*.jsonl` (si existe) | `template-id`, `info.severity`, `info.name`, `matched-at`, `classification.cve-id` | hallazgo | **confirmado**, severidad tal cual |
| `scans/nuclei/*.txt` | línea estándar `[id] [proto] [severidad] url` | hallazgo | **confirmado**, severidad del tercer corchete; cualquier otra línea → `no_evaluable` |
| `scans/nikto/*.txt` | solo líneas con `CVE-` u `OSVDB-`; se descarta el ruido conocido («No CGI Directories found», «Server leaks inodes», métodos permitidos) | CVE → hallazgo; OSVDB → observacion baja | **confirmado** / **observacion**; media si no hay CVSS |
| `scans/web/ffuf_*.json` | `results[]` + `-fs` del `commandline` | recurso accesible no enlazado | **observacion** info (inventario; no se llama vulnerabilidad); sin `-fs` → `no_evaluable` |
| `scans/web/http_inject_*.tsv` | columnas `nivel param clase payload codigo tamano ms evidencia` | `CONFIRMADO` → hallazgo; `FUERTE` → candidato; `DEBIL` → descartado | crítico (`cmd`/`sqli*`/`ssti`), alto (`xss`), medio (`redirect`) |
| `scans/web/sqlmap_*.txt` | línea `- Veredicto: …` | `INYECTABLE` → hallazgo; `NO INYECTABLE` → sin hallazgo; `NO DETERMINADO` → `no_evaluable` | **confirmado** crítico |
| `scans/web/sqli_findings_*.txt` | `URL\|código:tamaño\|base:código:tamaño` | diferencial respecto de la base | **candidato** media (requiere revisión; no prueba inyección) |
| `scans/web/rate_limit_*.txt` + `.tsv` | línea `- Veredicto: …` y filas del TSV | `SIN FRENO` → hallazgo; `FRENADO` → control presente (sin hallazgo); `NO DETERMINADO` → `no_evaluable` | **confirmado** alto, con el texto de alcance que ya trae el resumen |
| `scans/web/security_headers_*.txt` | cabeceras presentes; faltantes entre las cuatro | observación por cabecera ausente | **observacion** media/baja; HSTS solo en https |
| `scans/web/headers_*.txt` | estado y servidor | contexto del activo y **guarda** para lo anterior | info |
| `scans/web/technologies_*.txt` | producto/versión | **no es hallazgo**: enriquece el activo | — |
| `scans/api/methods.txt` | `METODO (código)` | métodos con 2xx distintos de GET/HEAD/POST → observacion baja | **observacion** (solo con `--incluir-sin-objetivo` o `--todos`) |
| `scans/ssh/auth_methods.txt` | métodos soportados | `password` → observacion media | **observacion** (misma regla de atribución) |
| `scans/database/anon.txt` | contenido de una consulta anónima | no vacío → hallazgo; vacío → se ignora salvo que el log de la herramienta confirme conexión | **confirmado** alto |
| `scans/*/errores.log` | existencia y tamaño | se lista como incidencia de ejecución, nunca como hallazgo | — |

## Modelo de datos (`findings.json`)

```json
{
  "meta": {
    "objetivo": "127.0.0.1",
    "modo": "unico",
    "generado_en": "2026-11-05T12:00:00",
    "scans_dir": "/…/scans",
    "cliente": "No indicado",
    "auditor": "kali",
    "herramientas": ["nmap", "nuclei", "ffuf"]
  },
  "activos": [
    {"host": "127.0.0.1", "puertos": [{"puerto": 8080, "servicio": "http", "producto": "SimpleHTTP/0.6"}]}
  ],
  "hallazgos": [
    {
      "id": "9f2c…",
      "titulo": "Inyección SQL confirmada en el parámetro id",
      "categoria": "web",
      "severidad": "critica",
      "confianza": "confirmado",
      "activo": "https://192.0.2.1:443",
      "tecnica": "sqlmap (--technique=BEU)",
      "descripcion": "…",
      "impacto_cliente": "…",
      "recomendacion": "…",
      "esfuerzo": "medio",
      "cve": null,
      "cvss": null,
      "evidencia": [{"archivo": "scans/web/sqlmap_….txt", "linea": 12, "extracto": "- Veredicto: INYECTABLE (id): boolean-based blind"}],
      "referencias": ["https://owasp.org/…"]
    }
  ],
  "no_evaluable": [
    {"fuente": "scans/web/security_headers_8443.txt", "motivo": "archivo vacío y sin headers_8443.txt pareado"}
  ],
  "descartados": [
    {"fuente": "scans/web/ffuf_8080.json", "motivo": "tamaño igual a la línea base (catch-all)"}
  ]
}
```

`severidad` ∈ `critica | alta | media | baja | info`. `confianza` ∈
`confirmado | candidato | observacion`. Los textos de `descripcion`, `impacto_cliente`,
`recomendacion` y `esfuerzo` salen de una tabla por regla, en español y sin inventar datos: los
huecos variables son activo, parámetro y evidencia. Cuando un dato no existe, el texto lo dice
(«CVSS no consultado», «cliente no indicado»), no se rellena con un valor plausible.

## Los dos informes

Markdown y HTML autocontenido (CSS embebido, sin CDN; imprimible a PDF desde el navegador).
Nombres: `informe_tecnico.md/.html`, `informe_cliente.md/.html`.

**Técnico**
1. Portada: objetivo o lista de objetivos, fecha, alcance, herramientas y versiones si constan.
2. Resumen: conteo por severidad y confianza, activos y puertos.
3. Hallazgos confirmados: id, severidad, activo, técnica, descripción, evidencia con `archivo:línea`
   y extracto, reproducción (plantilla o comando que ya quedó en la evidencia), recomendación,
   CVE/CVSS si consta.
4. Candidatos: misma ficha corta, con «qué falta para confirmarlo».
5. Observaciones (endurecimiento).
6. Descartados: conteo por motivo (eco, catch-all, 429, timeout…).
7. Apéndice A: **no evaluable**, con la fuente y qué falta para poder evaluarla.
8. Apéndice B: metodología por fases y limitaciones.

**Cliente**
1. Portada: cliente, auditor, fecha, alcance (sin rutas internas).
2. Resumen ejecutivo en lenguaje de negocio: qué se ha probado, qué se ha encontrado y qué
   significa, en 3–5 párrafos construidos de plantillas con datos reales.
3. Tabla de riesgo: conteo por severidad, con una frase de impacto por nivel.
4. Hallazgos principales: título, «qué significa para el negocio», impacto, recomendación y
   esfuerzo (bajo/medio/alto). Sin payloads, sin rutas internas, sin nombres de herramientas
   internas.
5. Plan de acción 30/60/90 días, ordenado por severidad y esfuerzo.
6. Endurecimiento recomendado (las observaciones, agrupadas).
7. Qué no se probó y límites del alcance, incluido un recuento de «N pruebas requieren revisión»
   si hay candidatos, sin entrar en detalle técnico.
8. Glosario breve.

Regla de oro: el informe de cliente solo puede afirmar lo que está en `hallazgos` con
`confianza=confirmado`; los `candidato` se mencionan solo como recuento y los `observacion` van a
la sección de endurecimiento, nunca como explotados.

## Integración en el gestor

- **`R` en el menú principal** (nueva acción, junto a `T`): submenú `1` técnico, `2` cliente,
  `3` ambos. Pide cliente y auditor la primera vez y los recuerda en
  `11_Reports/.report_profile` (git-ignored); Enter conserva el valor. Usa el objetivo de la
  sesión, ejecuta el generador, muestra las rutas y ofrece abrir el HTML con `xdg-open`.
- **Módulo `11`**: sigue listando los scripts; `report_generator.sh` pasa a ser el envoltorio
  amigable (`Uso: ./report_generator.sh [tipo]`, `Ejemplo: ./report_generator.sh ambos`). Las
  banderas antiguas se mantienen como alias: `--executive` → cliente, `--technical` → técnico,
  `--full` / `--all` → ambos.
- **`?`**: añade la sección «Informes» y remite a `docs/MANUAL-GESTOR.md`.
- El motor **no pide confirmación** (solo lee archivos), pero recuerda en cabecera que el alcance
  es el de `scope.yaml`; no lo parsea en v1 (evita depender de PyYAML) y no bloquea.

## Salidas, versionado y compatibilidad

- Nuevo destino: `11_Reports/generated/<slug>/` con los cuatro documentos y `findings.json`.
  Se añade a `.gitignore`, igual que `11_Reports/.report_profile`.
- `executive/`, `technical/` y `final_report/` dejan de escribirse; se quedan para informes
  antiguos y su contenido sigue ignorado. `README.md` y `FLUJO.md` del módulo se actualizan.
- `phase_status.bash` cuenta `11_Reports` como hecha si hay `generated/*/findings.json` o, por
  compatibilidad, un informe en `technical/` o `final_report/`.
- `run_all_reports.sh` llamará al envoltorio con `--all` (ambos informes) y mantendrá el
  empaquetado de evidencia.
- `09_Automation/python/report_generator.py` se convierte en aviso de obsolescencia que delega en
  el motor: conserva `--input`/`--output` (el `--output` solo aporta el directorio; los nombres
  pasan a ser los dos informes), imprime el aviso y nunca vuelve a convertir palabras en
  hallazgos.

## CLI

```bash
# envoltorio del gestor (slots)
./11_Reports/report_generator.sh ambos

# motor directo
python3 11_Reports/report_engine.py \
  --objetivo 127.0.0.1 --tipo ambos --scans ../scans \
  --salida 11_Reports/generated/127.0.0.1 --cliente "ACME" --auditor "…" [--abrir]
```

| Opción | Defecto | Qué hace |
|---|---|---|
| `--objetivo` | objetivo de `.session` | solo entra lo atribuible a ese host |
| `--tipo` | `ambos` | `tecnico` / `cliente` / `ambos` |
| `--scans` | `<repo>/scans` | raíz de resultados |
| `--salida` | `11_Reports/generated/<slug>` | destino |
| `--cliente` / `--auditor` | perfil / usuario del sistema | portada |
| `--todos` | no | agrega todos los objetivos en un informe multiobjetivo |
| `--incluir-sin-objetivo` | no | añade fuentes no atribuibles, marcadas |
| `--desde-json <ruta>` | no | re-renderiza sin volver a escanear (permite editar el registro) |
| `--json` | no | imprime el resumen por stdout para automatizar |
| `--abrir` | no | abre el HTML al terminar |

Códigos de salida: `0` informes escritos · `1` uso o E/S · `3` no había nada evaluable
(los informes se escriben igualmente y lo dicen en portada y apéndice).

## Pruebas

Nueva suite `tests/run_reports.sh` con fixtures de formato real en `tests/fixtures/reports/`:

| Caso | Aserto |
|---|---|
| XML de nmap con puerto abierto y un CVE en `<script>` | 1 confirmado (CVE) + 1 observación (puerto), severidad correcta |
| JSONL de nuclei con `severity: high` | confirmado, severidad alta, `matched-at` como activo |
| TXT de nuclei estándar y una línea basura | 1 hallazgo; la basura va a `no_evaluable` |
| Nikto con «No CGI Directories found» y con un `CVE-` | 0 hallazgos por el ruido; 1 por el CVE |
| ffuf con `-fs 96` y un hit de 96 bytes | 0 confirmados; el hit aparece en `descartados` |
| ffuf con `-fs 96` y un hit de 5000 bytes | 1 observación de inventario |
| ffuf sin `-fs` en `commandline` | `no_evaluable`, 0 confirmados |
| `rate_limit` `SIN FRENO` / `FRENADO` / `NO DETERMINADO` | hallazgo alto / sin hallazgo / `no_evaluable` |
| sqlmap `INYECTABLE`, `NO INYECTABLE`, `NO DETERMINADO` | 1 crítico / 0 / `no_evaluable` |
| `sqli_findings` con y sin diferencial | candidato / nada |
| `http_inject` `CONFIRMADO`, `FUERTE`, `DEBIL` | hallazgo / candidato / descartado |
| `security_headers` vacío sin `headers_*.txt` | `no_evaluable`, no «faltan cabeceras» |
| **trampa de palabras**: archivo con `password`, `inject`, `CVE-2024-1234` en texto suelto | 0 hallazgos |
| atribución: `127.0.0.1` con `127.0.0.10` en el mismo `scans/` | solo entra el primero |
| fuente sin objetivo (`api/methods.txt`) | apéndice; entra marcada con `--incluir-sin-objetivo` |
| dedupe: mismo CVE en XML y en JSONL | 1 hallazgo con 2 evidencias |
| dedupe: sqlmap + http_inject + sqli_findings sobre el mismo parámetro | 1 confirmado crítico con 3 evidencias |
| determinismo: dos ejecuciones | `findings.json` idéntico salvo `generado_en` |
| `--desde-json` | re-renderiza y respeta una edición del registro |
| cliente vs técnico | el de cliente no contiene `scans/`, payloads ni candidatos como explotados; el técnico sí cita `archivo:línea` |
| sin datos | exit 3, informe con apéndice `no_evaluable` |

Además:
- `tests/run_smoke.sh`: hoy afirma que `report_generator.sh` escribe «PLANTILLA». Pasa a
  comprobar que, con un fixture de `scans/`, genera un informe real y que la cabecera ya no dice
  PLANTILLA. Cambio deliberado.
- `tests/run_tests.sh`: `11_Reports/report_generator.sh` sale de la lista de «modo manual» y pasa a
  comprobarse como `slots` (`[tipo]`), incluido su `Ejemplo:`. El shim de
  `09_Automation/python/report_generator.py` sigue en modo `manual`.
- `bash -n` y `py_compile` siguen pasando.

## Manual

`docs/MANUAL-GESTOR.md`, en español, con: instalación y requisitos; arranque; objetivo de sesión;
recorrido por fases con el orden recomendado; marcas (`[intrusiva]`, `[manual]`, `[generador]`);
cómo se generan los dos informes (menú `R` y línea de comandos); perfil de cliente; atribución y
`--todos`; cómo leer los estados (`CONFIRMADO` ≠ `FUERTE`; `NO DETERMINADO` ≠ limpio); qué mirar
en el apéndice de no evaluable; alcance y seguridad; problemas frecuentes (herramienta no
instalada, `errores.log`, sin objetivo, informe vacío). Enlazado desde el `?` del menú y desde
`README.md`.

## Límites conocidos

- Solo se evalúa lo que las herramientas ya escribieron; un escaneo que no se ejecutó no se
  inventa.
- Nikto sin CVE se queda en observación: su texto no permite afirmar explotación.
- Un hit de ffuf es inventario, no vulnerabilidad: para subirlo haría falta verificar contenido
  (futuro).
- La severidad de un CVE sin CVSS consta como «media» y el informe dice que no se consultó.
- Un WAF que contesta `403` a todo sigue siendo un hueco de precisión en fuzzing; se marca
  `no_evaluable` si no hay `-fs` y se explica.
- La atribución por nombre es heurística: si un operador renombra un archivo quitándole el host,
  ese archivo pasa a «sin objetivo atribuible», no a otro informe.
- `--todos` es la única vía de mezclar objetivos; el informe lo dice en portada.

## Decisiones tomadas aquí (no del partner)

- Cuatro estados de confianza (confirmado / candidato / observacion / descartado): separar
  «diferencial» de «explotado» evita vender como probado lo que solo es sospechoso.
- Las observaciones de endurecimiento **sí** aparecen en el informe de cliente, en sección aparte:
  son recomendaciones legítimas; lo que no se hace es presentarlas como explotadas.
- Los candidatos no se detallan en el informe de cliente: solo un recuento y la recomendación de
  revisarlos.
- HTML autocontenido en vez de depender de CDN o de Pandoc: tiene que abrirse en cualquier equipo
  del cliente, sin red.
- No se toca ningún escáner en v1: el `-fs` de ffuf se recupera de su `commandline` y nuclei se
  parsea en su formato de texto estándar. Si en el futuro se añade `-jsonl`, el motor ya lo
  prefiere.
- `scope.yaml` no se parsea: la portada declara el alcance como el objetivo, y el motor no bloquea
  porque no toca la red. Evita una dependencia de PyYAML en un motor que debe ser stdlib.
