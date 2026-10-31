# Diseño — Arreglo de defectos del framework (enfoque B)

- **Fecha:** 2026-10-31
- **Estado:** pendiente de aprobación
- **Origen:** prueba real contra la app de facturación recurrente del engagement del 2026-10-31 (host no registrado aquí; ver el informe en `11_Reports/final_report/`, que está git-ignored)
- **Revisión:** pasó por un revisor independiente; sus objeciones están resueltas en «Resoluciones» al final.

## Intención y por qué

La prueba contra un objetivo real destapó ocho defectos de la herramienta. Cinco de ellos producen
salida silenciosamente incorrecta (falsos positivos, archivos que se pisan, informes vacíos), que es
el peor tipo de fallo en una herramienta de auditoría: el operador cree que tiene un resultado y no
lo tiene. El objetivo es que la herramienta deje de mentir, no que haga más cosas.

## Objetivo

Que cada defecto detectado en campo quede cerrado con una prueba de regresión que falle antes del
arreglo y pase después, sin romper las suites existentes (61 + 11 asserts y el smoke).

## No objetivos

- **Consumir resultados reales en `report_generator.sh`.** Decidido con el usuario: es una pieza
  aparte, posterior. Aquí solo se corrige que el generador *afirme* ser automático cuando no lo es.
- Probar peticiones autenticadas JSON. Corresponde al trabajo de Burp (fase siguiente).
- Migrar los ~100 scripts que escriben nombres sin el objetivo. Lista cerrada abajo; el resto queda
  como migración incremental documentada.
- Cambiar el comportamiento de la opción `99` del gestor.

## Anti-objetivos

- Suprimir el `stderr` de forma más elegante en vez de hacerlo visible.
- "Arreglar" el fuzzing subiendo el umbral de códigos HTTP: eso no elimina el catch-all.

## Restricciones

- Bash, estilo existente: sin `set -e`, mensajes en español, `Uso:`/`Ejemplo:` funcionales.
- Autolocalización: nada de rutas absolutas ni dependencia del `cwd`.
- La librería va en `00_Config/lib/*.bash` para que el gestor no la liste ni `run_all_*` la ejecute.
- LF, no CRLF.

## Enfoques considerados

| | Enfoque | Compromiso |
|---|---|---|
| A | Parche quirúrgico, defecto a defecto | Mínimo riesgo, pero el bug de nombres vuelve con el próximo script |
| **B** | **Parche + librería de salidas en `00_Config/lib/`** | **Más trabajo; mata la clase de bug y sigue el patrón ya establecido** |
| C | B + generador de informes que consume `scans/` | Funcionalidad nueva que arrastra el diseño de Burp |

**Elegido: B**, por decisión del usuario. C queda como pieza posterior.

## La librería nueva: `00_Config/lib/scans.bash`

Mismo contrato que las demás: quien devuelve un valor imprime **solo** el valor por stdout; la
interfaz va a stderr. Resuelve su ruta con `${BASH_SOURCE[0]:-$0}`, igual que el resto tras el #1.

| Función | Contrato |
|---|---|
| `scans_root` | Raíz `scans/` del repo, resuelta desde el propio archivo |
| `scans_dir <tool>` | Crea y devuelve `<repo>/scans/<tool>`. Conserva los nombres actuales (`web`, `nuclei`…) para que `phase_status.bash` siga funcionando |
| `scans_slug <objetivo>` | Sustituye `:` y `/` por `_`; sufijo estable del nombre |
| `scans_baseline_size <url>` | Pide una ruta aleatoria inexistente y devuelve el tamaño del relleno (catch-all); `0` si no hay catch-all |
| `scans_signature <url>` | Devuelve `código:tamaño` de una URL. Es la primitiva que usa `sql_injection.sh` para comparar contra un valor benigno |

`scans_baseline_size` detecta *catch-all*; `scans_signature` compara peticiones equivalentes. Son
cosas distintas y el diseño las separa a propósito (ver Resolución 1).

## Las correcciones

1. **Portabilidad de la librería (los 5 archivos, no uno).** `BASH_SOURCE[0]` no existe en `zsh`; al
   sourcear desde ahí, `session.bash` escribía `.session` en la raíz del repo. Se aplica
   `${BASH_SOURCE[0]:-$0}` en `session.bash`, `params.bash`, `phase_status.bash`, `prompt.bash` y en
   la nueva `scans.bash`. *Test:* sourcear las cinco desde `zsh` y comprobar que resuelven bajo
   `00_Config/`.
2. **`02_Recon/run_all_recon.sh` acepta objetivo.** Hoy ignora el argumento y escanea las tres
   primeras líneas de `targets.txt`; en la prueba habría lanzado todo contra `192.168.1.10`, fuera de
   alcance. Pasa a: `<objetivo>` opcional; con argumento escanea solo ese; sin argumento mantiene el
   comportamiento actual. Se le añade `Uso:`/`Ejemplo:` (hoy no tiene, así que `params_mode` devuelve
   `none` y el menú del módulo nunca le pasa objetivo). *Test:* con argumento no lee `targets.txt`.
3. **Nombres de salida con el objetivo.** Lista cerrada de migración:
   `04_Enumeration/web/enum_web.sh` y `enum_web_advanced.sh` (hoy `headers_443.txt`,
   `security_headers_8443.txt`…), y `03_Scanners/network_scanners/nmap/nmap_smart.sh`
   (`smart_ports.nmap`). Los escáneres de `03_Scanners/web_scanners/` ya incluyen el objetivo con un
   `${URL//[:\/]/_}` inline: pasan a usar `scans_slug` sin cambiar el nombre resultante, así que no
   rompen nada. *Test:* dos objetivos en el mismo puerto producen dos archivos distintos.
4. **`sql_injection.sh` sin falsos positivos.** Antes marcaba cualquier `200/301/302/500` (90
   "hallazgos", todos falsos). Ahora, por cada parámetro, toma la firma de una petición con valor
   benigno y solo reporta cuando el payload produce una firma **distinta**; si el sitio tiene catch-all
   y todas las firmas coinciden, reporta cero. *Tests:* (a) catch-all → 0 hallazgos; (b) servidor
   normal que responde 404 a todo → 0 hallazgos.
5. **`ffuf` con línea base.** `-mc 200,301,302,403` deja pasar toda ruta de una SPA; se añade
   `-fs <tamaño base>` calculado con `scans_baseline_size`. *Test:* catch-all → 0 resultados.
6. **`report_generator.py` deja de pisar el HTML.** `output.replace('.html', '.json')` es un no-op si
   la extensión no es `.html`, y el JSON sobrescribe el HTML. Pasa a `os.path.splitext`. *Test:*
   `--output x.md` genera `x.md` y `x.json`.
7. **`report_generator.sh` honesto.** Se rotula como plantilla mientras no consuma resultados, en el
   informe y en pantalla. No se disfraza de automático.
8. **`executive/` y `technical/` fuera del índice.** Están versionados, así que añadir reglas a
   `.gitignore` no basta (confirmado por el revisor). Se sacan con `git rm --cached` —siguen en disco,
   las plantillas reales están en `templates/`— y se ignoran los `.md` conservando `.gitkeep`.
   *Test:* `git status --porcelain` limpio **para esas dos rutas concretas** tras ejecutar el generador.
9. **`stderr` visible en los escáneres.** Los 8 escáneres hoja de `03_Scanners` pasan de
   `2>/dev/null` a `2>>"$OUTPUT_DIR/errores.log"`, y cada uno imprime la ruta del log al terminar,
   avisando si no está vacío. `run_all_scanners.sh` resume al final qué logs quedaron con contenido.
   *Test:* un fallo forzado deja rastro en el log y el aviso aparece.

## Resoluciones de la revisión

1. **Qué es la línea base.** El revisor tenía razón: si la base fuera solo el catch-all, en un servidor
   normal (404) la base sería `0` y todo `200` "diferiría", reproduciendo los 90 falsos positivos. Por
   eso hay dos primitivas: `scans_baseline_size` (¿hay catch-all?) y `scans_signature` (firma de la
   misma petición con valor benigno). El test (b) existe justo para cubrir el caso que faltaba.
2. **El gestor no cambia de comportamiento.** La opción `99` sigue usando `auto_recon.sh`; solo se
   actualiza el comentario que justifica esa elección, que si no queda desfasado. Cambiar la fase a
   `run_all_recon.sh` multiplicaría por 15 lo que hace hoy la opción `99`, y eso es una decisión de
   seguridad, no un arreglo.
3. **`deepseeenum_web.sh`: actualización en paralelo** (decisión del usuario). Su heredoc recibe la
   versión corregida, de modo que regenerar produce el script arreglado y no revierte el #3 ni el #5.
4. **Migración acotada** a la lista del punto 3. No se reescriben los ~100 scripts restantes: el riesgo
   de tocar todos los `run_all_*` de golpe supera el beneficio.
5. **Portabilidad en los cinco archivos**, no solo en `session.bash`; si no, `prompt.bash` seguiría
   resolviendo mal desde `zsh`.
6. **`git rm --cached` autorizado** (decisión del usuario).
7. **El log se anuncia.** El anti-objetivo era que el error se vea; un log que nadie señala sigue
   permitiendo que "0 hallazgos" mienta. Se imprime ruta y aviso.
8. **Las suites siguen siendo portables.** Los tests que necesitan `zsh` o `git` se saltan con aviso
   si la herramienta no está, y son obligatorios en Kali. No se cambia el requisito de que
   `tests/*.sh` corran sin terminal.
9. **`run_all_scanners.sh` no tiene `OUTPUT_DIR`**: no se le inventa uno; resume los logs de los
   escáneres hoja.

## Decisiones que tomo yo, no el usuario

- **`errores.log` en vez de `2>&1`.** Volcar `stderr` a la consola rompería el parseo de la salida que
  el gestor muestra. Un archivo por directorio de herramienta conserva la evidencia.
- **`scans_slug` centraliza la limpieza** de `:` y `/`; los scripts dejan de repetir el `sed`.
- **POST/JSON no entra aquí.** Se resuelve con la petición capturada en Burp, en la fase siguiente.
- **`scans_dir` conserva los nombres actuales** de directorio para no romper `phase_status.bash`.

## Qué queda para el que construya

- Nombres exactos de los archivos de prueba y orden de los asserts.
- Si `scans_baseline_size` debe cachear por URL dentro de una ejecución (hoy: no).
- Redacción de la nota en `AGENTS.md` sobre la convención de nombres.

## Verificación

- Cada test nuevo: rojo antes del arreglo, verde después.
- `tests/run_tests.sh`, `tests/run_e2e.sh`, `tests/run_smoke.sh`, `tests/run_wizard.sh` en verde.
- `bash -n` capturando `stderr` en los scripts tocados (recordar que devuelve 0 ante un heredoc sin
  cerrar).
- Repetición de los casos reales: `enum_web.sh` contra un catch-all → 0 hallazgos; `sql_injection.sh`
  contra el mismo → 0 hallazgos.
