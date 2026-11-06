# Arreglos del framework — 2026-10-31

Documento de referencia de los once arreglos que salieron de la prueba en vivo
contra una app real de facturación recurrente (VPS de producción; el host y la IP no
se escriben aquí a propósito — ver más abajo «Datos del engagement»). El informe de la
auditoría y la lista de defectos original está en
`CyberSecurity-Framework/11_Reports/final_report/informe_<objetivo>_2026-10-31.md`.
El diseño aprobado está en `docs/superpowers/specs/2026-10-31-arreglos-framework-design.md`
y el plan ejecutado en `docs/superpowers/plans/2026-10-31-arreglos-framework.md`.

## Lo que cambió

### 1. `00_Config/lib/scans.bash` (nuevo)

Rutas, nombres y línea base compartidos. Contrato:

| Función | Devuelve |
|---|---|
| `scans_root` | `<repo>/scans` |
| `scans_dir <tool>` | `<repo>/scans/<tool>`, creado. **Solo imprime la ruta** |
| `scans_slug <objetivo>` | `:` y `/` sustituidos por `_` |
| `scans_signature <url>` | `código:tamaño` de la respuesta |
| `scans_baseline_size <url>` | tamaño del relleno catch-all, o `0` si el servidor responde 404 de verdad |
| `scans_ffuf_count <json>` | hallazgos reales en la salida de ffuf (`results`), no la `url` de la configuración |

La línea base se calcula pidiendo una ruta aleatoria que no debería existir: si
el servidor contesta 2xx/3xx con contenido, sirve lo mismo para todo y ese
tamaño es el que hay que filtrar. Es la diferencia entre "0 hallazgos" y "90
falsos positivos".

### 2. Portabilidad bajo zsh

Las cinco librerías resuelven su propio fichero con `${BASH_SOURCE[0]:-$0}`.
En bash `BASH_SOURCE` trae la ruta; en zsh queda vacío y `$0` es el fichero
sourceado. Sin eso, `SESSION_CONFIG_DIR` caía en la raíz del repo y el
`.session` se escribía fuera de su sitio.

### 3. `run_all_recon.sh` acepta objetivo

Antes ignoraba sus argumentos y usaba las tres primeras líneas de
`targets.txt` — con un objetivo de sesión distinto, escaneaba otros equipos.
La opción `99` del gestor sigue usando `auto_recon.sh`, que encadena menos.

### 4. Enumeración web: nombres y línea base

`enum_web.sh`, `enum_web_advanced.sh`, `nuclei_scan.sh`, `nuclei_cves.sh` y
`nikto_scan.sh` incluyen el objetivo en el nombre del fichero (dos objetivos
ya no se pisan) y `ffuf` se invoca con `-fs <tamaño base>`. El bucle de
archivos sensibles compara cada respuesta con la línea base.

`deepseeenum_web.sh` es un generador: su heredoc se mantiene en paralelo con
`enum_web.sh` y regenerar produce un fichero idéntico byte a byte.

### 5. Escáneres: nombres con objetivo

`nmap_smart.sh` usa `smart_ports_<slug>.*`, `smart_services_<slug>.*`,
`smart_vuln_<slug>.*`.

### 6. `sql_injection.sh` con línea base

Cada parámetro se sondea con un valor benigno y cada payload se compara con
esa respuesta: solo se reporta lo que difiere. Contra el catch-all de la app
real eso pasa de 90 falsos positivos a 0.

### 7. `stderr` a `errores.log`

Los ocho escáneres hoja de `03_Scanners/` redirigen el error de la herramienta
a `$OUTPUT_DIR/errores.log` y avisan de la ruta si quedó con contenido.
`run_all_scanners.sh` lista al final los logs no vacíos, después del banner de
cierre. Sin esto, un fallo de ejecución se lee como "0 hallazgos".

### 8. `report_generator.py`: el JSON ya no pisa el HTML

`self.output_file.replace('.html', '.json')` devolvía la misma ruta si
`--output` no acababa en `.html` (un `.md`, por ejemplo), así que el JSON
sobrescribía el HTML. Ahora `os.path.splitext(...)[0] + ".json"`.

### 9. Informes marcados como PLANTILLA

`report_generator.sh` no lee nada de `scans/`: escribe un esqueleto con huecos
`[FECHA]`, `[NOMBRE_CLIENTE]`. Cada informe generado lleva ahora una cabecera
`> ⚠️ **PLANTILLA**`, un aviso por pantalla y un pie que ya no dice "generado
automáticamente".

### 10. Informes generados fuera del índice

`11_Reports/executive/*.md` y `11_Reports/technical/*.md` están en
`.gitignore` y fuera de git: el generador los reescribe en cada ejecución. Las
plantillas de verdad están en `11_Reports/templates/`.

### 11. Convención escrita

`AGENTS.md` § Writing new scripts recoge las cuatro reglas: nombres con slug,
línea base antes de fuzzing, `errores.log` en vez de `2>/dev/null`, y
`${BASH_SOURCE[0]:-$0}` en las librerías.

## Verificación

- `bash tests/run_tests.sh` → **110 pasan, 0 fallan** (partía de 61).
- `bash tests/run_e2e.sh` → 11 pasan, 0 fallan.
- `bash tests/run_smoke.sh` → 0 fallos.
- `bash tests/run_wizard.sh` → 0 errores.
- `bash -n` sobre los 114 `.sh` del framework, capturando stderr: limpio.
- `python3 -m py_compile` sobre los 6 `.py`: limpio.

Las suites usan `curl`, `ffuf`, `nmap`, `nuclei` y `sqlmap` falsos en `PATH`,
así que no necesitan red, servidor ni una herramienta instalada.

## Datos del engagement

El host, la IP y la autorización del cliente **no viven en el repositorio**. El
remoto es público y `.gitignore` ya excluye los árboles con IPs reales por esa
misma razón. La copia de trabajo de ese día (alcance y objetivos reales) queda
en `/tmp/opencode/engagement-2026-10-31/`, fuera de git, y el informe en
`11_Reports/final_report/`, que también está ignorado. `00_Config/scope.yaml`
y `targets.txt` vuelven a sus valores de ejemplo: si se dejan con el host del
engagement, `scope_allows` lo seguirá aceptando en la siguiente sesión.

## Segunda pasada: lo que la revisión destapó

Una revisión con contexto fresco sobre los 12 commits encontró cinco cosas que
la primera pasada no vio. Todas están corregidas:

- **Datos del engagement en el índice.** Un `git add -A` metió `scope.yaml` y
  `targets.txt` con el host y la IP reales en un commit. Ambos vuelven a sus
  valores de ejemplo y el host ya no aparece en ningún fichero versionado.
- **`sql_injection.sh` podía fingir un objetivo limpio.** Solo probaba `https`
  en el 443 (no en el 8443), y sin conexión todas las firmas eran `000:0` →
  "sin diferencias". Ahora 8443 va por TLS, se comprueba la conexión antes de
  probar nada y se aborta con aviso si no hay respuesta.
- **La línea base no distinguía "sin catch-all" de cuatro casos que sí lo
  son.** Devolvía `0` para un 404 limpio y también para un WAF que contesta 403
  con cuerpo, un redirect sin cuerpo o un fallo de conexión. Ahora devuelve
  cadena vacía cuando no hay catch-all, acepta el 403 como catch-all y trata el
  tamaño `0` como un valor legítimo de filtro.
- **`errores.log` se acumulaba.** Una línea de error de hace un mes hacía que
  cada ejecución posterior avisara sin motivo. Los ocho escáneres lo truncan al
  empezar.
- **`run_all_scanners.sh` cerraba en verde sin mirar.** Si el `nmap` de
  descubrimiento de puertos fallaba, decía "no hay puertos web abiertos". Ahora
  distingue "no se pudo descubrir" de "no hay puertos".

También: `run_all_recon.sh` se ancla a su directorio (invocado desde otra ruta
no ejecutaba nada y aun así decía "completado"), los tests dejan de escribir el
`.session` real del operador y de borrar hallazgos ajenos, y el contador de
ffuf ya no cuenta la `url` de la configuración.

## Lo que sigue abierto

- `validate_target` no valida IPs bajo zsh: usa `BASH_REMATCH`, que zsh no
  rellena. Los dominios sí funcionan. Pendiente menor.
- Diez `run_all_*.sh` invocan a sus hermanos con `./hermano/...` sin anclarse
  a su directorio: funcionan desde el gestor, que siempre entra en el módulo,
  pero no lanzados desde otra ruta. Está documentado en `AGENTS.md`; arreglarlo
  son diez líneas y una pasada de tests, fuera del alcance de esta sesión.
- `report_generator.sh` y `report_generator.py` siguen sin consumir los
  resultados reales de `scans/`. Ahora lo dicen, que es la parte honesta; un
  generador que los lea es trabajo aparte.
