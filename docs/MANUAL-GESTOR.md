# Manual del Gestor Interactivo

Guía de uso de `cyber_framework.sh`, el punto de entrada interactivo del framework de auditoría de seguridad.

---

## Requisitos e instalación

### Sistema

- **Kali Linux 2024+** (recomendado) o cualquier distribución Linux con Bash 4.0+
- 8 GB RAM mínimo
- 50 GB espacio en disco

### Dependencias

```bash
sudo apt update
sudo apt install -y nmap masscan hydra ffuf sqlmap nikto whatweb \
    aircrack-ng wireshark tshark john hashcat \
    python3 python3-pip git tree
```

**Nota:** El gestor funciona sin herramientas de pentesting instaladas; cada script avisa si falta la suya.

### Instalación del framework

```bash
git clone https://github.com/Medina07P/CyberSecurity.git
cd CyberSecurity/CyberSecurity-Framework
find . -name "*.sh" -exec chmod +x {} \;
find . -name "*.py" -exec chmod +x {} \;
```

---

## Arranque

```bash
cd CyberSecurity-Framework
./cyber_framework.sh
```

Al arrancar, el gestor pregunta el **objetivo de sesión** (host o dominio). Puedes escribirlo o elegirlo de `00_Config/targets.txt`. Se guarda en `00_Config/.session` y se propone como valor por defecto en todos los scripts que piden un host.

La cabecera muestra:
- El objetivo actual
- Qué módulos tienen ya resultados (fases completadas)

### Teclas principales

| Tecla | Acción |
|---|---|
| `00`–`13` | Entrar en un módulo (también vale `0`–`9`) |
| `T` | Cambiar el objetivo de la sesión |
| `R` | Generar informes (técnico, cliente o ambos) |
| `99` | Flujo completo (ejecuta todas las fases en orden) |
| `?` | Ayuda, con el orden recomendado de fases |
| `Q` | Salir |

Cada script declara sus parámetros en su propia línea `Uso:`, así que el gestor pregunta exactamente los que necesita —también en los que piden dos o más— y ofrece el valor del `Ejemplo:` como defecto al pulsar Enter.

---

## Objetivo de sesión

El objetivo se guarda en `00_Config/.session` (git-ignored) y se usa para:

1. **Atribución de archivos**: el motor de informes solo incluye resultados atribuibles a ese host.
2. **Valor por defecto**: los scripts que piden un host lo proponen automáticamente.
3. **Filtrado**: evita mezclar resultados de distintos objetivos o laboratorios.

Al fijar el objetivo (`T` o el que escribes al arrancar), el gestor lo **registra solo** en dos sitios:

- `00_Config/scope.yaml`: el host en `targets.ips`, o el dominio **y** su comodín `*.dominio`
  en `targets.domains`. Se crea `scope.yaml.bak` y se valida el YAML; si algo falla, se avisa y
  el objetivo de la sesión sigue valiendo.
- `00_Config/targets.txt`: una línea `<host>|—|—|Registrado al fijar el objetivo|B` bajo una
  cabecera fechada. El `—` significa "puerto y protocolo desconocidos" y es lo que entiende
  `parse_targets.py`; `B` es prioridad baja.

Con eso el objetivo aparece en la lista de `T` la próxima vez y el flujo completo ya no te
dirá que está fuera de alcance. Para deshacerlo no hay comando: borra a mano las líneas de
`scope.yaml` y `targets.txt` (o restaura `scope.yaml.bak`).

> Ojo: como el gestor registra lo que fijas, la comprobación de alcance pasa a ser un
> **registro** de lo que has usado, no una barrera. La autorización real es el documento de
> `authorization.document` en `scope.yaml`.
>
> Y ojo también con git: `scope.yaml` y `targets.txt` **están versionados**, así que el dominio
> real de un cliente aparecerá en `git status` en cuanto lo fijes. No hagas `git add -A` a
> ciegas en este repo.

Si defines varios objetivos en `00_Config/targets.txt`, el gestor te los ofrece como lista. Puedes cambiarlo en cualquier momento con `T`.

### Sin objetivo

Si no defines un objetivo de sesión, el motor de informes:
- Avisa y se comporta como `--todos` (incluye todo lo que haya en `scans/`)
- O puedes usar `--incluir-sin-objetivo` para añadir fuentes no atribuibles, marcadas como tales

---

## Recorrido por fases

El orden recomendado es:

1. **00_Config**: valida el alcance (`scope.yaml`) y los objetivos (`targets.txt`)
2. **01_OSINT**: inteligencia de fuentes abiertas (dominios, empresas y archivos locales)
3. **02_Recon**: descubrimiento de hosts vivos
4. **03_Scanners**: escaneo de puertos y vulnerabilidades
5. **04_Enumeration**: enumeración de servicios
6. **05_Exploitation** y **06_PostExploitation**: solo si tienes autorización explícita
7. **07_Wireless**: menú de mantenimiento local; no acredita auditoría inalámbrica
8. **08_Forensics**: análisis forense
9. **09_Automation**: automatización y workflows
10. **10_Evidence**: gestión de evidencias
11. **11_Reports**: generación de informes
12. **12_Knowledge_Base**: base de conocimiento
13. **13_Labs**: laboratorios de práctica

### Flujo rápido

```bash
# Ejecutar todas las fases en orden (pide confirmación)
99
```

El flujo completo comprueba el alcance de `scope.yaml` y pide confirmación antes de ejecutar scripts intrusivos.

---

## Módulo 03: escáneres guiados

Al entrar en **03** aparece un menú específico:

1. **Comprobar herramientas**: consulta disponibilidad local; no escanea,
   instala ni actualiza nada.
2. **Puertos y servicios básicos**: 100 puertos TCP con Nmap y detección ligera
   de servicios, sin NSE ni detección de SO. Propone el objetivo de sesión;
   sin sesión no usa una IP de ejemplo.
3. **Analizar una URL**: elige Nikto o Nuclei e introduce una URL HTTP(S)
   completa con esquema, puerto y ruta. No se adivina el esquema desde la sesión.
4. **Burp manual**: abre el lanzador y explica la captura; Community no escanea
   ni guarda proyectos.
5. **Avanzado**: conserva los diez scripts. Smart completo, NSE, Nmap agresivo,
   Masscan, RustScan y run_all son intensivos y piden confirmación adicional.

Antes del análisis básico o web se muestra herramienta, objetivo e intensidad.
Solo una confirmación afirmativa ejecuta. `0` o `!` cancela la pregunta de
objetivo; EOF no inicia herramientas. El menú nunca eleva privilegios.

Los fallos de herramientas son **NO DETERMINADO**, no «sin vulnerabilidades».
El orquestador resume ejecutadas, fallidas y omitidas; los logs conservan el
historial fechado. Una omisión no equivale a una evaluación limpia.

Nuclei se limita a plantillas HTTP con tasa 10/s y concurrencia 2, sin
Interactsh ni comprobaciones de actualización. El flujo web no reemplaza una
prueba autenticada con petición capturada en Burp.

Detalles y verificación aislada en `CyberSecurity-Framework/03_Scanners/README.md`.

## Módulo 04: enumeración guiada sin perder capacidades

`04` permite comprobar herramientas, elegir SSH/FTP/SMB/LDAP/bases de datos/web/API,
ejecutar el flujo completo original, ver resultados del objetivo y acceder a
las **16 entradas**, incluidos auxiliares y ambos generadores.

El menú muestra las operaciones y pide confirmación. Se conservan accesos
anónimos, credenciales por defecto, usuarios, todos los métodos HTTP y fuzzing:
**no son comprobaciones pasivas**. En particular POST/PUT/DELETE/PATCH pueden
modificar datos, NSE `ftp-*` puede ser intrusivo y Redis `KEYS *` puede ser costoso.

Web/API pide URL completa; conserva esquema, puerto, ruta y query. El visor no
atribuye archivos antiguos a la sesión por suposición. Los nuevos resultados
llevan host/puerto y metadata; un fallo no se presenta como «sin hallazgos» ni
reutiliza un resultado previo como actual. Los diagnósticos se conservan fechados.

`0`/`!` cancela la pregunta de objetivo/puerto; EOF o confirmación negativa no
ejecuta herramientas. La CLI histórica sigue disponible y no añade prompts
interactivos nuevos. No se instala nada ni se eleva privilegios automáticamente.

Detalles, riesgos y ejemplos: `CyberSecurity-Framework/04_Enumeration/README.md`.

## Módulo 05: explotación guiada

`05` ofrece un menú guiado con las capacidades de explotación ya disponibles:

1. **Herramientas**: fuerza bruta SSH/FTP, Kerberos, CVE, WiFi, payloads y shells.
2. **Web capturada**: `http_inject.sh`, `sqlmap_request.sh`, `rate_limit_probe.sh` sobre una petición capturada en Burp.
3. **Web por URL/host**: `xss.sh`, `sql_injection.sh`, `web_attack.sh` (fuzzing).
4. **SSH/FTP**: fuerza bruta con hydra.
5. **Bases de datos**: MySQL, PostgreSQL, Redis.
6. **Kerberos**: ataque con kinit aislado.
7. **CVE**: sonda de versión (sin payload).
8. **Payload/shell**: generación de reverse shells.
9. **WiFi**: escaneo con iwlist (requiere interfaz).
10. **Plantillas**: plantillas de explotación.
11. **Flujos completos**: `run_all_attacks.sh`, `run_all_exploits.sh`.
12. **Resultados**: visor de evidencia (`show_results.sh`).
13. **Lista completa**: todas las entradas (reutiliza `run_module_scripts`).
14. **Volver**.

Todas las opciones piden confirmación antes de ejecutar y no elevan privilegios automáticamente. Las hojas capturadas mantienen sus contratos y permisos independientes (`SQLMAP_SI`, `SQLMAP_ENUMERAR`, `SQLMAP_TABLA`).

Detalles, riesgos y ejemplos: `CyberSecurity-Framework/05_Exploitation/README.md` y `docs/EXPLOTACION-2026-11-10.md`.

## Módulo 07: mantenimiento inalámbrico

Al entrar en **07** aparece un menú específico:

- **1 — Comprobar herramientas**: consulta `command -v` sin ejecutar binarios.
  Informa presencia o ausencia de sudo, ip, iw, airodump-ng, aireplay-ng,
  aircrack-ng, hcitool, bluetoothctl, sdptool y gatttool. No instala nada.
- **2 — Guía y límites**: texto local, sin leer capturas ni validar evidencia.
- **11 — Lista original**: conserva las diez entradas y las confirmaciones del
  listado genérico; abrirlo no ejecuta automáticamente hojas o flujos.
- **0 — Volver**: regresa al menú principal. EOF vuelve sin despachar acciones;
  una opción inválida muestra aviso. Las opciones 1 y 2 pausan al terminar.

La comprobación no eleva privilegios, cambia interfaces/servicios ni transmite
por radio. Presencia en PATH no acredita adaptador compatible, permisos,
funcionamiento operacional o auditoría realizada. El acceso a las operaciones
originales no las convierte en pasivas ni sustituye autorización y revisión
específica; no ejecutar el flujo completo como smoke test.

`wifi_handshake.sh` imprime una guía: **no captura ni verifica automáticamente
un handshake**. El mantenimiento no modifica ni valida operacionalmente las
diez hojas/flujo, y no implementa el plan operacional integral de 07.

Detalles e inventario: `CyberSecurity-Framework/07_Wireless/README.md` y
`USE.md` en ese módulo. Regresión aislada y límites:
`docs/WIRELESS-MANTENIMIENTO-2026-11-11.md`.

## Marcas en la lista de scripts

Las marcas avisan antes de ejecutar:

- **`[intrusiva]`** — escaneo intensivo, fuerza bruta, explotación, persistencia o limpieza: pide confirmación aparte. Ejemplos: `nmap_aggressive.sh`, `hydra_brute.sh`, `rate_limit_probe.sh`.
- **`[manual]`** — usa banderas o subcomandos: escribes la línea de argumentos completa. Ejemplos: `nmap_smart.sh` (si tiene `--flags`), `interface_manager.sh`.
- **`[generador]`** — escribe otro script, no escanea nada. Ejemplos: `enum_smb.sh`, `deepseeenum_web.sh` (escriben el script real en su primera ejecución; `ps_exec.sh` y `linpeas.sh` hacen lo propio).

---

## Informes

### Menú `R`

Desde el menú principal, pulsa `R` para acceder al submenú de informes:

```
1. Informe técnico
2. Informe de cliente
3. Ambos informes
```

El gestor:
1. Pide **cliente** y **auditor** la primera vez y los guarda en `11_Reports/.report_profile` (git-ignored). Enter conserva el valor.
2. Usa el objetivo de la sesión.
3. Ejecuta el motor de informes (`11_Reports/report_engine.py`).
4. Muestra las rutas de los informes generados.
5. Ofrece abrir el HTML con `xdg-open`.

### Los dos informes

- **Técnico** (`informe_tecnico.md` y `.html`): hallazgos con severidad, activo, técnica, evidencia (`archivo:línea`), reproducción, recomendación y referencias.
- **Cliente** (`informe_cliente.md` y `.html`): resumen ejecutivo, riesgo de negocio, plan de acción, sin payloads ni rutas internas.

Ambos se generan en `11_Reports/generated/<objetivo>/`.

### Línea de comandos

```bash
# Envoltorio amigable (slots)
./11_Reports/report_generator.sh [tipo]
# Ejemplo: ./11_Reports/report_generator.sh ambos

# Motor directo
python3 11_Reports/report_engine.py \
  --objetivo 127.0.0.1 --tipo ambos --scans ../scans \
  --salida 11_Reports/generated/127.0.0.1 --cliente "ACME" --auditor "Ana"
```

### Opciones del motor

| Opción | Defecto | Qué hace |
|---|---|---|
| `--objetivo` | objetivo de `.session` | solo entra lo atribuible a ese host |
| `--tipo` | `ambos` | `tecnico` / `cliente` / `ambos` |
| `--scans` | `<repo>/scans` | raíz de resultados |
| `--salida` | `11_Reports/generated/<slug>` | destino |
| `--cliente` / `--auditor` | perfil / usuario del sistema | portada |
| `--todos` | no | agrega todos los objetivos en un informe multiobjetivo |
| `--incluir-sin-objetivo` | no | añade fuentes no atribuibles, marcadas |
| `--desde-json <ruta>` | no | re-renderiza sin volver a escanear: edita `findings.json` (no el Markdown) y vuelve a generar |
| `--json` | no | imprime el resumen JSON por stdout |
| `--abrir` | no | abre el HTML al terminar |

### Perfil de cliente

El perfil se guarda en `11_Reports/.report_profile` (git-ignored) con formato:

```
cliente=ACME
auditor=Ana
```

Se crea la primera vez que usas `R` o puedes editarlo manualmente. Enter conserva el valor.

---

## Cómo leer los veredictos

### Resultados OSINT

`01_OSINT` no inventa perfiles a partir de un usuario: consulta enlaces del sitio
de referencia, búsquedas de cuentas GitHub y APIs compatibles configuradas en
`K` (Brave para redes, GitHub y Hunter para correos). Sin Brave no hay búsqueda
web general de redes; las fuentes omitidas, bloqueadas o fallidas quedan visibles.
Un candidato no prueba pertenencia y un enlace desde el sitio tampoco acredita
propiedad. No se confunden cuentas GitHub con emails ni certificados con hosts activos.

`run_all_osint.sh <dominio> [archivo] [empresa]` comparte las consultas en una
sesión. Deja archivo vacío para dar empresa sin extraer metadatos. Las rutas de
archivo relativas se resuelven desde el directorio del llamador. En redes puedes
dar empresa, directorio de salida opcional y dominio de referencia opcional.

La fuerza bruta **DNS de subdominios** solo se activa al dar un diccionario local
en el tercer campo de `subdomain_finder.sh` y confirmar `DNS_SI`; el cuarto campo
es la IP de resolver opcional. Nunca se activa en run_all. Máximo 1.000 nombres,
5 consultas DNS/s agregadas y 120 s; controles wildcard previos y resultados
ambiguos separados de los resueltos. No incluye AXFR ni ataques de contraseñas.

Cada ejecución guarda `resultados.json`, `resumen.txt` y `errores.log` en una
carpeta única bajo los directorios ignorados de `01_OSINT` (run_all usa
`domains/`). No usa `scans/` para estos artefactos. Código 0 significa fuentes
intentadas completadas, no cobertura exhaustiva; 1 es parcial/fallo, 2 es entrada
o configuración inválida. El resumen muestra omisiones y límites.

Consulta [el README de OSINT](../CyberSecurity-Framework/01_OSINT/README.md) para
ejemplos, claves compatibles y las limitaciones de theHarvester (omitido en esta
entrega por reintentos/errores opacos). Estos datos no son vulnerabilidades ni
se integran automáticamente en los informes de vulnerabilidades.

### Estados de confianza

- **`confirmado`**: la herramienta demostró explotación o un diferencial concluyente. Ejemplos: `sqlmap` inyectable, `http_inject` confirmado, `SIN FRENO`, CVE de nuclei.
- **`candidato`**: diferencial reproducible que aún no prueba explotación. Ejemplos: `http_inject` fuerte, `sqli_findings` con diferencial.
- **`observacion`**: configuración observada directamente, sin explotar. Ejemplos: puerto abierto, cabecera ausente, auth por contraseña.
- **`descartado`**: eco, catch-all, `429`, timeout. Se cuenta y se explica, no se publica.

### Diferencias importantes

- **`CONFIRMADO` ≠ `FUERTE`**: `CONFIRMADO` es un hallazgo demostrado; `FUERTE` es un candidato que requiere revisión.
- **`NO DETERMINADO` ≠ limpio**: significa que la herramienta no pudo concluir (por ejemplo, sqlmap ante un `429`). Va al apéndice de **no evaluable**, nunca a «sin riesgo».
- **Ausencia de evidencia ≠ evidencia de ausencia**: un `security_headers_*.txt` vacío no significa «faltan cabeceras»; hace falta el `headers_*.txt` pareado con un 2xx/3xx. Si no está, `no_evaluable`.

### Apéndice de no evaluable

El técnico incluye un **Apéndice A: no evaluable** con la fuente y qué falta para poder evaluarla. Ejemplos:
- Archivo vacío y sin el pareado necesario
- Fuente sin objetivo atribuible
- `NO DETERMINADO` de una herramienta

Si ves «N pruebas requieren revisión» en el informe de cliente, mira este apéndice en el técnico.

---

## Alcance y seguridad

### Alcance

Todos los scripts deben ejecutarse dentro del alcance definido en `00_Config/scope.yaml`. El flujo completo (`99`) lo comprueba y pide confirmación.

El motor de informes **no parsea** `scope.yaml` en v1 (evita depender de PyYAML) y **no bloquea**: la portada declara el alcance como el objetivo de sesión.

### Seguridad

- Los escaneos van a `scans/<herramienta>/` en la raíz del repositorio, se lance el script desde donde se lance. Los artefactos OSINT quedan en los directorios ignorados de `01_OSINT` descritos arriba.
- `scans/` está en `.gitignore`: contiene IPs y hallazgos de cada sesión, no se sube al repositorio.
- Los scripts intrusivos (`[intrusiva]`) piden confirmación aparte.
- Nunca ejecutes `99` como prueba de humo: ejecuta fuerza bruta, explotación y limpieza contra todos los objetivos configurados.

### Herramientas no instaladas

Si una herramienta no está instalada, el script avisa y continúa (o sale con error, según el caso). Los resultados parciales se guardan en `scans/` y los errores en `scans/<herramienta>/errores.log`.

---

## Problemas frecuentes

### Herramienta no instalada

**Síntoma:** el script dice «herramienta no encontrada» o «command not found».

**Solución:** instala la herramienta con `apt` o verifica que está en el `PATH`. El gestor funciona sin herramientas de pentesting; cada script avisa si falta la suya.

### `errores.log`

**Síntoma:** un script termina con 0 hallazgos pero sospechas que falló.

**Solución:** mira `scans/<herramienta>/errores.log`. Si está vacío, el script terminó sin errores. Si tiene contenido, la herramienta falló (no el script).

### Sin objetivo

**Síntoma:** el motor de informes dice «sin objetivo» o genera un informe multiobjetivo.

**Solución:** define el objetivo con `T` o edita `00_Config/.session`. Si quieres incluir todo, usa `--todos` o `--incluir-sin-objetivo`.

### Informe vacío

**Síntoma:** el informe dice «0 hallazgos» o «no hay datos evaluable».

**Causas:**
1. No se ejecutó ningún escáner (no hay archivos en `scans/`).
2. El objetivo de sesión no coincide con los archivos (atribución).
3. Todos los archivos son `no_evaluable` (vacíos, sin pareado, `NO DETERMINADO`).

**Solución:** verifica que hay resultados en `scans/`, que el objetivo es correcto y que las herramientas terminaron sin errores.

### `429` / `503` en los resultados

**Síntoma:** ves `429` o `503` en los archivos de `scans/`.

**Significado:** la herramienta fue frenada (rate limiting). No es un hallazgo, es una incidencia de ejecución. El motor lo clasifica como `descartado` o `no_evaluable`, según el caso.

**Solución:** revisa `errores.log` y considera reducir la velocidad de escaneo o respetar `Retry-After`.

### El informe de cliente no menciona un hallazgo

**Síntoma:** el técnico menciona un hallazgo pero el de cliente no.

**Causa:** el informe de cliente solo puede afirmar lo que está en `hallazgos` con `confianza=confirmado`. Los `candidato` se mencionan solo como recuento («N pruebas requieren revisión») y los `observacion` van a la sección de endurecimiento, nunca como explotados.

**Solución:** mira el técnico para ver el detalle, o espera a que el candidato se confirme con una prueba adicional.

---

## Claves de API

Las herramientas de OSINT y de reconocimiento leen sus claves de API de ficheros y bases
de datos distintos, y cuando falta una clave casi ninguna lo dice: theHarvester y h8mail
siguen arrancando y devuelven menos resultados. El framework centraliza las claves en un
único registro (`00_Config/credentials/api-keys.yaml`, ignorado por git) y escribe desde
ahí los ficheros de cada herramienta.

Entra con `K` en el menú principal, o con **`00 → 5. scripts/api_keys.py`**.
Ambas entradas abren el mismo menú guiado: no debes escribir subcomandos ni
pegar claves en una línea de argumentos. Desde `00`, la opción `0` vuelve al
módulo de configuración; desde `K`, vuelve al menú principal.

```
  K) 🔑 Claves de API  (6 herramientas · N con claves · M vacías)
     1) Pedir las claves que falten en cada herramienta
     2) Pedir las claves de una herramienta
     3) Ver el estado detallado
     4) Sincronizar el registro con las herramientas
     5) Importar lo que ya tienen las herramientas
     0) Volver al menú principal
```

- **Pedir** (`2` o la CLI `pedir <herramienta> [--campo X]`): sin `--campo` pregunta solo
  los campos vacíos. Enter deja el campo como está; `-` lo borra también del fichero de la
  herramienta. Con terminal no se ve lo que tecleas; por tubería avisa de que el eco es
  visible. No acepta valores con espacios: parece texto, no una clave. Si la clave tiene
  menos de 8 caracteres avisa (no bloquea): puede ser un error de tecleo.
- **Estado** (`3`): tabla con las claves puestas y el estado de cada herramienta.
  - `puesta (sin verificar)` — hay valor, no se ha probado contra el servicio.
  - `puesta (h8mail necesita -c)` — h8mail solo lee su INI si lo llamas con `-c`.
  - `vacía` — la herramienta está inicializada y no hay ningún valor.
  - `sin inicializar` — la herramienta no tiene todavía su fichero o base de datos.
  - `no instalada` — ni binario ni fichero.
  - `diverge` — la herramienta guarda un valor que el registro no explica; `5` lo importa.
- **Sincronizar** (`4`): vuelca el registro en todas las herramientas que ya tengan fichero
  o valores; no crea ficheros vacíos.
- **Importar** (`5`): trae al registro lo que la herramienta ya tenía.

Ninguna salida muestra el valor de una clave: solo presencia y longitud. El registro no
sustituye a las herramientas: si borras `api-keys.yaml`, las claves que ya estaban en sus
ficheros siguen ahí (`sincronizar`/`importar` las recuperan).

### Las otras opciones de configuración

- **`00 → 1`** ejecuta cuatro comprobaciones de solo lectura (validación,
  verificación, resumen de objetivos y estado de claves). No abre asistentes ni
  importa/sincroniza claves. Si un paso falla, continúa y termina con código 1,
  sin anunciar éxito global; los errores de herramientas quedan visibles.
- **`00 → 2`** abre el asistente de objetivos y pide confirmar antes de escribir.
- **`00 → 3/4`** comprueban archivos y estructura; devuelven 1 si falta algo.
- **`00 → 6`** muestra el resumen actual de objetivos, sin modificarlos. La CLI
  permite exportar JSON/CSV; un archivo ausente, ilegible o una salida no
  escribible produce error claro y código 1, no un traceback ni éxito silencioso.

«Ejecución directa» significa que no hacen falta argumentos externos. El
asistente muestra sus preguntas y las comprobaciones muestran sus resultados.
La CLI directa de api_keys sigue requiriendo un subcomando; el gestor evita
invocarla vacía al abrir el menú guiado.

---

## Referencia rápida de comandos

### Arranque y navegación

```bash
./cyber_framework.sh          # Arrancar el gestor
T                              # Cambiar objetivo
K                              # Claves de API
R                              # Generar informes
99                             # Flujo completo
?                              # Ayuda
Q                              # Salir
```

### Informes

```bash
# Desde el gestor
R → 1 (técnico) / 2 (cliente) / 3 (ambos)

# Desde la línea de comandos
./11_Reports/report_generator.sh ambos
python3 11_Reports/report_engine.py --objetivo 127.0.0.1 --tipo ambos

# Re-renderizar desde JSON
python3 11_Reports/report_engine.py --desde-json 11_Reports/generated/127.0.0.1/findings.json
```

### Configuración

```bash
nano 00_Config/scope.yaml      # Editar alcance
nano 00_Config/targets.txt     # Editar objetivos
nano 11_Reports/.report_profile # Editar perfil de cliente
```

### Claves de API

```bash
H=00_Config/scripts/api_keys.py
python3 $H estado                     # Tabla de estado
python3 $H estado --json              # Lo mismo, para scripts
python3 $H estado --faltan shodan     # 0 = completa, 1 = faltan, 2 = no existe
python3 $H pedir theharvester         # Pide las vacías, una por una
python3 $H pedir shodan --campo key   # Una concreta (Enter conserva, '-' borra)
python3 $H sincronizar                # Registro → ficheros de herramienta
python3 $H importar amass             # Fichero de herramienta → registro
```

### Verificación

```bash
cd 00_Config && ./scripts/validate_config.sh
```

```bash
cd CyberSecurity-Framework
./tests/run_tests.sh           # Librería del gestor y forma de Uso: de cada script
./tests/run_e2e.sh             # Script recibe argumento tecleado
./tests/run_smoke.sh           # Navegación del menú
./tests/run_reports.sh         # Motor de informes
bash ./tests/run_wizard.sh     # Asistente de configuración
```

### Resultados

```bash
tree scans/                    # Ver todos los resultados
tree 11_Reports/generated/     # Ver informes generados
cat scans/<herramienta>/errores.log  # Ver errores de una herramienta
```

---

## Documentación adicional

- `AGENTS.md`: conocimiento operativo, cómo están hechas las cosas y por qué.
- `docs/CLEANUP-2026-10-30.md`: sesión de limpieza, 44 ficheros en cuarentena, 8 bugs corregidos.
- `docs/GESTOR-2026-10-30.md`: diseño del gestor, parser de `Uso:`, sesión, estado de fases.
- `docs/SCANS-PATHS-2026-10-30.md`: por qué todos los resultados van a `<repo>/scans/`.
- `docs/ARREGLOS-FRAMEWORK-2026-10-31.md`: once fixes tras la primera prueba real.
- `docs/BURP-HTTP-INJECT-2026-10-31.md`: Burp y `http_inject.sh`.
- `docs/SQLMAP-Y-FRENOS-2026-10-31.md`: sqlmap, `Retry-After` y rate limiting.
- `docs/RATE-LIMIT-2026-10-31.md`: prueba de rate limiting.
- `docs/PATHS-KALI-2026-10-31.md`: rutas absolutas y relativas en Kali.

---

**Última actualización:** 2026-11-10
