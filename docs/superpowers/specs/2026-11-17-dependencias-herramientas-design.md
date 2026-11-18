# Diseño: herramientas adicionales interactivas en la tecla `D`

**Fecha:** 2026-11-17
**Estado:** propuesto, pendiente de aprobación del documento
**Origen:** petición del usuario en conversación — la tecla `D` (dependencias)
solo instala paquetes `apt`; cinco binarios quedan en `DEPENDENCIES_NO_APT`
como puro texto informativo (`ollama`, `avml`, `lime`, `volatility`,
`nmap-vulners`). El usuario pidió que fueran "interactivas, que se puedan
descargar y verificar todos"; tras acotar el alcance en conversación
(ver "Diferencias con la petición original"), quedó aprobado automatizar
**ollama+modelo, avml y nmap-vulners**, dejando `lime` y `volatility` (v2)
como guía, sin automatizar.

## Intención y por qué

El framework es de código abierto: alguien que lo clona debe poder dejarlo
funcionando sin salir del gestor ni memorizar comandos. Hoy, cinco
herramientas que otros módulos sí usan (forense, automatización del asistente
IA, escaneo de vulnerabilidades) no tienen ruta de instalación desde `D`:
la persona tiene que leer `DEPENDENCIES_NO_APT`, copiar un comando a mano y
confiar en que lo escribió bien.

## Goals

1. La tecla `D` ofrece una segunda opción ("herramientas adicionales") junto
   a la instalación por `apt` ya existente, con el mismo patrón de selección
   numerada + `todas` que ya usa esa opción.
2. Esa opción cubre exactamente tres binarios: `ollama` (+ un catálogo de
   modelos a elegir, ver Goal 6), `avml`, `nmap-vulners`.
3. Cada instalación es **verificable** después: la tecla `D` puede confirmar
   que el binario no solo está en el `PATH` (o en su ruta fija), sino que
   responde de forma reconocible (ya existe este patrón para `avml` en
   `08_Forensics/memory/memory_dump.sh`; se reutiliza, no se duplica).
4. Cada instalación pide su propia confirmación explícita, con el riesgo y
   el tamaño de descarga de *esa* herramienta en el texto — nunca un
   "escribe 'instalar'" genérico que cubra tres cosas distintas a la vez.
5. `lime` y `volatility` (v2) siguen exactamente como están: informativos,
   con su motivo ya escrito en `DEPENDENCIES_NO_APT`. Esta pieza no las toca.
6. **Catálogo de modelos para Ollama, con descripción explícita de cada
   uno** (nunca solo un nombre): el general ya recomendado por
   `hardware.py`, **Qwen2.5-Coder** (oficial, Alibaba — recomendación
   principal, por evidencia práctica de benchmarks ofensivos por encima de
   los modelos "etiquetados de seguridad"), **Foundation-Sec-8B-Instruct**
   (Cisco, especialista real) y **DeepHat/WhiteRabbitNeo** (comunidad, sin
   censura a propósito — con aviso explícito siempre visible). Ver
   "Diseño → Ollama + modelo" para la tabla completa y las fuentes.
7. **Cualquier descarga de modelo se mide contra los recursos reales de la
   máquina antes de lanzarse.** Si el tamaño elegido no entra en la RAM
   libre, no se descarga nada: se muestra el error con las cifras reales y
   qué tamaño sí entraría, con una vía explícita (y distinta) para forzarlo
   a sabiendas.

## Non-goals y anti-goals

- **Anti-goal: nunca cargar un módulo de kernel.** `lime` queda fuera del
  alcance precisamente porque automatizarlo —aunque "solo" fuera compilar—
  empuja hacia esa frontera que `08_Forensics/USE.md` ya decidió no cruzar.
  No se reabre esa decisión aquí.
- No se reemplaza `volatility` (v2) por nada: ya está superado por
  `volatility3`, que la opción `apt` existente instala.
- No se instala nada sin que el usuario confirme explícitamente esa
  herramienta en concreto.
- No se asume `sudo` interactivo con contraseña en ningún punto nuevo: se
  sigue el patrón ya existente de `dependencies_install` (`sudo apt-get
  install`), que asume que `sudo` ya puede pedir contraseña igual que hace
  hoy para los paquetes `apt`.
- No se introduce una dependencia nueva (`jq`, etc.) para esto: `python3` ya
  es una dependencia declarada y se usa para el parseo que lo necesite
  (API de GitHub).
- No se reimplementa la tabla de modelos del asistente de IA
  (`00_Config/lib/ai/hardware.py`): esta pieza la consume, no la duplica.

## Constraints (verificadas en el repo y por investigación, 2026-11-17)

- `00_Config/lib/dependencies.bash` ya separa `DEPENDENCIES_MAP` (apt) de
  `DEPENDENCIES_NO_APT` (solo texto) y tiene un caso especial en
  `dependencies_binary_ok` para `nmap-vulners` basado en un fichero, no un
  binario en `PATH`.
- **Hallazgo de la investigación — el fichero por defecto está mal:**
  `dependencies_binary_ok` comprueba
  `/usr/share/nmap/scripts/nmap-vulners.nse`, pero el script real del
  proyecto `vulnersCom/nmap-vulners` se llama `vulners.nse` (confirmado
  contra el paquete `nmap` de Debian y la documentación de NSE). Con el
  nombre actual, la comprobación nunca reconocería una instalación hecha
  siguiendo el método oficial. Se corrige el nombre por defecto como parte
  de esta pieza (manteniendo `NMAP_VULNERS_PATH` como variable de
  sobrescritura para los tests, igual que hoy).
- `avml`/`lime` se reconocen en `memory_dump.sh` únicamente por `PATH`
  (`command -v`), sin variable de ruta alternativa — a diferencia de
  `nmap-vulners`. Por tanto `avml` tiene que quedar en el `PATH` del sistema
  tras instalarse (`/usr/local/bin`), no en una carpeta propia del
  framework, o `memory_dump.sh` no lo vería.
- El instalador oficial de Ollama (`https://ollama.com/install.sh`) escribe
  en `/usr/local/bin`, crea un usuario de sistema y un servicio `systemd`,
  y ya resuelve su propio `sudo` internamente si no se ejecuta como root.
  No hay una versión "sin root" oficial distinta: se ejecuta tal cual.
- `microsoft/avml` publica binarios en sus *releases* de GitHub; la
  investigación no encontró ficheros de suma de verificación publicados
  oficialmente. La integridad depende de HTTPS + dominio de GitHub, no de
  una firma verificable — esto se documenta tal cual, sin afirmar una
  verificación que no existe.
- `vulnersCom/nmap-vulners` se instala copiando `vulners.nse` (y, si se
  quiere paridad completa, `http-vulners-regex.nse`) a
  `/usr/share/nmap/scripts/`, seguido de `nmap --script-updatedb`; el
  directorio es propiedad de `root` en Kali.
- `00_Config/lib/ai/hardware.py` ya expone `read_mem_available_gib()`,
  `has_nvidia_gpu()` y `recommend_model()` con la tabla de modelos y el
  `pull_command`; esta pieza los invoca vía `python3`, no reescribe la
  tabla en Bash (la revisión de la rama del asistente ya señaló esa
  duplicación como código a evitar).
  `Recommendation.size_label` es una etiqueta de **parámetros** (p. ej.
  `"~14B"`), no un tamaño de descarga: `size_label` y el peso real en disco
  del modelo cuantizado (p. ej. `qwen2.5:14b` ronda los 9 GB) son cosas
  distintas. Tocar el contrato de `Recommendation` para añadir GB reabriría
  un módulo ya revisado e integrado — fuera de alcance aquí. En vez de eso,
  esta pieza añade una tabla pequeña y propia de GB aproximados para el
  aviso de descarga, indexada por las mismas constantes de nombre de modelo
  que ya define `hardware.py` (`MODEL_1B`, `MODEL_3B`, `MODEL_7B`,
  `MODEL_14B`): reutiliza el nombre del modelo recomendado, no la lógica de
  qué modelo recomendar ni el contrato de `Recommendation`.
- **Investigación de modelos especializados en ciberseguridad (2026-11-17):**
  no existe una categoría oficial "ciberseguridad" en la librería de Ollama;
  todo lo disponible es subida de comunidad o un tirón directo a un GGUF de
  Hugging Face (`ollama run hf.co/<repo>:<cuantización>`, mecanismo que
  Ollama sí soporta oficialmente). Hallazgos, con fuente:
  - [Foundation-Sec-8B / Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct)
    (Cisco Foundation AI, Apache-2.0, [informe técnico](https://arxiv.org/abs/2504.21039)):
    único especialista con procedencia de empresa real, preentrenado con
    ~5.100M tokens de datos de seguridad sobre Llama 3.1 8B. GGUF de
    conversores conocidos (mradermacher, QuantFactory, Mungert); sin
    entrada oficial en la librería de Ollama, se tira vía `hf.co/`.
  - [DeepHat](https://huggingface.co/WhiteRabbitNeo) (antes WhiteRabbitNeo):
    proyecto de investigación en seguridad, Apache-2.0, 7B/32B sobre
    Qwen2.5-Coder, **presentado desde su origen como modelo sin censura a
    propósito**. Lo disponible en Ollama son subidas de comunidad de
    versiones 2024 (v1.5a/v2.0), no la V2 actual.
  - [Qwen2.5-Coder](https://registry.ollama.ai/library/qwen2.5-coder):
    **librería oficial de Ollama** (Alibaba), seis tamaños (0.5B a 32B),
    Apache-2.0 salvo el 3B (licencia Qwen Research, más restrictiva). El
    benchmark de [TrustedSec sobre LLMs autoalojados para ofensiva](https://trustedsec.com/blog/benchmarking-self-hosted-llms-for-offensive-security)
    y una [guía de bug bounty con LLMs locales](https://humbertojunior.com.br/infosec/pentest/bugbounty/tools/2026/07/08/local-llms-for-bug-bounty.html)
    señalan modelos de código generalistas fuertes por encima de los
    modelos "etiquetados de seguridad" para tareas ofensivas reales — de
    ahí que sea la recomendación principal del catálogo, no solo una
    alternativa.
  - Otras subidas sueltas sin organización ni informe detrás (p. ej.
    `xploiter/pentester`) se investigaron y se descartan del catálogo: sin
    procedencia verificable.
- **Tabla nueva de tamaño en disco y RAM mínima recomendada por fila del
  catálogo** (aproximada, para el aviso de descarga y el guardrail de
  recursos — no existía antes de esta pieza, vive junto al instalador, no
  en `hardware.py`):

  | Fila | Tamaño | Descarga aprox. | RAM libre recomendada |
  |---|---|---|---|
  | General (`hardware.py`) | 1B/3B/7B/14B según tabla existente | tabla existente | tabla existente |
  | Qwen2.5-Coder | 0.5B/1.5B/3B/7B/14B/32B | ~0,4 GB a ~20 GB según tamaño | igual que el tamaño en parámetros equivalente de la tabla general |
  | Foundation-Sec-8B-Instruct | ~8B fijo | ~5 GB (Q4) | ~7-14 GiB |
  | DeepHat/WhiteRabbitNeo | 7B o 32B | ~5 GB / ~20 GB | ~7-14 GiB / ~20+ GiB |

  Los valores exactos de cada tamaño quedan para el builder (ver "Dejado al
  builder"); esta tabla fija el orden de magnitud y la fuente de verdad
  (ninguna cifra sale de adivinar en tiempo de ejecución).
- `00_Config/lib/osint/credentials.py` ya expone `load_credentials(registry,
  harvester_dirs)`, de solo lectura, que devuelve un `github` si el
  registro central (`00_Config/credentials/api-keys.yaml`, vía `K`/
  `api_keys.py`) lo tiene guardado. El paso de `avml` la reutiliza para
  decidir si autentica la llamada a la API de *releases* de GitHub, sin
  reimplementar el parseo. Si no hay clave guardada, pregunta una vez,
  explícitamente opcional, si quiere darla para evitar el límite de 60
  peticiones/hora sin autenticar; si la escribe, se persiste con el mismo
  comando que ya existe (`api_keys.py poner theharvester github.key --stdin`
  — el campo real bajo la herramienta `theharvester`, no `poner github
  GITHUB_API <valor>` como decía una redacción anterior de este párrafo),
  no con un almacenamiento propio — nunca se imprime el valor, igual que ya
  garantiza `api_keys.py` para todas las claves. Un Enter la omite sin más
  preguntas y la llamada sigue anónima.
- Patrón de confirmación ya existente a seguir:
  `dependencies_install()` imprime qué va a hacer y exige una palabra
  exacta por `stdin` antes de ejecutar `sudo apt-get install -y`.

## Approaches considerados

1. **Un único "instalar todo lo no-apt" sin distinguir riesgo.** Simple,
   pero mezclaría una descarga de varios GB (modelo de Ollama) con un
   `git clone` de un script de 50 KB bajo una sola confirmación. Rechazado
   en conversación.
2. **Automatizar los cinco, incluida la compilación de `lime`.** Añade una
   build de kernel frágil y específica por máquina a un flujo que hoy es
   "pulsa, confirma, listo"; para alguien nuevo es más probable que
   produzca un error confuso que una ganancia real. Rechazado en
   conversación.
3. **Automatizar `ollama`+modelo, `avml` y `nmap-vulners`; dejar `lime` y
   `volatility` (v2) como guía, tal como están.** *(Elegida por el
   usuario.)* Cubre las tres herramientas que tienen un método oficial,
   reproducible y verificable en cualquier máquina, sin tocar la decisión
   ya tomada sobre módulos de kernel ni reabrir una herramienta
   descontinuada.

## Diseño

### Menú (`dependencies_menu` en `cyber_framework.sh`)

```
━━━ DEPENDENCIAS ━━━

03_Scanners:
  ✓ nmap
  ...
Dependencias adicionales:
  ✗ ollama (se instala con «curl -fsSL https://ollama.com/install.sh | sh», no es un paquete apt)
  ✗ avml (binario de GitHub (Microsoft), no se instala por apt)
  ✗ nmap-vulners (script NSE que se clona/copia a mano a /usr/share/nmap/scripts/)
  ✗ lime (módulo de kernel que se compila, no se instala aquí)
  ✗ volatility (reemplazado por volatility3; solo se documenta)

Paquetes que faltan e instalan por apt:
  1) nmap
  ...

 1) Instalar dependencias por apt (elegir de la lista)
 2) Instalar/verificar herramientas adicionales (Ollama, avml, nmap-vulners)
 0) Volver al menú principal
```

- La opción `2` solo aparece activa para `ollama`, `avml`, `nmap-vulners`;
  `lime` y `volatility` siguen listados arriba como hoy, sin entrada en ese
  submenú (el texto ya explica por qué).
- Dentro de la opción `2`: mismo patrón que la `1` (lista numerada de lo que
  falta entre esos tres, `dependencies_resolve_selection` reutilizada,
  entrada `todas`/números/`0`/cancela).
- Tras resolver la selección, cada herramienta elegida se instala **en su
  propio paso**, con su propia pregunta de confirmación (texto distinto
  por herramienta: tamaño/riesgo de *esa* descarga), y su propio resultado
  impreso (✓/✗ + motivo si falla) antes de pasar a la siguiente.
- Al terminar la opción `2`, se vuelve a mostrar el estado (✓/✗) de las tres
  para que la persona vea el resultado sin tener que releer el menú
  principal.

### Ollama + modelo

1. Confirmación 1 (instalar Ollama): mensaje explica que ejecuta el
   instalador oficial (`curl -fsSL https://ollama.com/install.sh | sh`),
   que puede pedir la contraseña de `sudo` por su cuenta y que instala un
   servicio en segundo plano. Palabra de confirmación propia (p. ej.
   `OLLAMA_SI`, a decidir con el resto de literales del proyecto).
2. Verificación: `command -v ollama` tras el instalador; si falta, se
   informa el fallo sin continuar al paso del modelo.
3. Si `ollama` quedó disponible, se ofrece aparte (puede declinarse sin
   deshacer el paso 1) un **catálogo de cuatro opciones**, cada una con su
   descripción explícita en el propio menú — nunca solo un nombre:

   | # | Modelo | Qué es, en una línea honesta |
   |---|---|---|
   | 1 | General por RAM/GPU (`hardware.recommend_model()`, ya existente) | Modelo generalista; el que ya recomienda el asistente de IA según esta máquina. Sin entrenamiento específico de seguridad. |
   | 2 | **Qwen2.5-Coder** (`qwen2.5-coder:0.5b`…`32b`, librería **oficial** de Ollama, Alibaba) | Modelo de código generalista, no "de ciberseguridad", pero los benchmarks prácticos de seguridad ofensiva (TrustedSec, guías de bug bounty) lo señalan por encima de los modelos etiquetados "de seguridad". Apache-2.0 en todos los tamaños salvo el 3B (licencia Qwen Research, más restrictiva). Recomendación principal de este catálogo. |
   | 3 | **Foundation-Sec-8B-Instruct** (Cisco Foundation AI, vía `hf.co/<conversor>/Foundation-Sec-8B-Instruct-GGUF`) | El único especialista de ciberseguridad con procedencia de empresa real: preentrenado con ~5.100M tokens de datos de seguridad, Apache-2.0, informe técnico publicado. Tamaño fijo ~8B. |
   | 4 | **DeepHat / WhiteRabbitNeo** (comunidad, 7B o 32B, vía `hf.co/...` o repos de usuario) | Proyecto de investigación en seguridad que se presenta **sin censura a propósito** (las barreras de seguridad del modelo están quitadas deliberadamente). No es una subida oficial de una empresa. Se ofrece igual, pero con este aviso siempre visible antes de confirmar. |

   Las filas 2-4 muestran además el tamaño de descarga real en GB (tabla
   propia nueva, no la de `hardware.py`; ver "Constraints") y el tamaño en
   parámetros concreto elegido (p. ej. "Qwen2.5-Coder 7B, ~4,7 GB").
4. **Guardrail de recursos, para cualquiera de las cuatro filas:** antes de
   lanzar el `ollama pull`, se compara la RAM libre
   (`hardware.read_mem_available_gib()`, reutilizada) contra lo que ese
   tamaño concreto necesita (misma tabla nueva del punto 3). Si no alcanza,
   **no se descarga nada**: se muestra el error con las dos cifras reales
   (libre vs. necesaria) y qué tamaño de la misma familia sí entraría.
   Una segunda confirmación explícita, literal y distinta de las anteriores
   (p. ej. escribir `CONTINUAR_IGUAL`) permite forzarlo a sabiendas de que
   puede ir muy lento o colgarse; sin esa palabra exacta, se cancela solo
   ese pull y se puede elegir otro tamaño u otra fila.
5. Un "no" en el paso 3, o un guardrail no superado sin forzarlo, no es un
   fallo de la pieza: Ollama queda instalado e igual de usable por la tecla
   `I` en su modo sin modelo.
6. Si el `pull` se ejecuta, verificación con `ollama list` (o equivalente)
   buscando el nombre exacto.

### avml

1. Confirmación: explica que descarga un binario de las *releases* de
   `microsoft/avml` en GitHub a `/usr/local/bin/avml` (con `sudo` para la
   copia final) y que **no hay suma de verificación oficial que
   comprobar** — la integridad depende de HTTPS, no de una firma.
2. Antes de llamar a la API: si el registro de claves ya tiene un `github`
   guardado (`osint.credentials.load_credentials`, reutilizada), se usa en
   la cabecera `Authorization`. Si no, se pregunta una vez, opcional, si
   quiere darlo (para evitar el límite de 60 peticiones/hora sin
   autenticar); si lo escribe, se guarda con `api_keys.py poner github
   GITHUB_API <valor>` (mismo registro que usa OSINT) y se usa también en
   esta llamada; un Enter lo omite y sigue anónimo. El valor nunca se
   imprime.
3. Se resuelve la última versión y la URL del binario llamando a la API de
   releases de GitHub (`curl` + `python3 -c` para extraer `tag_name` y la
   URL del asset de Linux x86_64 del JSON — sin añadir `jq`).
4. Descarga a un fichero temporal, luego `chmod +x` y `sudo install`/`mv`
   a `/usr/local/bin/avml` (ruta fija: `memory_dump.sh` lo busca solo por
   `PATH`).
5. Verificación: reutiliza el mismo patrón de reconocimiento que
   `memory_dump.sh` (`avml --help` contiene `avml`, `usage:` y
   `<FILENAME>`/`<OUTPUT>`), no solo "el fichero existe".

### nmap-vulners

1. **Corrección previa:** el nombre de fichero por defecto en
   `dependencies_binary_ok`/`NMAP_VULNERS_PATH` pasa de
   `nmap-vulners.nse` a `vulners.nse` (el nombre real del proyecto). Se
   actualiza la prueba existente que fija ese nombre.
2. Confirmación: explica que clona `vulnersCom/nmap-vulners` de GitHub y
   copia `vulners.nse` (y `http-vulners-regex.nse`) a
   `/usr/share/nmap/scripts/` con `sudo`, y que ejecuta
   `sudo nmap --script-updatedb` al final.
3. Verificación: el fichero existe en la ruta fija (ya cubierto por
   `dependencies_binary_ok`, con el nombre corregido).

## Pruebas

Suite existente `tests/run_dependencies.sh` se amplía, siempre aislada
(`PATH` cerrado, sin red real, sin `sudo` real): los tres instaladores se
prueban con dobles de `curl`/`git`/`sudo` en un `PATH` sintético que
registran su invocación exacta (mismo patrón que ya usa esa suite para
`apt-get`), nunca contra la red o el sistema real. Casos a cubrir: la
confirmación exacta por herramienta (cualquier otra entrada cancela sin
invocar nada), que una herramienta ya presente no se reinstala, que el
fallo de una no bloquea ni invoca a la siguiente, el parseo del JSON de
releases de GitHub con una respuesta sintética fija (no una llamada real),
y la corrección del nombre de fichero de `nmap-vulners`
(`vulners.nse`). Para el catálogo de modelos: las cuatro filas aparecen con
su descripción; el guardrail de recursos bloquea con un `read_mem_available_gib`
sintético bajo y una fila que pide más RAM de la disponible (sin llegar a
`ollama pull`), lo deja pasar con uno que sí entra, y la confirmación
`CONTINUAR_IGUAL` (o el literal que fije el builder) fuerza el forzado y
solo ese camino llega a invocar el doble de `ollama`. Nunca se ejecuta
`curl`/`git`/`sudo`/`ollama` reales desde los tests.

## Criterios de éxito

- La tecla `D` deja claro, sin leer código, qué de lo que falta se puede
  instalar desde ahí y qué no (y por qué, para `lime`/`volatility`).
- Instalar Ollama, avml o nmap-vulners desde `D` deja el binario detectable
  por el resto del framework exactamente como ya lo busca (`PATH` para
  avml/ollama, `vulners.nse` en su ruta fija para nmap-vulners).
- Ningún paso nuevo ejecuta nada sin una confirmación específica a esa
  herramienta.
- Ninguna fila del catálogo de modelos se presenta sin su descripción
  honesta (procedencia, censura/sin censura, tamaño); nunca solo un nombre.
- Ninguna descarga de modelo se lanza si la RAM libre no alcanza para el
  tamaño elegido, salvo forzado explícito y distinto de las demás
  confirmaciones.
- `tests/run_dependencies.sh` sigue en verde y cubre los instaladores y el
  guardrail de recursos con dobles, nunca con red/sudo/ollama reales.

## Dejado al builder

Literal exacto de cada palabra de confirmación (incluida la de forzar el
guardrail de recursos); nombre exacto de las funciones Bash nuevas;
formato exacto del submenú, de la tabla del catálogo y de los mensajes;
mecanismo exacto para invocar `hardware.recommend_model()`/
`read_mem_available_gib()` desde Bash (script `python3 -c` inline vs. un
pequeño *entry point* dedicado); dónde vive la tabla nueva de tamaño/RAM
por fila del catálogo (constante en el propio `dependencies.bash` vs. un
fichero de datos separado); cifras finas de GB/RAM por tamaño dentro del
orden de magnitud ya fijado; qué variante exacta de DeepHat/WhiteRabbitNeo
y de Foundation-Sec-8B-Instruct (qué repo GGUF, qué cuantización) se fija
como *pull command* de cada fila; si se copia también
`http-vulners-regex.nse` o solo `vulners.nse`; estructura exacta de los
dobles de test para `curl`/`git`/`sudo`/`ollama`.

## Diferencias con la petición original

La petición inicial era "todas las herramientas y dependencias... incluido
Ollama y sus modelos". En conversación se acotó a tres (`ollama`+modelo,
`avml`, `nmap-vulners`) tras señalar que `lime` entra en conflicto con una
decisión de seguridad ya tomada (nunca cargar un módulo de kernel) y que
`volatility` (v2) ya está descontinuado a favor de `volatility3`. El
usuario aprobó esa acotación explícitamente, y después pidió dos
ampliaciones sobre el paso de Ollama, ambas incorporadas arriba: que toda
descarga de modelo se mida siempre contra los recursos reales de la
máquina (Goal 7, guardrail en "Ollama + modelo"), y que se investiguen y
ofrezcan modelos especialistas en ciberseguridad "desde pequeños hasta
algunos grandes" (Goal 6, catálogo de cuatro filas con su investigación en
"Constraints"). Qwen2.5-Coder se añadió al catálogo a petición expresa del
usuario tras preguntar mi opinión sobre Qwen, con la evidencia que lo
respalda citada en "Constraints".
