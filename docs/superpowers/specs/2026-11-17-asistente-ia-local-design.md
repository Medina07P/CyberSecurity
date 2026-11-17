# Diseño: asistente de IA local del framework (tecla `I`)

**Fecha:** 2026-11-17
**Estado:** propuesto, pendiente de aprobación del documento
**Origen:** plan pegado por el usuario ("Plan de Integración: IA Local") y tres
rondas de conversación que lo acotaron. Este diseño **sustituye** a ese plan donde
difieren (ver "Diferencias con el plan original").

## Intención y por qué

Quien ejecuta el framework puede ser alguien con poco conocimiento técnico. Hoy
tiene que saber qué módulo abrir, interpretar a mano salidas de Nmap/Nikto/Nuclei,
entender el informe y buscar en `USE.md`/`README.md` cómo hacer cada cosa. El
usuario quiere un **asistente local, conversacional e intuitivo** que:

- lea todos los resultados del framework y los analice;
- ayude a entender el informe y a redactarlo;
- explique cualquier tema del framework y resuelva dudas de "cómo hago X";
- funcione con muy pocos comandos, guiado por menú;
- permita abrir un **contexto nuevo** para liberar el actual.

Todo ocurre en la máquina: ningún dato sale a servicios externos.

## Goals

1. Tecla nueva `I` en el menú principal que abre un menú guiado del asistente.
2. Modo conversación libre: cualquier texto que no sea una opción numérica es una
   pregunta.
3. Recuperación (RAG) sobre documentación del framework **y** resultados, con
   respuestas que citan fichero y línea de origen.
4. Recomendación automática de modelo según RAM/GPU; solo sugiere, nunca instala.
5. Gestión de contexto: ventana deslizante + resumen, aviso al acercarse al límite,
   y reinicio explícito ("conversación nueva") sin perder índice ni resúmenes.
6. Degradación segura: sin Ollama o sin modelo, el asistente sigue buscando y
   mostrando fragmentos con su fuente, y explica en lenguaje llano qué falta.
7. Salidas reproducibles para informes mediante subcomandos finos
   (`analizar`, `explicar-informe`, `borrador`), reutilizando el mismo núcleo.

## Non-goals y anti-goals

- **Anti-goal: el asistente nunca ejecuta nada.** Ni herramientas del framework, ni
  comandos de shell, ni escribe en `scans/`, `scope.yaml` o `targets.txt`. Solo
  sugiere pasos ("pulsa `3` en el menú principal…"), no comandos sueltos.
- Tomar decisiones autónomas (explotar, escalar, lanzar escaneos).
- Enviar datos a la nube o usar APIs externas de embeddings.
- Modificar los scripts existentes de módulos 00–13 (salvo el cambio mínimo en
  `cyber_framework.sh` descrito abajo).
- Un informe nunca se da por final: todo borrador lleva aviso de revisión humana.
- No sustituye a `report_engine.py`: la clasificación determinista de hallazgos
  sigue siendo suya; la IA la lee y la explica, no la reemplaza.

## Constraints (verificados en el repo y la máquina, 2026-11-17)

- Hardware de esta máquina: 5,7 GiB RAM (≈3,6 disponibles), 4 vCPU, sin GPU
  (VMware SVGA), 12 GB de disco libre. `llama3.1:8b` y `qwen2.5:14b` no caben.
  La velocidad en CPU es de pocos tokens/s: los prompts deben ser cortos.
- `chromadb` no está instalado y es pesado; la base de conocimiento son 27 `.md`
  (~4.000 palabras). No se usa.
- Python 3.13, `requests` y `yaml` disponibles. Ollama no está instalado.
- El gestor descubre con `find` cualquier `.py` bajo el módulo, **excluyendo rutas
  con `/lib/` y `/tests/`**; la marca `[generador]` es solo para scripts que
  escriben otros scripts. Un `.py` se lanza con `python3 <ruta>` desde la raíz del
  framework.
- El patrón de tecla ya existe: `K` → `keys_menu`, `D` → `dependencies_menu`,
  funciones en `00_Config/lib/*.bash` sourceadas por `cyber_framework.sh` y
  despachadas en el `case` del bucle principal (líneas ~1165–1170).
- `scans/` pesa ~67 MB y contiene IPs, banners y credenciales reales; está en
  `.gitignore`. Todo índice o resumen derivado debe ir también ignorado.
- Contenido de `scans/` y de la web auditada es **no confiable**: puede contener
  texto que parezca instrucciones (inyección de prompt). El modelo no tiene
  herramientas, y los fragmentos se pasan como datos delimitados.
- Reglas del repo: sin `set -e`, mensajes al usuario en español, sin rutas
  hardcodeadas (autolocalización), `.sh`/`.py` en LF, pruebas aisladas (HOME y
  rutas sintéticas), **nunca** `tests/run_tests.sh` sobre un checkout con datos.
- Instalar Ollama (`curl | sh`), descargar modelos y `pip install` los ejecuta el
  usuario; el asistente solo muestra el comando exacto.

## Approaches considerados

1. **Tres scripts por tarea** (como el plan original). Simple y reproducible, pero
   no responde dudas libres ni explica el framework, y exige conocer comandos.
2. **Chat único con RAG sobre todo.** Cubre todo lo pedido, pero sin salidas fijas
   el borrador de informe y el análisis no son repetibles.
3. **Núcleo compartido + chat guiado + subcomandos finos.** *(Elegida por el
   usuario.)* El chat resuelve dudas abiertas; los subcomandos dan salidas
   repetibles; ambos usan el mismo núcleo.

## Diseño

### Estructura

- `CyberSecurity-Framework/00_Config/lib/ai/` — paquete Python (excluido del
  descubrimiento por la ruta `/lib/`): cliente Ollama, recomendador de modelo,
  indexador/recuperador BM25, gestor de contexto, plantillas de prompt, lector de
  fuentes.
- `CyberSecurity-Framework/00_Config/lib/ai_menu.bash` — `ai_menu`, el menú guiado
  (patrón de `keys_menu`/`dependencies_menu`). Sourceado por `cyber_framework.sh`.
- `CyberSecurity-Framework/09_Automation/ai/ai_assistant.py` — punto de entrada
  con cabecera `Uso:`/`Ejemplo:`; es lo que invoca el menú y lo que el usuario
  avanzado puede lanzar. Subcomandos: sin argumentos → chat; `analizar`,
  `explicar-informe`, `borrador`, `modelo` (recomendación), `reindexar`, `estado`.
- `CyberSecurity-Framework/tests/run_ai.sh` — suite nueva, aislada.
- Datos derivados (índice, resúmenes por herramienta, historial de conversación):
  `CyberSecurity-Framework/09_Automation/ai/data/`, ignorado por git y con modo
  `700`/`600`.
- Cambio mínimo en `cyber_framework.sh`: `source` de `ai_menu.bash`, línea `I` en
  el menú principal (con su fila en la leyenda/ayuda y en el mensaje de "opción
  inválida") y `I|i) ai_menu ;;` en el `case`. Es la única modificación a un
  fichero existente; hay que actualizar `tests/run_smoke.sh` en consecuencia.
- Documentación: `docs/ASISTENTE-IA-2026-11-17.md` (guía en español, requisitos),
  sección en `docs/MANUAL-GESTOR.md` y mención en `README.md`.

### Menú guiado (comportamiento)

```
🤖 Asistente del framework      modelo: qwen2.5:3b ✔   contexto: 12 %
Objetivo de la sesión: <objetivo>

 1) Entender mis resultados
 2) Explicarme el informe
 3) Ayudarme a redactar el informe
 4) Tengo una duda / no sé cómo hacer algo
 5) Empezar conversación nueva
 0) Volver
```

- Un número elige opción; **cualquier otro texto se trata como pregunta** (opción 4).
- EOF o `0` vuelven al gestor sin efectos. El menú nunca bloquea el gestor: un
  fallo del asistente devuelve código ≠ 0 con mensaje claro y vuelve al menú.
- Primera vez / sin modelo: mensaje en lenguaje llano con qué falta (Ollama,
  modelo, paquete), el modelo recomendado para esta máquina y el comando exacto a
  copiar. La búsqueda sin modelo sigue disponible (devuelve fragmentos citados).
- La opción 1 usa `findings.json` y los resúmenes por herramienta; la 2 lee los
  informes generados por `report_engine.py` y los explica sin jerga; la 3 genera un
  borrador de resumen ejecutivo/técnico a partir de `findings.json` y evidencias,
  marcado como borrador; la 4 es el modo pregunta libre.
- Las respuestas están en español, sin jerga; los términos técnicos se definen
  brevemente la primera vez que aparecen. Cada respuesta cita sus fuentes
  (`ruta:línea`); si el recuperador no encuentra base, el asistente lo dice en vez
  de inventar. Si la pregunta se resuelve con una función del gestor, indica la
  opción de menú.

### Fuentes indexadas

- **Documentación:** `README.md`, `USE.md`, `FLUJO.md` de cada módulo,
  `12_Knowledge_Base/**`, `docs/**` del repo, y las cabeceras `Uso:`/`Ejemplo:`
  de los scripts (vía el lector de `params.bash` o equivalente en Python).
- **Resultados:** `findings.json` (fuente preferente: ya clasificado y con guardas),
  informes generados en `11_Reports/`, `scans/<herramienta>/` y salidas por módulo
  (OSINT, enumeración, evidencias) en modo solo lectura. Las salidas crudas se
  fragmentan y se limitan por tamaño; los resúmenes por herramienta se generan una
  vez y se cachean con el hash de la fuente para invalidarlos.
- **Excluido por defecto:** `10_Evidence/credentials`, `06_PostExploitation/loot`,
  `00_Config/credentials/`, claves de API y cualquier `.session`. Un interruptor
  explícito (con confirmación) puede incluirlos; por defecto no se leen.
- Enlaces simbólicos no se siguen; los ficheros se leen sin ejecutarlos.

### Recuperación

BM25 en Python puro sobre fragmentos (por sección de `.md`, por bloque en salidas
de escáneres). No requiere modelo, dependencia ni red. Embeddings de Ollama
(`nomic-embed-text`) son una mejora **opcional** y posterior, no parte de este
alcance salvo que el builder lo justifique.

### Cliente de modelo

- Endpoint por defecto `http://localhost:11434`; se rechaza un endpoint que no sea
  loopback salvo confirmación explícita (principio "nada sale de la máquina").
- Timeouts claros; un error de conexión → mensaje en español, código ≠ 0, sin
  traza. Solo `requests` + `yaml` (ya presentes); sin dependencias nuevas.
- Configuración en `09_Automation/ai/ai_config.yaml` (modelo elegido, endpoint,
  límites de contexto/recuperación, interruptores de fuentes).

### Recomendador de modelo

Lee `MemAvailable` y presencia de GPU NVIDIA (`nvidia-smi`, sin ejecutar nada más)
y propone un modelo con tabla aproximada: <3 GiB libres → ~1–1,5B; 3–7 → ~3B;
7–14 → 7–8B Q4; >14 o GPU con VRAM suficiente → 14B. Muestra el `ollama pull`
exacto y por qué; el usuario puede fijar otro modelo en la config. Los umbrales
exactos y los nombres de modelos vigentes son decisión del builder (se comprobarán
al implementar; el catálogo de Ollama cambia).

### Gestión de contexto

- Presupuesto de tokens por turno derivado del modelo y la RAM (ventana pequeña
  por defecto en máquinas modestas).
- Historial: últimos N turnos literales + resumen acumulado del resto. El
  indicador `contexto: NN %` se muestra en la cabecera.
- Al superar ~80 % se avisa ("la conversación está larga, ¿empezamos una nueva?").
- "Conversación nueva" (opción 5 o escribir `nueva`): descarta el historial en
  memoria y, si el usuario quiere, guarda antes un resumen breve; **no** toca el
  índice ni los resúmenes de resultados. También descarga el modelo de la memoria
  de Ollama si procede (`keep_alive: 0`).

### Seguridad y privacidad

- Solo lectura; sin `shell=True`, sin subprocesos salvo la lectura de
  `/proc/meminfo` y, opcionalmente, `nvidia-smi` con ruta fija y salida acotada.
- Los fragmentos de `scans/` se marcan como **datos no confiables** en el prompt;
  el modelo no dispone de herramientas ni de escritura.
- Respuestas y registros no se imprimen con claves ni valores de credenciales.
- `data/` ignorado por git; se documenta en `.gitignore` y en la guía.
- Alcance: el asistente no amplía ni declara el alcance autorizado
  (`scope.yaml`); si le preguntan, remite al fichero.

### Pruebas

`tests/run_ai.sh` con aislamiento completo (HOME, rutas y `data/` sintéticos,
fuentes copiadas a un temporal, PATH cerrado). Un **servidor Ollama falso** en
loopback devuelve respuestas fijas, así que no se necesita modelo real. Cubre:
recomendador con `meminfo` sintético; BM25 con KB de ejemplo; exclusión de
credenciales/loot; citas de fuente; degradación sin endpoint (código ≠ 0, mensaje);
gestión de contexto y "nueva"; menú por stdin (EOF, `0`, número, texto libre);
detección del `.py` por el gestor; rechazo de endpoint no loopback; guarda `md5sum`
de `scope.yaml`/`targets.txt` reales. Debe pasar `bash -n` con stderr capturado y
`python -m py_compile`. Las suites existentes **no** se ejecutan sobre este
checkout; si se quiere regresión, en copia limpia con configuración sintética.

## Diferencias con el plan original

- Ubicación: el núcleo vive en `00_Config/lib/ai/` y no solo en `09_Automation/ai/`
  (para que el descubrimiento no lo liste como herramientas).
- Se **toca** `cyber_framework.sh` (tecla `I`); el plan decía no hacerlo. Es
  necesario para el acceso guiado.
- Sin ChromaDB; BM25 propio. Embeddings opcionales y después.
- Modelo por defecto según recursos, no `llama3.1:8b` fijo.
- `11_Reports/report_generator.py` no existe: el motor es `report_engine.py` +
  `report_generator.sh`; se consumen sus salidas, no se importa su código.
- Se añade chat, gestión de contexto, citas de fuente y explicación de cualquier
  tema del framework, ausentes en el plan.
- Verificación: no se ejecuta `tests/run_tests.sh` sobre datos reales; se usa la
  suite nueva aislada.

## Decisiones tomadas tras la revisión del builder (mías, revisables)

- **Objetivo de sesión como filtro por defecto.** Los fragmentos llevan etiqueta de
  objetivo (slug) y las opciones 1–3 solo usan resultados del objetivo de la sesión;
  mezclar objetivos requiere elegirlo explícitamente. Evita colar hallazgos de un
  cliente en el borrador de otro.
- **Credenciales dentro de `scans/`.** Además de excluir rutas, el indexador pasa
  una redacción: lista de exclusión por herramienta (fuerza bruta/hydra/login) y
  regex para contraseñas, hashes y tokens, que se sustituyen por `[REDACTADO]`
  **antes** de indexar y de formar el prompt. Lo redactado no llega al modelo ni a
  los registros. Las pruebas lo cubren con fixtures sintéticos.
- **Opción 2 sin informe.** Si falta o está obsoleto `findings.json`/informe
  (obsoleto = más antiguo que el resultado más reciente del objetivo en `scans/`),
  el asistente dice "pulsa `R` primero"; nunca lo genera él.
- **Historial.** Solo en memoria; se guarda en `data/` únicamente si el usuario
  guarda el resumen al pedir "conversación nueva". Los resúmenes guardados van
  etiquetados por objetivo y no se reutilizan con otro.
- **Menú `I` siempre visible.** Si falta Python o un paquete, `I` explica qué falta
  y vuelve. Solo Ollama (`/api/chat`, `keep_alive`); no se soportan endpoints
  compatibles con OpenAI.
- **Descubrimiento y `99`.** `ai_assistant.py` aparecerá bajo el módulo 09 como
  cualquier `.py`; `99` solo encadena `run_all_*.sh`. Al ser interactivo se añade a
  `dangerous.txt` para que el gestor pida confirmación. El builder confirma que
  `run_all_automation.sh`/`orchestrator.py` no lo ejecutan.
- **Sin modelo, opciones 1–3.** Ruta determinista: 1 muestra los hallazgos de
  `findings.json` ordenados por severidad con su evidencia; 2 muestra las secciones
  del informe; 3 entrega la plantilla de borrador con los datos rellenados y sin
  redacción libre. Con modelo, se añade la explicación en lenguaje llano.

## Criterios de éxito

- Con Ollama ausente, el framework y el menú funcionan igual; `I` explica qué falta.
- Una persona sin experiencia completa las tareas de las opciones 1–4 solo con
  números y lenguaje natural.
- Toda respuesta con base cita fuente; sin base, lo dice.
- "Conversación nueva" libera el contexto sin perder índice ni resúmenes.
- `tests/run_ai.sh` en verde y las suites existentes siguen pasando en copia limpia.
- Ningún dato derivado queda fuera de `.gitignore`; credenciales/loot no se indexan
  por defecto.

## Dejado al builder

Umbrales y nombres exactos de la tabla de modelos; tamaño de fragmento y valores de
BM25; formato exacto de los resúmenes cacheados y su invalidación; plantillas de
prompt y estilo de las respuestas; formato del historial; si el resumen de contexto
lo genera el propio modelo o una heurística extractiva; textos de menú y mensajes;
si los embeddings opcionales entran ahora o después.
