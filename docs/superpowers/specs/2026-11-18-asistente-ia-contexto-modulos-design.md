# Diseño: contexto fijo de módulos y persistencia del resumen en el asistente IA

**Fecha:** 2026-11-18
**Estado:** propuesto, pendiente de aprobación del documento
**Origen:** conversación de esta sesión, continuación directa de `feat/asistente-ia-local`
(opciones 6/7 ya mergeadas a `develop` en `de1a3fb`). El usuario pidió explícitamente
dos cosas sobre la base existente: que la IA explique cómo hacer algo sin ejecutarlo
cuando el usuario no sabe cómo funciona, y que tenga "un contexto que se guarde en
alguna parte para que no se pierda".

## Intención y por qué

El asistente ya responde con RAG (BM25) sobre documentación y resultados en la
opción 4 ("tengo una duda") y, desde hoy, también admite conversación libre sin
ningún contexto adjunto (opción 7, `SYSTEM_LIBRE`). Dos huecos concretos quedaron
sobre esa base:

1. La conversación libre no sabe nada de los 14 módulos del framework (00–13):
   si alguien pregunta "¿qué tecla uso para...?" en modo libre, la regla actual
   le dice al modelo que remita a las opciones 1–4 en vez de responder, aunque
   esa es información fija y pública del propio framework, no un dato inventable
   del objetivo de la persona.
2. `_save_summary()` (`00_Config/lib/ai/menu.py`) escribe el resumen de la
   conversación en `09_Automation/ai/data/summaries/<slug>.md` al pedirlo la
   opción 5, pero **nada lo vuelve a leer**: `make_assistant()`
   (`09_Automation/ai/ai_assistant.py`) siempre construye una `Conversation`
   vacía. El resumen guardado es, hoy, un callejón sin salida.

## Goals

1. Tabla fija y corta (dato embebido, no generada por búsqueda) con las 14
   entradas 00–13: tecla, nombre y una línea de qué hace cada módulo.
2. Esa tabla se añade al prompt `system` compartido por ambos modos (preguntas
   con documentos y conversación libre), para que cualquiera de los dos pueda
   responder directamente preguntas generales del tipo "¿qué hace el módulo
   03?" o "¿con qué tecla hago X?" sin depender de que la búsqueda documental
   acierte.
3. Al abrir el asistente para un objetivo que ya tiene un resumen guardado
   (`summaries/<slug>.md`), se carga automáticamente como contexto inicial de
   `Conversation`, y la cabecera del menú lo anuncia explícitamente.
4. El guardado de resumen (opción 5) no cambia; la carga es la pieza nueva y
   simétrica.

## Non-goals / anti-goals

- **Anti-goal: la tabla de módulos no es una invitación a ejecutar nada.** Es
  texto fijo ("qué hace cada módulo"), nunca un comando ni un atajo para que el
  modelo "lance" algo; la regla de "no ejecuto nada, solo te digo qué tecla
  pulsar" sigue intacta en ambos prompts.
- No sustituye la búsqueda BM25 de la opción 4 sobre `README.md`/`USE.md`
  detallados: la tabla es un resumen de una línea por módulo para preguntas
  generales, no reemplaza explicaciones largas con cita `[ruta:líneas]`.
- No empieza a guardar el resumen automáticamente al cerrar: la opción 5 sigue
  preguntando `s/N` como hoy. Solo la **carga** pasa a ser automática.
- No persiste conversación "sin objetivo de sesión": igual que hoy, el
  resumen se guarda y se carga por `slug` del objetivo, nunca de forma global.
- No cambia el formato, ubicación ni permisos (`600`) de
  `summaries/<slug>.md`: los resúmenes ya guardados por la rama anterior deben
  seguir siendo legibles.
- No añade un nuevo límite de tamaño distinto al que ya existe
  (`Conversation.estimate_tokens`/`_cap`/`SUMMARY_CAP`): reutiliza el mecanismo
  existente en vez de inventar otro.

## Constraints (verificadas en el repo, 2026-11-18)

- `Conversation` (`00_Config/lib/ai/context.py`) es una clase pura en memoria:
  no toca el sistema de ficheros. La carga/guardado de disco vive en la capa de
  arriba (`menu.py`/`ai_assistant.py`), como ya hace `_save_summary`.
- Todo texto que llegue al modelo pasa por `redact.redact()` antes. El fichero
  de resumen ya se escribió redactado al guardarlo, pero se vuelve a redactar
  al cargarlo (defensa en profundidad: el mismo criterio que llevó a que
  `--desde-json` del motor de informes redacte otra vez, porque `redact()` es
  idempotente y el coste sobre texto ya limpio es nulo — ver nota de
  `report_engine.py` del 2026-11-18 en `AGENTS.md`).
- `make_assistant()` no recibe hoy ningún parámetro de "resumen inicial"; la
  firma puede extenderse sin romper los subcomandos CLI (`analizar`,
  `explicar-informe`, `borrador`, `modelo`, `reindexar`, `estado`), que no usan
  conversación multi-turno.
- El fichero de resumen usa `sources.slug()`; la carga debe usar exactamente la
  misma función para encontrar el fichero correcto.
- Las 14 entradas de módulos son estables (ver `docs/MENU-OPCIONES.md`); no
  hace falta generarlas dinámicamente ni leer disco para construir la tabla.

## Approaches considerados

**Contexto de módulos:**
- **A (elegido).** Tabla fija y corta, embebida en código Python, sin I/O.
  Barata en tokens, consistente turno a turno, no depende de que cada
  `README.md` tenga una frase resumen útil.
- B. Generarla a partir del primer párrafo de cada `README.md` de módulo.
  Descartada: calidad/longitud desigual entre módulos, y requiere I/O además
  del índice BM25 que ya existe para búsquedas más profundas.
- C. No tocar nada, dejar que opción 4 la cubra por búsqueda. Descartada: no
  resuelve el caso pedido (conversación libre, opción 7, sin búsqueda).

**Persistencia del resumen:**
- **A (elegido).** Carga automática y silenciosa-pero-anunciada al abrir el
  asistente para un objetivo con resumen guardado.
- B. Preguntar al abrir si se quiere recuperar. Descartada: el usuario pidió
  explícitamente que "no se pierda", lo que apunta a continuidad por defecto,
  no a un paso manual adicional.
- C. Exigir un comando explícito de menú para cargar. Descartada por el mismo
  motivo que B, y porque añade una opción de menú más para algo que debería
  ser el comportamiento esperado por defecto.

## Diseño

### 1. Tabla de módulos — nuevo fichero `00_Config/lib/ai/modules.py`

- Constante `MODULES`: tupla de `(tecla, nombre, resumen)` con las 14 entradas
  00–13 (no se incluyen `R`/`T`/`K`/`?`/`Q`: el usuario pidió "contexto de los
  módulos", y esas son acciones del propio gestor, no módulos del framework;
  quedan cubiertas, si hace falta citarlas, por la documentación ya indexada).
- Función `modules_context_block() -> str`: una línea por módulo, formato
  `«NN» Nombre — resumen.`, pensada para pegarse tal cual dentro de un prompt
  `system`. Determinista, sin leer disco.

### 2. Inyección en los prompts (`00_Config/lib/ai/prompts.py`)

- La tabla se añade al texto de **ambos** prompts (`SYSTEM` y `SYSTEM_LIBRE`),
  no solo al de conversación libre: no cuesta nada mantenerla siempre presente
  y evita diverger la lógica entre los dos modos. Se construye una sola vez al
  importar el módulo (constante derivada), no en cada llamada.
- No se cuenta como un `Chunk` del índice ni ocupa un cupo de `top_k`: es texto
  de instrucción fijo, igual que el resto de `SYSTEM`/`SYSTEM_LIBRE`.

### 3. Carga del resumen guardado al iniciar

- Nueva función `load_saved_summary(data_dir: Path, slug: str) -> Optional[str]`
  en `00_Config/lib/ai/assistant.py` (vive junto al núcleo, no en `menu.py`,
  para poder probarla sin stdin/stdout):
  - Lee `Path(data_dir) / "summaries" / f"{slug}.md"`.
  - Si no existe, no es fichero regular, o falla la lectura: devuelve `None`
    (silencioso, mismo comportamiento que hoy).
  - Quita la primera línea de encabezado (`# Resumen de la conversación...`) y
    conserva el resto como cuerpo.
  - Pasa el cuerpo por `redact.redact()` y por el mismo recorte que usa
    `Conversation._cap` (se reutiliza esa función, no se duplica el límite).
- `make_assistant()` (`09_Automation/ai/ai_assistant.py`), tras construir
  `Conversation`, llama a `load_saved_summary(data_dir(), sources.slug(target))`
  cuando hay `target`, y si devuelve texto no vacío hace
  `conv.summary = texto` antes de devolver el `Assistant`. Se añade un
  atributo `asis.resumen_recuperado: bool` para que el menú sepa si avisar.
- `menu.py`, en la cabecera que ya se imprime al abrir el menú (o en el primer
  mensaje mostrado), añade una línea cuando `asis.resumen_recuperado` es
  verdadero: `"He recuperado el resumen de tu conversación anterior sobre
  «<objetivo>»."` Sin resumen guardado, cero cambios visibles.
  - **Aclaración (resuelta tras revisión del builder check):** el aviso
    aparece **una sola vez**, en el primer dibujado de la cabecera dentro de
    `run()`, no en cada redibujado posterior (respuestas, vueltas de los
    submodos 5/6/7, Enter vacío, etc. — eso contradice la intención del
    Goal 3 y el propio nombre de la bandera). Mecanismo: `run()` consume la
    bandera tras imprimirla, igual que hace con otro estado efímero de
    sesión — no se expone como un aviso persistente estilo "contexto largo"
    o "modelo no disponible" (esos sí se repiten porque describen un estado
    que sigue vigente; este describe un evento puntual ya ocurrido). Queda a
    cargo del implementador decidir si se mutina `asis.resumen_recuperado` a
    `False` tras imprimir o si se usa una variable local en `run()`; cualquier
    forma vale mientras el aviso no sobreviva al primer dibujado.

## Qué queda a cargo del implementador

- Texto exacto de cada línea de `MODULES` (una frase por módulo, basada en
  `docs/MENU-OPCIONES.md`); orden `00`→`13`.
- Punto exacto del menú donde se imprime el aviso de resumen recuperado
  (cabecera existente vs. primera línea tras el título) — cualquiera que no
  rompa los tests de navegación de `tests/test_ai_menu.py`.
- Suite de pruebas (TDD): extender `tests/test_ai_assistant.py` (nombres
  reales de la suite verificados en el builder check; no existen
  `test_ai_prompts.py` ni `test_ai_assistant_cli.py` separados) para la tabla
  de módulos en ambos `SYSTEM*` y para `load_saved_summary` (fichero ausente,
  fichero normal, fichero que excede el cap, fichero con contenido a
  redactar), y un caso en `tests/test_ai_cli.py` para el aviso de cabecera
  (ya ejercita `menu.run()` con redibujados múltiples, p. ej.
  `test_header_refreshes_when_ollama_starts_mid_session`) comprobando que el
  aviso sale una vez y no sobrevive al segundo redibujado.
- Actualizar `docs/ASISTENTE-IA-2026-11-17.md` si el comportamiento visible
  cambia lo suficiente como para que la guía quede desactualizada (ya está
  desactualizada respecto a las opciones 6/7; no es objetivo de este trabajo
  corregir eso salvo que choque directamente con lo nuevo).
