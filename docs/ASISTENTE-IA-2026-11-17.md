# Asistente IA local

Un ayudante que vive en tu propio ordenador y te explica, en lenguaje sencillo, lo que
han encontrado las herramientas del framework. Se abre con la tecla `I` del gestor.

**Qué es y qué no es.** Lee los resultados del objetivo de la sesión y la documentación
del framework, y te responde citando de dónde sale cada dato. **No ejecuta nada**: no
lanza escaneos, no abre herramientas, no modifica tu configuración. Tampoco sustituye
al motor de informes (`R`): los borradores que escribe son un punto de partida que una
persona debe revisar.

## Qué necesitas

- El framework y un **objetivo de sesión** fijado con `T`.
- Para las opciones 2 y 3, haber generado los informes con `R` (el asistente explica el
  informe que ya existe; no lo crea).
- Opcional, pero recomendable: **Ollama** con un modelo descargado. Sin él, el asistente
  sigue funcionando en modo determinista (ver más abajo).

### Instalar Ollama y descargar un modelo

Estos comandos los ejecutas tú, en una terminal, cuando quieras. El framework no los
lanza nunca. Instala Ollama siguiendo las instrucciones de https://ollama.com y arráncalo:

```bash
ollama serve
```

Pregunta al asistente qué modelo le conviene a tu máquina:

```bash
python3 09_Automation/ai/ai_assistant.py modelo
```

Muestra el modelo recomendado según la memoria libre y si hay GPU NVIDIA, junto con el
comando exacto para descargarlo. Orientación (constantes de
`00_Config/lib/ai/hardware.py`):

| Memoria libre | Modelo sugerido | Tamaño |
|---|---|---|
| menos de 3 GiB (sin GPU) | `llama3.2:1b` | ~1B |
| 3 a 7 GiB, o GPU NVIDIA | `qwen2.5:3b` | ~3B |
| 7 a 14 GiB | `qwen2.5:7b` | ~7B |
| más de 14 GiB | `qwen2.5:14b` | ~14B |

Los nombres no se han comprobado contra el catálogo en vivo de Ollama. Antes de fiarte,
descarga el modelo y confirma que existe:

```bash
ollama pull qwen2.5:3b
ollama list
```

Si el nombre ya no existe, elige uno parecido en ollama.com y ponlo en `modelo:` dentro
de `09_Automation/ai/ai_config.yaml`.

## Inicio rápido

1. Arranca el gestor: `cd CyberSecurity-Framework && ./cyber_framework.sh`.
2. Fija el objetivo con `T` y, si quieres explicar o redactar informes, genera con `R`.
3. Pulsa `I`. Elige una opción o escribe tu pregunta directamente.

## Las cinco opciones del menú

| Opción | Para qué sirve |
|---|---|
| 1 Entender mis resultados | Resume los hallazgos del objetivo, de más a menos grave, y explica qué significan |
| 2 Explicarme el informe | Recorre el informe ya generado sección por sección |
| 3 Ayudarme a redactar el informe | Propone un borrador ejecutivo o técnico |
| 4 Tengo una duda / no sé cómo hacer algo | Responde sobre el framework usando su documentación |
| 5 Empezar conversación nueva | Olvida la conversación actual (ver «Contexto») |
| 0 Volver | Regresa al gestor |

También puedes escribir una pregunta libre en el menú sin elegir número. Pulsar Ctrl+C
mientras responde cancela esa respuesta y vuelve al menú; el fin de entrada (Ctrl+D) lo cierra.

Las respuestas citan la fuente con el formato `ruta:líneas`. Si no hay base en los
datos para responder, lo dice en lugar de inventar.

## Contexto de la conversación

El asistente recuerda los últimos turnos literalmente y resume lo anterior para no
quedarse sin espacio. Con **conversación nueva** (opción 5) libera ese contexto. Antes
de hacerlo puede ofrecerte guardar un resumen en
`09_Automation/ai/data/summaries/<objetivo>.md`, un fichero privado (permisos 600).
Empezar de nuevo no borra el índice ni tus resultados.

## Privacidad

- Solo lee la documentación y los resultados **del objetivo de la sesión**.
- Excluye credenciales, botín (`loot`) y claves de API. Los secretos que aparezcan en
  otros textos se tapan (redacción) **antes** de indexar y antes de construir cualquier
  mensaje para el modelo.
- El modelo corre en tu máquina. El endpoint por defecto es `http://127.0.0.1:11434` y un
  endpoint remoto solo se acepta si activas `permitir_endpoint_remoto: true`.
- Sus datos (índice, resúmenes) viven en `09_Automation/ai/data/`, ignorado por git.

## Modo determinista (sin Ollama o sin modelo)

Si Ollama no está en marcha o el modelo no está descargado, el asistente te dice qué
falta y las opciones siguen funcionando sin modelo: los hallazgos se ordenan por
gravedad, el informe se muestra por secciones y el borrador sale de una plantilla.
Es menos conversacional, pero igual de trazable.

## Subcomandos

Para usarlo sin menú: `python3 09_Automation/ai/ai_assistant.py <subcomando>`.

| Subcomando | Hace |
|---|---|
| `analizar` | Equivale a la opción 1 |
| `explicar-informe` | Equivale a la opción 2 |
| `borrador [ejecutivo\|tecnico]` | Equivale a la opción 3 |
| `modelo` | Muestra el modelo recomendado y cómo descargarlo |
| `reindexar` | Reconstruye el índice de búsqueda |
| `estado` | Informa de Ollama, modelo, objetivo e índice |

Sin subcomando abre el menú. Códigos de salida: `0` correcto, `1` fallo (por ejemplo
falta algo imprescindible), `2` uso incorrecto o subcomando desconocido.

## Configuración

`09_Automation/ai/ai_config.yaml`: `modelo`, `endpoint`, `permitir_endpoint_remoto`,
`contexto_max_tokens`, `turnos_literales`, `top_k` e `incluir_credenciales`
(déjalo en `false`). Variables de entorno `AI_DATA_DIR` y `AI_CONFIG` redirigen datos y
configuración; `AI_FRAMEWORK_ROOT` es solo para pruebas.

## Solución de problemas

- **Ollama no está en marcha:** arráncalo con `ollama serve` y vuelve a probar; mientras
  tanto funciona el modo determinista.
- **Falta el modelo:** ejecuta `ollama pull <modelo>` (usa `modelo` para ver cuál) y
  comprueba con `ollama list`.
- **Responde despacio:** en CPU un modelo de 3B puede tardar decenas de segundos por
  respuesta y uno de 7B mucho más. Prueba un modelo más pequeño o respuestas más cortas.
  Medido el 2026-11-18 contra `qwen2.5:3b` real en Kali sin GPU (4 núcleos, bajo presión
  de memoria): ~3 tokens/s de generación, ~96.7s para una respuesta de 283 tokens con 4
  fragmentos de contexto. El timeout del cliente (`00_Config/lib/ai/ollama_client.py`)
  es de 300s por eso; si aun así corta, baja a un modelo más pequeño que 3B
  (tecla `D` → opción 2 → catálogo → `llama3.2:1b` o `qwen2.5-coder:0.5b`/`1.5b`) en vez
  de alargar la espera más.
- **No hay objetivo:** pulsa `T` en el gestor y fija uno.
- **El informe está desfasado o falta:** pulsa `R` para regenerarlo y repite.

## Límites

- Los modelos pequeños pueden equivocarse o exagerar: contrasta con la cita de origen.
- Los borradores llevan un aviso de revisión humana; no los entregues sin revisar.
- El asistente no ejecuta herramientas ni comandos por ti, ni siquiera si se lo pides.
- No sustituye al motor de informes (`R`) ni valida que un hallazgo sea real.
- Las pruebas automatizadas siguen usando un Ollama simulado. El 2026-11-18 se midió
  latencia real contra `qwen2.5:3b` en Kali sin GPU (ver «Responde despacio» arriba),
  pero eso no es una validación operativa completa del asistente ni de la calidad de
  sus respuestas sobre datos reales.

## Pruebas

```bash
cd CyberSecurity-Framework
bash tests/run_ai.sh
```

Son sintéticas: sin red ni Ollama, y comprueban que `scope.yaml`, `targets.txt` y el
registro de claves reales no cambian.
