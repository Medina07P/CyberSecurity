# Cierre de los 8 Minor diferidos del asistente IA — 2026-11-18

## Intención

Cerrar los 8 huecos Minor documentados en `AGENTS.md` (ronda "Cierre de huecos
de la revisión final del asistente IA, 2026-11-18") y en
`docs/RETOMAR-ASISTENTE-IA-MINORS-2026-11-18.md`. El usuario pidió abordar
los 8, sin excluir ninguno.

## Alcance (los 8, uno por uno)

1. **Aviso de procedencia perdido en el primer plegado.** `context._cap()`
   recorta por el principio; si `Conversation.summary` ya lleva el aviso
   (`_AVISO_RESUMEN_CARGADO`) pegado delante y el cuerpo es largo, el primer
   `_fold()` puede recortar justo el aviso. Fix: `_cap()` reconoce el aviso
   como prefijo fijo — si el texto empieza con él, lo separa, recorta solo el
   resto y lo vuelve a anteponer sin que cuente contra `SUMMARY_CAP` (mismo
   trato que ya recibe en la carga inicial). La constante del aviso se mueve
   a `context.py` (para que `_cap` la conozca sin import circular) y
   `assistant.py` la reexporta bajo el mismo nombre privado que ya usan los
   tests (`_AVISO_RESUMEN_CARGADO`).

2. **Tope de lectura conserva los primeros 200 KB.** `load_saved_summary()`
   lee con `f.read(SUMMARY_READ_BYTES)` desde el principio. Fix: si el
   fichero mide más que `SUMMARY_READ_BYTES`, buscar con `seek` a
   `tamaño - SUMMARY_READ_BYTES` y leer desde ahí hasta EOF (los últimos
   bytes, no los primeros); si no, leer desde el principio como ahora. La
   decodificación tolerante (`errors="replace"`) sigue aplicándose solo
   cuando hubo recorte, porque el corte de cabeza puede caer a mitad de un
   carácter multibyte. Nota aceptada: en ese caso (fichero >200 KB editado a
   mano) la línea de cabecera puede perderse si cae en la parte descartada;
   no afecta a los ficheros que el programa escribe (3-4 KB).

3. **`build_client()` sin test del caso real "Ollama parado".** Nuevo test en
   `tests/test_ai_assistant.py` (o `test_ai_cli.py`, el que ya cubra `ask()`):
   un cliente no-`None` cuyo `chat()` lanza `OllamaError` y `index.search`
   no encuentra fragmentos — confirma que `ask()` igual intenta consultar al
   modelo (ya corregido en la ronda anterior) y que el fallo del cliente cae
   al texto determinista con el `notice` del error, sin traceback.

4. **Aviso de cabecera atado a la primera vuelta del bucle.** `menu.run()`
   usa `primera_vuelta` tanto para decidir cuándo mostrar el aviso como
   (implícitamente) para no repetirlo. Fix: una bandera dedicada
   `aviso_resumen_mostrado = False`, independiente de cualquier noción de
   "primera vuelta", que se consulta junto con `resumen_recuperado` y
   `status[0]` (modelo disponible) en cada vuelta; se muestra la primera vez
   que ambas son verdad y se marca `True` para no repetir. `primera_vuelta`
   deja de existir si no tenía otro uso (confirmado: no lo tenía).

5. **Docstring desactualizado en `assistant.py`.** La cabecera del módulo
   dice "Sin fragmentos no se llama al modelo"; se actualiza a reflejar el
   fix de la ronda anterior (sin fragmentos, si hay cliente, se consulta al
   modelo igualmente, sin bloque de fragmentos citados).

6. **Doc menciona la opción 7 bajo un encabezado que no la lista.**
   `docs/ASISTENTE-IA-2026-11-17.md`: el encabezado "Las cinco opciones del
   menú" (o como se llame en el fichero) se corrige para reflejar que hay
   más de cinco (incluye 6 y 7), o se mueve el párrafo de la tabla de
   módulos bajo un encabezado correcto. Solo texto, sin tocar contrato.

7. **Dos coberturas de test flojas.**
   - `test_no_chunks_with_client_still_calls_model`: además de comprobar que
     se llamó al modelo, comprobar que la pregunta en sí viaja en los
     mensajes pasados a `client.chat()`.
   - La prueba de extremo a extremo (`test_recovered_summary_reaches_the_model_request`,
     vía opción 7): añadir (o una prueba hermana) que cubra la ruta
     `ask()`/opción 4 con el resumen recuperado, comprobando que el aviso de
     procedencia llega en el cuerpo real de la petición HTTP capturada por
     `FAKE_OLLAMA_LOG`.

8. **`_forget_saved_summary` crea `summaries/` de paso.** `_summaries_dir()`
   siempre hace `mkdir(parents=True, exist_ok=True)` + `chmod`. Fix: parámetro
   `create: bool = True`; cuando es `False` (comprobaciones de solo lectura:
   `_saved_summary_path`, usado por `_forget_saved_summary` y por el aviso de
   `_nueva`), no se crea el directorio ni se toca su permiso — si no existe,
   la ruta devuelta simplemente no existe y `.is_file()`/`unlink()` se
   comportan igual que ahora (False / `OSError` capturado). `_save_summary`
   (que sí necesita escribir) sigue llamando con el valor por defecto.

## No-goals

- No se reabre el Non-goal explícito del spec original sobre el límite de
  2000 caracteres en sí (solo se corrige que el aviso no se pierda dentro de
  ese límite).
- No se cambia el contrato de `Conversation.messages()` ni el envoltorio de
  confianza del resumen persistido (ya documentado y aceptado en la ronda
  anterior).
- No se toca `docs/ASISTENTE-IA-2026-11-17.md` más allá del encabezado
  incorrecto (punto 6).

## Decisiones ya tomadas con el usuario

- Los 8 se abordan en esta misma rama de trabajo (confirmado por
  `AskUserQuestion`).
- Minor #1: `_cap` trata el aviso como prefijo protegido (confirmado).
- Minor #4: bandera dedicada, independiente de "primera vuelta" (confirmado).
- Minor #8: parámetro `create=False` para las rutas de solo lectura
  (confirmado).

## Qué queda al que implemente

- Nombres exactos de variables/parámetros dentro de lo ya fijado aquí.
- Redacción exacta de los docstrings/doc (puntos 5 y 6).
- Ubicación exacta de los nuevos tests (punto 3 y 7) dentro de los ficheros
  de test existentes, siguiendo la convención ya usada en cada uno.
- Proceso: worktree aislado, TDD por punto (o agrupando los puramente
  mecánicos 5-6-8), `tests/run_ai.sh` en verde antes de pedir revisión final
  independiente, igual que en las rondas anteriores de esta misma rama.
