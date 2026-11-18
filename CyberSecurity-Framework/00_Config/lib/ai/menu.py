"""Menú guiado del asistente IA local.

`run(stdin, stdout, assistant_factory)` dibuja un menú sencillo pensado para
alguien con pocos conocimientos técnicos y traduce cada entrada a una acción del
núcleo (`Assistant`). Nunca ejecuta herramientas del framework ni escribe fuera
del directorio de datos: solo lee la entrada, pide respuestas al núcleo y las
imprime, citando siempre el origen.

Reglas de entrada:

- ``1``–``4`` eligen opción; ``5`` o ``nueva`` empiezan conversación nueva.
- ``0`` o ``salir`` vuelven al gestor; lo mismo hace EOF (fin de la entrada).
- Cualquier otro texto no vacío es una pregunta libre (opción 4).
- Una línea vacía o con solo espacios se ignora.
- ``Ctrl+C`` mientras se responde cancela solo esa respuesta y vuelve al menú;
  en el propio menú, ``Ctrl+C`` sale con código 0.

El núcleo decide si hay modelo disponible (``assistant.client``): sin modelo, las
respuestas siguen mostrando fragmentos citados de la documentación y resultados.
"""
import os
import stat
from pathlib import Path

from . import config, hardware

TITULO = "🤖 Asistente del framework"
OPCIONES = (
    " 1) Entender mis resultados",
    " 2) Explicarme el informe",
    " 3) Ayudarme a redactar el informe",
    " 4) Tengo una duda / no sé cómo hacer algo",
    " 5) Empezar conversación nueva",
    " 6) Elegir modelo de IA",
    " 7) Hablar libremente con el modelo (sin buscar en los documentos)",
    " 0) Volver",
)
CANCELADA = "\n(Respuesta cancelada. Volvemos al menú.)"
INSTALA_OLLAMA = ("Para usar el modelo, instala Ollama desde ollama.com y "
                  "arráncalo con «ollama serve».")


def _recommendation():
    mem = hardware.read_mem_available_gib()
    return hardware.recommend_model(mem, hardware.has_nvidia_gpu(), hardware.has_amd_gpu())


def _model_status(assistant):
    """(disponible, nombre_modelo, marca, lineas_de_lo_que_falta).

    Sondeo en vivo (``is_up``/``has_model`` son una petición local rápida):
    si el usuario arranca Ollama a mitad de sesión sin cerrar el menú, la
    cabecera lo refleja en la siguiente vuelta en vez de quedar pegada al
    estado que había al abrir el asistente.
    """
    client = assistant.client
    if client is not None and client.is_up() and client.has_model():
        return True, client.model, "✔", []
    rec = _recommendation()
    modelo = client.model if client is not None else rec.model
    faltan = [
        "No hay un modelo de lenguaje disponible; respondo buscando en la "
        "documentación y los resultados y citando su origen.",
        INSTALA_OLLAMA,
        "Modelo recomendado para esta máquina: %s (%s). %s" % (
            rec.model, rec.size_label, rec.reason),
        "Descárgalo con:  %s" % rec.pull_command,
    ]
    return False, modelo, "✗", faltan


def _writer(stdout):
    def write(trozo):
        stdout.write(trozo)
        stdout.flush()
    return write


def _print_answer(stdout, answer):
    """Imprime el texto (si no se transmitió ya) y las fuentes/avisos."""
    if not answer.used_model:
        stdout.write(answer.text.rstrip("\n") + "\n")
    else:
        stdout.write("\n")
    if answer.sources:
        stdout.write("Fuentes: " + ", ".join(answer.sources) + "\n")
    if answer.notice and answer.notice not in answer.text:
        stdout.write(answer.notice.rstrip("\n") + "\n")
    stdout.flush()


def _summaries_dir(assistant, create: bool = True):
    data = getattr(assistant, "data_dir", None)
    if not data:
        return None
    d = Path(data) / "summaries"
    if not create:
        return d
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(Path(data), 0o700)
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _save_summary(assistant, stdout):
    texto = assistant.conversation.reset(save_summary=True)
    if not texto:
        stdout.write("No había conversación que resumir; empezamos de cero.\n")
        return
    d = _summaries_dir(assistant)
    if d is None:
        stdout.write("No hay dónde guardar el resumen; empezamos de cero.\n")
        return
    slug = assistant.slug or "sin_objetivo"
    etiqueta = assistant.target or "sin objetivo"
    destino = d / ("%s.md" % slug)
    cuerpo = ("# Resumen de la conversación — objetivo: %s\n\n%s\n"
              % (etiqueta, texto))
    fd = os.open(str(destino), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(cuerpo)
    finally:
        try:
            os.chmod(str(destino), 0o600)
        except OSError:
            pass
    stdout.write("Resumen guardado en %s\n" % destino)


def _saved_summary_path(assistant):
    d = _summaries_dir(assistant, create=False)
    if d is None:
        return None
    slug = assistant.slug or "sin_objetivo"
    return d / ("%s.md" % slug)


def _forget_saved_summary(assistant) -> bool:
    """Borra el resumen guardado en disco, si existía. Devuelve si había
    algo que borrar (para que quien llama pueda avisar o no)."""
    path = _saved_summary_path(assistant)
    if path is None:
        return False
    existia = path.is_file()
    try:
        path.unlink()
    except OSError:
        existia = False
    assistant.resumen_recuperado = False
    return existia


def _nueva(assistant, stdin, stdout):
    # Si ya hay un resumen guardado, la persona debe saber que responder que
    # no también lo borra — sin esto, "N" (la respuesta por defecto, también
    # la que da un EOF) descarta en silencio algo que se guardó a propósito
    # en una sesión anterior.
    hay_guardado = (_saved_summary_path(assistant) or Path(os.devnull)).is_file()
    aviso = (" (s/N; N borra también el resumen guardado anterior) "
            if hay_guardado else " (s/N) ")
    stdout.write("¿Guardar un resumen antes de empezar de nuevo?" + aviso)
    stdout.flush()
    resp = stdin.readline()
    if resp and resp.strip().lower() in ("s", "si", "sí"):
        _save_summary(assistant, stdout)
    else:
        assistant.conversation.reset(save_summary=False)
        if _forget_saved_summary(assistant):
            stdout.write("Resumen guardado anterior borrado.\n")
        stdout.write("Empezamos una conversación nueva.\n")
    client = assistant.client
    if client is not None:
        try:
            client.unload()
        except Exception:
            pass
    stdout.flush()


def _elegir_modelo(assistant, stdin, stdout):
    """Lista los modelos ya descargados en Ollama y persiste el elegido en la
    configuración; si hay un cliente activo, el cambio aplica ya mismo, sin
    reabrir el asistente."""
    client = assistant.client
    actual = client.model if client is not None else _recommendation().model
    stdout.write("Modelo configurado ahora mismo: %s\n" % actual)
    instalados = client.list_models() if client is not None else []
    if instalados:
        stdout.write("Modelos instalados en Ollama:\n")
        for i, nombre in enumerate(instalados, 1):
            marca = " (actual)" if nombre == actual else ""
            stdout.write("  %d) %s%s\n" % (i, nombre, marca))
        stdout.write("Elige un número de la lista, escribe el nombre de otro "
                     "modelo ya descargado o deja la línea vacía para cancelar: ")
    else:
        stdout.write("No se pudo listar modelos instalados (Ollama no responde "
                     "o no tiene ninguno descargado). Escribe el nombre exacto "
                     "de un modelo ya descargado (ollama pull <modelo>) o deja "
                     "la línea vacía para cancelar: ")
    stdout.flush()
    respuesta = (stdin.readline() or "").strip()
    if not respuesta:
        stdout.write("Sin cambios.\n")
        return
    nuevo = respuesta
    if respuesta.isdigit():
        indice = int(respuesta)
        if 1 <= indice <= len(instalados):
            nuevo = instalados[indice - 1]
        else:
            stdout.write("Número fuera de rango; sin cambios.\n")
            return
    if nuevo == actual:
        stdout.write("Ya estaba configurado ese modelo.\n")
        return
    try:
        config.save_model(nuevo)
    except OSError:
        stdout.write("No se pudo guardar la configuración; sin cambios.\n")
        return
    if client is not None:
        client.model = nuevo
    stdout.write("Modelo configurado: %s\n" % nuevo)


def _chat_libre(assistant, stdin, stdout):
    """Sub-bucle de conversación abierta: se queda charlando turno a turno,
    como con un asistente de IA genérico, hasta que la persona lo deja (línea
    vacía, '0', EOF o Ctrl+C esperando el siguiente mensaje). Un Ctrl+C
    mientras el modelo responde solo cancela ese turno y sigue en el modo."""
    disponible, _, _, faltan = _model_status(assistant)
    if not disponible:
        stdout.write("\nPara hablar libremente hace falta un modelo de IA "
                     "cargado y disponible:\n")
        for linea in faltan:
            stdout.write("  " + linea + "\n")
        return
    stdout.write("\nModo de conversación libre (no busca en los documentos "
                 "del framework; para eso usa 1-4). Escribe lo que quieras; "
                 "una línea vacía o «0» vuelve al menú.\n\n")
    stdout.flush()
    while True:
        stdout.write("Tú: ")
        stdout.flush()
        try:
            linea = stdin.readline()
        except KeyboardInterrupt:
            stdout.write("\n")
            return
        if linea == "":          # EOF
            return
        mensaje = linea.strip()
        if not mensaje or mensaje.lower() in ("0", "salir"):
            return
        try:
            ans = assistant.chat_libre(mensaje, stream_to=_writer(stdout))
        except KeyboardInterrupt:
            stdout.write(CANCELADA + "\n")
            continue
        _print_answer(stdout, ans)


def _answer_free(assistant, stdout, pregunta):
    return assistant.ask(pregunta, stream_to=_writer(stdout))


def _run_option(assistant, stdin, stdout, eleccion):
    if eleccion == "1":
        return _print_answer(stdout, assistant.understand_results(
            stream_to=_writer(stdout)))
    if eleccion == "2":
        return _print_answer(stdout, assistant.explain_report(
            stream_to=_writer(stdout)))
    if eleccion == "3":
        stdout.write("¿Resumen ejecutivo o técnico? (ejecutivo/técnico) ")
        stdout.flush()
        tipo = (stdin.readline() or "").strip().lower()
        kind = "tecnico" if tipo.startswith("t") else "ejecutivo"
        return _print_answer(stdout, assistant.draft_report(
            kind, stream_to=_writer(stdout)))
    if eleccion == "4":
        stdout.write("Escribe tu pregunta: ")
        stdout.flush()
        pregunta = (stdin.readline() or "").strip()
        if not pregunta:
            stdout.write("No he recibido ninguna pregunta.\n")
            return None
        return _print_answer(stdout, _answer_free(assistant, stdout, pregunta))
    return None


def _header(stdout, assistant, status):
    disponible, modelo, marca, faltan = status
    ctx = assistant.conversation.usage_percent()
    stdout.write("\n%s      modelo: %s %s   contexto: %d %%\n"
                 % (TITULO, modelo, marca, ctx))
    objetivo = assistant.target or "(sin objetivo; fíjalo con la tecla T)"
    stdout.write("Objetivo de la sesión: %s\n" % objetivo)
    if assistant.conversation.needs_warning():
        stdout.write("Aviso: la conversación está larga; valora empezar una "
                     "nueva (opción 5).\n")
    if not disponible:
        for linea in faltan:
            stdout.write("  " + linea + "\n")
    stdout.write("\n")
    for linea in OPCIONES:
        stdout.write(linea + "\n")
    stdout.write("\nElige una opción (número) o escribe tu pregunta: ")
    stdout.flush()


def run(stdin, stdout, assistant_factory):
    """Bucle del menú guiado. Devuelve 0 al salir con normalidad.

    Ctrl+C mientras se responde (o un Ctrl+C que el cliente del modelo difiere
    hasta justo después) cancela esa respuesta y vuelve a dibujar el menú: por
    eso la cabecera y el despacho van dentro del mismo ``try``. Solo el Ctrl+C
    estando a la espera de una opción (en ``readline``) sale con código 0.
    """
    assistant = assistant_factory()
    aviso_resumen_mostrado = False
    while True:
        try:
            status = _model_status(assistant)
            if (not aviso_resumen_mostrado and status[0]
                    and getattr(assistant, "resumen_recuperado", False)):
                stdout.write(
                    "He recuperado el resumen de tu conversación anterior "
                    "sobre «%s».\n" % assistant.target)
                aviso_resumen_mostrado = True
            _header(stdout, assistant, status)
            try:
                linea = stdin.readline()
            except KeyboardInterrupt:
                stdout.write("\n")
                return 0
            if linea == "":          # EOF
                return 0
            texto = linea.strip()
            if not texto:
                continue
            bajo = texto.lower()
            if bajo in ("0", "salir"):
                return 0
            if bajo == "nueva" or texto == "5":
                _nueva(assistant, stdin, stdout)
            elif texto == "6":
                _elegir_modelo(assistant, stdin, stdout)
            elif texto == "7":
                _chat_libre(assistant, stdin, stdout)
            elif texto in ("1", "2", "3", "4"):
                _run_option(assistant, stdin, stdout, texto)
            else:
                _print_answer(stdout, _answer_free(assistant, stdout, texto))
        except KeyboardInterrupt:
            stdout.write(CANCELADA + "\n")
            stdout.flush()
            continue
    return 0
