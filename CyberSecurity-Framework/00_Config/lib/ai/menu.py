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

from . import hardware

TITULO = "🤖 Asistente del framework"
OPCIONES = (
    " 1) Entender mis resultados",
    " 2) Explicarme el informe",
    " 3) Ayudarme a redactar el informe",
    " 4) Tengo una duda / no sé cómo hacer algo",
    " 5) Empezar conversación nueva",
    " 0) Volver",
)
CANCELADA = "\n(Respuesta cancelada. Volvemos al menú.)"
INSTALA_OLLAMA = ("Para usar el modelo, instala Ollama desde ollama.com y "
                  "arráncalo con «ollama serve».")


def _recommendation():
    mem = hardware.read_mem_available_gib()
    gpu = hardware.has_nvidia_gpu()
    return hardware.recommend_model(mem, gpu)


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


def _summaries_dir(assistant):
    data = getattr(assistant, "data_dir", None)
    if not data:
        return None
    d = Path(data) / "summaries"
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


def _nueva(assistant, stdin, stdout):
    stdout.write("¿Guardar un resumen antes de empezar de nuevo? (s/N) ")
    stdout.flush()
    resp = stdin.readline()
    if resp and resp.strip().lower() in ("s", "si", "sí"):
        _save_summary(assistant, stdout)
    else:
        assistant.conversation.reset(save_summary=False)
        stdout.write("Empezamos una conversación nueva.\n")
    client = assistant.client
    if client is not None:
        try:
            client.unload()
        except Exception:
            pass
    stdout.flush()


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
    while True:
        try:
            status = _model_status(assistant)
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
            elif texto in ("1", "2", "3", "4"):
                _run_option(assistant, stdin, stdout, texto)
            else:
                _print_answer(stdout, _answer_free(assistant, stdout, texto))
        except KeyboardInterrupt:
            stdout.write(CANCELADA + "\n")
            stdout.flush()
            continue
    return 0
