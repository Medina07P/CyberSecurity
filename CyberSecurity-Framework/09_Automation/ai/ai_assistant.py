#!/usr/bin/env python3
# ============================================================
#  AI_ASSISTANT.py  —  Asistente de IA local del framework
#  Uso: ./ai_assistant.py [subcomando]
#  Ejemplo: ./ai_assistant.py estado
# ============================================================
#
# Sin subcomando abre el menú guiado (y el modo pregunta libre). Con subcomando
# produce una salida reproducible sin necesidad de modelo:
#
#   analizar            explica los hallazgos del objetivo (opción 1)
#   explicar-informe    explica el informe generado (opción 2)
#   borrador [ejecutivo|tecnico]   borrador de resumen (opción 3; por defecto ejecutivo)
#   modelo              recomendación de modelo y comando de descarga
#   reindexar           reconstruye el índice de documentación y resultados
#   estado              estado del modelo/Ollama, índice, objetivo y datos
#
# El asistente NUNCA ejecuta herramientas ni escribe fuera de su directorio de
# datos; solo lee el árbol del framework y, opcionalmente, consulta un Ollama
# local. Rutas ancladas a la ubicación del script (no dependen del cwd).
import os
import sys
from pathlib import Path

# El código del asistente vive en 00_Config/lib/ai (para que el descubrimiento
# de herramientas no lo liste). Se resuelve desde la ubicación REAL del script.
_SCRIPT_DIR = Path(__file__).resolve().parent          # 09_Automation/ai
_REAL_FW = _SCRIPT_DIR.parents[1]                       # CyberSecurity-Framework
sys.path.insert(0, str(_REAL_FW / "00_Config" / "lib"))

from ai import config, hardware, menu, sources          # noqa: E402
from ai import index as index_mod                        # noqa: E402
from ai.assistant import Assistant                        # noqa: E402
from ai.context import Conversation                        # noqa: E402
from ai.index import Index                                  # noqa: E402
from ai.ollama_client import OllamaClient, OllamaError      # noqa: E402

USAGE = ("Uso del asistente -> ./ai_assistant.py [subcomando]\n"
         "Subcomandos: analizar | explicar-informe | borrador [ejecutivo|tecnico] "
         "| modelo | reindexar | estado\n"
         "Sin subcomando abre el menú guiado.")


# --- resolución de rutas y entorno -----------------------------------------

def framework_root() -> Path:
    env = os.environ.get("AI_FRAMEWORK_ROOT")
    return Path(env).resolve() if env else _REAL_FW


def data_dir() -> Path:
    env = os.environ.get("AI_DATA_DIR")
    d = Path(env) if env else (_SCRIPT_DIR / "data")
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def read_target(fw: Path):
    sf = os.environ.get("SESSION_FILE")
    path = Path(sf) if sf else (fw / "00_Config" / ".session")
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                return line.strip()
    except OSError:
        pass
    return None


def build_client(cfg):
    """OllamaClient local, o None si el endpoint no es local sin permiso."""
    try:
        return OllamaClient(cfg["endpoint"], cfg["modelo"],
                            allow_remote=cfg["permitir_endpoint_remoto"])
    except OllamaError:
        return None


def model_available(client) -> bool:
    return bool(client is not None and client.is_up() and client.has_model())


def get_index(fw: Path, cfg: dict, data: Path, note=None) -> Index:
    path = data / "index.json"
    idx = Index.load(path)
    if idx is not None and not idx.stale(fw):
        return idx
    if note:
        note("Preparando el índice… (puede tardar la primera vez)\n")
    fp = index_mod.fingerprint(fw)
    docs = sources.discover(fw, include_credentials=cfg["incluir_credenciales"])
    idx = Index.build(docs, fingerprint=fp)
    idx.save(path)
    return idx


def make_assistant(fw, cfg, idx, target, client):
    conv = Conversation(max_tokens=cfg["contexto_max_tokens"],
                        literal_turns=cfg["turnos_literales"])
    asis = Assistant(fw, client, idx, conv, target, top_k=cfg["top_k"])
    asis.data_dir = str(data_dir())
    return asis


def recommendation():
    return hardware.recommend_model(hardware.read_mem_available_gib(),
                                    hardware.has_nvidia_gpu())


# --- impresión de respuestas de subcomando ---------------------------------

def _emit(answer, stdout=sys.stdout, stderr=sys.stderr):
    stdout.write(answer.text.rstrip("\n") + "\n")
    if answer.sources:
        stdout.write("Fuentes: " + ", ".join(answer.sources) + "\n")
    if answer.notice and answer.notice not in answer.text:
        stderr.write(answer.notice.rstrip("\n") + "\n")


# --- subcomandos ------------------------------------------------------------

def cmd_menu(fw, cfg, data):
    idx = get_index(fw, cfg, data, note=sys.stdout.write)
    target = read_target(fw)
    client = build_client(cfg)
    client_menu = client if model_available(client) else None

    def factory():
        return make_assistant(fw, cfg, idx, target, client_menu)

    return menu.run(sys.stdin, sys.stdout, factory)


def _deterministic_assistant(fw, cfg, data):
    """Asistente sin modelo: ruta determinista, nunca toca la red."""
    idx = get_index(fw, cfg, data, note=sys.stderr.write)
    return make_assistant(fw, cfg, idx, read_target(fw), None)


def cmd_analizar(fw, cfg, data):
    _emit(_deterministic_assistant(fw, cfg, data).understand_results())
    return 0


def cmd_explicar(fw, cfg, data):
    _emit(_deterministic_assistant(fw, cfg, data).explain_report())
    return 0


def cmd_borrador(fw, cfg, data, kind):
    if kind not in ("ejecutivo", "tecnico"):
        sys.stderr.write("Tipo de borrador no válido: %s (usa 'ejecutivo' o "
                         "'tecnico').\n%s\n" % (kind, USAGE))
        return 2
    _emit(_deterministic_assistant(fw, cfg, data).draft_report(kind))
    return 0


def cmd_modelo(cfg):
    rec = recommendation()
    print("Modelo recomendado para esta máquina: %s (%s)" % (rec.model, rec.size_label))
    print("Motivo: %s" % rec.reason)
    print("Modelo configurado ahora mismo: %s" % cfg["modelo"])
    print("Para descargar el recomendado:  %s" % rec.pull_command)
    print("Puedes fijar otro modelo editando %s" % config.default_path())
    return 0


def cmd_reindexar(fw, cfg, data):
    path = data / "index.json"
    fp = index_mod.fingerprint(fw)
    docs = sources.discover(fw, include_credentials=cfg["incluir_credenciales"])
    idx = Index.build(docs, fingerprint=fp)
    idx.save(path)
    print("Índice reconstruido: %d fragmentos en %s" % (len(idx.chunks), path))
    return 0


def cmd_estado(fw, cfg, data):
    target = read_target(fw)
    print("Objetivo de la sesión: %s" % (target or "(sin objetivo)"))
    print("Directorio de datos: %s" % data)
    idx_path = data / "index.json"
    if idx_path.is_file():
        import datetime
        edad = datetime.datetime.fromtimestamp(idx_path.stat().st_mtime)
        print("Índice: %s (actualizado %s)" % (idx_path, edad.strftime("%Y-%m-%d %H:%M")))
    else:
        print("Índice: aún no construido (se creará al primer uso).")
    client = build_client(cfg)
    if client is None:
        estado = "endpoint no local o no configurado (no se usará modelo)"
    elif not client.is_up():
        estado = "Ollama no está en marcha (arráncalo con «ollama serve»)"
    elif not client.has_model():
        estado = "el modelo %s no está instalado (%s)" % (cfg["modelo"],
                                                          recommendation().pull_command)
    else:
        estado = "modelo %s disponible" % cfg["modelo"]
    print("Estado del modelo: %s" % estado)
    return 0


DISPATCH = {
    "analizar": lambda fw, cfg, data, rest: cmd_analizar(fw, cfg, data),
    "explicar-informe": lambda fw, cfg, data, rest: cmd_explicar(fw, cfg, data),
    "borrador": lambda fw, cfg, data, rest: cmd_borrador(
        fw, cfg, data, rest[0] if rest else "ejecutivo"),
    "reindexar": lambda fw, cfg, data, rest: cmd_reindexar(fw, cfg, data),
    "estado": lambda fw, cfg, data, rest: cmd_estado(fw, cfg, data),
}


def main(argv):
    cfg = config.load()
    fw = framework_root()
    data = data_dir()

    if not argv:
        return cmd_menu(fw, cfg, data)

    sub, rest = argv[0], argv[1:]
    if sub in ("-h", "--help", "ayuda"):
        print(USAGE)
        return 0
    if sub == "modelo":
        return cmd_modelo(cfg)
    handler = DISPATCH.get(sub)
    if handler is None:
        sys.stderr.write("Subcomando desconocido: %s\n%s\n" % (sub, USAGE))
        return 2
    return handler(fw, cfg, data, rest)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(0)
    except OllamaError as e:
        sys.stderr.write(e.user_message + "\n")
        sys.exit(1)
    except BrokenPipeError:
        sys.exit(0)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("El asistente falló: %s\n" % e)
        sys.exit(1)
