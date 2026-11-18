"""Núcleo del asistente IA local: recuperación con citas y respaldo sin modelo.

Opciones del menú guiado:

- ``ask`` (opción 4): pregunta libre. Recupera fragmentos de documentación y
  resultados (siempre hay documentación, incluso sin objetivo) y responde
  citando fuentes. Sin fragmentos no se llama al modelo.
- ``understand_results`` (opción 1): explica ``findings.json`` del objetivo.
- ``explain_report`` (opción 2): explica el informe generado; si falta o está
  obsoleto, remite a la tecla R.
- ``draft_report`` (opción 3): borrador de resumen ejecutivo/técnico.

Principios: solo lectura sobre el árbol del framework; nunca importa el motor de
informes (lee el JSON directamente); las credenciales se redactan antes de que
cualquier texto llegue al modelo o a la respuesta.
"""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import context as _context
from .context import AVISO_RESUMEN_CARGADO as _AVISO_RESUMEN_CARGADO
from . import prompts
from . import redact as _redact
from . import sources
from .index import Chunk, tokenize
from .ollama_client import OllamaError

TOP_K = 5
MAX_FINDINGS = 12          # cuántos hallazgos entran en el contexto del modelo
FINDING_CHARS = 600        # tope de caracteres por hallazgo en ese contexto
REPORT_CHARS = 200_000     # tope al leer un informe

# Vocabulario y orden de severidad del motor de informes (11_Reports/lib/model.py).
SEVERITY_ORDER = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "info": 4}
_ORDER_LABEL = {0: "crítica", 1: "alta", 2: "media", 3: "baja", 4: "informativa",
                99: "sin clasificar"}

REVIEW_NOTICE = ("Esto es un borrador y necesita revisión humana antes de "
                 "entregarse.")
REPORTS_REL = "11_Reports/generated"
RESULTS_QUERY = "resultados escaneo servicios puertos vulnerabilidades hallazgos abierto"

NO_TARGET = ("No hay objetivo de sesión fijado. Fíjalo con la tecla T en el "
             "menú principal y vuelve a intentarlo.")

# Saludos y cortesías sin contenido técnico: un «Hola» no debe disparar una
# búsqueda en la documentación. Sin esto, index.search puede devolver
# fragmentos irrelevantes solo porque la palabra aparece ahí por casualidad
# (p. ej. como valor de prueba en un script), y el modelo —siguiendo la regla
# de no inventar— responde "no encuentro base" a un simple saludo.
_SALUDOS = {"hola", "holaa", "holaaa", "buenas", "buenos", "dias", "tardes",
           "noches", "hey", "ey", "saludos", "que", "tal"}
_SALUDO_RESPUESTA = (
    "¡Hola! Soy el asistente del framework. Puedo ayudarte a entender tus "
    "resultados (opción 1), explicarte el informe (opción 2), ayudarte a "
    "redactarlo (opción 3) o responder dudas sobre cómo usar el framework "
    "(opción 4, o escribe tu pregunta directamente). ¿En qué te ayudo?"
)


def _is_greeting(terms: set) -> bool:
    return bool(terms) and terms <= _SALUDOS


@dataclass
class Answer:
    text: str
    sources: List[str] = field(default_factory=list)
    used_model: bool = False
    notice: Optional[str] = None


# --- utilidades deterministas (sin modelo) ----------------------------------

def _sev_order(finding: dict) -> int:
    return SEVERITY_ORDER.get(str(finding.get("severidad", "")).lower(), 99)


def _sev_label(finding: dict) -> str:
    return _ORDER_LABEL.get(_sev_order(finding), "sin clasificar")


def _sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: (_sev_order(f), str(f.get("activo", "")),
                                           str(f.get("titulo", ""))))


def _cites(chunks: list) -> List[str]:
    seen, out = set(), []
    for c in chunks:
        cid = c.cite()
        if cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def _fragments_text(chunks: list) -> str:
    out = ["No hay un modelo de lenguaje disponible, así que no puedo redactar "
           "una explicación. Estos son los fragmentos más relevantes que he "
           "encontrado; revisa su origen entre corchetes:", ""]
    for c in chunks:
        out.append("[%s]" % c.cite())
        out.append(_redact.redact(c.text.strip()))
        out.append("")
    return "\n".join(out).rstrip()


def _findings_deterministic(target: str, findings: list) -> str:
    out = ["Resultados de «%s», ordenados de más grave a menos grave:" % target, ""]
    for f in findings:
        out.append("[%s] %s — activo: %s" % (
            _sev_label(f), f.get("titulo", "(sin título)"), f.get("activo", "?")))
        desc = f.get("descripcion")
        if desc:
            out.append("  Qué es: %s" % desc)
        rec = f.get("recomendacion")
        if rec:
            out.append("  Qué hacer: %s" % rec)
        cve = f.get("cve")
        if cve:
            out.append("  Referencia (CVE): %s" % cve)
        out.append("")
    out.append("Sin modelo de lenguaje no añado interpretación: esto es lo que "
               "dice el informe tal cual.")
    return _redact.redact("\n".join(out))


def _draft_template(target: str, kind: str, findings: list) -> str:
    titulo = "ejecutivo" if kind == "ejecutivo" else "técnico"
    out = ["BORRADOR de resumen %s — objetivo «%s»" % (titulo, target),
           "(%s)" % REVIEW_NOTICE, ""]
    if not findings:
        out.append("No se registraron hallazgos para este objetivo.")
    by_sev: dict = {}
    for f in findings:
        by_sev.setdefault(_sev_order(f), []).append(f)
    for sev in sorted(by_sev):
        out.append("== Severidad %s ==" % _ORDER_LABEL.get(sev, "sin clasificar"))
        for f in by_sev[sev]:
            out.append("- %s (activo: %s)" % (
                f.get("titulo", "(sin título)"), f.get("activo", "?")))
            if kind == "ejecutivo":
                imp = f.get("impacto_cliente") or f.get("descripcion")
                if imp:
                    out.append("    Impacto para el negocio: %s" % imp)
            else:
                desc = f.get("descripcion")
                if desc:
                    out.append("    Detalle técnico: %s" % desc)
            rec = f.get("recomendacion")
            if rec:
                out.append("    Recomendación: %s" % rec)
        out.append("")
    return _redact.redact("\n".join(out).rstrip())


def _report_deterministic(target: str, text: str) -> str:
    return _redact.redact(
        "Informe de «%s» (mostrado tal cual, sin modelo para resumirlo):\n\n%s"
        % (target, text))


def _findings_chunk(rel: str, slug: Optional[str], findings: list) -> Chunk:
    """Un único fragmento con el contexto acotado de los hallazgos para el modelo."""
    parts = []
    for f in findings[:MAX_FINDINGS]:
        block = ("[%s] %s (activo: %s)\n  %s\n  Recomendación: %s" % (
            f.get("severidad", "?"), f.get("titulo", "(sin título)"),
            f.get("activo", "?"), f.get("descripcion", ""),
            f.get("recomendacion", "")))
        parts.append(block[:FINDING_CHARS])
    text = _redact.redact("\n\n".join(parts))
    n = max(1, text.count("\n") + 1)
    return Chunk(rel, 1, n, text, "informe", slug)


SUMMARY_READ_BYTES = 200_000       # tope de lectura, mismo orden que REPORT_CHARS


def load_saved_summary(data_dir, slug: Optional[str]) -> Optional[str]:
    """Lee <data_dir>/summaries/<slug>.md si existe y devuelve, con un aviso
    de procedencia antepuesto, su cuerpo (sin la línea de cabecera real),
    redactado. El cuerpo (sin el aviso) se recorta al mismo límite que usa
    Conversation; el aviso no cuenta contra ese tope. None si no hay nada
    que cargar o la lectura falla."""
    if not slug:
        return None
    path = Path(data_dir) / "summaries" / ("%s.md" % slug)
    try:
        if not path.is_file() or path.is_symlink():
            return None
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            tamano = f.tell()
            truncado = tamano > SUMMARY_READ_BYTES
            f.seek(-SUMMARY_READ_BYTES if truncado else 0,
                   os.SEEK_END if truncado else os.SEEK_SET)
            datos = f.read()
        texto = datos.decode("utf-8", errors=("replace" if truncado else "strict"))
    except (OSError, UnicodeDecodeError):
        return None
    lineas = texto.splitlines()
    if lineas and lineas[0].startswith("# Resumen de la conversación"):
        lineas = lineas[1:]
    cuerpo = "\n".join(lineas).strip()
    # Idempotente: si lo que se guardó la vez anterior ya llevaba el aviso
    # (porque este mismo texto, ya cargado, se volvió a guardar sin más),
    # se quita antes de volver a anteponer uno solo. Sin esto, cada ciclo
    # cargar → guardar → cargar añade una copia más del aviso.
    while cuerpo.startswith(_AVISO_RESUMEN_CARGADO):
        cuerpo = cuerpo[len(_AVISO_RESUMEN_CARGADO):].strip()
    if not cuerpo:
        return None
    return _AVISO_RESUMEN_CARGADO + _context._cap(_redact.redact(cuerpo))


# --- asistente --------------------------------------------------------------

class Assistant:
    def __init__(self, framework_root, client, index, conversation, target,
                 *, top_k: int = TOP_K):
        self.framework_root = Path(framework_root)
        self.repo = self.framework_root.parent
        self.client = client
        self.index = index
        self.conversation = conversation
        self.target = target
        self.top_k = top_k

    @property
    def slug(self) -> Optional[str]:
        return sources.slug(self.target) if self.target else None

    # -- rutas del objetivo --------------------------------------------------
    def _report_dir(self) -> Path:
        return self.framework_root / "11_Reports" / "generated" / (self.slug or "")

    def _findings_path(self) -> Path:
        return self._report_dir() / "findings.json"

    def _findings_rel(self) -> str:
        return "%s/%s/findings.json" % (REPORTS_REL, self.slug)

    def _report_file(self) -> Optional[Path]:
        d = self._report_dir()
        for name in ("informe_tecnico.md", "informe_cliente.md"):
            p = d / name
            if p.is_file() and not p.is_symlink():
                return p
        return None

    def _rel(self, path: Path) -> str:
        return os.path.relpath(path, self.framework_root).replace(os.sep, "/")

    def _load_findings(self):
        """Devuelve (estado, hallazgos). estado ∈ {'ok','ausente','dañado'}."""
        path = self._findings_path()
        if not path.is_file() or path.is_symlink():
            return "ausente", None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "dañado", None
        if not isinstance(data, dict):
            return "dañado", None
        hallazgos = data.get("hallazgos")
        if not isinstance(hallazgos, list):
            return "dañado", None
        return "ok", [f for f in hallazgos if isinstance(f, dict)]

    def _newest_scan_mtime(self) -> Optional[float]:
        slug = self.slug
        scans = self.repo / "scans"
        if not slug or not scans.is_dir() or scans.is_symlink():
            return None
        newest = None
        for dp, dns, fns in os.walk(scans, followlinks=False):
            for fn in fns:
                if slug not in fn:
                    continue
                try:
                    m = os.lstat(os.path.join(dp, fn)).st_mtime
                except OSError:
                    continue
                if newest is None or m > newest:
                    newest = m
        return newest

    def _report_stale(self, report: Path) -> bool:
        newest = self._newest_scan_mtime()
        if newest is None:
            return False
        try:
            fm = self._findings_path().stat().st_mtime
            rm = report.stat().st_mtime
        except OSError:
            return False
        return min(fm, rm) < newest

    def _press_R(self, prefix: str) -> str:
        return (prefix + " Pulsa la tecla R en el menú principal para generar o "
                "actualizar el informe, y vuelve a intentarlo.")

    # -- motor compartido ----------------------------------------------------
    def _model(self, question, chunks, srcs, stream_to, *, use_history,
               deterministic_text):
        history = self.conversation.messages() if use_history else []
        msgs = prompts.build_messages(question, chunks, history)
        try:
            # El flujo (stream_to) es solo para mostrar en pantalla: un secreto
            # partido entre trozos no se puede redactar de forma incremental y
            # no se acumula todo el flujo para no romper la experiencia en vivo.
            # Lo que se devuelve y se guarda sí pasa por la redacción final.
            text = _redact.redact(self.client.chat(msgs, stream_to=stream_to))
        except OllamaError as e:
            return Answer(deterministic_text, sources=srcs, used_model=False,
                          notice=e.user_message)
        if use_history:
            self.conversation.add("user", question)
            self.conversation.add("assistant", text)
        return Answer(text, sources=srcs, used_model=True)

    # -- opción 4: pregunta libre -------------------------------------------
    def ask(self, question, stream_to=None) -> Answer:
        if not isinstance(question, str) or not question.strip():
            return Answer("Escribe tu pregunta y te ayudo. Por ejemplo: «¿qué "
                          "significa este resultado de Nmap?».")
        # Un secreto pegado en la pregunta no debe llegar al modelo, al
        # historial ni a los resúmenes guardados.
        q = _redact.redact(question.strip())
        if _is_greeting(set(tokenize(q))):
            return Answer(_SALUDO_RESPUESTA)
        chunks = self.index.search(q, k=self.top_k, target=self.slug)
        no_basis = ("No encuentro base en la documentación ni en los "
                   "resultados para responder a eso. Prueba a reformular "
                   "la pregunta o fija un objetivo con la tecla T.")
        if not chunks:
            if self.client is None:
                return Answer(no_basis)
            return self._model(q, [], [], stream_to, use_history=True,
                               deterministic_text=no_basis)
        srcs = _cites(chunks)
        if self.client is None:
            return Answer(_fragments_text(chunks), sources=srcs)
        return self._model(q, chunks, srcs, stream_to, use_history=True,
                           deterministic_text=_fragments_text(chunks))

    # -- opción 7: conversación libre con el modelo --------------------------
    def chat_libre(self, mensaje, stream_to=None) -> Answer:
        """Charla abierta con el modelo, sin buscar en la documentación ni
        exigir que la respuesta esté anclada en fragmentos citados — como
        hablar con un asistente de IA genérico. Sin modelo no hay nada
        determinista que devolver (no hay fragmentos de los que tirar)."""
        if not isinstance(mensaje, str) or not mensaje.strip():
            return Answer("Escribe algo y te respondo.")
        if self.client is None:
            return Answer("Para hablar libremente hace falta un modelo de IA "
                          "cargado. Instala Ollama (tecla D, opción 2) o, si "
                          "ya lo tienes, elige un modelo con la opción 6 de "
                          "este menú.")
        # Un secreto pegado en el mensaje no debe llegar al modelo ni al
        # historial, igual que en ask().
        m = _redact.redact(mensaje.strip())
        history = self.conversation.messages()
        msgs = prompts.build_free_messages(m, history)
        try:
            text = _redact.redact(self.client.chat(msgs, stream_to=stream_to))
        except OllamaError as e:
            return Answer("No pude obtener respuesta del modelo.",
                          used_model=False, notice=e.user_message)
        self.conversation.add("user", m)
        self.conversation.add("assistant", text)
        return Answer(text, used_model=True)

    # -- opción 1: entender resultados --------------------------------------
    def understand_results(self, stream_to=None) -> Answer:
        if self.target is None:
            return Answer(NO_TARGET, notice=NO_TARGET)
        estado, findings = self._load_findings()
        if estado == "dañado":
            return Answer("El archivo de hallazgos (findings.json) está dañado o "
                          "no se puede leer. Pulsa la tecla R en el menú "
                          "principal para volver a generarlo.")
        if estado == "ausente":
            return self._results_from_scans(stream_to)
        if not findings:
            return Answer("El informe de «%s» no contiene hallazgos todavía: no "
                          "hay nada que explicar." % self.target,
                          sources=[self._findings_rel()])
        ordered = _sort_findings(findings)
        det = _findings_deterministic(self.target, ordered)
        rel = self._findings_rel()
        if self.client is None:
            return Answer(det, sources=[rel])
        chunk = _findings_chunk(rel, self.slug, ordered)
        q = ("Explícame en lenguaje llano qué significan estos resultados y qué "
             "debería priorizar.")
        return self._model(q, [chunk], [rel], stream_to, use_history=False,
                           deterministic_text=det)

    def _results_from_scans(self, stream_to) -> Answer:
        chunks = self.index.search(RESULTS_QUERY, k=self.top_k, target=self.slug,
                                   kinds={"resultado"})
        if not chunks:
            return Answer("Todavía no hay resultados ni informe para «%s». Lanza "
                          "algún escaneo y, cuando termine, pulsa la tecla R para "
                          "generar el informe." % self.target)
        srcs = _cites(chunks)
        if self.client is None:
            return Answer(_fragments_text(chunks), sources=srcs)
        q = ("Explícame en lenguaje llano qué significan estos resultados de "
             "escaneo y qué debería mirar primero.")
        return self._model(q, chunks, srcs, stream_to, use_history=False,
                           deterministic_text=_fragments_text(chunks))

    # -- opción 2: explicar el informe --------------------------------------
    def explain_report(self, stream_to=None) -> Answer:
        if self.target is None:
            return Answer(NO_TARGET, notice=NO_TARGET)
        estado, _ = self._load_findings()
        report = self._report_file()
        if estado != "ok" or report is None:
            return Answer(self._press_R(
                "Aún no hay un informe completo para «%s»." % self.target))
        if self._report_stale(report):
            return Answer(self._press_R(
                "El informe de «%s» es más antiguo que los últimos resultados: "
                "se ha quedado desactualizado." % self.target))
        text = ""
        try:
            text = report.read_text(encoding="utf-8", errors="replace")[:REPORT_CHARS]
        except OSError:
            text = ""
        rel = self._rel(report)
        det = _report_deterministic(self.target, text)
        if self.client is None:
            return Answer(det, sources=[rel])
        chunk = Chunk(rel, 1, max(1, text.count("\n") + 1),
                      _redact.redact(text), "informe", self.slug)
        q = "Explícame este informe sin jerga, apartado por apartado."
        return self._model(q, [chunk], [rel], stream_to, use_history=False,
                           deterministic_text=det)

    # -- opción 3: borrador de informe --------------------------------------
    def draft_report(self, kind, stream_to=None) -> Answer:
        if kind not in ("ejecutivo", "tecnico"):
            raise ValueError("tipo de borrador desconocido: %r (usa 'ejecutivo' "
                             "o 'tecnico')" % (kind,))
        if self.target is None:
            return Answer(NO_TARGET + " " + REVIEW_NOTICE, notice=NO_TARGET)
        estado, findings = self._load_findings()
        if estado != "ok":
            return Answer("No hay hallazgos para redactar un borrador de «%s». "
                          "Pulsa la tecla R en el menú principal para generar el "
                          "informe primero. %s" % (self.target, REVIEW_NOTICE))
        ordered = _sort_findings(findings or [])
        det = _draft_template(self.target, kind, ordered)
        rel = self._findings_rel()
        if self.client is None:
            return Answer(det, sources=[rel])
        chunk = _findings_chunk(rel, self.slug, ordered)
        q = ("Redacta un borrador de resumen %s a partir de estos hallazgos, en "
             "lenguaje llano. Deja claro al principio que es un borrador y que "
             "necesita revisión humana antes de entregarse." % kind)
        ans = self._model(q, [chunk], [rel], stream_to, use_history=False,
                          deterministic_text=det)
        low = ans.text.lower()
        if "borrador" not in low or "revisión humana" not in low:
            ans.text = ans.text.rstrip() + "\n\n" + REVIEW_NOTICE
        return ans
