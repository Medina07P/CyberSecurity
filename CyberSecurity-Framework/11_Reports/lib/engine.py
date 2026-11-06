"""Motor de informes: recoge, filtra y agrega hallazgos.

``collect`` recorre las fuentes descubiertas, ejecuta los parsers registrados
y devuelve un ``Collected`` con los hallazgos, activos, incidencias y lo que
no se pudo evaluar. ``filter_findings`` selecciona los hallazgos que
pertenecen al objetivo de la sesión.

Solo biblioteca estándar, como el resto del motor.
"""

from dataclasses import dataclass, field
from pathlib import Path

from .attribution import belongs_to, normalize_host
from .model import Finding, relpath
from .sources import discover

__all__ = ["Collected", "collect", "filter_findings"]


@dataclass
class Collected:
    """Resultado de ``collect``: hallazgos, activos e incidencias."""

    findings: list[Finding]
    activos: dict[str, dict]
    no_evaluable: list[dict]
    descartados: list[dict]
    objetivos: list[str]
    evaluado: bool
    incidencias: list[dict] = field(default_factory=list)


def filter_findings(
    findings: list[Finding],
    objetivo: str | None,
    incluir_sin_objetivo: bool,
    todos: bool,
) -> list[Finding]:
    """Filtra hallazgos por objetivo.

    - ``todos``: devuelve todos los hallazgos sin filtrar.
    - Activo vacío: solo se incluye si ``incluir_sin_objetivo``.
    - Activo no vacío: solo si ``belongs_to(activo, objetivo)``.
    """
    if todos:
        return list(findings)

    result: list[Finding] = []
    for f in findings:
        if f.activo == "":
            if incluir_sin_objetivo:
                result.append(f)
            continue
        if objetivo is not None and belongs_to(f.activo, objetivo):
            result.append(f)
    return result


def collect(
    scans_dir: Path,
    repo_root: Path,
    objetivo: str | None,
    incluir_sin_objetivo: bool = False,
    todos: bool = False,
) -> Collected:
    """Descubre fuentes, ejecuta parsers y agrega resultados.

    - Los ``errores.log`` no vacíos se registran como incidencias.
    - Las fuentes sin parser registrado se omiten (no evaluadas aún).
    - Si un parser lanza una excepción, se registra como ``no_evaluable``.
    - ``evaluado`` es ``True`` si al menos un parser se ejecutó con éxito.
    """
    sources = discover(scans_dir)

    all_findings: list[Finding] = []
    activos: dict[str, dict] = {}
    no_evaluable: list[dict] = []
    descartados: list[dict] = []
    evaluados: list[bool] = []
    incidencias: list[dict] = []

    for source in sources:
        if source.kind == "errores":
            try:
                size = source.path.stat().st_size
            except OSError:
                size = 0
            if size > 0:
                incidencias.append({
                    "fuente": relpath(source.path, repo_root),
                    "motivo": f"{size} bytes de error",
                })
            continue

        if source.parser is None:
            # Sin parser registrado: no se evalúa, no se reclama.
            continue

        try:
            result = source.parser(source.path, repo_root)
        except Exception as exc:
            no_evaluable.append({
                "fuente": relpath(source.path, repo_root),
                "motivo": f"fallo del parser: {exc}",
            })
            evaluados.append(False)
            continue

        all_findings.extend(result.findings)
        for activo in result.activos:
            host = activo.get("host", "")
            if host:
                activos[host] = activo
        no_evaluable.extend(result.no_evaluable)
        descartados.extend(result.descartados)
        evaluados.append(result.evaluado)

    filtered = filter_findings(all_findings, objetivo, incluir_sin_objetivo, todos)

    # Objetivos: hosts de activos conocidos y de hallazgos filtrados.
    objetivo_set: set[str] = set()
    for host in activos:
        objetivo_set.add(host)
    for f in filtered:
        if f.activo:
            objetivo_set.add(normalize_host(f.activo))

    return Collected(
        findings=filtered,
        activos=activos,
        no_evaluable=no_evaluable,
        descartados=descartados,
        objetivos=sorted(objetivo_set),
        evaluado=any(evaluados),
        incidencias=incidencias,
    )
