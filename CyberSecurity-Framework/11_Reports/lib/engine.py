"""Motor de informes: recoge, filtra y agrega hallazgos.

``collect`` recorre las fuentes descubiertas, ejecuta los parsers registrados
y devuelve un ``Collected`` con los hallazgos, activos, incidencias y lo que
no se pudo evaluar. ``filter_findings`` selecciona los hallazgos que
pertenecen al objetivo de la sesión.

Solo biblioteca estándar, como el resto del motor.
"""

from dataclasses import dataclass, field, replace
from pathlib import Path

from .attribution import belongs_to, guess_host, normalize_host
from .model import Finding, ParseResult, merge_findings, sort_findings, relpath
from .sources import discover

__all__ = ["Collected", "collect", "filter_findings"]

_SIN_OBJETIVO = "sin objetivo atribuible"


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
    """Filtra hallazgos por objetivo y marca los incluidos sin atribución."""
    if todos:
        return [
            replace(f, activo=_SIN_OBJETIVO) if f.activo == "" else f
            for f in findings
        ]

    result: list[Finding] = []
    for f in findings:
        if f.activo == "":
            if incluir_sin_objetivo:
                result.append(replace(f, activo=_SIN_OBJETIVO))
            continue
        if objetivo is not None and belongs_to(f.activo, objetivo):
            result.append(f)
    return result


def _filter_assets(
    assets: list[dict],
    objetivo: str | None,
    incluir_sin_objetivo: bool,
    todos: bool,
) -> list[dict]:
    """Selecciona activos por su host; un host vacío exige el permiso explícito."""
    selected: list[dict] = []
    for asset in assets:
        host = asset.get("host", "")
        if todos or (host and objetivo is not None and belongs_to(host, objetivo)):
            selected.append(asset)
        elif not host and incluir_sin_objetivo:
            selected.append(asset)
    return selected


def _content_hosts(result: ParseResult) -> set[str]:
    """Hosts declarados por los registros; tienen prioridad sobre el nombre."""
    hosts = {
        normalize_host(f.activo)
        for f in result.findings
        if f.activo and f.activo != _SIN_OBJETIVO
    }
    hosts.update(
        normalize_host(asset.get("host", ""))
        for asset in result.activos
        if asset.get("host", "")
    )
    return {host for host in hosts if host}


def _selected_source(
    source_host: str | None,
    content_hosts: set[str],
    objetivo: str | None,
    incluir_sin_objetivo: bool,
    todos: bool,
) -> bool:
    """Decide si una fuente entra antes de agregar cualquiera de sus datos."""
    if todos:
        return True
    if content_hosts:
        return bool(
            objetivo is not None
            and any(belongs_to(host, objetivo) for host in content_hosts)
        )
    if source_host:
        return bool(objetivo is not None and belongs_to(source_host, objetivo))
    return incluir_sin_objetivo


def _add_unattributed(no_evaluable: list[dict], source, repo_root: Path) -> None:
    """Deja constancia de una fuente omitida sin inventarle un objetivo."""
    no_evaluable.append({
        "fuente": relpath(source.path, repo_root),
        "motivo": _SIN_OBJETIVO,
    })


def collect(
    scans_dir: Path,
    repo_root: Path,
    objetivo: str | None,
    incluir_sin_objetivo: bool = False,
    todos: bool = False,
) -> Collected:
    """Descubre fuentes, atribuye cada una y agrega solo lo incluido.

    El host declarado por los registros manda sobre el nombre del fichero. Una
    fuente sin host no aporta hallazgos, activos, descartes ni incidencias sin
    ``incluir_sin_objetivo``; en su lugar queda en el apéndice de no evaluable.
    """
    sources = discover(scans_dir)

    all_findings: list[Finding] = []
    activos: dict[str, dict] = {}
    no_evaluable: list[dict] = []
    descartados: list[dict] = []
    evaluados: list[bool] = []
    incidencias: list[dict] = []

    for source in sources:
        source_host = source.host or guess_host(source.path.name)

        if source.kind == "errores":
            selected = _selected_source(
                source_host, set(), objetivo, incluir_sin_objetivo, todos
            )
            if not selected:
                if not source_host:
                    _add_unattributed(no_evaluable, source, repo_root)
                continue
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
            selected = _selected_source(
                source_host, set(), objetivo, incluir_sin_objetivo, todos
            )
            if not selected:
                if not source_host:
                    _add_unattributed(no_evaluable, source, repo_root)
                continue
            no_evaluable.append({
                "fuente": relpath(source.path, repo_root),
                "motivo": f"fallo del parser: {exc}",
            })
            evaluados.append(False)
            continue

        content_hosts = _content_hosts(result)
        selected = _selected_source(
            source_host, content_hosts, objetivo, incluir_sin_objetivo, todos
        )
        if not selected:
            if not source_host and not content_hosts:
                _add_unattributed(no_evaluable, source, repo_root)
            continue

        all_findings.extend(filter_findings(
            result.findings, objetivo, incluir_sin_objetivo, todos
        ))
        for activo in _filter_assets(
            result.activos, objetivo, incluir_sin_objetivo, todos
        ):
            host = activo.get("host", "")
            if host in activos:
                # Fusionar con el activo existente
                existing = activos[host]
                # Fusionar puertos por (protocolo, puerto)
                existing_ports = {(p.get("protocolo", "tcp"), p.get("puerto")) for p in existing.get("puertos", [])}
                for puerto in activo.get("puertos", []):
                    key = (puerto.get("protocolo", "tcp"), puerto.get("puerto"))
                    if key not in existing_ports:
                        existing.setdefault("puertos", []).append(puerto)
                        existing_ports.add(key)
                # Fusionar tecnologías
                existing_tech = set(existing.get("tecnologias", []))
                for tech in activo.get("tecnologias", []):
                    if tech not in existing_tech:
                        existing.setdefault("tecnologias", []).append(tech)
                        existing_tech.add(tech)
                # Fusionar otros campos sin perder datos
                for key, value in activo.items():
                    if key not in existing:
                        existing[key] = value
            else:
                activos[host] = activo
        no_evaluable.extend(result.no_evaluable)
        descartados.extend(result.descartados)
        evaluados.append(result.evaluado)

    # Objetivos: solo hosts de activos y hallazgos efectivamente incluidos.
    objetivo_set: set[str] = {
        normalize_host(host) for host in activos if host
    }
    for finding in all_findings:
        if finding.activo and finding.activo != _SIN_OBJETIVO:
            objetivo_set.add(normalize_host(finding.activo))

    # Fusionar hallazgos con la misma clave y ordenar por gravedad
    all_findings = sort_findings(merge_findings(all_findings))

    return Collected(
        findings=all_findings,
        activos=activos,
        no_evaluable=no_evaluable,
        descartados=descartados,
        objetivos=sorted(objetivo_set),
        evaluado=any(evaluados),
        incidencias=incidencias,
    )
