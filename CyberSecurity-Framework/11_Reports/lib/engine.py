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
from .coverage import entry

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
    cobertura: list[dict] = field(default_factory=list)


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
    framework_root: Path | None = None,
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
    cobertura: list[dict] = []

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
            if source.kind != 'ignored' and _selected_source(source_host, set(), objetivo, incluir_sin_objetivo, todos):
                state = 'no_evaluable' if source.kind == 'blocked' else 'no_soportada'
                cobertura.append(entry('03', source.path, repo_root, source_host, state,
                                       'Enlace/archivo no regular rechazado' if state == 'no_evaluable' else 'Fuente sin parser compatible'))
            elif source.kind == 'blocked' and not source_host:
                cobertura.append(entry('03', source.path, repo_root, '', 'no_evaluable', 'Enlace/archivo no regular rechazado; sin objetivo atribuible'))
            elif source.kind == 'unsupported' and not source_host:
                cobertura.append(entry('03/09', source.path, repo_root, '', 'no_soportada', 'Fuente sin parser ni objetivo atribuible'))
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
            cobertura.append(entry('03', source.path, repo_root, source_host, 'no_evaluable', 'Fallo del parser'))
            continue

        content_hosts = _content_hosts(result)
        selected = _selected_source(
            source_host, content_hosts, objetivo, incluir_sin_objetivo, todos
        )
        if not selected:
            if not source_host and not content_hosts:
                _add_unattributed(no_evaluable, source, repo_root)
            continue

        evaluated = result.evaluado
        if source.kind in ('masscan', 'rustscan'):
            evaluated = bool(filter_findings(result.findings, objetivo, incluir_sin_objetivo, todos))
            if not evaluated and result.evaluado:
                no_evaluable.append({'fuente': relpath(source.path, repo_root),
                                     'motivo': 'Sin puertos abiertos verificables para la selección; finalización y actualidad no acreditadas'})
        module = {'exploitation': '05', 'postexploitation': '06'}.get(source.kind, '03/04/05')
        selected_hosts = sorted(h for h in content_hosts if todos or (objetivo and belongs_to(h, objetivo)))
        coverage_host = selected_hosts[0] if len(selected_hosts) == 1 else (source_host if not selected_hosts else '')
        cobertura.append(entry(module, source.path, repo_root, coverage_host,
                               'evaluada' if evaluated else 'no_evaluable',
                               'Lectura estructurada; no implica ausencia de vulnerabilidades' if evaluated else 'Fuente sin evaluación concluyente'))
        if source.kind in ('masscan', 'rustscan'):
            cobertura[-1]['motivo'] += '; finalización y actualidad no acreditadas'
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
                    else:
                        previous = next(p for p in existing['puertos'] if (p.get('protocolo', 'tcp'), p.get('puerto')) == key)
                        for field in ('servicio', 'producto'):
                            if not previous.get(field) and puerto.get(field):
                                previous[field] = puerto[field]
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
        evaluados.append(evaluated)

    if framework_root is not None:
        from .parsers.prior_modules import collect_prior
        prior, evaluated = collect_prior(framework_root, repo_root, objetivo, incluir_sin_objetivo, todos)
        cobertura.extend(prior)
        evaluados.append(evaluated)

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
        cobertura=cobertura,
    )
