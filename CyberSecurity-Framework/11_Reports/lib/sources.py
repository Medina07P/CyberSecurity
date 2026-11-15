"""Descubrimiento y clasificación de fuentes de hallazgos.

Recorre el directorio de resultados del framework y clasifica cada fichero
en un tipo de fuente conocido. Los parsers se cargan de forma diferida: los
módulos que los registran viven en ``lib/parsers/`` y se importan con
tolerancia a ``ImportError`` para que las tareas posteriores solo tengan que
añadir su módulo sin tocar este fichero.

Solo biblioteca estándar, como el resto del motor.
"""

import fnmatch
import importlib
import json
from functools import lru_cache
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .model import ParseResult
from .coverage import walk
from .attribution import guess_host

__all__ = ["Source", "PARSERS", "register", "discover"]


@dataclass
class Source:
    """Fuente de hallazgos: un fichero clasificado y su parser (si existe)."""

    path: Path
    kind: str
    parser: Callable[[Path, Path], ParseResult] | None
    host: str | None = None


PARSERS: dict[str, Callable[[Path, Path], ParseResult]] = {}


def register(kind: str, fn: Callable[[Path, Path], ParseResult]) -> None:
    """Registra un parser para un tipo de fuente."""
    PARSERS[kind] = fn


@lru_cache(maxsize=1)
def postexploitation_engine():
    """Un único validador de 06 para runtime, visor y parser."""
    path = Path(__file__).resolve().parents[2] / '00_Config/lib/postexploitation_evidence.py'
    spec = importlib.util.spec_from_file_location('_report_postexploitation', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_PARSER_MODULES = (
    "nmap", "nuclei", "nikto", "ffuf", "http_inject",
    "sqlmap", "sqli_findings", "rate_limit", "headers", "host_sources",
    "exploitation",
    "postexploitation",
    "scanner_ports",
)

_loaded = False


def evidence_metadata(path):
    """None si no hay sidecar; diccionario inválido si el presente no es fiable."""
    for suffix in ('.attempt.json', '.meta.json'):
        sidecar = Path(str(path)+suffix)
        if any(p.is_symlink() for p in (sidecar, *sidecar.parents)):
            return {'estado': 'NO_DETERMINADO', 'invalid': True}
        if not sidecar.exists(): continue
        try:
            from .exploitation_metadata import read_object
            meta = read_object(sidecar)
            if (isinstance(meta, dict) and meta.get('version') == 1
                    and isinstance(meta.get('host'), str) and meta['host']
                    and isinstance(meta.get('puerto'), int) and not isinstance(meta['puerto'], bool)
                    and 1 <= meta['puerto'] <= 65535
                    and meta.get('estado') in ('EJECUTADO','CONFIRMADO','DENEGADO','CERRADO','FILTRADO','OMITIDO','NO_DETERMINADO')):
                return meta
        except (ValueError, OSError, TypeError):
            pass
        return {'estado': 'NO_DETERMINADO', 'invalid': True}
    return None


def _load_parsers() -> None:
    """Carga diferida de los módulos de parsers.

    Cada módulo se importa con tolerancia a ``ImportError``; si el módulo
    aún no existe (tareas futuras), simplemente se ignora.
    El flag _loaded se marca solo después de completar la importación.
    """
    global _loaded
    if _loaded:
        return
    for module_name in _PARSER_MODULES:
        try:
            importlib.import_module(f".parsers.{module_name}", package="lib")
        except ImportError:
            pass
    _loaded = True


# Tabla de clasificación: (directorio, patrón de nombre) → kind.
_DIR_RULES: list[tuple[str, str, str]] = [
    ("masscan", "masscan_*.json", "masscan"),
    ("rustscan", "rustscan_*.txt", "rustscan"),
    ("nmap", "*.xml", "nmap"),
    ("nuclei", "*.jsonl", "nuclei_jsonl"),
    ("nuclei", "*.txt", "nuclei_txt"),
    ("nikto", "*.txt", "nikto"),
    ("web", "ffuf_*.json", "ffuf"),
    ("web", "http_inject_*.tsv", "http_inject"),
    ("web", "sqlmap_*.txt", "sqlmap"),
    ("web", "sqli_findings_*.txt", "sqli_findings"),
    ("web", "rate_limit_*.txt", "rate_limit"),
    ("web", "security_headers_*.txt", "security_headers"),
    ("web", "headers_*.txt", "headers"),
    ("web", "technologies_*.txt", "technologies"),
    ("api", "methods.txt", "api"),
    ("api", "methods_*.tsv", "api"),
    ("ssh", "auth_methods.txt", "ssh"),
    ("ssh", "auth_methods_*.txt", "ssh"),
    ("database", "anon.txt", "db"),
    ("database", "anon_*.txt", "db"),
]


def _classify(path: Path, scans_dir: Path) -> str:
    """Clasifica un fichero según su directorio padre y nombre."""
    try:
        rel = path.resolve().relative_to(scans_dir.resolve())
    except ValueError:
        return "ignored"

    parts = rel.parts
    if len(parts) < 2:
        return "ignored"

    directory = parts[0]
    name = parts[-1]

    # Cualquier */errores.log es tipo «errores».
    if name == "errores.log":
        return "errores"

    # Runs de explotación: scans/<tool>/exploitation_*/run.json
    if name == "run.json" and len(parts) >= 3 and parts[-2].startswith("exploitation_"):
        return "exploitation"
    # Runs de post-explotación: scans/<tool>/postexploitation_*/run.json
    if name == "run.json" and len(parts) >= 3 and parts[-2].startswith("postexploitation_"):
        return "postexploitation"

    for dir_pat, file_pat, kind in _DIR_RULES:
        if directory == dir_pat and fnmatch.fnmatch(name, file_pat):
            return kind

    if directory in {'masscan', 'rustscan', 'audits'} and path.suffix in {'.txt', '.json', '.xml', '.log'}:
        return 'unsupported'
    return "ignored"


def discover(scans_dir: Path) -> list[Source]:
    """Recorre ``scans_dir`` y devuelve una ``Source`` por fichero encontrado."""
    _load_parsers()
    scans_path = Path(scans_dir)
    sources: list[Source] = []
    for path, blocked in walk(scans_path):
        if blocked:
            sources.append(Source(path=path, kind='blocked', parser=None, host=guess_host(path.name)))
            continue
        kind = _classify(path, scans_path)
        parser = PARSERS.get(kind)
        host = None
        # Nuevas evidencias de 04: el último intento manda, sin borrar el
        # resultado histórico conservado. Los ficheros heredados no se atribuyen.
        meta = evidence_metadata(path) if parser is not None else None
        if meta is not None:
            host = meta.get('host')
            state = meta['estado']
            if parser and state in ('NO_DETERMINADO', 'OMITIDO'):
                def failed(source, root, state=state):
                    from .model import relpath
                    return ParseResult(evaluado=False, no_evaluable=[{'fuente': relpath(source, root), 'motivo': 'último intento: '+state}])
                parser = failed
        sources.append(Source(path=path, kind=kind, parser=parser, host=host))

    # Selección por identidad completa; un manifiesto sin identidad fiable no
    # permite presentar éxitos anteriores de esa carpeta como evidencia actual.
    postexploitation = [s for s in sources if s.kind == "postexploitation"]
    if postexploitation:
        grupos: dict[tuple, list[Source]] = {}
        invalid_directories = set()
        for s in postexploitation:
            try:
                from .exploitation_metadata import read_object
                data = read_object(s.path)
                if not isinstance(data, dict):
                    raise ValueError('manifiesto no es un objeto')
                host, port = postexploitation_engine().validate_target(
                    data.get('host'), data.get('puerto'))
                postexploitation_engine().validate_order(data)
                if not isinstance(data.get('herramienta'), str) or not data['herramienta']:
                    raise ValueError('sin herramienta')
                clave = (host, port, data['herramienta'])
                s.host = host
            except (OSError, ValueError, TypeError):
                invalid_directories.add(s.path.parent.parent)
                clave = (None, s.path)
            grupos.setdefault(clave, []).append(s)

        conservar: set[Path] = set()
        for grp in grupos.values():
            if len(grp) <= 1:
                conservar.update(s.path for s in grp)
                continue
            def _clave_run(s: Source):
                d = json.loads(s.path.read_text(encoding="utf-8"))
                return postexploitation_engine()._clave(d)
            ultimo = max(grp, key=_clave_run)
            conservar.add(ultimo.path)

        sources = [
            s for s in sources
            if s.kind != "postexploitation" or s.path in conservar
        ]
        for s in sources:
            if s.kind == 'postexploitation' and s.path.parent.parent in invalid_directories:
                def unattributed(source, root):
                    from .model import relpath
                    return ParseResult(evaluado=False, no_evaluable=[{
                        'fuente': relpath(source, root),
                        'motivo': 'manifiesto sin identidad fiable en esta carpeta; revisar último intento'}])
                s.parser = unattributed

    # Identidad completa y orden temporal del productor. Un run no atribuible
    # bloquea conservadoramente los éxitos de esa carpeta, como en 06.
    from .exploitation_metadata import identity, order, read_object
    exploitation = [s for s in sources if s.kind == "exploitation"]
    if exploitation:
        grupos = {}
        invalid_directories = set()
        orders = {}
        for s in exploitation:
            try:
                data = read_object(s.path)
                clave = identity(s.path, data)
                s.host = clave[0]
                orders[s.path] = order(data)
            except (OSError, ValueError, TypeError):
                invalid_directories.add(s.path.parent.parent)
                clave = (None, s.path)
            grupos.setdefault(clave, []).append(s)

        conservar: set[Path] = set()
        for grp in grupos.values():
            ultimo = max(grp, key=lambda s: orders[s.path]) if len(grp) > 1 else grp[0]
            conservar.add(ultimo.path)

        sources = [
            s for s in sources
            if s.kind != "exploitation" or s.path in conservar
        ]
        for s in sources:
            if s.kind == 'exploitation' and s.path.parent.parent in invalid_directories:
                def blocked(source, root):
                    from .model import relpath
                    return ParseResult(evaluado=False, no_evaluable=[{
                        'fuente': relpath(source, root),
                        'motivo': 'manifiesto sin identidad u orden fiable en esta carpeta; revisar último intento'}])
                s.parser = blocked

    return sources
