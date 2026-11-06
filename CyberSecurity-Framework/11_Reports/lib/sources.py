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
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .model import ParseResult

__all__ = ["Source", "PARSERS", "register", "discover"]


@dataclass
class Source:
    """Fuente de hallazgos: un fichero clasificado y su parser (si existe)."""

    path: Path
    kind: str
    parser: Callable[[Path, Path], ParseResult] | None


PARSERS: dict[str, Callable[[Path, Path], ParseResult]] = {}


def register(kind: str, fn: Callable[[Path, Path], ParseResult]) -> None:
    """Registra un parser para un tipo de fuente."""
    PARSERS[kind] = fn


_PARSER_MODULES = (
    "nmap", "nuclei", "nikto", "ffuf", "http_inject",
    "sqlmap", "sqli_findings", "rate_limit", "headers", "host_sources",
)

_loaded = False


def _load_parsers() -> None:
    """Carga diferida de los módulos de parsers.

    Cada módulo se importa con tolerancia a ``ImportError``; si el módulo
    aún no existe (tareas futuras), simplemente se ignora.
    """
    global _loaded
    if _loaded:
        return
    _loaded = True
    for module_name in _PARSER_MODULES:
        try:
            importlib.import_module(f".parsers.{module_name}", package="lib")
        except ImportError:
            pass


# Tabla de clasificación: (directorio, patrón de nombre) → kind.
_DIR_RULES: list[tuple[str, str, str]] = [
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
    ("ssh", "auth_methods.txt", "ssh"),
    ("database", "anon.txt", "db"),
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

    for dir_pat, file_pat, kind in _DIR_RULES:
        if directory == dir_pat and fnmatch.fnmatch(name, file_pat):
            return kind

    return "ignored"


def discover(scans_dir: Path) -> list[Source]:
    """Recorre ``scans_dir`` y devuelve una ``Source`` por fichero encontrado."""
    _load_parsers()
    scans_path = Path(scans_dir)
    if not scans_path.is_dir():
        return []

    sources: list[Source] = []
    for path in sorted(scans_path.rglob("*")):
        if not path.is_file():
            continue
        kind = _classify(path, scans_path)
        parser = PARSERS.get(kind)
        sources.append(Source(path=path, kind=kind, parser=parser))
    return sources
