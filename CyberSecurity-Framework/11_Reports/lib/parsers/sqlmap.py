"""Parser de los veredictos de sqlmap.

sqlmap solo escribe líneas de resumen; lo único que interesa aquí son las
que empiezan por ``- Veredicto:``. El orden de comprobación importa:
``NO INYECTABLE`` contiene ``INYECTABLE``, así que se prueba primero.

- ``INYECTABLE (param): técnica`` → confirmado, severidad critica.
- ``NO INYECTABLE`` → no produce hallazgo (sqlmap lo descartó).
- ``NO DETERMINADO`` → no evaluable (la prueba no concluyó, p.ej. por 429).

El host sale de ``- Objetivo: host:port (scheme)`` y el parámetro de los
paréntesis del veredicto. Clave de deduplicación: ``sqli|host|param``.

Solo biblioteca estándar.
"""

import re
from pathlib import Path

from lib.attribution import normalize_host
from lib.catalog import build
from lib.model import Evidence, ParseResult, relpath
from lib.sources import register

__all__ = ["parse"]

_OBJETIVO_RE = re.compile(r"^- Objetivo:\s+(.+?)(?:\s+\(([^)]+)\))?\s*$")
_VEREDICTO_RE = re.compile(r"^- Veredicto:\s+(.+)$")
_PARAM_RE = re.compile(r"\(([^)]+)\)")


def _vacio(archivo: str) -> ParseResult:
    """Un fichero sin contenido no se evalúa: no hay nada que leer."""
    return ParseResult(
        evaluado=False,
        no_evaluable=[{"fuente": archivo, "motivo": "archivo vacío"}],
    )


def _lineas(path: Path) -> list[str]:
    """Líneas del fichero sin el salto y con los bytes rotos reemplazados."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return [linea.rstrip("\r\n") for linea in fh]


def parse(path: Path, repo_root: Path) -> ParseResult:
    """Traduce un resumen de sqlmap a hallazgos del informe.

    Solo las líneas de veredicto cuentan. Un ``NO INYECTABLE`` no produce
    hallazgo; un ``NO DETERMINADO`` queda como ``no_evaluable`` porque la
    prueba no concluyó.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)
    lineas = _lineas(path)
    if not any(linea.strip() for linea in lineas):
        return _vacio(archivo)

    host = ""
    findings: list = []
    no_evaluable: list[dict] = []
    vistos: set[str] = set()

    for numero, linea in enumerate(lineas, 1):
        linea = linea.strip()
        if not linea:
            continue

        m_obj = _OBJETIVO_RE.match(linea)
        if m_obj:
            host = normalize_host(m_obj.group(1))
            continue

        m_ver = _VEREDICTO_RE.match(linea)
        if not m_ver:
            continue

        texto = m_ver.group(1).strip()

        # "NO INYECTABLE" antes de "INYECTABLE": uno contiene al otro.
        if texto.startswith("NO INYECTABLE"):
            continue

        if texto.startswith("NO DETERMINADO"):
            no_evaluable.append({
                "fuente": archivo, "linea": numero,
                "motivo": "sqlmap no pudo determinar la inyección",
            })
            continue

        if texto.startswith("INYECTABLE"):
            m_param = _PARAM_RE.search(texto)
            param = m_param.group(1).strip() if m_param else ""
            tecnica = texto.split(":", 1)[-1].strip() if ":" in texto else ""
            clave = f"sqli|{host}|{param}"
            if clave in vistos:
                continue
            vistos.add(clave)

            findings.append(build(
                "sqlmap.sqli",
                key=clave,
                activo=host,
                evidencia=[Evidence(archivo=archivo, linea=numero, extracto=linea[:120])],
                variables={"parametro": param, "tecnica_sqlmap": tecnica or "la técnica que identificó la herramienta"},
            ))
            continue

    return ParseResult(findings=findings, no_evaluable=no_evaluable)


register("sqlmap", parse)
