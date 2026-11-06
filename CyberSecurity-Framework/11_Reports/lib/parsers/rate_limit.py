"""Parser de los veredictos de rate_limit_probe.sh.

rate_limit_probe.sh repite N veces la petición de login variando solo la
contraseña y clasifica el resultado:

- ``SIN FRENO`` → no se observó limitación: confirmado, severidad alta.
- ``FRENADO`` (con o sin motivo) → el servidor frenó: sin hallazgo.
- Cualquier otro veredicto (incluido ``NO DETERMINADO``) → no evaluable.

El host sale de ``- Objetivo: host:port (scheme)``; el endpoint de
``- Petición: METODO /ruta``. Clave de deduplicación:
``rate_limit|host|endpoint``.

Cuando existe un ``.tsv`` hermano con los datos brutos, la primera fila
de datos se añade como segunda evidencia para dar trazabilidad.

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
_PETICION_RE = re.compile(r"^- Petición:\s+(.+)$")
_VEREDICTO_RE = re.compile(r"^- Veredicto:\s+(.+)$")


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


def _primera_fila_tsv(path_tsv: Path) -> str | None:
    """Primera fila de datos del TSV hermano, o ``None`` si no existe."""
    if not path_tsv.is_file():
        return None
    with open(path_tsv, encoding="utf-8", errors="replace", newline="") as fh:
        for numero, linea in enumerate(fh):
            linea = linea.rstrip("\r\n")
            if numero == 0:
                continue  # cabecera
            if linea.strip():
                return linea.strip()
    return None


def _endpoint(peticion: str) -> str:
    """Ruta del endpoint a partir de ``METODO /ruta``."""
    partes = peticion.strip().split(None, 1)
    if len(partes) >= 2:
        return partes[1].strip()
    return peticion.strip()


def parse(path: Path, repo_root: Path) -> ParseResult:
    """Traduce un veredicto de rate_limit a un hallazgo del informe.

    Solo ``SIN FRENO`` produce hallazgo confirmado; ``FRENADO`` no produce
    nada; cualquier otro veredicto es ``no_evaluable``.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)
    lineas = _lineas(path)
    if not any(linea.strip() for linea in lineas):
        return _vacio(archivo)

    host = ""
    peticion = ""
    veredicto_texto = ""
    veredicto_linea = 0

    for numero, linea in enumerate(lineas, 1):
        linea = linea.strip()
        if not linea:
            continue

        m_obj = _OBJETIVO_RE.match(linea)
        if m_obj:
            host = normalize_host(m_obj.group(1))
            continue

        m_pet = _PETICION_RE.match(linea)
        if m_pet:
            peticion = m_pet.group(1).strip()
            continue

        m_ver = _VEREDICTO_RE.match(linea)
        if m_ver:
            veredicto_texto = m_ver.group(1).strip()
            veredicto_linea = numero
            continue

    if not veredicto_texto:
        return ParseResult(
            evaluado=False,
            no_evaluable=[{"fuente": archivo, "motivo": "sin línea de veredicto"}],
        )

    endpoint = _endpoint(peticion) if peticion else "/"
    clave = f"rate_limit|{host}|{endpoint}"

    if veredicto_texto.startswith("FRENADO"):
        return ParseResult()

    if veredicto_texto.startswith("SIN FRENO"):
        evidencia: list[Evidence] = [
            Evidence(archivo=archivo, linea=veredicto_linea, extracto=f"- Veredicto: {veredicto_texto}")
        ]
        tsv_path = path.with_suffix(".tsv")
        fila_tsv = _primera_fila_tsv(tsv_path)
        if fila_tsv:
            evidencia.append(Evidence(
                archivo=relpath(tsv_path, repo_root),
                linea=2,
                extracto=fila_tsv[:120],
            ))
        finding = build(
            "rate_limit.no_throttle",
            key=clave,
            activo=host,
            evidencia=evidencia,
            variables={"endpoint": endpoint},
        )
        return ParseResult(findings=[finding])

    # Cualquier otro veredicto (NO DETERMINADO, etc.) → no evaluable.
    return ParseResult(
        evaluado=False,
        no_evaluable=[{
            "fuente": archivo, "linea": veredicto_linea,
            "motivo": f"veredicto no concluyente: {veredicto_texto}",
        }],
    )


register("rate_limit", parse)
