"""Parser de la salida JSON de ffuf con línea base obligatoria.

Uso: `parse(path, repo_root) -> ParseResult`.

ffuf responde `200` a cualquier ruta contra una aplicación que devuelve una
página por defecto (un SPA, por ejemplo), así que sin línea base cada
resultado parece un hallazgo. El JSON de ffuf guarda la orden completa en
`commandline`; cuando la tanda se lanzó con `-fs N` ese `N` es el tamaño del
eco del servidor y `baseline_from_commandline` lo recupera.

La regla es dura a propósito: sin `-fs` no se evalúa nada (ni un hallazgo ni
un descarte) porque no hay forma de distinguir el eco del servidor. Un
resultado del tamaño de la línea base es catch-all y va a `descartados`. Solo
un `2xx` o `3xx` con un tamaño distinto es una observación de inventario
(`ffuf.resource`): un recurso accesible no es una vulnerabilidad.

Solo biblioteca estándar, como el resto del motor.
"""

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from lib.attribution import normalize_host
from lib.catalog import build
from lib.model import Evidence, Finding, ParseResult, relpath
from lib.sources import register

__all__ = ["baseline_from_commandline", "parse"]

# `-fs 96` en la orden de ffuf. Acepta el valor entrecomillado (`-fs "96"`),
# que es lo que deja la shell cuando el operador copia la orden.
_BASELINE_RE = re.compile(r'(?:^|\s)-fs\s+"?(\d+)"?')

# `-u URL` en la orden de ffuf: de ahí sale el activo si un resultado no trae
# su propia `url`.
_URL_RE = re.compile(r'(?:^|\s)-u\s+"?([^\s"]+)"?')

# Estados HTTP que pueden ser inventario; el resto se descarta con su código.
_HALLAZGO_MIN = 200
_HALLAZGO_MAX = 399


def baseline_from_commandline(cmd: str) -> int | None:
    """Tamaño del catch-all declarado con `-fs N`, o `None` si no consta.

    Nunca se adivina: una orden sin `-fs` devuelve `None` y el parser deja el
    fichero como no evaluable.
    """
    if not isinstance(cmd, str):
        return None
    coincidencia = _BASELINE_RE.search(cmd)
    return int(coincidencia.group(1)) if coincidencia else None


def _url_de_la_orden(cmd: str) -> str:
    """URL de `-u` en la orden de ffuf, o cadena vacía si no consta."""
    if not isinstance(cmd, str):
        return ""
    coincidencia = _URL_RE.search(cmd)
    return coincidencia.group(1) if coincidencia else ""


def _numero(valor) -> int | None:
    """Entero de un campo del JSON; `None` si no es un número válido."""
    if isinstance(valor, bool):
        return None
    if isinstance(valor, int):
        return valor
    if isinstance(valor, str) and valor.strip().isdigit():
        return int(valor.strip())
    return None


def _texto(valor) -> str:
    """Texto recortado de un campo del JSON; cualquier otra cosa es vacío."""
    return valor.strip() if isinstance(valor, str) else ""


def _vacio(archivo: str) -> ParseResult:
    """Un fichero sin contenido no se evalúa: no hay nada que leer."""
    return ParseResult(
        evaluado=False,
        no_evaluable=[{"fuente": archivo, "motivo": "archivo vacío"}],
    )


def _sin_baseline(archivo: str, resultados: list) -> ParseResult:
    """Sin `-fs` no se puede separar el eco del servidor: no se evalúa.

    Se deja un `no_evaluable` por resultado (o uno para el fichero si la
    tanda no encontró nada), nunca un hallazgo.
    """
    motivo = "sin línea base (-fs): no se puede distinguir el eco del servidor"
    if resultados:
        no_evaluable = [{"fuente": archivo, "motivo": motivo} for _ in resultados]
    else:
        no_evaluable = [{"fuente": archivo, "motivo": motivo}]
    return ParseResult(evaluado=False, no_evaluable=no_evaluable)


def _recurso(url: str) -> str:
    """Ruta del recurso para el texto del catálogo; si no hay, la URL."""
    if not url:
        return "/"
    try:
        ruta = urlsplit(url).path
    except ValueError:
        return url
    return ruta or "/"


def _observacion(
    archivo: str,
    url: str,
    host: str,
    status: int,
    length: int,
) -> Finding:
    """Un `ffuf.resource`: inventario de superficie, no una vulnerabilidad."""
    return build(
        "ffuf.resource",
        key=f"ffuf|{host}|{url}",
        activo=host,
        evidencia=[Evidence(
            archivo=archivo,
            linea=None,
            extracto=f"{url} ({status}, {length})",
        )],
        variables={"recurso": _recurso(url)},
        severidad="info",
        confianza="observacion",
    )


def parse(path: Path, repo_root: Path) -> ParseResult:
    """Traduce un JSON de ffuf a hallazgos del informe.

    Sin `-fs` en `commandline` no hay evaluación posible. Con línea base, un
    resultado de ese tamaño es el catch-all y va a `descartados`; un estado
    fuera de `2xx`/`3xx` también; solo el resto es observación de inventario.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)

    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        crudo = fh.read()
    if not crudo.strip():
        return _vacio(archivo)

    try:
        datos = json.loads(crudo)
    except ValueError:
        return ParseResult(
            evaluado=False,
            no_evaluable=[{"fuente": archivo, "motivo": "JSON inválido"}],
        )
    if not isinstance(datos, dict):
        return ParseResult(
            evaluado=False,
            no_evaluable=[{"fuente": archivo, "motivo": "JSON sin objeto"}],
        )

    resultados = datos.get("results")
    if resultados is None:
        resultados = []
    if not isinstance(resultados, list):
        return ParseResult(
            evaluado=False,
            no_evaluable=[{"fuente": archivo, "motivo": "results no es una lista"}],
        )

    baseline = baseline_from_commandline(datos.get("commandline"))
    if baseline is None:
        return _sin_baseline(archivo, resultados)

    if not resultados:
        return ParseResult()

    url_orden = _url_de_la_orden(datos.get("commandline"))
    findings: list[Finding] = []
    descartados: list[dict] = []
    no_evaluable: list[dict] = []
    vistos: set[str] = set()

    for resultado in resultados:
        if not isinstance(resultado, dict):
            no_evaluable.append({
                "fuente": archivo, "motivo": "resultado sin objeto",
            })
            continue

        status = _numero(resultado.get("status"))
        length = _numero(resultado.get("length"))
        url = _texto(resultado.get("url")) or url_orden
        activo = normalize_host(url)

        if status is None or length is None:
            no_evaluable.append({
                "fuente": archivo,
                "url": url,
                "motivo": "resultado sin estado o longitud",
            })
            continue

        if length == baseline:
            descartados.append({
                "fuente": archivo,
                "url": url,
                "status": status,
                "length": length,
                "motivo": "catch-all",
            })
            continue

        if not _HALLAZGO_MIN <= status <= _HALLAZGO_MAX:
            descartados.append({
                "fuente": archivo,
                "url": url,
                "status": status,
                "length": length,
                "motivo": f"status {status}",
            })
            continue

        finding = _observacion(archivo, url, activo, status, length)
        if finding.key in vistos:
            continue
        vistos.add(finding.key)
        findings.append(finding)

    return ParseResult(
        findings=findings,
        descartados=descartados,
        no_evaluable=no_evaluable,
    )


register("ffuf", parse)
