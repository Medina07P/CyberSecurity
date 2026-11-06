"""Parser de los veredictos de http_inject.sh.

http_inject prueba inyección en los parámetros de una petición capturada y
clasifica cada resultado como CONFIRMADO, FUERTE o DEBIL. Aquí solo se
traduce ese veredicto: CONFIRMADO es confirmado, FUERTE es candidato y
DEBIL se descarta. La severidad viene de la clase de inyección (cmd, sqli,
ssti → critica; xss → alta; redirect → media), no se reinterpreta.

El host sale del `contexto.txt` hermano cuando existe; si no, se intenta
adivinar del nombre del fichero con ``guess_host``.

Solo biblioteca estándar.
"""

import csv
from pathlib import Path

from lib.attribution import guess_host, normalize_host
from lib.catalog import build
from lib.model import Evidence, ParseResult, relpath
from lib.sources import register

__all__ = ["parse"]

_NIVEL = {
    "CONFIRMADO": "confirmado",
    "FUERTE": "candidato",
    "DEBIL": "descartado",
}

_CLASE_RULE = {
    "cmd": "http_inject.cmd",
    "sqli": "http_inject.sqli",
    "ssti": "http_inject.ssti",
    "xss": "http_inject.xss",
    "redirect": "http_inject.redirect",
}


def _vacio(archivo: str) -> ParseResult:
    """Un fichero sin contenido no se evalúa: no hay nada que leer."""
    return ParseResult(
        evaluado=False,
        no_evaluable=[{"fuente": archivo, "motivo": "archivo vacío"}],
    )


def _leer_contexto(path: Path) -> str | None:
    """Host del ``contexto.txt`` hermano, o ``None`` si no existe."""
    contexto = path.parent / path.stem / "contexto.txt"
    if not contexto.is_file():
        return None
    with open(contexto, encoding="utf-8", errors="replace") as fh:
        for linea in fh:
            linea = linea.strip()
            if linea.startswith("host="):
                valor = linea[5:].strip()
                return valor if valor else None
    return None


def _host(path: Path) -> str:
    """Host normalizado del contexto.txt o del nombre del fichero."""
    contexto = _leer_contexto(path)
    if contexto:
        return normalize_host(contexto)
    return normalize_host(guess_host(path.name) or "")


def parse(path: Path, repo_root: Path) -> ParseResult:
    """Traduce un TSV de http_inject a hallazgos del informe.

    Cada fila con ``nivel`` válido produce un hallazgo (confirmado o
    candidato) o un descarte (débil). La severidad la fija la clase; la
    confianza la fija el nivel. Claves de deduplicación por clase y
    parámetro.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)

    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        crudo = fh.read()
    if not crudo.strip():
        return _vacio(archivo)

    host = _host(path)
    findings: list = []
    descartados: list[dict] = []
    no_evaluable: list[dict] = []
    vistos: set[str] = set()

    lector = csv.DictReader(crudo.splitlines(), delimiter="\t")
    for idx, fila in enumerate(lector):
        nivel = (fila.get("nivel") or "").strip()
        param = (fila.get("param") or "").strip()
        clase = (fila.get("clase") or "").strip()
        confianza = _NIVEL.get(nivel)
        if confianza is None:
            no_evaluable.append({
                "fuente": archivo, "linea": idx + 2,
                "motivo": f"nivel desconocido: {nivel!r}",
            })
            continue

        if confianza == "descartado":
            descartados.append({
                "fuente": archivo, "linea": idx + 2,
                "param": param, "clase": clase,
                "motivo": "veredicto débil",
            })
            continue

        rule = _CLASE_RULE.get(clase)
        if rule is None:
            no_evaluable.append({
                "fuente": archivo, "linea": idx + 2,
                "motivo": f"clase desconocida: {clase!r}",
            })
            continue

        clave = f"{clase}|{host}|{param}"
        if clave in vistos:
            continue
        vistos.add(clave)

        payload = (fila.get("payload") or "").strip()
        codigo = (fila.get("codigo") or "").strip()
        tamano = (fila.get("tamano") or "").strip()
        extracto = f"{param}={payload} → {codigo} ({tamano}b)"

        findings.append(build(
            rule,
            key=clave,
            activo=host,
            evidencia=[Evidence(archivo=archivo, linea=idx + 2, extracto=extracto)],
            variables={"parametro": param},
            confianza=confianza,
        ))

    return ParseResult(findings=findings, descartados=descartados, no_evaluable=no_evaluable)


register("http_inject", parse)
