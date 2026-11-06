"""Parser de los diferenciales de sql_injection.sh.

sql_injection.sh compara la firma de cada respuesta con la línea base y
solo escribe los diferenciales: líneas ``URL|sig|base:SIG`` donde ``sig``
y ``base:SIG`` difieren. Por eso toda línea con diferencia es candidata:
la herramienta ya filtró los ecos del servidor.

La URL da el host y el parámetro (de la query). La clave de
deduplicación es ``sqli|host|param``, igual que sqlmap, para que el motor
los fusione cuando ambos confirman el mismo parámetro.

Solo biblioteca estándar.
"""

from pathlib import Path
from urllib.parse import urlparse, parse_qs

from lib.attribution import normalize_host
from lib.catalog import build
from lib.model import Evidence, ParseResult, relpath
from lib.sources import register

__all__ = ["parse"]


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


def _host_y_param(url: str) -> tuple[str, str]:
    """Host normalizado y primer parámetro de la query."""
    try:
        partes = urlparse(url)
    except ValueError:
        return "", ""
    host = normalize_host(partes.netloc or url)
    try:
        qs = parse_qs(partes.query)
    except Exception:
        qs = {}
    param = next(iter(qs), "")
    return host, param


def parse(path: Path, repo_root: Path) -> ParseResult:
    """Traduce los diferenciales de sql_injection.sh a hallazgos candidatos.

    Cada línea con diferencia entre firma y base es un ``candidato`` de
    severidad ``media``: el diferencial no prueba la inyección, solo
    señala un parámetro que reacciona de forma distinta a la base.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)
    lineas = _lineas(path)
    if not any(linea.strip() for linea in lineas):
        return _vacio(archivo)

    findings: list = []
    descartados: list[dict] = []
    no_evaluable: list[dict] = []
    vistos: set[str] = set()

    for numero, linea in enumerate(lineas, 1):
        linea = linea.strip()
        if not linea:
            continue

        partes = linea.split("|")
        if len(partes) < 3:
            no_evaluable.append({
                "fuente": archivo, "linea": numero,
                "motivo": "formato inesperado (faltan campos)",
            })
            continue

        url = partes[0].strip()
        sig = partes[1].strip()
        base_raw = partes[2].strip()
        base_sig = base_raw[5:].strip() if base_raw.startswith("base:") else base_raw.strip()

        host, param = _host_y_param(url)

        if sig == base_sig:
            descartados.append({
                "fuente": archivo, "linea": numero,
                "url": url, "motivo": "firma igual a la base",
            })
            continue

        clave = f"sqli|{host}|{param}"
        if clave in vistos:
            continue
        vistos.add(clave)

        findings.append(build(
            "sqli_findings.differential",
            key=clave,
            activo=host,
            evidencia=[Evidence(archivo=archivo, linea=numero, extracto=linea[:120])],
            variables={"parametro": param},
        ))

    return ParseResult(findings=findings, descartados=descartados, no_evaluable=no_evaluable)


register("sqli_findings", parse)
