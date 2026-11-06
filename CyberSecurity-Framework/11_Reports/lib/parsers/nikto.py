"""Parser de la salida de texto de nikto.

Uso: `parse(path, repo_root) -> ParseResult`. nikto mezcla en el mismo fichero
hallazgos, avisos de configuración y simple ruido del escaneo, así que aquí se
es conservador a propósito: solo las líneas que citan un CVE producen
`nikto.cve` y solo las que citan un OSVDB producen `nikto.osvdb`. Todo lo demás
se ignora en silencio, no como `no_evaluable`, porque el ruido de nikto no debe
inflar el apéndice del informe.

Las cabeceras de seguridad que nikto comenta (`X-Frame-Options` y compañía)
quedan fuera a propósito: las evalúa el parser de cabeceras sobre la respuesta
real del servidor, y publicarlas dos veces sería un duplicado.

Solo biblioteca estándar, como el resto del motor.
"""

import re
from pathlib import Path

from lib.attribution import guess_host
from lib.catalog import build
from lib.model import Evidence, Finding, ParseResult, relpath
from lib.sources import register

__all__ = ["NOISE", "parse"]

# Ruido conocido de nikto, en minúsculas: la comparación se hace sobre la
# línea bajada a minúsculas. Cubre los avisos del escaneo, la enumeración de
# métodos permitidos y las cabeceras que pertenecen al parser de cabeceras.
NOISE: tuple[str, ...] = (
    "no cgi directories found",
    "server leaks inodes",
    "allowed http methods",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
)

# `CVE-2020-1234`: cuatro dígitos de año y cuatro o más del identificador.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# `OSVDB-3092`: identificador numérico de la base OSVDB.
_OSVDB_RE = re.compile(r"OSVDB-\d+")

# Longitud máxima del extracto literal de la evidencia, como en nmap y nuclei.
_EXTRACTO_MAX = 120


def _lineas(path: Path) -> list[str]:
    """Líneas del fichero sin el salto y con los bytes rotos reemplazados."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return [linea.rstrip("\r\n") for linea in fh]


def _es_ruido(linea: str) -> bool:
    """¿La línea es uno de los avisos que este parser descarta?"""
    minusculas = linea.lower()
    return any(ruido in minusculas for ruido in NOISE)


def _vacio(archivo: str) -> ParseResult:
    """Un fichero sin contenido no se evalúa: no hay nada que leer."""
    return ParseResult(
        evaluado=False,
        no_evaluable=[{"fuente": archivo, "motivo": "archivo vacío"}],
    )


def _evidencia(archivo: str, numero: int, linea: str) -> list[Evidence]:
    """Evidencia de una línea de nikto: fichero, número y extracto literal."""
    return [Evidence(archivo=archivo, linea=numero, extracto=linea[:_EXTRACTO_MAX])]


def _cve(numero: int, linea: str, cve: str, activo: str, archivo: str) -> Finding:
    """Un `nikto.cve` confirmado; nikto no publica CVSS, así que no se inventa."""
    return build(
        "nikto.cve",
        key=f"cve|{cve}|{activo}",
        activo=activo,
        evidencia=_evidencia(archivo, numero, linea),
        severidad="media",
        confianza="confirmado",
        cve=cve,
        cvss=None,
    )


def _osvdb(numero: int, linea: str, osvdb: str, activo: str, archivo: str) -> Finding:
    """Un `nikto.osvdb`: observación de inventario, no una vulnerabilidad."""
    return build(
        "nikto.osvdb",
        key=f"nikto.osvdb:{activo}:{osvdb}",
        activo=activo,
        evidencia=_evidencia(archivo, numero, linea),
        variables={"osvdb": osvdb},
        severidad="baja",
        confianza="observacion",
    )


def parse(path: Path, repo_root: Path) -> ParseResult:
    """Traduce un `.txt` de nikto a hallazgos del informe.

    Solo las líneas que empiezan por `+` se miran, y de ellas solo las que
    citan un CVE (primero) o un OSVDB (después). El resto se descarta sin
    dejar rastro en el apéndice.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)
    lineas = _lineas(path)

    if not any(linea.strip() for linea in lineas):
        return _vacio(archivo)

    # El nombre del fichero identifica el activo; si no lo dice, el hallazgo
    # queda sin atribuir en vez de atribuirlo a un host inventado.
    activo = guess_host(path.name) or ""

    findings: list[Finding] = []
    vistos: set[str] = set()

    for numero, linea in enumerate(lineas, 1):
        if not linea.lstrip().startswith("+"):
            continue
        if _es_ruido(linea):
            continue

        cve = _CVE_RE.search(linea)
        osvdb = _OSVDB_RE.search(linea)
        if cve:
            finding = _cve(numero, linea, cve.group(0), activo, archivo)
        elif osvdb:
            finding = _osvdb(numero, linea, osvdb.group(0), activo, archivo)
        else:
            continue

        if finding.key in vistos:
            continue
        vistos.add(finding.key)
        findings.append(finding)

    return ParseResult(findings=findings)


register("nikto", parse)
