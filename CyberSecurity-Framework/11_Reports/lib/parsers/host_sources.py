"""Parser de las fuentes que no identifican el objetivo por sí mismas.

Son las fuentes peor atribuidas del framework y cada una se resuelve a su
manera:

- ``api/methods.txt``: no lleva ni el host ni el endpoint, solo el método y el
  código que devolvió la enumeración. Un método con efecto de escritura que
  responde 2xx queda como observación baja con el activo vacío, de modo que
  solo aparece con ``--incluir-sin-objetivo`` o ``--todos`` y nunca se
  atribuye a un host que no lo produjo.
- ``ssh/auth_methods.txt``: la salida de nmap trae el host en la línea
  ``Nmap scan report for … (addr)``; si no aparece, se adivina del nombre del
  fichero. ``password`` dentro del bloque de métodos es una observación de
  configuración: no se prueba ninguna credencial.
- ``database/anon.txt``: contiene solo la salida de la consulta anónima. Si
  hay contenido, el acceso anónimo está confirmado; si está vacío, no se
  evalúa, porque un fichero vacío no demuestra que la conexión se intentara.
- ``web/technologies_*.txt``: whatweb solo enriquece el activo con sus
  tecnologías; nunca produce hallazgos.

Solo biblioteca estándar.
"""

import re
from pathlib import Path

from lib.attribution import guess_host, normalize_host
from lib.catalog import build
from lib.model import Evidence, ParseResult, relpath
from lib.sources import register

__all__ = ["parse_api", "parse_ssh", "parse_db", "parse_technologies"]

_METODO_RE = re.compile(r"([A-Z]+)\s+\((\d{3})\)")
_METODOS_ESCRITURA = frozenset({"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"})

_HOST_NMAP_RE = re.compile(r"Nmap scan report for .*\(([0-9.]+)\)")
_BLOQUE_SSH_RE = re.compile(r"ssh-auth-methods", re.IGNORECASE)
_PASSWORD_RE = re.compile(r"\bpassword\b", re.IGNORECASE)

# Pares ``Nombre[valor]`` de whatweb. El valor puede traer espacios, comas y
# puntos; los corchetes adicionales (``Country[RESERVED][ZZ]``) no son pares.
_TECNOLOGIA_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*)\[([^\]]*)\]")
_TECNOLOGIAS_IGNORADAS = frozenset({"country", "ip", "title"})


def _lineas(path: Path) -> list[str]:
    """Líneas del fichero sin el salto y con los bytes rotos reemplazados."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return [linea.rstrip("\r\n") for linea in fh]


def parse_api(path: Path, repo_root: Path) -> ParseResult:
    """Traduce los métodos con efecto de escritura de ``methods.txt``.

    Solo los métodos que modifican estado y respondieron 2xx producen
    hallazgo; GET, HEAD, POST, OPTIONS y los 4xx/5xx no se informan. El
    activo queda vacío a propósito: el fichero no dice de qué host salió.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)
    findings = []
    vistos: set[str] = set()

    for numero, linea in enumerate(_lineas(path), 1):
        match = _METODO_RE.search(linea)
        if not match:
            continue
        metodo = match.group(1)
        codigo = int(match.group(2))
        if metodo not in _METODOS_ESCRITURA or not 200 <= codigo < 300:
            continue
        if metodo in vistos:
            continue
        vistos.add(metodo)
        findings.append(build(
            "api.method",
            key=f"api.method|{metodo}",
            activo="",
            evidencia=[Evidence(
                archivo=archivo,
                linea=numero,
                extracto=linea.strip()[:120],
            )],
            variables={"metodo": metodo, "codigo": str(codigo)},
        ))

    return ParseResult(findings=findings)


def parse_ssh(path: Path, repo_root: Path) -> ParseResult:
    """Informa la autenticación SSH por contraseña si el bloque la anuncia.

    El bloque empieza en la línea del script ``ssh-auth-methods`` y sigue
    mientras las líneas vengan prefijadas por ``|``, que es como nmap marca
    la salida de un script. Una palabra ``password`` fuera del bloque no
    cuenta.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)
    host = guess_host(path.name) or ""
    findings = []
    vistos: set[str] = set()
    en_bloque = False

    for numero, linea in enumerate(_lineas(path), 1):
        match_host = _HOST_NMAP_RE.search(linea)
        if match_host:
            host = match_host.group(1)
            en_bloque = False
            continue
        if _BLOQUE_SSH_RE.search(linea):
            en_bloque = True
            continue
        if not en_bloque:
            continue
        if not linea.lstrip().startswith("|"):
            en_bloque = False
            continue
        if not _PASSWORD_RE.search(linea) or host in vistos:
            continue
        vistos.add(host)
        findings.append(build(
            "ssh.password_auth",
            key=f"ssh.password_auth|{host}",
            activo=host,
            evidencia=[Evidence(
                archivo=archivo,
                linea=numero,
                extracto=linea.strip()[:120],
            )],
        ))

    return ParseResult(findings=findings)


def parse_db(path: Path, repo_root: Path) -> ParseResult:
    """Confirma el acceso anónimo a la base de datos solo con contenido.

    La evidencia es la primera línea no vacía de la respuesta. Un fichero
    vacío es ``no_evaluable``: pudo ser una conexión fallida sin mensaje, así
    que no se afirma nada.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)

    for numero, linea in enumerate(_lineas(path), 1):
        if not linea.strip():
            continue
        return ParseResult(findings=[build(
            "db.anonymous",
            key="db.anonymous",
            activo="",
            evidencia=[Evidence(
                archivo=archivo,
                linea=numero,
                extracto=linea.strip()[:120],
            )],
        )])

    return ParseResult(
        evaluado=False,
        no_evaluable=[{
            "fuente": archivo,
            "motivo": "archivo vacío: no consta que la conexión se intentara",
        }],
    )


def _tecnologias(linea: str) -> list[str]:
    """Pares ``Nombre[valor]`` útiles de una línea de whatweb.

    Se descartan ``Country``, ``IP`` y ``Title``: no describen la tecnología
    del servicio. Los valores vacíos tampoco se anotan.
    """
    resultado: list[str] = []
    for match in _TECNOLOGIA_RE.finditer(linea):
        nombre, valor = match.group(1), match.group(2).strip()
        if nombre.lower() in _TECNOLOGIAS_IGNORADAS or not valor:
            continue
        resultado.append(f"{nombre}: {valor}")
    return resultado


def _host_de_linea(linea: str) -> str:
    """Host de la URL con la que whatweb encabeza cada resultado, o ``""``."""
    partes = linea.strip().split(None, 1)
    if not partes or "://" not in partes[0]:
        return ""
    return normalize_host(partes[0])


def parse_technologies(path: Path, repo_root: Path) -> ParseResult:
    """Enriquece los activos con las tecnologías que detectó whatweb.

    No produce hallazgos. El host sale de la URL de la línea y, si la línea
    no la trae, del nombre del fichero. Un activo sin host reconocible no se
    anota: el motor lo descartaría de todas formas.
    """
    path = Path(path)
    activos: dict[str, list[str]] = {}

    for linea in _lineas(path):
        tecnologias = _tecnologias(linea)
        if not tecnologias:
            continue
        host = _host_de_linea(linea) or guess_host(path.name) or ""
        if not host:
            continue
        destino = activos.setdefault(host, [])
        for tecnologia in tecnologias:
            if tecnologia not in destino:
                destino.append(tecnologia)

    return ParseResult(activos=[
        {"host": host, "tecnologias": tecnologias}
        for host, tecnologias in activos.items()
    ])


register("api", parse_api)
register("ssh", parse_ssh)
register("db", parse_db)
register("technologies", parse_technologies)
