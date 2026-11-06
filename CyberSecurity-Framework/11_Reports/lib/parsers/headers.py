"""Parser de cabeceras de seguridad con guarda de respuesta.

El motor recibe dos ficheros por activo, con el mismo sufijo:

- ``security_headers_<sufijo>.txt``: solo las cabeceras de seguridad que
  encontró la enumeración web.
- ``headers_<sufijo>.txt``: la respuesta HTTP completa, con su línea de
  estado.

Un ``security_headers`` vacío no prueba que falten cabeceras: curl pudo
fallar. La guarda es la primera línea del fichero pareado y tiene que ser una
respuesta 2xx o 3xx. Sin pareja o sin respuesta exitosa no se afirma ninguna
ausencia: se declara ``no_evaluable``.

Strict-Transport-Security solo se evalúa sobre HTTPS, porque en HTTP no
tendría sentido pedirla.

Solo biblioteca estándar.
"""

import re
from pathlib import Path

from lib.attribution import guess_host
from lib.catalog import build
from lib.model import Evidence, ParseResult, relpath
from lib.sources import register

__all__ = ["REQUIRED", "parse_security", "parse_context"]

# (cabecera requerida, regla del catálogo) en el orden en que se informa.
REQUIRED: tuple[tuple[str, str], ...] = (
    ("content-security-policy", "headers.missing.csp"),
    ("x-frame-options", "headers.missing.xfo"),
    ("strict-transport-security", "headers.missing.hsts"),
    ("x-content-type-options", "headers.missing.xcto"),
)

_PREFIJO = "security_headers_"
_GUARD_RE = re.compile(r"^HTTP/\S+\s+[23]\d\d")
_PISTAS_HTTPS = ("https", "443", "8443")


def _lineas(path: Path) -> list[str]:
    """Líneas del fichero sin el salto y con los bytes rotos reemplazados."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return [linea.rstrip("\r\n") for linea in fh]


def _pareado(path: Path) -> Path:
    """Fichero de respuesta HTTP pareado: mismo sufijo, prefijo ``headers_``."""
    nombre = path.name
    if nombre.startswith(_PREFIJO):
        return path.with_name("headers_" + nombre[len(_PREFIJO):])
    return path.with_name("headers_" + nombre)


def _es_https(path: Path) -> bool:
    """¿El activo se sirve por HTTPS? Se deduce del nombre y del sufijo.
    
    Usa tokens exactos para evitar falsos positivos: `4430` no es https.
    """
    import re as _re
    nombre = path.name.lower()
    # Token exacto: "https" como palabra completa o sufijo
    if "https" in nombre:
        # Verificar que es un token completo, no parte de otro
        if _re.search(r'\bhttps\b', nombre):
            return True
    # Tokens de puerto exactos: _443, _8443, o fin de sufijo
    # Buscar patrones como _443, _8443, o que termine en 443 o 8443
    if _re.search(r'[_\-]443(?:\D|$)', nombre) or _re.search(r'[_\-]8443(?:\D|$)', nombre):
        return True
    # Si termina en 443 o 8443 (sin más dígitos después)
    if _re.search(r'(?:^|[_\-])443$', nombre) or _re.search(r'(?:^|[_\-])8443$', nombre):
        return True
    return False


def _guarda(pareado: Path, repo_root: Path) -> tuple[int, str, str] | None:
    """Línea de estado del fichero pareado si es una respuesta 2xx o 3xx.

    Devuelve ``(línea, extracto, archivo_relativo)`` o ``None`` cuando no hay
    pareja o la primera línea no es una respuesta exitosa.
    """
    if not pareado.is_file():
        return None
    try:
        lineas = _lineas(pareado)
    except OSError:
        return None
    if not lineas:
        return None
    if not _GUARD_RE.match(lineas[0]):
        return None
    return 1, lineas[0].strip(), relpath(pareado, repo_root)


def _presente(nombre: str, lineas: list[str]) -> bool:
    """¿El fichero de cabeceras trae ya esa cabecera?"""
    buscado = nombre + ":"
    return any(linea.strip().lower().startswith(buscado) for linea in lineas)


def _csp_tiene_frame_ancestors(lineas: list[str]) -> bool:
    """¿La CSP contiene la directiva frame-ancestors?"""
    for linea in lineas:
        stripped = linea.strip().lower()
        if stripped.startswith("content-security-policy:"):
            # Extraer el valor de CSP
            valor = stripped[len("content-security-policy:"):].strip()
            if "frame-ancestors" in valor:
                return True
    return False


def _primera_cabecera(lineas: list[str]) -> tuple[int, str] | None:
    """Primera cabecera no vacía del fichero de seguridad y su número de línea."""
    for numero, linea in enumerate(lineas, 1):
        if linea.strip():
            return numero, linea.strip()
    return None


def parse_security(path: Path, repo_root: Path) -> ParseResult:
    """Traduce las cabeceras de seguridad ausentes a hallazgos del informe.

    Sin respuesta pareada 2xx/3xx no se reclama nada: se devuelve un único
    ``no_evaluable``. Con guarda, cada cabecera requerida que no aparezca en
    el fichero de seguridad es un hallazgo; las presentes no se informan.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)
    guarda = _guarda(_pareado(path), repo_root)
    if guarda is None:
        return ParseResult(
            evaluado=False,
            no_evaluable=[{"fuente": archivo, "motivo": "sin respuesta verificable"}],
        )

    lineas = _lineas(path)
    cabecera = _primera_cabecera(lineas)
    if cabecera is not None:
        numero, extracto = cabecera
        evidencia = [Evidence(archivo=archivo, linea=numero, extracto=extracto)]
    else:
        numero, extracto, archivo_pareado = guarda
        evidencia = [Evidence(archivo=archivo_pareado, linea=numero, extracto=extracto)]

    activo = guess_host(path.name) or ""
    https = _es_https(path)
    csp_tiene_frame_ancestors = _csp_tiene_frame_ancestors(lineas)
    findings = []
    for nombre, regla in REQUIRED:
        if nombre == "strict-transport-security" and not https:
            continue
        # Si CSP tiene frame-ancestors, no reportar XFO ausente
        if nombre == "x-frame-options" and csp_tiene_frame_ancestors:
            continue
        if _presente(nombre, lineas):
            continue
        findings.append(build(
            regla,
            key=f"{regla}|{activo}",
            activo=activo,
            evidencia=evidencia,
        ))

    return ParseResult(findings=findings)


def parse_context(path: Path, repo_root: Path) -> ParseResult:
    """Anota la respuesta HTTP pareada como contexto del activo.

    No produce hallazgos: quien los emite es ``security_headers_*.txt`` y no
    puede hacerlo sin esta respuesta. Aquí solo queda constancia del activo,
    de su línea de estado y del fichero que la contiene.
    """
    path = Path(path)
    lineas = _lineas(path)
    if not lineas or not lineas[0].strip():
        return ParseResult()
    return ParseResult(activos=[{
        "host": guess_host(path.name) or "",
        "fuente": relpath(path, repo_root),
        "estado": lineas[0].strip(),
    }])


register("security_headers", parse_security)
register("headers", parse_context)
