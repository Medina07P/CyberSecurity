"""Parser de los resultados de nuclei: JSONL preferente y texto estándar.

nuclei escribe dos formatos y aquí cada uno tiene su función. `parse_jsonl`
lee una salida `-jsonl`, donde cada línea es un objeto con `template-id`,
`info` y `matched-at`; `parse_txt` lee la salida de consola, donde cada línea
tiene la forma `[plantilla] [protocolo] [severidad] url`. En el texto no se
adivina: una línea que no tenga esa forma es `no_evaluable` con su número de
línea, porque un `.txt` con la palabra «CVE» en prosa no es un hallazgo.

La severidad de nuclei (`critical|high|medium|low|info|unknown`) se traduce al
vocabulario del informe (`critica|alta|media|baja|info`). Un valor ausente o no
reconocido se queda en `info`, salvo que la línea traiga un CVE: entonces es
`media`, porque una referencia a una vulnerabilidad conocida no puede
degradarse a observación.

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

__all__ = ["severity", "parse_jsonl", "parse_txt"]

# Severidad de nuclei -> severidad del informe. `unknown` cae en `info`; si la
# línea trae un CVE, `_severidad` la sube a `media`.
_SEVERIDAD: dict[str, str] = {
    "critical": "critica",
    "high": "alta",
    "medium": "media",
    "low": "baja",
    "info": "info",
    "unknown": "info",
}

# Severidades que no se degradan aunque haya CVE: la herramienta ya las fijó.
_CONOCIDAS = frozenset({"critical", "high", "medium", "low", "info"})

# Línea estándar de la salida de texto: `[plantilla] [protocolo] [severidad] url`.
_LINEA_TXT = re.compile(r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)")

# `CVE-2021-44228`: la plantilla que lleva ese nombre cita el CVE.
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")

# Longitud máxima del extracto literal de la evidencia, como en nmap: una
# línea JSONL puede arrastrar la petición y la respuesta completas.
_EXTRACTO_MAX = 120


def severity(raw: str) -> str:
    """Traduce la severidad de nuclei al vocabulario del informe.

    Un valor ausente o no reconocido es `info`: no se afirma más de lo que
    publicó la herramienta.
    """
    return _SEVERIDAD.get(str(raw or "").strip().lower(), "info")


def _severidad(raw: str, cve: str | None) -> str:
    """Severidad del hallazgo; una desconocida con CVE se queda en `media`."""
    if cve and str(raw or "").strip().lower() not in _CONOCIDAS:
        return "media"
    return severity(raw)


def _lineas(path: Path) -> list[str]:
    """Líneas del fichero sin el salto y con los bytes rotos reemplazados."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return [linea.rstrip("\r\n") for linea in fh]


def _utiles(lineas: list[str]) -> list[tuple[int, str]]:
    """Líneas no vacías con su número; las líneas en blanco se saltan."""
    return [(numero, linea) for numero, linea in enumerate(lineas, 1) if linea.strip()]


def _vacio(archivo: str) -> ParseResult:
    """Un fichero sin contenido no se evalúa: no hay nada que leer."""
    return ParseResult(
        evaluado=False,
        no_evaluable=[{"fuente": archivo, "motivo": "archivo vacío"}],
    )


def _host_y_ruta(activo: str) -> tuple[str, str]:
    """Host normalizado y ruta del activo, para la clave de deduplicación."""
    activo = (activo or "").strip()
    try:
        partes = urlsplit(activo)
    except ValueError:
        return normalize_host(activo), "/"
    ruta = partes.path if (partes.scheme or partes.netloc) else ""
    return normalize_host(activo), ruta or "/"


def _texto(valor) -> str:
    """Texto recortado de un campo del JSON; cualquier otra cosa es vacío."""
    return valor.strip() if isinstance(valor, str) else ""


def _cve(info: dict) -> str | None:
    """Primera referencia de `info.classification.cve-id` (texto o lista)."""
    clasificacion = info.get("classification")
    if not isinstance(clasificacion, dict):
        return None
    crudo = clasificacion.get("cve-id")
    if isinstance(crudo, str):
        return crudo.strip() or None
    if isinstance(crudo, list):
        for elemento in crudo:
            if isinstance(elemento, str) and elemento.strip():
                return elemento.strip()
    return None


def _cve_de_plantilla(plantilla: str) -> str | None:
    """CVE que da nombre a la plantilla de texto, si lo lleva."""
    coincidencia = _CVE_RE.search(plantilla)
    return coincidencia.group(0) if coincidencia else None


def _hallazgo(
    plantilla: str,
    nombre: str,
    cve: str | None,
    severidad: str,
    activo: str,
    evidencia: Evidence,
    vistos: set[str],
) -> Finding | None:
    """Un hallazgo `nuclei.template`, o `None` si la clave ya estaba vista."""
    host, ruta = _host_y_ruta(activo)
    clave = f"nuclei|{plantilla}|{host}|{ruta}"
    if clave in vistos:
        return None
    vistos.add(clave)

    return build(
        "nuclei.template",
        key=clave,
        activo=activo,
        evidencia=[evidencia],
        variables={"plantilla": plantilla, "nombre": nombre},
        severidad=severidad,
        cve=cve,
    )


def parse_jsonl(path: Path, repo_root: Path) -> ParseResult:
    """Traduce una salida `-jsonl` de nuclei a hallazgos del informe."""
    path = Path(path)
    archivo = relpath(path, repo_root)
    utiles = _utiles(_lineas(path))
    if not utiles:
        return _vacio(archivo)

    findings: list[Finding] = []
    no_evaluable: list[dict] = []
    vistos: set[str] = set()

    for numero, linea in utiles:
        try:
            registro = json.loads(linea)
        except ValueError:
            no_evaluable.append({
                "fuente": archivo, "linea": numero, "motivo": "JSON inválido",
            })
            continue
        if not isinstance(registro, dict):
            no_evaluable.append({
                "fuente": archivo, "linea": numero, "motivo": "JSON sin objeto",
            })
            continue

        plantilla = _texto(registro.get("template-id"))
        if not plantilla:
            no_evaluable.append({
                "fuente": archivo, "linea": numero, "motivo": "sin template-id",
            })
            continue

        info = registro.get("info")
        info = info if isinstance(info, dict) else {}
        cve = _cve(info)
        finding = _hallazgo(
            plantilla,
            _texto(info.get("name")),
            cve,
            _severidad(_texto(info.get("severity")), cve),
            _texto(registro.get("matched-at")),
            Evidence(
                archivo=archivo,
                linea=numero,
                extracto=linea[:_EXTRACTO_MAX],
            ),
            vistos,
        )
        if finding is not None:
            findings.append(finding)

    return ParseResult(findings=findings, no_evaluable=no_evaluable)


def parse_txt(path: Path, repo_root: Path) -> ParseResult:
    """Traduce una salida de texto de nuclei a hallazgos del informe.

    Solo la línea estándar `[plantilla] [protocolo] [severidad] url` produce
    hallazgo; cualquier otra línea no vacía queda como `no_evaluable` con su
    número, sin intentar leer un CVE ni una URL de la prosa.
    """
    path = Path(path)
    archivo = relpath(path, repo_root)
    utiles = _utiles(_lineas(path))
    if not utiles:
        return _vacio(archivo)

    findings: list[Finding] = []
    no_evaluable: list[dict] = []
    vistos: set[str] = set()

    for numero, linea in utiles:
        coincidencia = _LINEA_TXT.match(linea)
        if coincidencia is None:
            no_evaluable.append({
                "fuente": archivo,
                "linea": numero,
                "motivo": "no es una línea estándar de nuclei",
            })
            continue

        plantilla, _protocolo, severidad_cruda, url = coincidencia.groups()
        plantilla = plantilla.strip()
        cve = _cve_de_plantilla(plantilla)
        finding = _hallazgo(
            plantilla,
            "",
            cve,
            _severidad(severidad_cruda, cve),
            url,
            Evidence(
                archivo=archivo,
                linea=numero,
                extracto=linea[:_EXTRACTO_MAX],
            ),
            vistos,
        )
        if finding is not None:
            findings.append(finding)

    return ParseResult(findings=findings, no_evaluable=no_evaluable)


register("nuclei_jsonl", parse_jsonl)
register("nuclei_txt", parse_txt)
