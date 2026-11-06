"""Parser de los resultados de nmap en XML.

Uso: `parse(path, repo_root) -> ParseResult`. Cada host con
`<status state="up"/>` aporta un activo y cada puerto abierto una observación
`nmap.open_port` (nunca una vulnerabilidad). Cada CVE citado en un `<script>`,
esté en el puerto o en el host, aporta un `nmap.cve` confirmado; la severidad
sale de la puntuación que el propio script publica junto al CVE y, si no la
publica, se queda en `media` y el texto lo dice.

Un XML mal formado no se adivina: devuelve `evaluado=False` y el motivo.

Solo biblioteca estándar, como el resto del motor.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from lib.catalog import build
from lib.model import Evidence, Finding, ParseResult, relpath
from lib.sources import register

__all__ = ["parse"]

# `CVE-2021-41773`: cuatro dígitos de año y el identificador.
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")

# Longitud máxima del extracto literal de la evidencia.
_EXTRACTO_MAX = 120


def _severidad(score: float | None) -> str:
    """Severidad a partir de la puntuación; sin puntuación, `media`."""
    if score is None:
        return "media"
    if score >= 9:
        return "critica"
    if score >= 7:
        return "alta"
    if score >= 4:
        return "media"
    return "baja"


def _score(output: str, cve: str) -> float | None:
    """Puntuación que el script publica junto al CVE (`CVE-x: 7.5:`), si consta."""
    match = re.search(
        rf"{re.escape(cve)}[ \t]*:[ \t]*(\d+(?:\.\d+)?)(?![0-9])[ \t]*:",
        output,
    )
    if match is None:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _host(host_el: ET.Element) -> str | None:
    """Dirección IPv4 o IPv6 del host; una dirección MAC no es un activo."""
    for tipo in ("ipv4", "ipv6"):
        for address in host_el.findall("address"):
            if address.get("addrtype") == tipo and address.get("addr"):
                return address.get("addr")
    return None


def _esta_arriba(host_el: ET.Element) -> bool:
    """Solo los hosts que nmap marcó como `up` se evalúan."""
    status = host_el.find("status")
    return status is not None and status.get("state") == "up"


def _puerto(port_el: ET.Element) -> int | None:
    """Número de puerto de un `<port>`; `None` si no es un entero."""
    try:
        return int(port_el.get("portid", ""))
    except ValueError:
        return None


def _servicio(port_el: ET.Element) -> tuple[str, str]:
    """Nombre del servicio y producto tal como los anunció el servicio."""
    service = port_el.find("service")
    if service is None:
        return "", ""
    return service.get("name", "") or "", service.get("product", "") or ""


def _evidencia(archivo: str, extracto: str) -> list[Evidence]:
    """Evidencia de un hallazgo de nmap: fichero, sin línea y extracto literal."""
    return [Evidence(archivo=archivo, linea=None, extracto=extracto)]


def _puertos_abiertos(
    host_el: ET.Element, host: str, archivo: str
) -> tuple[list[Finding], list[dict]]:
    """Una observación `nmap.open_port` por puerto abierto y la lista del activo."""
    findings = []
    puertos: list[dict] = []
    vistos: set[str] = set()

    for port_el in host_el.findall("ports/port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        numero = _puerto(port_el)
        if numero is None:
            continue
        protocolo = port_el.get("protocol", "tcp")
        servicio, producto = _servicio(port_el)
        puertos.append({"puerto": numero, "protocolo": protocolo, "servicio": servicio, "producto": producto})

        key = f"nmap.open_port:{protocolo}:{host}:{numero}"
        if key in vistos:
            continue
        vistos.add(key)

        extracto = f"{numero}/{protocolo} open"
        if servicio:
            extracto += f" {servicio}"
        if producto:
            extracto += f" {producto}"
        variables = {"puerto": str(numero)}
        if servicio:
            variables["servicio"] = servicio

        findings.append(
            build(
                "nmap.open_port",
                key=key,
                activo=f"{host}:{numero}",
                evidencia=_evidencia(archivo, extracto[:_EXTRACTO_MAX]),
                variables=variables,
                severidad="info",
                confianza="observacion",
            )
        )
    return findings, puertos


def _cves(
    host_el: ET.Element, host: str, archivo: str, vistos: set[str]
) -> list[Finding]:
    """Un `nmap.cve` confirmado por CVE y puerto, sin repetir el mismo CVE."""
    findings = []

    # Scripts de puerto, estén en un puerto abierto o no: el script se ejecutó.
    for port_el in host_el.findall("ports/port"):
        numero = _puerto(port_el)
        if numero is None:
            continue
        for script in port_el.findall("script"):
            findings.extend(
                _cves_de_script(script, host, numero, archivo, vistos)
            )

    # Scripts de host (por ejemplo `vulners` sin puerto asociado): se atribuyen
    # al host, no a un puerto inventado.
    for script in host_el.findall("hostscript/script"):
        findings.extend(_cves_de_script(script, host, None, archivo, vistos))

    return findings


def _cves_de_script(
    script: ET.Element, host: str, puerto: int | None, archivo: str, vistos: set[str]
) -> list[Finding]:
    """CVEs citados en la salida de un `<script>`, con su puntuación si consta."""
    script_id = script.get("id", "script")
    salida = (script.get("output", "") or "").strip()
    if not salida:
        return []

    extracto = f"{script_id}: {salida[:_EXTRACTO_MAX]}"
    activo = f"{host}:{puerto}" if puerto is not None else host
    findings = []

    for cve in sorted(set(_CVE_RE.findall(salida))):
        key = f"cve|{cve}|{host}"
        if key in vistos:
            continue
        vistos.add(key)

        score = _score(salida, cve)
        findings.append(
            build(
                "nmap.cve",
                key=key,
                activo=activo,
                evidencia=_evidencia(archivo, extracto),
                severidad=_severidad(score),
                confianza="confirmado",
                cve=cve,
                cvss=score,
            )
        )
    return findings


def parse(path: Path, repo_root: Path) -> ParseResult:
    """Traduce un XML de nmap a hallazgos, activos y lo que no se pudo evaluar."""
    path = Path(path)
    archivo = relpath(path, repo_root)

    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        return ParseResult(
            evaluado=False,
            no_evaluable=[{"fuente": archivo, "motivo": str(exc)}],
        )

    findings = []
    activos = []
    vistos_cve: set[str] = set()

    for host_el in root.iter("host"):
        if not _esta_arriba(host_el):
            continue
        host = _host(host_el)
        if not host:
            continue

        de_puertos, puertos = _puertos_abiertos(host_el, host, archivo)
        findings.extend(de_puertos)
        findings.extend(_cves(host_el, host, archivo, vistos_cve))
        activos.append({"host": host, "puertos": puertos})

    return ParseResult(findings=findings, activos=activos)


register("nmap", parse)
