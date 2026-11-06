"""Modelo de hallazgos del motor de informes.

Los parsers producen `Finding`; este módulo define además el identificador
estable (derivado de `key`), la fusión de duplicados, el orden de presentación
y la conversión a/desde diccionarios para `findings.json`.

Solo biblioteca estándar: el motor debe funcionar en cualquier Kali sin
dependencias adicionales.
"""

import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path

SEVERITY_ORDER = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "info": 4}
CONFIDENCE_ORDER = {"confirmado": 0, "candidato": 1, "observacion": 2}


def stable_id(key: str) -> str:
    """Identificador reproducible de un hallazgo, derivado de su clave."""
    return hashlib.sha1(key.encode()).hexdigest()


@dataclass(frozen=True)
class Evidence:
    """Prueba de un hallazgo: fichero, línea (si consta) y extracto literal."""

    archivo: str
    linea: int | None
    extracto: str


@dataclass
class Finding:
    """Hallazgo normalizado, independiente del formato de la herramienta."""

    rule: str
    key: str
    titulo: str
    categoria: str
    severidad: str
    confianza: str
    activo: str
    tecnica: str
    descripcion: str
    impacto_cliente: str
    recomendacion: str
    esfuerzo: str
    cve: str | None
    cvss: float | None
    evidencia: list[Evidence]
    referencias: list[str]

    @property
    def id(self) -> str:
        return stable_id(self.key)


@dataclass
class ParseResult:
    """Lo que devuelve un parser: hallazgos, activos y lo que no pudo evaluar."""

    findings: list[Finding] = field(default_factory=list)
    activos: list[dict] = field(default_factory=list)
    no_evaluable: list[dict] = field(default_factory=list)
    descartados: list[dict] = field(default_factory=list)
    evaluado: bool = True


def _strength(finding: Finding) -> tuple[int, int]:
    return (SEVERITY_ORDER[finding.severidad], CONFIDENCE_ORDER[finding.confianza])


def merge_findings(items: list[Finding]) -> list[Finding]:
    """Fusiona hallazgos con la misma `key`.

    Conserva los datos del más grave (severidad y, en empate, confianza),
    une la evidencia sin repetir `(archivo, linea, extracto)`, une las
    referencias, conserva el primer CVE no nulo y el CVSS más alto.
    """
    groups: dict[str, list[Finding]] = {}
    for item in items:
        groups.setdefault(item.key, []).append(item)

    merged: list[Finding] = []
    for group in groups.values():
        winner = min(group, key=_strength)

        evidencia: list[Evidence] = []
        vistos: set[tuple[str, int | None, str]] = set()
        referencias: list[str] = []
        for finding in group:
            for evidence in finding.evidencia:
                marca = (evidence.archivo, evidence.linea, evidence.extracto)
                if marca not in vistos:
                    vistos.add(marca)
                    evidencia.append(evidence)
            for referencia in finding.referencias:
                if referencia not in referencias:
                    referencias.append(referencia)

        cve = winner.cve or next((f.cve for f in group if f.cve), None)
        cvss = max((f.cvss for f in group if f.cvss is not None), default=None)

        merged.append(replace(winner, cve=cve, cvss=cvss,
                              evidencia=evidencia, referencias=referencias))
    return merged


def sort_findings(items: list[Finding]) -> list[Finding]:
    """Orden de presentación: gravedad, confianza, activo e id."""
    return sorted(items, key=lambda f: (_strength(f), f.activo, f.id))


def finding_to_dict(finding: Finding) -> dict:
    """Serializa un hallazgo para `findings.json`."""
    return {
        "id": finding.id,
        "rule": finding.rule,
        "key": finding.key,
        "titulo": finding.titulo,
        "categoria": finding.categoria,
        "severidad": finding.severidad,
        "confianza": finding.confianza,
        "activo": finding.activo,
        "tecnica": finding.tecnica,
        "descripcion": finding.descripcion,
        "impacto_cliente": finding.impacto_cliente,
        "recomendacion": finding.recomendacion,
        "esfuerzo": finding.esfuerzo,
        "cve": finding.cve,
        "cvss": finding.cvss,
        "evidencia": [
            {"archivo": e.archivo, "linea": e.linea, "extracto": e.extracto}
            for e in finding.evidencia
        ],
        "referencias": list(finding.referencias),
    }


def finding_from_dict(data: dict) -> Finding:
    """Reconstruye un hallazgo leído de `findings.json`."""
    return Finding(
        rule=data["rule"],
        key=data["key"],
        titulo=data["titulo"],
        categoria=data["categoria"],
        severidad=data["severidad"],
        confianza=data["confianza"],
        activo=data["activo"],
        tecnica=data["tecnica"],
        descripcion=data["descripcion"],
        impacto_cliente=data["impacto_cliente"],
        recomendacion=data["recomendacion"],
        esfuerzo=data["esfuerzo"],
        cve=data.get("cve"),
        cvss=data.get("cvss"),
        evidencia=[
            Evidence(e["archivo"], e["linea"], e["extracto"])
            for e in data.get("evidencia", [])
        ],
        referencias=list(data.get("referencias", [])),
    )


def relpath(path: Path, repo_root: Path) -> str:
    """Ruta relativa POSIX a la raíz del repositorio.
    
    Usa os.path.relpath para permitir rutas con .. si el path no cuelga de repo_root.
    Esto es importante cuando --scans apunta a un directorio externo.
    """
    import os
    try:
        return os.path.relpath(Path(path).resolve(), Path(repo_root).resolve()).replace(os.sep, '/')
    except ValueError:
        # En Windows, relpath puede fallar si están en diferentes unidades
        return Path(path).name
