"""Contratos de una ejecución; ningún estado persiste entre objetivos."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


@dataclass(frozen=True)
class Limits:
    request_seconds: float = 15
    tool_seconds: float = 120
    api_calls: int = 10
    dns_candidates: int = 1000
    dns_workers: int = 2
    dns_qps: float = 5

    def __post_init__(self):
        for name, cap in [('request_seconds', 15), ('tool_seconds', 120), ('api_calls', 10),
                          ('dns_candidates', 1000), ('dns_workers', 2), ('dns_qps', 5)]:
            if not 0 < getattr(self, name) <= cap:
                raise ValueError('Límite fuera del rango permitido: ' + name)


@dataclass(frozen=True)
class Evidence:
    kind: str
    value: str
    source: str
    attribution: str
    detail: str


@dataclass
class SourceResult:
    source: str
    status: str
    evidence: list[Evidence]
    error: str = ''


@dataclass
class Run:
    target: str
    output: Path
    limits: Limits = field(default_factory=Limits)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    run_id: str = field(default_factory=lambda: uuid4().hex)
    results: list[SourceResult] = field(default_factory=list)
    cache: dict = field(default_factory=dict, repr=False)
    secrets: list[str] = field(default_factory=list, repr=False)
