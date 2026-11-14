"""Shared evidence contracts, without filesystem side effects."""
from dataclasses import dataclass
from pathlib import Path


class EvidenceError(Exception):
    """Operational failure (exit status 1)."""


class UsageError(EvidenceError):
    """Invalid invocation (exit status 2)."""


@dataclass
class Record:
    id: str
    kind: str
    format: str
    payload: Path
    metadata: Path
    target: str | None


@dataclass
class Issue:
    path: Path
    code: str
    message: str


@dataclass
class Inventory:
    records: list[Record]
    issues: list[Issue]


@dataclass
class VerifiedRecord:
    record: Record
    size: int
    sha256: str
    metadata_size: int
    metadata_sha256: str


@dataclass
class Verification:
    entries: list[VerifiedRecord]
    issues: list[Issue]

    @property
    def ok(self) -> bool:
        return bool(self.entries) and not self.issues
