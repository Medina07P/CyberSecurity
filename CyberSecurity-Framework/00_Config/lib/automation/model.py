"""Immutable shared values. No process, environment or configuration access."""
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


class PlanError(ValueError):
    """Invalid plan or typed input (CLI rc 2)."""


class PreflightError(RuntimeError):
    """Unavailable or unsafe backend (CLI rc 1)."""


def _freeze(value):
    """Copy containers recursively; reject opaque mutable objects."""
    if isinstance(value, Mapping):
        return MappingProxyType({_freeze(k): _freeze(v) for k, v in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, bytes, int, float, bool, Path)):
        return value
    raise PlanError('Tipo de entrada no inmutable')


@dataclass(frozen=True)
class ActionSpec:
    id: str
    input_types: Mapping[str, str]
    required: tuple[str, ...]
    gates: tuple[str, ...]
    tools: tuple[str, ...]
    network: bool
    effects: str
    limitations: str

    def __post_init__(self):
        object.__setattr__(self, 'input_types', _freeze(self.input_types))
        for field in ('required', 'gates', 'tools'):
            object.__setattr__(self, field, tuple(getattr(self, field)))


@dataclass(frozen=True)
class Step:
    id: str
    action: str
    inputs: Mapping[str, object]
    depends_on: tuple[str, ...]

    def __post_init__(self):
        object.__setattr__(self, 'inputs', _freeze(self.inputs))
        object.__setattr__(self, 'depends_on', tuple(self.depends_on))


@dataclass(frozen=True)
class Plan:
    name: str
    steps: tuple[Step, ...]
    timeout: int

    def __post_init__(self):
        object.__setattr__(self, 'steps', tuple(self.steps))


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]
    timeout: int

    def __post_init__(self):
        object.__setattr__(self, 'argv', tuple(self.argv))
        object.__setattr__(self, 'env', _freeze(self.env))


@dataclass(frozen=True)
class StepResult:
    id: str
    state: str
    rc: int | None
    reason: str


@dataclass(frozen=True)
class RunResult:
    rc: int
    run_dir: Path | None
    steps: tuple[StepResult, ...]
    reason_code: str = ''

    def __post_init__(self):
        object.__setattr__(self, 'steps', tuple(self.steps))


@dataclass(frozen=True)
class Permissions:
    targets: frozenset[str]
    grants: frozenset[tuple[str, str]]

    def __post_init__(self):
        object.__setattr__(self, 'targets', frozenset(self.targets))
        object.__setattr__(self, 'grants', frozenset(tuple(pair) for pair in self.grants))


@dataclass(frozen=True)
class RuntimeContext:
    framework: Path
    repo: Path
    python: Path
    path: str
