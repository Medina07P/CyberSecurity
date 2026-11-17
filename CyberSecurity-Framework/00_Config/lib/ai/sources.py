"""Descubrimiento de fuentes indexables del framework (solo lectura, ya redactadas)."""
import fnmatch
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from . import redact as _redact

KINDS = ("doc", "resultado", "informe")

# Herramientas de fuerza bruta / login: su salida contiene credenciales probadas.
BRUTEFORCE_TOOL_DIRS = frozenset({
    "hydra", "medusa", "ncrack", "patator", "crackmapexec", "john", "hashcat",
    "web_login_bruteforce", "login_bruteforce", "rate_limit",
})
BRUTEFORCE_MARKERS = ("brute", "hydra", "crack")

# Rutas (relativas al framework) que pueden contener credenciales.
CREDENTIAL_DIRS = ("10_Evidence/credentials", "06_PostExploitation/loot",
                   "00_Config/credentials")
CREDENTIAL_NAMES = frozenset({".session", "api-keys.yaml", "api_key", "api_keys.yaml",
                              ".env", "shadow"})
# Material secreto por nombre (sin distinguir mayúsculas), con cualquier sufijo.
CREDENTIAL_GLOBS = ("id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "*.pem", "*.pem.*",
                    "*.key", "*.key.*", ".env.*", "*.kdbx", "*.p12", "*.pfx", "shadow.*")

SKIP_DIRS = frozenset({".git", "__pycache__", "node_modules", "tests", ".superpowers"})
TEXT_SUFFIXES = frozenset({".md", ".txt", ".log", ".json", ".xml", ".csv", ".tsv",
                           ".nmap", ".gnmap", ".yaml", ".yml", ".html"})
REPORTS_REL = "11_Reports/generated"
# Directorio de datos del propio asistente (índice y resúmenes). Nunca se indexa:
# si lo hiciéramos, el índice se ingiere a sí mismo e invalida su propio caché.
DATA_DIR_REL_PARTS = ("09_Automation", "ai", "data")


def slug(target: str) -> str:
    return target.replace(":", "_").replace("/", "_")


def _abs(path) -> str:
    try:
        return os.path.abspath(str(path))
    except (OSError, ValueError):
        return str(path)


def is_data_path(framework_root, path, exclude=None) -> bool:
    """¿``path`` pertenece al directorio de datos del asistente?

    Dos reglas, por secuencia de componentes (no por subcadena):
    - exclusión relativa fija ``09_Automation/ai/data`` bajo el framework;
    - exclusión explícita opcional ``exclude`` (p. ej. un ``AI_DATA_DIR`` que
      caiga dentro del árbol del framework), comparada por prefijo de ruta.
    """
    fw = Path(framework_root)
    try:
        rel = Path(path).relative_to(fw).parts
        if tuple(rel[:len(DATA_DIR_REL_PARTS)]) == DATA_DIR_REL_PARTS:
            return True
    except ValueError:
        pass
    if exclude is not None:
        base = _abs(exclude)
        cand = _abs(path)
        if cand == base or cand.startswith(base + os.sep):
            return True
    return False


@dataclass(frozen=True)
class Document:
    path: str
    kind: str
    target: Optional[str]
    text: str


def _is_brute(tool: str) -> bool:
    t = tool.lower()
    return t in BRUTEFORCE_TOOL_DIRS or any(m in t for m in BRUTEFORCE_MARKERS)


def _brute_path(parts) -> bool:
    """Deny-list por CUALQUIER componente de ruta (directorios y nombre de fichero)."""
    *dirs, fn = parts
    if any(_is_brute(d) for d in dirs):
        return True
    low = fn.lower()
    stem = low.split(".")[0]
    return any(stem == t or stem.startswith(t + "_") for t in BRUTEFORCE_TOOL_DIRS)


def _read(path: str, limit: int) -> Optional[str]:
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as f:
            data = f.read(limit)
    except OSError:
        return None
    return _redact.redact(data.decode("utf-8", errors="replace"))


def _walk(root: Path) -> Iterator[Path]:
    for dp, dns, fns in os.walk(root, followlinks=False):
        dns[:] = sorted(d for d in dns
                        if d not in SKIP_DIRS and not os.path.islink(os.path.join(dp, d)))
        for fn in sorted(fns):
            yield Path(dp) / fn


def _rel(p: Path, base: Path) -> str:
    return os.path.relpath(p, base).replace(os.sep, "/")


def discover(framework_root: Path, *, include_credentials: bool = False,
             max_file_bytes: int = 2_000_000, exclude=None) -> Iterator[Document]:
    fw = Path(framework_root)
    repo = fw.parent
    seen = set()

    def credential(rel_fw: str, name: str) -> bool:
        low = name.lower()
        return name in CREDENTIAL_NAMES or low in CREDENTIAL_NAMES or any(
            fnmatch.fnmatchcase(low, g) for g in CREDENTIAL_GLOBS) or any(
            rel_fw == d or rel_fw.startswith(d + "/") for d in CREDENTIAL_DIRS)

    def emit(p: Path, kind: str, target: Optional[str], cred: bool):
        if cred and not include_credentials:
            return None
        if not cred and p.suffix.lower() not in TEXT_SUFFIXES:
            return None
        text = _read(str(p), max_file_bytes)
        if text is None:
            return None
        return Document(_rel(p, fw), kind, target, text)

    # 1) Framework: documentación, informes generados y (si se pide) credenciales.
    for p in _walk(fw):
        rel = _rel(p, fw)
        if _brute_path(rel.split("/")):
            continue
        if is_data_path(fw, p, exclude):
            continue
        cred = credential(rel, p.name)
        if rel.startswith(REPORTS_REL + "/"):
            parts = rel.split("/")
            kind, target = ("informe", parts[2]) if len(parts) > 3 else ("doc", None)
        else:
            kind, target = "doc", None
        d = emit(p, kind, target, cred)
        if d and d.path not in seen:
            seen.add(d.path)
            yield d

    # 2) docs/ en la raíz del repo.
    docs = repo / "docs"
    if docs.is_dir() and not docs.is_symlink():
        for p in _walk(docs):
            if _brute_path(p.relative_to(docs).parts):
                continue
            if is_data_path(fw, p, exclude):
                continue
            d = emit(p, "doc", None, False)
            if d and d.path not in seen:
                seen.add(d.path)
                yield d

    # 3) scans/<tool>/<tool>_<slug>.ext
    scans = repo / "scans"
    if scans.is_dir() and not scans.is_symlink():
        for p in _walk(scans):
            rel = p.relative_to(scans).parts
            if len(rel) < 2 or _brute_path(rel):
                continue
            if is_data_path(fw, p, exclude):
                continue
            tool = rel[0]
            stem = p.stem
            target = stem[len(tool) + 1:] if stem.startswith(tool + "_") else None
            d = emit(p, "resultado", target or None, False)
            if d and d.path not in seen:
                seen.add(d.path)
                yield d
