"""Índice BM25 en Python puro con citas ``ruta:inicio-fin`` y filtro por objetivo."""
import hashlib
import json
import math
import os
import re
import tempfile
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from . import sources as _sources

VERSION = 1
CHUNK_LINES = 40
MAX_CHUNKS_PER_DOC = 500
K1 = 1.5
B = 0.75

_SPLIT = re.compile(r"[^a-z0-9]+")
_DOTTED = re.compile(r"[a-z0-9]+(?:[.\-][a-z0-9]+)+")
_HEADING = re.compile(r"^ {0,3}#{1,6}\s")
_FENCE = re.compile(r"^ {0,3}(```|~~~)")


@dataclass(frozen=True)
class Chunk:
    path: str
    line_start: int
    line_end: int
    text: str
    kind: str
    target: Optional[str]

    def cite(self) -> str:
        return "%s:%d-%d" % (self.path, self.line_start, self.line_end)


def _fold(s: str) -> str:
    s = unicodedata.normalize("NFKD", s.lower())
    return "".join(c for c in s if not unicodedata.combining(c))


def tokenize(text: str) -> List[str]:
    """Minúsculas sin acentos; además de las partes, IPs/CVE/ids con punto o guion enteros."""
    low = _fold(text)
    toks = [t for t in _SPLIT.split(low) if len(t) > 1]
    toks.extend(m.group(0) for m in _DOTTED.finditer(low))
    return toks


def _blocks(lo: int, hi: int, n: int):
    for s in range(lo, hi, n):
        yield s, min(s + n, hi)


def _lines(text: str) -> List[str]:
    """Líneas como las cuenta un editor: solo ``\\n`` separa (``\\r`` final se quita)."""
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    return [p[:-1] if p.endswith("\r") else p for p in parts]


def _chunk_doc(d, chunk_lines: int) -> List[Chunk]:
    lines = _lines(d.text)
    n = max(1, chunk_lines)
    spans = []
    if d.path.lower().endswith(".md"):
        start, fenced = 0, False
        for i, ln in enumerate(lines):
            if _FENCE.match(ln):
                fenced = not fenced
            elif not fenced and i > start and _HEADING.match(ln):
                spans.extend(_blocks(start, i, n))
                start = i
        spans.extend(_blocks(start, len(lines), n))
    else:
        spans.extend(_blocks(0, len(lines), n))
    out = []
    for s, e in spans[:MAX_CHUNKS_PER_DOC]:
        body = "\n".join(lines[s:e])
        if body.strip():
            out.append(Chunk(d.path, s + 1, e, body, d.kind, d.target))
    return out


def fingerprint(framework_root: Path, exclude=None) -> str:
    """Hash de (ruta, mtime_ns, tamaño) de las fuentes candidatas; sin leer cuerpos.

    El directorio de datos del asistente (fijo ``09_Automation/ai/data`` y el
    ``exclude`` explícito) se omite para que el índice no se invalide por sí mismo.
    """
    fw = Path(framework_root)
    h = hashlib.sha256()
    entries = []
    for root in (fw, fw.parent / "docs", fw.parent / "scans"):
        if not root.is_dir() or root.is_symlink():
            continue
        for p in _sources._walk(root):
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            if _sources.is_data_path(fw, p, exclude):
                continue
            entries.append((str(p), st.st_mtime_ns, st.st_size))
    for e in sorted(entries):
        h.update(repr(e).encode("utf-8", "replace"))
    return h.hexdigest()


class Index:
    def __init__(self, chunks: List[Chunk], fp: Optional[str] = None):
        self.chunks = chunks
        self.fingerprint = fp
        self._tf = [Counter(tokenize(c.text)) for c in chunks]
        self._len = [sum(t.values()) for t in self._tf]
        self._avg = (sum(self._len) / len(chunks)) if chunks else 0.0
        self._df = Counter()
        for t in self._tf:
            self._df.update(t.keys())

    @classmethod
    def build(cls, docs: Iterable, chunk_lines: int = CHUNK_LINES,
              fingerprint: Optional[str] = None) -> "Index":
        chunks: List[Chunk] = []
        for d in docs:
            chunks.extend(_chunk_doc(d, chunk_lines))
        return cls(chunks, fingerprint)

    def search(self, query: str, *, k: int = 5, target: Optional[str] = None,
               kinds: Optional[set] = None) -> List[Chunk]:
        terms = set(tokenize(query))
        n = len(self.chunks)
        if not terms or not n or k <= 0:
            return []
        scored = []
        for i, c in enumerate(self.chunks):
            if c.target is not None and c.target != target:
                continue
            if kinds is not None and c.kind not in kinds:
                continue
            tf, dl, score = self._tf[i], self._len[i], 0.0
            for t in terms:
                f = tf.get(t, 0)
                if not f:
                    continue
                df = self._df[t]
                idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
                norm = 1 - B + B * dl / self._avg if self._avg else 1.0
                score += idf * f * (K1 + 1) / (f + K1 * norm)
            if score > 0:
                scored.append((-score, c.path, c.line_start, i))
        scored.sort()
        return [self.chunks[i] for _, _, _, i in scored[:k]]

    def stale(self, framework_root: Path, exclude=None) -> bool:
        if not self.fingerprint:
            return True
        return fingerprint(framework_root, exclude) != self.fingerprint

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        data = {"version": VERSION, "fingerprint": self.fingerprint,
                "chunks": [[c.path, c.line_start, c.line_end, c.text, c.kind, c.target]
                           for c in self.chunks]}
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".index-", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path: Path) -> Optional["Index"]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or data.get("version") != VERSION:
                return None
            raw = data["chunks"]
            if not isinstance(raw, list):
                return None
            chunks = []
            for row in raw:
                if not isinstance(row, list) or len(row) != 6:
                    return None
                p, a, b, t, k, g = row
                if (not isinstance(p, str) or not isinstance(t, str)
                        or type(a) is not int or type(b) is not int
                        or k not in _sources.KINDS
                        or not (g is None or isinstance(g, str))):
                    return None
                chunks.append(Chunk(p, a, b, t, k, g))
            fp = data.get("fingerprint")
            return cls(chunks, fp if isinstance(fp, str) else None)
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return None
