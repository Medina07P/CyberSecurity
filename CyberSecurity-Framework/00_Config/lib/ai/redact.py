"""Redacción de secretos antes de que un texto llegue a un índice o a un prompt.

Los patrones son orientados a línea y acotados (sin cuantificadores anidados),
para que una línea de 1 MB no provoque retroceso catastrófico.
"""
import re

MARK = "[REDACTADO]"

_KEYED = re.compile(
    r"(?i)((?:password|passwd|pwd|api[_-]?key|apikey|token|secret|\bpass)"
    r"[\"']?[ \t]*[=:][ \t]*[\"']?)[^\s\"',&;]+")
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]+")
_CRYPT = re.compile(r"\$(?:1|5|6|2[abxy]|y)\$[^\s:]+")
_GH = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")
_URL_USERINFO = re.compile(r"(://[^\s/:@]{1,256}:)[^\s/@]{1,512}(@)")
_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,64}(?![0-9A-Za-z])")


def _hex(m):
    return MARK if len(m.group(0)) in (32, 40, 64) else m.group(0)


def redact(text: str) -> str:
    text = _CRYPT.sub(MARK, text)
    text = _GH.sub(MARK, text)
    text = _BEARER.sub(lambda m: m.group(1) + " " + MARK, text)
    text = _URL_USERINFO.sub(lambda m: m.group(1) + MARK + m.group(2), text)
    text = _KEYED.sub(lambda m: m.group(1) + MARK, text)
    text = _HEX.sub(_hex, text)
    return text
