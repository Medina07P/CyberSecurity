"""Redacción de secretos antes de que un texto llegue a un índice o a un prompt.

Los patrones son orientados a línea y acotados (sin cuantificadores anidados),
para que una línea de 1 MB no provoque retroceso catastrófico.
"""
import re

MARK = "[REDACTADO]"

_KEYS = (r"(?:aws_)?secret[_-]?(?:access[_-]?)?key|access[_-]?key|private[_-]?key"
         r"|password|passwd|pwd|api[_-]?key|apikey|token|secret|\bpass")
_VALUE = r"(?:\"[^\"\r\n]{0,4096}\"|'[^'\r\n]{0,4096}'|[^\s\"',&;]+)"
_KEYED = re.compile(r"(?i)((?:" + _KEYS + r")[\"']?[ \t]*[=:][ \t]*)" + _VALUE)
_CLI_LONG = re.compile(
    r"(?i)(--(?:password|passwd|pass|pwd|token|secret|api-?key)(?:[ \t]+|=))" + _VALUE)
# Nmap acota cada puerto a 1-5 dígitos (<=65535), separados por ',' o '-'. Una
# tirada de 6+ dígitos pegados (p. ej. una contraseña numérica tras "-p") no
# encaja en esa forma y sí se redacta.
_CLI_P = re.compile(
    r"(?<![\w-])(-p[ \t]+)"
    r"(?![TUtu]?:?[0-9]{1,5}(?:[,\-][0-9]{1,5})*(?:[ \t]|$))" + _VALUE)
_COOKIE = re.compile(r"(?i)\b((?:Set-)?Cookie[ \t]*:[ \t]*)[^\r\n]+")
_AUTH = re.compile(r"(?i)\b(Authorization[ \t]*:[ \t]*)[^\r\n]+")
_AWS = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b")
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----")
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]+")
_CRYPT = re.compile(r"\$(?:1|5|6|2[abxy]|y)\$[^\s:]+")
_GH = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")
_URL_USERINFO = re.compile(r"(://[^\s/:@]{1,256}:)[^\s/@]{1,512}(@)")
_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,64}(?![0-9A-Za-z])")


def _hex(m):
    return MARK if len(m.group(0)) in (32, 40, 64) else m.group(0)


def _pem(text: str) -> str:
    out, pos = [], 0
    while True:
        m = _PEM_BEGIN.search(text, pos)
        if not m:
            break
        out.append(text[pos:m.start()])
        out.append(MARK)
        e = _PEM_END.search(text, m.end())
        if not e:  # sin cierre: se redacta hasta el final del texto
            return "".join(out)
        pos = e.end()
    out.append(text[pos:])
    return "".join(out)


def redact(text: str) -> str:
    text = _pem(text)
    text = _COOKIE.sub(lambda m: m.group(1) + MARK, text)
    text = _AUTH.sub(lambda m: m.group(1) + MARK, text)
    text = _AWS.sub(MARK, text)
    text = _CLI_LONG.sub(lambda m: m.group(1) + MARK, text)
    text = _CLI_P.sub(lambda m: m.group(1) + MARK, text)
    text = _CRYPT.sub(MARK, text)
    text = _GH.sub(MARK, text)
    text = _BEARER.sub(lambda m: m.group(1) + " " + MARK, text)
    text = _URL_USERINFO.sub(lambda m: m.group(1) + MARK + m.group(2), text)
    text = _KEYED.sub(lambda m: m.group(1) + MARK, text)
    text = _HEX.sub(_hex, text)
    return text
