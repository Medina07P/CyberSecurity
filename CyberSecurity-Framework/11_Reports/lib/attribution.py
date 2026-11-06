"""Atribución de ficheros y activos al objetivo de la sesión.

Una sola regla manda aquí: un activo pertenece al objetivo cuando su host
normalizado es **igual** al del objetivo. Nunca por subcadena — `127.0.0.10`
no es `127.0.0.1` — porque un informe de cliente que mezcle los datos de dos
objetivos es peor que un informe incompleto.

`guess_host` es el camino inverso: adivina el activo a partir del nombre de un
fichero de resultados (`nuclei_https___127.0.0.1_8080.txt`) para poder
atribuirlo. Si no lo reconoce devuelve `None`; quien llama debe tratar ese
`None` como «no atribuible», nunca como «pertenece».

IPv6 queda fuera del alcance de esta versión.

Solo biblioteca estándar, como el resto del motor.
"""

import re

__all__ = ["slug", "normalize_host", "host_of", "port_of", "guess_host", "belongs_to"]

_SLUG_CHARS = re.compile(r"[:/]")
_AUTHORITY_CUT = re.compile(r"[/?#]")
_SEPARATORS = re.compile(r"[\\/]")
_HAS_LETTER = re.compile(r"[a-z]")

# IPv4 con bordes de verdad: ni una letra ni un dígito ni un punto pegados por
# delante, así `127.0.0.1` no sale de `v127.0.0.1` ni de `1127.0.0.1`; y por
# detrás se rechaza otro dígito o un punto seguido de dígitos, para que
# `127.0.0.10` no se lea como `127.0.0.1`, pero `127.0.0.1.txt` sí valga.
# Cada octeto se valida en rango para que `192.168.1.1000` no se cuele.
_IPV4 = re.compile(
    r"(?<![0-9A-Za-z.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![0-9])(?![.][0-9])"
)

# Un host con puntos: etiquetas alfanuméricas, guiones solo por dentro.
_HOSTISH = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)

# Tokens que arrastra un nombre de fichero y que no son el activo.
_IGNORED_TOKENS = frozenset({"http", "https", "www"})

# Extensiones de los ficheros que lee este motor: `informe.txt` no es un host.
# Un candidato que termina en una de ellas se recorta y se vuelve a validar,
# así `nuclei_example.com.txt` sigue siendo el activo `example.com`. No están
# las que además son TLD reales (`.md`, `.io`, `.sh`): un objetivo `example.md`
# tiene que seguir atribuyéndose.
_FILE_EXTENSIONS = frozenset({
    "txt", "log", "json", "csv", "tsv", "xml", "html", "htm",
    "png", "jpg", "jpeg", "pdf", "yaml", "yml", "req", "resp", "out",
})


def slug(target: str) -> str:
    """Nombre de fichero que usa el framework: `:` y `/` pasan a `_`.

    Es la misma sustitución que `scans_slug` de `00_Config/lib/scans.bash`,
    carácter a carácter, para que el motor encuentre los ficheros que las
    herramientas ya escribieron.
    """
    return _SLUG_CHARS.sub("_", "" if target is None else str(target))


def _split_authority(raw: str) -> tuple[str, str | None]:
    """Parte un activo o URL en `(host, puerto)`.

    Quita esquema, credenciales, ruta, query y fragmento. El puerto se devuelve
    como texto (o `None` si no hay). Con más de un `:` se asume IPv6, fuera de
    alcance: se devuelve el texto tal cual y sin puerto.
    """
    text = "" if raw is None else str(raw).strip()
    if not text:
        return "", None

    scheme = text.find("://")
    if scheme != -1:
        text = text[scheme + 3:]
    text = _AUTHORITY_CUT.split(text, 1)[0]

    userinfo = text.rfind("@")
    if userinfo != -1:
        text = text[userinfo + 1:]

    if text.count(":") > 1:
        return text, None

    host, sep, port = text.partition(":")
    return host, (port if sep else None)


def normalize_host(raw: str) -> str:
    """Host comparable: sin esquema, credenciales, ruta ni puerto.

    Pasa a minúsculas y quita el punto final (`example.com.`). Un IPv6 no se
    toca: se devuelve tal cual, porque esta versión no lo interpreta.
    """
    host, _ = _split_authority(raw)
    if host.count(":") > 1:
        return host
    return host.strip().lower().rstrip(".")


def host_of(raw: str) -> str:
    """Host de un activo, con el nombre que usan los parsers.

    Es la misma normalización que `normalize_host`; existe para que el campo
    `activo` de un hallazgo se lea con un nombre explícito.
    """
    return normalize_host(raw)


def port_of(raw: str) -> int | None:
    """Puerto del activo, o `None` si no consta, no es numérico o no es válido."""
    _, port = _split_authority(raw)
    if not port or not re.fullmatch(r"[0-9]{1,5}", port):
        return None
    value = int(port)
    return value if 0 < value < 65536 else None


def _domain_of(candidate: str) -> str | None:
    """Valida un candidato con puntos y devuelve el host, o `None`."""
    labels = candidate.split(".")
    # El nombre del fichero arrastra su extensión: `example.com.txt` es
    # `example.com`, y `8080.txt` se queda sin host y se descarta.
    while len(labels) > 1 and labels[-1].lower() in _FILE_EXTENSIONS:
        labels.pop()

    if len(labels) < 2:
        return None
    tld = labels[-1].lower()
    if len(tld) < 2 or not tld.isalpha():
        return None

    name = [label.lower() for label in labels[:-1]]
    # El sufijo tiene que colgar de algo con letras: `8080.txt` no es un host.
    if not any(_HAS_LETTER.search(label) for label in name):
        return None
    # `http`, `https` y `www` son tokens del nombre del fichero, no el activo.
    if all(label in _IGNORED_TOKENS for label in name):
        return None
    return ".".join(labels).lower()


def guess_host(text: str) -> str | None:
    """Adivina el activo en el nombre de un fichero de resultados.

    Mira solo el nombre (no las carpetas), busca primero una IPv4 y después un
    dominio con al menos un punto. Devuelve `None` si el nombre no lo dice:
    `security_headers_8080.txt` no identifica ningún activo.
    """
    if not text:
        return None
    name = _SEPARATORS.split(str(text).strip())[-1]
    if not name:
        return None

    ipv4 = _IPV4.search(name)
    if ipv4:
        return ipv4.group(0)

    for match in _HOSTISH.finditer(name):
        host = _domain_of(match.group(0))
        if host:
            return host
    return None


def belongs_to(activo: str, objetivo: str) -> bool:
    """¿El activo es el objetivo? Compara hosts normalizados, nunca subcadenas."""
    host_activo = normalize_host(activo)
    host_objetivo = normalize_host(objetivo)
    if not host_activo or not host_objetivo:
        return False
    return host_activo == host_objetivo
