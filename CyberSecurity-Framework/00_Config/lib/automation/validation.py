"""Pure lexical input validation. Paths are data: never stat/open/resolve here."""
import ipaddress
from pathlib import Path
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

from .model import PlanError


def _text(value):
    if not isinstance(value, str) or not value or any(unicodedata.category(c).startswith('C') for c in value):
        raise PlanError('Texto vacío o con controles')
    return value


def _host(value, domain_only=False):
    text = _text(value).lower()
    if text.endswith('.'):
        text = text[:-1]
    try:
        address = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError:
        if (len(text) > 253 or re.fullmatch(r'[0-9.]+', text)
                or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                           for label in text.split('.'))):
            raise PlanError('Objetivo IPv4/dominio inválido') from None
        return text
    if domain_only:
        raise PlanError('Se requiere dominio, no IP')
    return str(address)


def _integer(value, maximum):
    if isinstance(value, str) and re.fullmatch(r'[0-9]+', value) and len(value) <= 6:
        value = int(value)
    if type(value) is not int or not 1 <= value <= maximum:
        raise PlanError('Entero fuera de rango')
    return value


def validate(kind: str, value: object) -> object:
    """Return canonical typed data or PlanError; no implicit reads or defaults."""
    if kind in ('target', 'domain'):
        return _host(value, kind == 'domain')
    if kind in ('port', 'max_attempts', 'max_seconds', 'timeout'):
        return _integer(value, {'port': 65535, 'max_attempts': 200,
                                'max_seconds': 300, 'timeout': 86400}[kind])
    if kind == 'ports':
        if isinstance(value, (list, tuple)):
            items = value
        else:
            items = _text(value).split(',')
        ports = []
        seen = set()
        for item in items:
            if isinstance(item, str) and re.fullmatch(r'[0-9]+-[0-9]+', item):
                first, last = (_integer(part, 65535) for part in item.split('-'))
                if first > last:
                    raise PlanError('Rango de puertos invertido')
                expanded = range(first, last + 1)
            else:
                expanded = (_integer(item, 65535),)
            for port in expanded:
                if port in seen:
                    raise PlanError('Puertos duplicados')
                seen.add(port)
                ports.append(port)
        if not ports:
            raise PlanError('Lista de puertos vacía')
        return tuple(ports)
    if kind == 'url':
        text = _text(value)
        if ('#' in text or '\\' in text or any(c.isspace() for c in text)
                or re.search(r'%(?:0[0-9a-f]|1[0-9a-f]|7f)', text, re.I)):
            raise PlanError('URL con fragmento, espacios o controles')
        try:
            parts = urlsplit(text)
            if parts.scheme not in ('http', 'https') or not parts.netloc or '@' in parts.netloc:
                raise ValueError()
            host = _host(parts.hostname)
            port = parts.port
            if parts.netloc.endswith(':'):
                raise ValueError()
            if port is not None:
                port = _integer(port, 65535)
            authority = host + (f':{port}' if port is not None else '')
            return urlunsplit((parts.scheme, authority, parts.path, parts.query, ''))
        except (ValueError, TypeError):
            raise PlanError('URL HTTP(S) inválida') from None
    if kind == 'path':
        return Path(_text(str(value) if isinstance(value, Path) else value))
    if kind == 'product':
        text = _text(value)
        if text.startswith('-') or text != text.strip() or re.search(r'[#;&|`$<>\\\"\'(){}\[\]*?!~]', text):
            raise PlanError('Producto con opciones o metacaracteres')
        return text
    if kind in ('account', 'database', 'table', 'id', 'scheme'):
        text = _text(value)
        patterns = {'account': r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}',
                    'database': r'[A-Za-z0-9_][A-Za-z0-9_-]{0,63}',
                    'table': r'[A-Za-z0-9_][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z0-9_][A-Za-z0-9_-]{0,63})?',
                    'id': r'[a-z][a-z0-9_]{0,47}', 'scheme': r'https?'}
        if not re.fullmatch(patterns[kind], text):
            raise PlanError('Identificador/esquema inválido')
        return text
    raise PlanError('Tipo de entrada desconocido')
