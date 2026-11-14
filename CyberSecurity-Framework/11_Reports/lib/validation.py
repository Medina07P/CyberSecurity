"""Validación de entradas editables antes de renderizar o escribir informes."""
import ipaddress
import math
import re
from urllib.parse import urlsplit

from .attribution import belongs_to, normalize_host
from .model import CONFIDENCE_ORDER, SEVERITY_ORDER


def target(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('objetivo vacío o inválido')
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    parsed = urlsplit(value if '://' in value else '//' + value)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('objetivo con credenciales no permitido')
    if parsed.scheme and parsed.scheme not in {'http', 'https'}:
        raise ValueError('esquema de objetivo inválido')
    # Provocar validación de puerto y corchetes antes de normalizar.
    parsed.port
    host = normalize_host(value)
    if not host or any(char.isspace() for char in host):
        raise ValueError('objetivo inválido')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                                     for part in host.split('.')):
            raise ValueError('objetivo inválido')
    return host


def document(data: dict) -> None:
    """Valida tipos usados por ambos renderizadores, incluidos JSON heredados."""
    if not isinstance(data, dict) or not isinstance(data.get('meta'), dict):
        raise ValueError('registro y meta deben ser objetos')
    if type(data.get('evaluado')) is not bool or not isinstance(data.get('activos'), dict):
        raise ValueError('evaluado/activos inválidos')
    for key in ('findings', 'objetivos', 'no_evaluable', 'descartados'):
        if not isinstance(data.get(key), list):
            raise ValueError(f'{key} debe ser una lista')
    for key in ('incidencias', 'cobertura'):
        if not isinstance(data.get(key, []), list):
            raise ValueError(f'{key} debe ser una lista')
    if not all(isinstance(host, str) for host in data['objetivos']):
        raise ValueError('objetivos inválidos')
    for key in ('no_evaluable', 'descartados', 'incidencias'):
        for item in data.get(key, []):
            if not isinstance(item, dict) or not all(isinstance(v, str) or (k == 'linea' and type(v) is int and v > 0) for k, v in item.items()):
                raise ValueError(f'{key} contiene registros inválidos')
    for item in data.get('cobertura', []):
        if (not isinstance(item, dict) or set(item) != {'modulo', 'fuente', 'objetivo', 'estado', 'motivo'}
                or not all(isinstance(v, str) for v in item.values())
                or item['estado'] not in {'evaluada', 'contexto', 'no_evaluable', 'no_soportada'}):
            raise ValueError('cobertura inválida')
    for key, value in data['meta'].items():
        if key == 'herramientas':
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ValueError('herramientas inválidas')
        elif not isinstance(value, str):
            raise ValueError(f'meta.{key} debe ser texto')
    for host, asset in data['activos'].items():
        if not isinstance(host, str) or not isinstance(asset, dict) or not isinstance(asset.get('host'), str):
            raise ValueError('activo inválido')
        ports = asset.get('puertos', [])
        if not isinstance(ports, list):
            raise ValueError('puertos inválidos')
        for port in ports:
            if not isinstance(port, dict) or type(port.get('puerto')) is not int or not 1 <= port['puerto'] <= 65535:
                raise ValueError('puerto inválido')
            if not all(isinstance(v, str) for k, v in port.items() if k != 'puerto'):
                raise ValueError('metadata de puerto inválida')
    texts = ('rule', 'key', 'titulo', 'categoria', 'severidad', 'confianza', 'activo', 'tecnica',
             'descripcion', 'impacto_cliente', 'recomendacion', 'esfuerzo')
    for finding in data['findings']:
        if not isinstance(finding, dict) or not all(isinstance(finding.get(k), str) for k in texts):
            raise ValueError('hallazgo inválido')
        if finding['severidad'] not in SEVERITY_ORDER or finding['confianza'] not in CONFIDENCE_ORDER:
            raise ValueError('confianza/severidad inválida')
        score = finding.get('cvss')
        if score is not None and (type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 10):
            raise ValueError('CVSS inválido')
        if finding.get('cve') is not None and not isinstance(finding['cve'], str):
            raise ValueError('CVE inválido')
        if not isinstance(finding.get('referencias', []), list) or not all(isinstance(x, str) for x in finding.get('referencias', [])):
            raise ValueError('referencias inválidas')
        if not isinstance(finding.get('evidencia'), list):
            raise ValueError('evidencia inválida')
        for proof in finding['evidencia']:
            if not isinstance(proof, dict) or not all(isinstance(proof.get(k), str) for k in ('archivo', 'extracto')):
                raise ValueError('evidencia inválida')
            line = proof.get('linea')
            if line is not None and (type(line) is not int or line < 1):
                raise ValueError('línea de evidencia inválida')


def scope(data: dict, objetivo: str | None, todos: bool, incluir_sin_objetivo: bool) -> None:
    if todos:
        return
    if not objetivo:
        raise ValueError('indique --objetivo o --todos explícitamente')
    meta = data['meta']
    if meta.get('modo') == 'todos':
        raise ValueError('registro multiobjetivo requiere --todos')
    hosts = list(data['objetivos']) + list(data['activos'])
    hosts += [asset['host'] for asset in data['activos'].values()]
    hosts += [f['activo'] for f in data['findings']]
    hosts += [item.get('objetivo', '') for item in data.get('cobertura', []) if item.get('objetivo')]
    if meta.get('objetivo'):
        hosts.append(meta['objetivo'])
    for host in hosts:
        if host in ('', 'sin objetivo atribuible'):
            if incluir_sin_objetivo:
                continue
            raise ValueError('registro sin objetivo atribuible requiere permiso explícito')
        if not belongs_to(host, objetivo):
            raise ValueError('registro contiene otro objetivo; use --todos solo si corresponde')
