"""Puertos observados en archivos Masscan/RustScan; no acredita último intento."""
import ipaddress
import json
from pathlib import Path
import re

from lib.catalog import build
from lib.coverage import regular
from lib.model import Evidence, ParseResult, relpath
from lib.sources import register

LIMIT = 'finalización y actualidad no acreditadas'
_SGR = re.compile(r'\x1b\[[0-9;]*m')


def _host(value):
    if not isinstance(value, str) or not value:
        raise ValueError('host inválido')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if (len(value) > 253 or re.fullmatch(r'[0-9.]+', value)
                or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                           for label in value.rstrip('.').split('.'))):
            raise ValueError('host inválido') from None
        return value.lower().rstrip('.')


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError('puerto inválido')
    return value


def _problem(result, archivo, reason):
    result.no_evaluable.append({'fuente': archivo, 'motivo': reason + '; ' + LIMIT})


def _add(result, kind, archivo, host, port, proto, position):
    asset = next((a for a in result.activos if a['host'] == host), None)
    if asset is None:
        asset = {'host': host, 'puertos': []}
        result.activos.append(asset)
    key = f'nmap.open_port:{proto}:{host}:{port}'
    if any(f.key == key for f in result.findings):
        return
    asset['puertos'].append({'puerto': port, 'protocolo': proto})
    activo = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    result.findings.append(build(
        kind + '.open_port', key=key, activo=activo,
        evidencia=[Evidence(archivo, None, f'{position}: {host} {port}/{proto} open')],
        variables={'puerto': str(port), 'protocolo': proto},
    ))


def parse_masscan(path: Path, repo_root: Path) -> ParseResult:
    archivo = relpath(path, repo_root)
    result = ParseResult(evaluado=False)
    try:
        data = json.loads(regular(path).read_text(encoding='utf-8'))
        if not isinstance(data, list):
            raise ValueError('array requerido')
    except (OSError, ValueError):
        _problem(result, archivo, 'JSON Masscan no evaluable')
        return result
    for number, record in enumerate(data, 1):
        try:
            if not isinstance(record, dict):
                raise ValueError('registro inválido')
            host = str(ipaddress.ip_address(record['ip'])) if isinstance(record.get('ip'), str) else ''
            if not host or not isinstance(record.get('ports'), list):
                raise ValueError('registro inválido')
            if not any(a['host'] == host for a in result.activos):
                result.activos.append({'host': host, 'puertos': []})
        except (KeyError, ValueError, TypeError):
            _problem(result, archivo, f'Registro {number} inválido')
            continue
        for index, port in enumerate(record['ports'], 1):
            try:
                if not isinstance(port, dict):
                    raise ValueError('puerto inválido')
                value = _port(port.get('port'))
                proto, state = port.get('proto'), port.get('status')
                if proto not in ('tcp', 'udp') or state not in ('open', 'closed', 'filtered'):
                    raise ValueError('estado/protocolo inválido')
                if state == 'open':
                    _add(result, 'masscan', archivo, host, value, proto, f'registro {number}/puerto {index}')
            except (ValueError, TypeError):
                _problem(result, archivo, f'Registro {number}/puerto {index} inválido')
    result.evaluado = bool(result.findings)
    if not result.evaluado:
        _problem(result, archivo, 'Sin observaciones de puertos abiertos verificables')
    return result


def parse_rustscan(path: Path, repo_root: Path) -> ParseResult:
    archivo = relpath(path, repo_root)
    result = ParseResult(evaluado=False)
    with regular(path).open(encoding='utf-8', errors='replace', newline='') as stream:
        text = stream.read()
    for number, raw in enumerate(text.split('\n'), 1):
        if raw.endswith('\r'):
            raw = raw[:-1]  # CRLF, no otros separadores de control.
        line = _SGR.sub('', raw)
        if not line.strip():
            continue
        try:
            if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in line):
                raise ValueError('control no permitido')
            match = re.fullmatch(r'Open (\[[0-9A-Fa-f:]+\]|[^\s:]+):([0-9]+)', line.strip())
            if match:
                host = _host(match[1][1:-1] if match[1].startswith('[') else match[1])
                ports = [_port(int(match[2]))]
            else:
                match = re.fullmatch(r'(\S+)\s*->\s*\[\s*([0-9 ,]*)\s*\]', line.strip())
                if not match:
                    raise ValueError('formato no admitido')
                host = _host(match[1])
                ports = [_port(int(p.strip())) for p in match[2].split(',')] if match[2].strip() else []
            if not any(a['host'] == host for a in result.activos):
                result.activos.append({'host': host, 'puertos': []})
            for port in ports:
                _add(result, 'rustscan', archivo, host, port, 'tcp', f'línea {number}')
        except ValueError:
            _problem(result, archivo, f'Línea {number} no admitida')
    result.evaluado = bool(result.findings)
    if not result.evaluado:
        _problem(result, archivo, 'Sin observaciones de puertos abiertos verificables')
    return result


register('masscan', parse_masscan)
register('rustscan', parse_rustscan)
