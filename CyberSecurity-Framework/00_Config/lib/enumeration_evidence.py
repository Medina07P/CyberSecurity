#!/usr/bin/env python3
"""Nombres acotados, publicación y selección de evidencia local de enumeración."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

STATES = {'EJECUTADO', 'CONFIRMADO', 'DENEGADO', 'CERRADO', 'FILTRADO', 'OMITIDO', 'NO_DETERMINADO'}


def name(prefix, host, port, url=''):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', prefix):
        raise ValueError('prefijo no válido')
    host = host.lower().rstrip('.')
    readable = re.sub(r'[^A-Za-z0-9.-]', '_', host)
    digest = hashlib.sha256((host+'|'+str(port)+'|'+url).encode()).hexdigest()[:16]
    if len(readable.encode()) > 140:
        readable = readable[:100]+'_'+digest
    suffix = '_'+digest if url else ''
    return f'{prefix}_{readable}_{port}{suffix}.txt'


def atomic_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.meta-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def publish(source, dest, host, port, tool, state, rc=0, url=''):
    if state not in STATES:
        raise ValueError('estado no válido')
    dest = Path(dest)
    metadata = {'version': 1, 'host': host.lower().rstrip('.'), 'puerto': int(port),
                'herramienta': tool, 'estado': state, 'fecha': datetime.now(timezone.utc).isoformat(),
                'rc': int(rc), 'url': url}
    # El intento más reciente se registra incluso si no se sustituye el resultado.
    atomic_json(str(dest)+'.attempt.json', metadata)
    if state not in ('NO_DETERMINADO', 'OMITIDO') and source and Path(source).is_file():
        os.replace(source, dest)
        atomic_json(str(dest)+'.meta.json', metadata)
    return metadata


def metadata(path):
    path = Path(path)
    for suffix in ('.attempt.json', '.meta.json'):
        sidecar = Path(str(path)+suffix)
        if sidecar.exists():
            try:
                data = json.loads(sidecar.read_text())
                if data.get('version') == 1 and data.get('estado') in STATES:
                    return data
            except (ValueError, OSError):
                pass
    return None


def classify(kind, output, error, rc):
    text = output + '\n' + error
    denied = {
        'ftp': r'(?m)^530\b', 'ldap': r'(?:ldap_bind:.*\((?:49|50)\)|result: (?:49|50)\b)',
        'smb': r'NT_STATUS_(?:ACCESS_DENIED|LOGON_FAILURE)',
        'mysql': r'ERROR 1045\b', 'postgres': r'FATAL:.*(?:password authentication failed|no pg_hba.conf entry)',
        'redis_info': r'(?m)^-NOAUTH\b', 'redis_keys': r'(?m)^-NOAUTH\b',
    }
    if kind in denied and re.search(denied[kind], text, re.I):
        return 'DENEGADO'
    if rc:
        return 'NO_DETERMINADO'
    if kind == 'nmap':
        if not re.search(r'^Nmap scan report for ', output, re.M): return 'NO_DETERMINADO'
        if re.search(r'^\d+/tcp\s+open\s', output, re.M): return 'EJECUTADO'
        if re.search(r'^\d+/tcp\s+closed\s', output, re.M): return 'CERRADO'
        if re.search(r'^\d+/tcp\s+(?:filtered|open\|filtered)\s', output, re.M): return 'FILTRADO'
        return 'NO_DETERMINADO'
    patterns = {
        'banner': r'(?m)^220\b', 'ftp': r'(?m)^230\b',
        'ldap': r'(?m)^dn:', 'smb': r'(?im)(user:\[|Sharename\s+Type|Domain Name:|blocks of size)',
        'mysql': r'(?m)^\d+\.\d+(?:\.\d+)?', 'postgres': r'(PostgreSQL \d+\.|List of databases)',
        'redis_info': r'(?m)^redis_version:\d+\.', 'redis_keys': r'(?m)^\*[0-9]+\s*$',
    }
    if kind == 'ldap' and re.search(r'result:\s*[1-9]', output): return 'NO_DETERMINADO'
    if kind in patterns and re.search(patterns[kind], output):
        return 'EJECUTADO' if kind == 'banner' else 'CONFIRMADO'
    return 'NO_DETERMINADO'


def show_results(root, host=''):
    root = Path(root)
    print('RESUMEN DE ENUMERACIONES — '+(host or 'todos los objetivos identificados'))
    found = False
    for service in ('ssh','ftp','smb','ldap','database','web','api','enumeration'):
        directory = root/service
        if not directory.exists(): continue
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.name.endswith(('.meta.json','.attempt.json')) or path.name == 'errores.log': continue
            info = metadata(path)
            if host and (not info or info.get('host') != host.lower().rstrip('.')): continue
            found = True
            if info:
                print(f'\n{service}: {info["host"]}:{info["puerto"]} — {info["estado"]} — {path.name}')
                if info['estado'] in ('NO_DETERMINADO','OMITIDO'):
                    print('Resultado histórico no utilizado como ejecución actual.'); continue
            else:
                print(f'\n{service}: sin atribución — {path.name}')
            if path.suffix in ('.txt','.tsv'):
                print('\n'.join(path.read_text(errors='replace').splitlines()[:8]))
    if not found: print('No hay resultados atribuibles para esta selección.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('name', 'publish', 'classify', 'list'))
    parser.add_argument('--prefix', default='resultado')
    parser.add_argument('--host', default='')
    parser.add_argument('--port', default=0, type=int)
    parser.add_argument('--root')
    parser.add_argument('--url', default='')
    parser.add_argument('--source', default='')
    parser.add_argument('--dest')
    parser.add_argument('--tool', default='enumeración')
    parser.add_argument('--state', default='EJECUTADO')
    parser.add_argument('--rc', default=0, type=int)
    parser.add_argument('--kind')
    parser.add_argument('--error', default='')
    args = parser.parse_args()
    try:
        if args.action == 'list':
            show_results(args.root, args.host)
        elif args.action == 'name':
            print(name(args.prefix, args.host, args.port, args.url))
        elif args.action == 'classify':
            print(classify(args.kind, Path(args.source).read_text(errors='replace'),
                           Path(args.error).read_text(errors='replace'), args.rc))
        else:
            publish(args.source, args.dest, args.host, args.port, args.tool, args.state, args.rc, args.url)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'No se pudo registrar evidencia: {exc}\n')


if __name__ == '__main__':
    main()
