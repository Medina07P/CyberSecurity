#!/usr/bin/env python3
"""Flujos HTTP de 04: todas las operaciones originales, con evidencia y frenos."""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

from enumeration_evidence import name, publish


class ProbeError(Exception):
    pass


def append_path(url, path):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip('/')+'/'+path.lstrip('/'), parts.query, ''))


def retry_delay(value):
    try:
        return max(0, int(value))
    except (ValueError, TypeError):
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None: date = date.replace(tzinfo=timezone.utc)
            return max(0, (date-datetime.now(timezone.utc)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return 1


@dataclass
class Response:
    url: str
    code: int
    body: bytes
    headers: str

    @property
    def signature(self):
        return self.code, len(self.body), hashlib.sha256(self.body).hexdigest()


class Session:
    def __init__(self, url, directory):
        parts = urlsplit(url)
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username is not None or parts.password is not None or parts.fragment:
            raise ProbeError('URL HTTP(S) no válida o con credenciales/fragmento')
        if any(c.isspace() or ord(c) < 32 for c in url) or '\\' in url:
            raise ProbeError('URL no válida')
        self.host = parts.hostname.lower().rstrip('.')
        self.port = parts.port or (443 if parts.scheme == 'https' else 80)
        if not 1 <= self.port <= 65535: raise ProbeError('Puerto no válido')
        self.url = url
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.work_context = tempfile.TemporaryDirectory(prefix='.http.', dir=self.directory)
        self.work = Path(self.work_context.name)
        self.log = self.directory/'errores.log'
        self.counter = 0

    def close(self):
        self.work_context.cleanup()

    def diagnostic(self, message):
        with self.log.open('a') as stream:
            stream.write(f'\n[{datetime.now(timezone.utc).isoformat()}] {self.url}: {message}\n')
        print(f'Diagnóstico actual: {self.log}', file=__import__('sys').stderr)

    def request(self, url, method='GET'):
        for attempt in range(2):
            self.counter += 1
            body = self.work/f'{self.counter}.data'
            headers = self.work/f'{self.counter}.headers'
            command = ['curl', '-q', '--noproxy', '*', '--connect-timeout', '5', '--max-time', '15',
                       '-skS', '-X', method, '-D', str(headers), '-o', str(body), '-w', '%{http_code}', '--url', url]
            if method == 'HEAD': command.insert(2, '--head')
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=17)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ProbeError(f'curl: {exc}') from exc
            if result.stderr: self.diagnostic(result.stderr)
            code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            if result.returncode or not 100 <= code <= 599 or not body.exists() or not headers.exists():
                raise ProbeError(f'petición {method} fallida, rc={result.returncode}, HTTP={code}: NO_DETERMINADO')
            response = Response(url, code, body.read_bytes(), headers.read_text(errors='replace'))
            if code not in (429, 503): return response
            self.diagnostic(f'FRENO HTTP {code} en {method}; intento {attempt+1}')
            if attempt: raise ProbeError(f'FRENO HTTP {code} persistente: se corta la tanda sin puntuar')
            value = next((line.split(':',1)[1].strip() for line in response.headers.splitlines() if line.lower().startswith('retry-after:')), '1')
            delay = retry_delay(value)
            if delay > 15: raise ProbeError('Retry-After supera presupuesto de 15s; no se reintenta antes de tiempo')
            time.sleep(delay)
        raise ProbeError('petición no determinada')

    def destination(self, prefix, extension='txt'):
        return self.directory/str(Path(name(prefix, self.host, self.port, self.url)).with_suffix('.'+extension))

    def save(self, prefix, data, state='EJECUTADO', extension='txt'):
        source = self.work/(prefix+'.data')
        source.write_bytes(data if isinstance(data, bytes) else data.encode())
        dest = self.destination(prefix, extension)
        publish(source, dest, self.host, self.port, self.directory.name, state, url=self.url)
        return dest

    def tool(self, prefix, command):
        if not shutil.which(command[0]):
            print(f'{command[0]} no instalado: OMITIDO; la capacidad sigue disponible al instalarlo.')
            publish('', self.destination(prefix), self.host, self.port, command[0], 'OMITIDO', url=self.url)
            return
        try:
            result = subprocess.run(command, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProbeError(str(exc)) from exc
        if result.stderr: self.diagnostic(result.stderr.decode(errors='replace'))
        if result.returncode: raise ProbeError(f'{command[0]} falló: rc={result.returncode}')
        self.save(prefix, result.stdout)

    def ffuf(self, baseline):
        if not shutil.which('ffuf'):
            print('ffuf no instalado: OMITIDO; no se ha hecho fuzzing.')
            publish('', self.destination('ffuf','json'), self.host, self.port, 'ffuf', 'OMITIDO', url=self.url)
            return
        command = ['ffuf', '-w', '/usr/share/wordlists/dirb/common.txt', '-u', append_path(self.url, 'FUZZ'),
                   '-mc', 'all', '-fc', '404', '-t', '20', '-json']
        results, pending = [], b''
        error = self.work/'ffuf.err'
        with error.open('wb') as stream:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stream, start_new_session=True)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic()+30
            previous_handler = signal.getsignal(signal.SIGTERM)
            def terminate(signum, frame):
                raise ProbeError('Cancelación SIGTERM: detener ffuf y no puntuar')
            signal.signal(signal.SIGTERM, terminate)
            try:
                while selector.get_map():
                    if time.monotonic() > deadline: raise ProbeError('ffuf: timeout de 30s')
                    for key, _ in selector.select(timeout=0.2):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        pending += data
                        while b'\n' in pending:
                            line, pending = pending.split(b'\n', 1)
                            try: row = json.loads(line)
                            except ValueError: continue
                            if not isinstance(row, dict): continue
                            row = row.get('result', row)
                            if not isinstance(row, dict) or 'status' not in row: continue
                            if row['status'] in (429, 503): raise ProbeError('ffuf: FRENO HTTP; tanda detenida sin puntuar (puede haber peticiones ya en vuelo)')
                            if row['status'] in (200,301,302,403) and not (baseline and row['status'] == baseline.code and row.get('length') == len(baseline.body)):
                                results.append(row)
                if process.wait(timeout=2): raise ProbeError('ffuf terminó con error')
            except BaseException:
                if process.poll() is None: os.killpg(process.pid, signal.SIGTERM)
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                raise
            finally:
                signal.signal(signal.SIGTERM, previous_handler)
                selector.close()
                process.stdout.close()
                if error.stat().st_size: self.diagnostic(error.read_text(errors='replace'))
        self.save('ffuf', json.dumps({'results': results}), extension='json')
        print(f'Fuzzing completado: {len(results)} candidatos tras filtrar baseline; requieren revisión.')


def baseline(session):
    response = session.request(append_path(session.url, 'enum_probe_'+uuid.uuid4().hex))
    return response if response.code in (200,301,302,403) else None


def same(response, base):
    return base is not None and response.signature == base.signature


def web(session):
    session.request(session.url)
    base = baseline(session)
    headers = session.request(session.url, 'HEAD')
    session.save('headers', headers.headers)
    session.tool('technologies', ['whatweb', '-a', '3', session.url])
    robots = session.request(append_path(session.url, 'robots.txt'))
    session.save('robots', robots.body)
    if same(robots, base): print('robots.txt: CATCH_ALL, no se confirma el archivo.')
    sitemap = session.request(append_path(session.url, 'sitemap.xml'))
    session.save('sitemap', sitemap.body, extension='xml')
    session.ffuf(base)


def advanced(session):
    session.request(session.url)
    base = baseline(session)
    headers = session.request(session.url, 'HEAD')
    selected = '\n'.join(line for line in headers.headers.splitlines() if line.lower().startswith(('x-frame-options:', 'x-content-type-options:', 'content-security-policy:', 'strict-transport-security:')))
    session.save('security_headers', selected)
    rows = []
    for path in ('.env','.git/config','backup.zip','config.php','wp-config.php','.htaccess','admin.php'):
        response = session.request(append_path(session.url, path))
        if response.code in (200,301,302,403) and not same(response, base):
            rows.append(f'{response.url}|{response.code}|CANDIDATO (requiere revisar contenido)')
    session.save('sensitive_files', '\n'.join(rows))


def api(session):
    session.request(session.url)
    base = baseline(session)
    endpoints = []
    for endpoint in ('api','v1','v2','rest','graphql','swagger','docs','openapi','apidocs','api/v1','api/v2','api/rest'):
        response = session.request(append_path(session.url, endpoint))
        state = 'CATCH_ALL' if same(response, base) else 'RESPUESTA'
        endpoints.append(f'{response.url}\t{response.code}\t{state}')
    session.save('endpoints', 'url\tcodigo\testado\n'+'\n'.join(endpoints), extension='tsv')
    methods = []
    for method in ('GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'):
        response = session.request(append_path(session.url, 'api'), method)
        if method == 'HEAD' and 200 <= response.code < 300: state='RESPUESTA_HEAD (sin prueba de endpoint)'
        elif same(response, base): state='CATCH_ALL'
        elif 200 <= response.code < 300: state='RESPUESTA_2XX'
        elif response.code == 405: state='NO_PERMITIDO'
        elif response.code in (401,403): state='DENEGADO'
        else: state='NO_DETERMINADO'
        methods.append(f'{method}\t{response.code}\t{response.url}\t{state}')
    session.save('methods', 'metodo\tcodigo\turl\tclasificacion\n'+'\n'.join(methods), extension='tsv')
    for document in ('swagger.json','openapi.json','api-docs'):
        response = session.request(append_path(session.url, document))
        if same(response, base) or response.code != 200: continue
        try: content = json.loads(response.body)
        except ValueError: continue
        if isinstance(content, dict) and isinstance(content.get('paths'), dict) and any(isinstance(content.get(k), str) for k in ('swagger','openapi')):
            session.save(document.replace('.','_'), response.body, extension='json')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('web','advanced','api','request','invalidate'))
    parser.add_argument('--url', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--method', default='GET')
    args = parser.parse_args()
    session = None
    try:
        session = Session(args.url, args.output)
        print(f'{args.mode}: {args.url} — todas las operaciones declaradas se mantienen.')
        if args.mode == 'invalidate':
            raise ProbeError('Sonda TCP sin evidencia concluyente; HTTP no evaluado')
        elif args.mode == 'request':
            response = session.request(args.url, args.method)
            session.save('response', response.body)
            session.save('response_headers', response.headers)
        else:
            globals()[args.mode](session)
        return 0
    except (ProbeError, ValueError, OSError) as exc:
        if session:
            session.diagnostic(str(exc))
            # Conservar bytes históricos, pero nunca presentarlos como éxito
            # del intento HTTP que acaba de fallar (incluida una tanda parcial).
            for sidecar in session.directory.glob('*.meta.json'):
                try:
                    previous = json.loads(sidecar.read_text())
                    if previous.get('version') == 1 and previous.get('url') == session.url:
                        dest = Path(str(sidecar)[:-len('.meta.json')])
                        publish('', dest, session.host, session.port, session.directory.name, 'NO_DETERMINADO', 1, session.url)
                except (ValueError, OSError):
                    continue
        print(f'NO_DETERMINADO: {exc}', file=__import__('sys').stderr)
        return 1
    finally:
        if session: session.close()


if __name__ == '__main__':
    raise SystemExit(main())
