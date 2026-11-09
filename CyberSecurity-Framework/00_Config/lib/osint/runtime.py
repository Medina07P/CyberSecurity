"""Red, procesos y artefactos: fallos explícitos y presupuestos por fuente."""
import json
from http.client import HTTPException
import re
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .model import Limits


class SourceError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


@contextmanager
def absolute_deadline(seconds):
    """Kali/POSIX: incluye DNS, apertura, redirecciones y lectura por goteo.

    No degradar silenciosamente a timeout de inactividad en otros entornos.
    El CLI llama desde el hilo principal; DNS workers no usan este transporte.
    """
    if not hasattr(signal, 'setitimer') or threading.current_thread() is not threading.main_thread():
        raise SourceError('skipped', 'HTTP requiere plazos POSIX en el hilo principal; fuente no consultada')
    if signal.getitimer(signal.ITIMER_REAL)[0] > 0:
        raise SourceError('skipped', 'Temporizador POSIX ocupado; fuente HTTP no consultada')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(signum, frame):
        raise TimeoutError('Plazo HTTP absoluto agotado')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class SafeRedirect(HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 2

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # APIs con credenciales nunca siguen redirecciones: ni token en URL ni
        # cabecera puede acabar en otro servicio o en un downgrade HTTP.
        if getattr(req, 'osint_private', False):
            raise SourceError('blocked', 'Redirección de API rechazada')
        if urlsplit(newurl).scheme not in ('http', 'https'):
            raise SourceError('blocked', 'Esquema de redirección rechazado')
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        if result and urlsplit(req.full_url).netloc != urlsplit(newurl).netloc:
            result.remove_header('Authorization')
        return result


@dataclass
class HttpResponse:
    status: int
    headers: dict
    body: bytes
    final_url: str

    def json(self):
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeError):
            raise SourceError('failed', 'Respuesta JSON inválida') from None


class HttpClient:
    def __init__(self, limits=None, opener=None, clock=time.monotonic,
                 sleep=time.sleep, wall_clock=time.time):
        self.limits = limits or Limits()
        self.opener = opener or build_opener(SafeRedirect()).open
        self.clock, self.sleep, self.wall_clock = clock, sleep, wall_clock
        self.calls, self.started = {}, {}
        self.stopped = {}

    def request(self, source, url, headers=None):
        if source in self.stopped:
            raise self.stopped[source]
        self.started.setdefault(source, self.clock())
        try:
            return self._request(source, url, headers)
        except SourceError as exc:
            self.stopped[source] = exc
            raise

    def _request(self, source, url, headers):
        if urlsplit(url).scheme not in ('https', 'http'):
            raise SourceError('failed', 'URL HTTP inválida')
        for attempt in range(2):
            remaining = self.limits.tool_seconds - (self.clock() - self.started[source])
            if remaining <= 0 or self.calls.get(source, 0) >= self.limits.api_calls:
                raise SourceError('timeout', 'Presupuesto de fuente agotado')
            self.calls[source] = self.calls.get(source, 0) + 1
            request = Request(url, headers={'User-Agent': 'CyberSecurity-OSINT/1', **(headers or {})})
            request.osint_private = bool(headers) or 'api_key=' in url
            try:
                with absolute_deadline(min(remaining, self.limits.request_seconds)):
                    try:
                        response = self.opener(request, timeout=min(remaining, self.limits.request_seconds))
                    except HTTPError as exc:
                        response = exc
                    with response:
                        code = response.status if hasattr(response, 'status') else response.code
                        response_headers = {k.lower(): v for k, v in response.headers.items()}
                        if code not in (429, 503):
                            if code in (401, 403):
                                raise SourceError('blocked', f'HTTP {code}: acceso bloqueado o credencial rechazada')
                            if not 200 <= code < 300:
                                raise SourceError('failed', f'HTTP {code}')
                            body = response.read(2 * 1024 * 1024 + 1)
                            if len(body) > 2 * 1024 * 1024:
                                raise SourceError('failed', 'Respuesta supera 2 MiB')
                            return HttpResponse(code, response_headers, body, response.geturl())
            except (TimeoutError, OSError, URLError, HTTPException) as exc:
                state = 'timeout' if isinstance(exc, TimeoutError) else 'failed'
                raise SourceError(state, 'Error de transporte HTTP (detalle omitido para proteger secretos)') from None
            if attempt:
                raise SourceError('blocked', f'HTTP {code} persistente; fuente detenida')
            wait = self._retry_after(response_headers.get('retry-after', '1'))
            remaining = self.limits.tool_seconds - (self.clock() - self.started[source])
            if wait >= remaining:
                raise SourceError('blocked', 'Retry-After excede el presupuesto; fuente detenida')
            self.sleep(wait)
        raise SourceError('failed', 'Fuente sin respuesta')

    def _retry_after(self, value):
        try:
            return max(0, int(value))
        except ValueError:
            try:
                return max(0, parsedate_to_datetime(value).timestamp() - self.wall_clock())
            except (TypeError, ValueError, OverflowError):
                return 1


def run_tool(argv, timeout):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, errors='replace', timeout=timeout)
    except FileNotFoundError:
        raise SourceError('skipped', 'Herramienta no instalada') from None
    except subprocess.TimeoutExpired:
        raise SourceError('timeout', 'Tiempo de herramienta agotado') from None
    except OSError:
        raise SourceError('failed', 'No se pudo ejecutar la herramienta') from None
    if result.returncode:
        raise SourceError('failed', f'Herramienta terminó con código {result.returncode}')
    return result


def exit_code(results):
    if any(r.status in ('failed', 'blocked', 'timeout') for r in results):
        return 1
    return 0 if any(r.status in ('ok', 'empty') for r in results) else 1


def redact(text, secrets):
    for secret in sorted(filter(None, secrets), key=len, reverse=True):
        text = text.replace(secret, '[REDACTADO]')
    return text


def _redact_data(value, secrets):
    if isinstance(value, str):
        return redact(value, secrets)
    if isinstance(value, dict):
        return {key: _redact_data(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_data(item, secrets) for item in value]
    return value


def write_run(run):
    slug = re.sub(r'[^\w.-]+', '_', run.target)[:100] or 'objetivo'
    destination = Path(run.output) / f'osint_{slug}_{run.run_id}'
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    states = {'ok': 'CON RESULTADOS', 'empty': 'SIN RESULTADOS', 'skipped': 'OMITIDA',
              'blocked': 'BLOQUEADA', 'failed': 'FALLIDA', 'timeout': 'TIEMPO AGOTADO'}
    payload = {'version': 1, 'target': run.target, 'timestamp': run.timestamp,
               'run_id': run.run_id, 'exit_code': exit_code(run.results),
               'sources': [asdict(r) for r in run.results]}
    summary = [f'Objetivo: {run.target}', f'Fecha UTC: {run.timestamp}']
    errors = []
    for r in run.results:
        summary.append(f'{r.source}: {states[r.status]} ({len(r.evidence)}) {r.error}')
        summary.extend(f'  {e.kind}: {e.value} [{e.attribution}] — {e.source}: {e.detail}' for e in r.evidence)
        if r.error:
            errors.append(f'{r.source}: {r.error}')
    for name, text in [('resultados.json', json.dumps(_redact_data(payload, run.secrets), ensure_ascii=False, indent=2)),
                       ('resumen.txt', '\n'.join(summary)), ('errores.log', '\n'.join(errors))]:
        path = destination / name
        path.write_text((text if name == 'resultados.json' else redact(text, run.secrets)) + '\n', encoding='utf-8')
        path.chmod(0o600)
    return destination
