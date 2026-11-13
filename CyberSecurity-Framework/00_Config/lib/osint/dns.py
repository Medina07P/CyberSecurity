"""DNS acotado y wildcard conservador. Solo consultas DNS, nunca AXFR."""
import ipaddress
import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .model import Evidence, SourceResult
from .runtime import SourceError, run_tool
from .sources import collect, evidence_result, in_domain


def normalize_domain(value):
    try:
        value = value.strip().rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('Dominio inválido') from None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('Se necesita un dominio, no una IP')
    if len(value) > 253 or '.' not in value or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')
    ):
        raise ValueError('Dominio inválido')
    return value


@dataclass
class DnsAnswer:
    name: str
    status: str
    records: dict[str, list[str]]


class DnsLimiter:
    def __init__(self, qps=5, clock=time.monotonic, sleep=time.sleep, seconds=120):
        if not 0 < qps <= 5:
            raise ValueError('DNS permite como máximo 5 consultas por segundo')
        self.clock, self.sleep, self.interval = clock, sleep, 1 / qps
        self.started, self.next_call, self.seconds = clock(), clock(), seconds
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            wait = max(0, self.next_call - self.clock())
            if self.clock() - self.started + wait >= self.seconds:
                raise SourceError('timeout', 'Presupuesto DNS agotado')
            if wait:
                self.sleep(wait)
            self.next_call = self.clock() + self.interval

    def remaining(self):
        return max(0, self.seconds - (self.clock() - self.started))


def validate_resolver(resolver):
    if resolver:
        try:
            ipaddress.ip_address(resolver)
        except ValueError:
            raise ValueError('El resolver debe ser una IP explícita') from None
    return resolver or None


def resolve_name(name, resolver, limiter):
    name = normalize_domain(name)
    resolver = validate_resolver(resolver)
    records = {}
    for kind in ('A', 'AAAA', 'CNAME'):
        try:
            limiter.wait()
            argv = ['dig', *(['@' + resolver] if resolver else []), name, kind,
                    '+tries=1', '+time=3', '+noall', '+comments', '+answer']
            result = run_tool(argv, min(4, limiter.remaining()))
        except SourceError as exc:
            if exc.status == 'skipped':
                raise
            return DnsAnswer(name, 'timeout' if exc.status == 'timeout' else 'failed', records)
        status = re.search(r'status:\s*(\w+)', result.stdout)
        if not status or status[1] not in ('NOERROR', 'NXDOMAIN'):
            return DnsAnswer(name, 'failed', records)
        if status[1] == 'NXDOMAIN':
            return DnsAnswer(name, 'absent', {})
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[2] == 'IN' and fields[3] in ('A', 'AAAA', 'CNAME'):
                rrtype, value = fields[3:5]
                try:
                    value = str(ipaddress.ip_address(value)) if rrtype != 'CNAME' else normalize_domain(value)
                except ValueError:
                    return DnsAnswer(name, 'failed', records)
                records.setdefault(rrtype, []).append(value)
    records = {kind: sorted(set(values)) for kind, values in records.items()}
    return DnsAnswer(name, 'resolved' if records else 'absent', records)


def load_wordlist(path, domain, limit):
    domain = normalize_domain(domain)
    # Evitar leer ficheros enormes antes de aplicar el límite de candidatos.
    names = dict()
    with Path(path).open(encoding='utf-8') as stream:
        for raw in stream:
            if len(raw) > 1024:
                raise ValueError('Línea de diccionario demasiado larga')
            label = raw.strip().lower()
            if not label or label.startswith('#'):
                continue
            name = normalize_domain(label + '.' + domain)
            names[name] = None
            if len(names) > limit:
                raise ValueError(f'Diccionario supera {limit} candidatos únicos')
    if not names:
        raise ValueError('Diccionario sin candidatos')
    return list(names)


def _signature(answer):
    return tuple(sorted((kind, tuple(sorted(set(values)))) for kind, values in answer.records.items()))


def _resolve_batch(run, source, domain, names, resolver):
    limiter = run.cache.setdefault('dns:limiter', DnsLimiter(run.limits.dns_qps, seconds=run.limits.tool_seconds))
    evidence, controls, failures, processed = [], [], 0, 0
    for _ in range(3):
        answer = resolve_name('osint-control-' + uuid4().hex[:16] + '.' + domain, resolver, limiter)
        if answer.status in ('failed', 'timeout'):
            return SourceResult(source, answer.status, [], 'No se pudo establecer control wildcard; DNS detenido')
        controls.append(_signature(answer))
    positive = [s for s in controls if s]
    rotating = bool(positive) and len(set(controls)) > 1
    any_failure = False
    for name in names:
        if limiter.remaining() <= 0:
            return SourceResult(source, 'timeout', evidence, f'DNS parcial: {processed}/{len(names)} candidatos; presupuesto agotado')
        answer = resolve_name(name, resolver, limiter)
        processed += 1
        if answer.status in ('failed', 'timeout'):
            failures += 1
            any_failure = True
            if failures >= 3 or answer.status == 'timeout':
                return SourceResult(source, answer.status, evidence, f'DNS parcial: {processed}/{len(names)}; fallos persistentes o timeout')
            continue
        failures = 0
        if answer.status == 'resolved':
            ambiguous = bool(positive) and (rotating or _signature(answer) in positive)
            evidence.append(Evidence('dns', name, source, 'ambiguo_wildcard' if ambiguous else 'resuelto',
                                     json.dumps(answer.records, sort_keys=True)))
    result = evidence_result(source, evidence)
    if any_failure:
        result.status = 'failed'
    result.error = f'DNS: {processed}/{len(names)} candidatos procesados; ambiguos no son descubrimientos confirmados'
    return result


def enumerate_dns(run, domain, wordlist, resolver=None, confirmed=False):
    if not confirmed:
        raise ValueError('Se requiere confirmación DNS_SI')
    domain = normalize_domain(domain)
    resolver = validate_resolver(resolver)
    names = load_wordlist(wordlist, domain, run.limits.dns_candidates)
    return collect(run, 'dns_bruteforce', lambda: _resolve_batch(run, 'dns_bruteforce', domain, names, resolver))


def resolve_discovered(run, domain, names, resolver=None):
    domain = normalize_domain(domain)
    resolver = validate_resolver(resolver)
    clean = sorted({normalize_domain(name) for name in names if in_domain(name, domain)})
    if len(clean) > run.limits.dns_candidates:
        return collect(run, 'dns', lambda: SourceResult('dns', 'timeout', [], 'Demasiados nombres; no se inició resolución'))
    if not clean:
        return collect(run, 'dns', lambda: SourceResult('dns', 'empty', []))
    return collect(run, 'dns', lambda: _resolve_batch(run, 'dns', domain, clean, resolver))
