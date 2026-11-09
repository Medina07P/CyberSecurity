"""Fuentes compartidas; cada operación emite un resultado, también si falla."""
import re
from urllib.parse import urlencode, urlsplit

from .model import Evidence, SourceResult
from .runtime import SourceError, run_tool


def in_domain(name, domain):
    return name == domain or name.endswith('.' + domain)


def collect(run, key, operation):
    cache_key = ('result', key)
    if cache_key not in run.cache:
        try:
            result = operation()
        except SourceError as exc:
            result = SourceResult(key, exc.status, [], str(exc))
        except (ValueError, TypeError, KeyError, UnicodeError):
            result = SourceResult(key, 'failed', [], 'Respuesta de fuente inválida')
        run.cache[cache_key] = result
        run.results.append(result)
    return run.cache[cache_key]


def evidence_result(source, evidence):
    # Deduplicación dentro de fuente, no se borra procedencia de otras fuentes.
    unique = list({(e.kind, e.value, e.attribution): e for e in evidence}.values())
    return SourceResult(source, 'ok' if unique else 'empty', unique)


def collect_site(run, client, url):
    def operation():
        response = client.request('site', url)
        content_type = response.headers.get('content-type', '').lower()
        html = response.body.decode('utf-8', errors='replace')
        if content_type and 'html' not in content_type:
            raise SourceError('failed', 'El sitio no devolvió HTML')
        if not re.search(r'<[a-zA-Z][^>]*>', html):
            raise SourceError('failed', 'Respuesta web no interpretable como HTML')
        if re.search(r'(captcha|cf-chl-|verify you are human|access denied)', html, re.I):
            raise SourceError('blocked', 'Sitio presenta un bloqueo o CAPTCHA; no se evade')
        run.cache['site:html'], run.cache['site:url'] = html, response.final_url
        # Referencia del documento observado; no vulnerabilidad ni propiedad.
        return evidence_result('site', [Evidence('page', response.final_url, url, 'observado', 'Documento HTML consultado')])
    return collect(run, 'site', operation)


def collect_certificates(run, client, domain):
    def operation():
        url = 'https://crt.sh/?' + urlencode({'q': '%.' + domain, 'output': 'json'})
        data = client.request('crtsh', url).json()
        if not isinstance(data, list):
            raise SourceError('failed', 'crt.sh no devolvió una lista de certificados')
        evidence = []
        for row in data:
            if not isinstance(row, dict) or not isinstance(row.get('name_value'), str):
                raise SourceError('failed', 'Certificado sin name_value válido')
            for name in row['name_value'].splitlines():
                name = name.strip().rstrip('.').lower()
                if '*' not in name and in_domain(name, domain) and re.fullmatch(r'[a-z0-9.-]+', name):
                    evidence.append(Evidence('subdomain', name, 'crt.sh', 'descubierto', 'Nombre en certificado; no implica resolución actual'))
        return evidence_result('crtsh', evidence)
    return collect(run, 'crtsh', operation)


def collect_tool(run, tool, domain):
    def operation():
        if tool == 'theHarvester':
            # Kali discovery/{bravesearch,huntersearch,crtsh}.py inspeccionados
            # 2026-11-09: reintentos internos y excepciones convertidas en listas
            # vacías. No hay presupuesto de solicitudes/estado fiable desde CLI.
            return SourceResult(tool, 'skipped', [], 'Sin integración compatible con presupuesto y errores; se usan adaptadores directos')
        if tool == 'whois':
            argv = ['whois', domain]
        elif tool == 'whatweb':
            argv = ['whatweb', '-a', '1', '--color=never', 'https://' + domain]
        else:
            raise SourceError('skipped', 'Herramienta no integrada')
        result = run_tool(argv, run.limits.tool_seconds)
        text = result.stdout.strip()
        if re.search(r'(rate.?limit|quota exceeded|access denied|connection refused)', text, re.I):
            raise SourceError('blocked', 'Herramienta reporta bloqueo de la fuente')
        return evidence_result(tool, [Evidence('raw', text, tool, 'observado', 'Salida de herramienta; no hallazgo de vulnerabilidad')] if text else [])
    return collect(run, tool, operation)
