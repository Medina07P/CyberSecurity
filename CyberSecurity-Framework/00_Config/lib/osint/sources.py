"""Fuentes compartidas; cada operación emite un resultado, también si falla."""
import re
from urllib.parse import urlencode, urlsplit

from .model import Evidence, SourceResult
from .runtime import SourceError, redact, run_tool


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
    # Import local: dns usa los contratos de sources; aquí el módulo ya está
    # inicializado. Compartir la validación evita aceptar SAN DNS malformados.
    from .dns import normalize_domain
    domain = normalize_domain(domain)
    cache_key = ('certificate_union', domain)
    if cache_key in run.cache:
        return run.cache[cache_key]

    def query(source, term):
        def operation():
            if 'crtsh' in client.stopped:
                return SourceResult(source, 'skipped', [], 'No consultada: proveedor crt.sh detenido por bloqueo o presupuesto')
            url = 'https://crt.sh/?' + urlencode({'q': term, 'output': 'json'})
            data = client.request('crtsh', url, independent_query=True).json()
            if not isinstance(data, list):
                raise SourceError('failed', 'crt.sh no devolvió una lista de certificados')
            evidence = []
            for row in data:
                if not isinstance(row, dict) or not isinstance(row.get('name_value'), str):
                    raise SourceError('failed', 'Certificado sin name_value válido')
                for raw in row['name_value'].splitlines():
                    if '*' in raw:
                        continue
                    try:
                        name = normalize_domain(raw)
                    except ValueError:
                        continue
                    if in_domain(name, domain):
                        evidence.append(Evidence('subdomain', name, source, 'descubierto',
                                                 'Nombre en certificado; no implica resolución actual'))
            return evidence_result(source, evidence)
        return collect(run, source, operation)

    exact = query('crtsh_exact', domain)
    wildcard = query('crtsh_wildcard', '%.' + domain)
    names = {}
    for result in (exact, wildcard):
        for entry in result.evidence:
            names.setdefault(entry.value, entry)
    union = evidence_result('crtsh', list(names.values()))
    for state in ('blocked', 'timeout', 'failed'):
        if any(result.status == state for result in (exact, wildcard)):
            union.status = state
            break
    if all(result.status == 'skipped' for result in (exact, wildcard)):
        union.status = 'skipped'
    union.error = '; '.join(f'{r.source}: {r.error}' for r in (exact, wildcard) if r.error)
    # La unión se devuelve a DNS pero NO añade otra fila duplicada al informe.
    run.cache[cache_key] = union
    return union


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
        diagnostic = redact(result.stderr.strip()[:2000], run.secrets)
        if diagnostic and (not text or re.search(r'(\berror\b|connection refused|timed out|failed|unable to connect)', diagnostic, re.I)):
            raise SourceError('failed', diagnostic)
        if tool == 'whatweb' and re.search(r'(ERROR Opening|Connection refused|Unable to connect)', text, re.I):
            raise SourceError('failed', redact(text[:2000], run.secrets))
        if re.search(r'(rate.?limit|quota exceeded|access denied|connection refused)', text, re.I):
            raise SourceError('blocked', 'Herramienta reporta bloqueo de la fuente')
        result = evidence_result(tool, [Evidence('raw', text, tool, 'observado', 'Salida de herramienta; no hallazgo de vulnerabilidad')] if text else [])
        result.error = diagnostic
        return result
    return collect(run, tool, operation)
