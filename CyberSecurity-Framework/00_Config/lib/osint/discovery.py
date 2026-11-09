"""Enlaces observados y APIs de búsqueda; una coincidencia no es atribución."""
import html as html_module
import re
from html.parser import HTMLParser
from urllib.parse import unquote, urlencode, urljoin, urlsplit, urlunsplit

from .model import Evidence, SourceResult
from .runtime import SourceError
from .sources import collect, collect_site, evidence_result, in_domain


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            self.links.extend(value for key, value in attrs if key == 'href' and value)


def profile_url(value):
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or '').lower()
        if parsed.scheme not in ('https', 'http') or parsed.username or parsed.password or parsed.port not in (None, 80, 443):
            return None
        host = host.removeprefix('www.')
        path = unquote(parsed.path).strip('/')
        parts = path.split('/')
        reserved = {'search', 'login', 'signup', 'home', 'explore', 'intent', 'share', 'sharer.php',
                    'settings', 'about', 'privacy', 'terms', 'help', 'accounts', 'p', 'reel', 'watch', 'i'}
        if not parts or parts[0].lower() in reserved:
            return None
        if host == 'linkedin.com':
            valid = len(parts) == 2 and parts[0] in ('company', 'school', 'in')
        elif host == 'tiktok.com':
            valid = len(parts) == 1 and path.startswith('@')
        else:
            valid = host in ('github.com', 'instagram.com', 'facebook.com', 'twitter.com', 'x.com') and len(parts) == 1
        if not valid or not re.fullmatch(r'@?[\w.-]+', parts[-1]) or parts[-1] in ('.', '..'):
            return None
        host = 'x.com' if host == 'twitter.com' else host
        return urlunsplit(('https', host, '/' + path, '', ''))
    except ValueError:
        return None


def extract_profiles(html, page_url, official):
    parser = Links(); parser.feed(html)
    result = {}
    for link in parser.links:
        url = profile_url(urljoin(page_url, link))
        if url:
            result[url] = Evidence('profile', url, page_url,
                                   'vinculado_desde_sitio' if official else 'candidato',
                                   'Enlace observado; no acredita propiedad ni disponibilidad del perfil')
    return list(result.values())


def extract_emails(text, domain, source):
    decoded = html_module.unescape(unquote(text))
    matches = re.findall(r'(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])', decoded)
    values = sorted({m.lower() for m in matches if m.rsplit('@', 1)[1].lower() == domain.lower()
                     and not m.startswith('.') and '..' not in m and len(m) <= 254})
    return [Evidence('email', value, source, 'publicado', 'Dirección observada; entregabilidad no comprobada') for value in values]


def _site_profiles(run, domain):
    page = run.cache.get('site:url', '')
    official = bool(page and in_domain((urlsplit(page).hostname or '').lower(), domain))
    return evidence_result('site_profiles', extract_profiles(run.cache.get('site:html', ''), page, official))


def discover_social(run, client, company, domain, keys):
    results = []
    if domain:
        results.append(collect_site(run, client, 'https://' + domain + '/'))
        if results[-1].status == 'ok':
            results.append(collect(run, 'site_profiles', lambda: _site_profiles(run, domain)))

    def github():
        # docs.github.com/rest/search/search#search-users, consultado 2026-11-09.
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if keys.get('github'):
            headers['Authorization'] = 'Bearer ' + keys['github']
        url = 'https://api.github.com/search/users?' + urlencode({'q': company, 'per_page': 30})
        data = client.request('github', url, headers).json()
        if not isinstance(data, dict) or not isinstance(data.get('items'), list):
            raise SourceError('failed', 'GitHub no devolvió items válidos')
        evidence = []
        for row in data['items']:
            if not isinstance(row, dict) or not isinstance(row.get('html_url'), str):
                raise SourceError('failed', 'Cuenta GitHub sin html_url válida')
            url = profile_url(row['html_url'])
            if url and urlsplit(url).hostname == 'github.com':
                evidence.append(Evidence('profile', url, 'github', 'candidato', f'Coincidencia de búsqueda: {company}; no prueba pertenencia'))
        result = evidence_result('github', evidence)
        if data.get('incomplete_results'):
            result.status, result.error = 'timeout', 'GitHub indica resultados incompletos'
        elif data.get('total_count', 0) > len(data['items']):
            result.error = 'Cobertura limitada a primera página (30 cuentas)'
        return result
    results.append(collect(run, 'github', github))

    def brave():
        if not keys.get('brave'):
            return SourceResult('brave', 'skipped', [], 'Sin clave Brave; no se realizó búsqueda web general')
        evidence = []
        # Contrato contrastado con Brave Search MCP oficial y Kali bravesearch.py.
        for host in ('linkedin.com', 'x.com', 'github.com', 'instagram.com', 'facebook.com', 'tiktok.com'):
            query = f'"{company}" site:{host}'
            url = 'https://api.search.brave.com/res/v1/web/search?' + urlencode({'q': query, 'count': 10})
            data = client.request('brave', url, {'Accept': 'application/json', 'X-Subscription-Token': keys['brave']}).json()
            if not isinstance(data, dict) or not isinstance(data.get('web'), dict) or not isinstance(data['web'].get('results'), list):
                raise SourceError('failed', 'Brave no devolvió resultados web válidos')
            for row in data['web']['results']:
                if not isinstance(row, dict) or not isinstance(row.get('url'), str):
                    raise SourceError('failed', 'Resultado Brave sin URL válida')
                profile = profile_url(row['url'])
                if profile:
                    evidence.append(Evidence('profile', profile, 'brave', 'candidato', f'Búsqueda: {query}; primera página, sin atribución'))
        return evidence_result('brave', evidence)
    results.append(collect(run, 'brave', brave))
    return results


def discover_emails(run, client, domain, keys):
    results = [collect_site(run, client, 'https://' + domain + '/')]
    if results[0].status == 'ok':
        results.append(collect(run, 'site_emails', lambda: evidence_result('site_emails', extract_emails(
            run.cache['site:html'], domain, run.cache['site:url']))))

    def hunter():
        if not keys.get('hunter'):
            return SourceResult('hunter', 'skipped', [], 'Sin clave Hunter; no consultado')
        # hunter.io/api-documentation/v2, 2026-11-09: X-API-KEY admitido;
        # preferir cabecera a query para que URLs nunca contengan secretos.
        url = 'https://api.hunter.io/v2/domain-search?' + urlencode({'domain': domain, 'limit': 10})
        data = client.request('hunter', url, {'X-API-KEY': keys['hunter'], 'Accept': 'application/json'}).json()
        if not isinstance(data, dict) or not isinstance(data.get('data'), dict) or not isinstance(data['data'].get('emails'), list):
            raise SourceError('failed', 'Hunter no devolvió emails válidos')
        evidence = []
        for row in data['data']['emails']:
            if not isinstance(row, dict) or not isinstance(row.get('value'), str):
                raise SourceError('failed', 'Email Hunter con formato inválido')
            evidence.extend(extract_emails(row['value'], domain, 'hunter'))
        result = evidence_result('hunter', evidence)
        result.error = 'Cobertura limitada a primera página (10 direcciones); sin verificación de entregabilidad'
        return result
    results.append(collect(run, 'hunter', hunter))
    return results
