"""Contexto de 01/02/07/08/10: metadata explícita, nunca cuerpos privados."""
from functools import lru_cache
import importlib
import importlib.util
from pathlib import Path
import re
import sys

from lib.attribution import belongs_to, guess_host
from lib.coverage import entry, walk
from lib.exploitation_metadata import read_object
from lib.validation import target


@lru_cache(maxsize=1)
def _inventory():
    # Reutilizar el lector metadata-only de 10; no verify(), no hashes/cuerpos.
    path = Path(__file__).resolve().parents[3] / '00_Config/lib/evidence/__init__.py'
    spec = importlib.util.spec_from_file_location('_reports_evidence', path,
                                                submodule_search_locations=[str(path.parent)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return importlib.import_module('.inventory', spec.name)


def _osint(path):
    data = read_object(path)
    if type(data.get('version')) is not int or data['version'] != 1:
        raise ValueError('versión OSINT inválida')
    host = target(data.get('target'))
    sources = data.get('sources')
    if not isinstance(sources, list) or not sources or type(data.get('exit_code')) is not int:
        raise ValueError('cobertura OSINT inválida')
    counts = {}
    records = 0
    for source in sources:
        if not isinstance(source, dict) or source.get('status') not in {'ok', 'empty', 'failed', 'blocked', 'timeout', 'omitted'}:
            raise ValueError('estado de fuente OSINT inválido')
        evidence = source.get('evidence')
        if not isinstance(evidence, list) or not all(isinstance(item, dict) for item in evidence):
            raise ValueError('evidencia OSINT inválida')
        state = source['status']
        counts[state] = counts.get(state, 0) + 1
        records += len(evidence)
    partial = any(state in counts for state in ('failed', 'blocked', 'timeout'))
    usable = bool(counts.get('ok', 0) + counts.get('empty', 0))
    state = 'no_evaluable' if partial or not usable else 'contexto'
    reason = f'OSINT: {len(sources)} fuentes; {records} registros; ' + ', '.join(f'{k}={v}' for k, v in sorted(counts.items()))
    return host, state, reason + '. Contexto, no vulnerabilidades.', usable


def collect_prior(framework_root, repo_root, objetivo, incluir_sin_objetivo=False, todos=False):
    """Devuelve cobertura y si algún parser OSINT evaluó fuentes utilizables."""
    fw = Path(framework_root)
    coverage = []
    evaluated = False
    roots = [('01', fw / '01_OSINT' / name) for name in ('domains', 'emails', 'social_media', 'subdomains', 'metadata')]
    roots += [('02', fw / '02_Recon'), ('07', fw / '07_Wireless/captures'),
              ('08', fw / '08_Forensics/analysis/runs')]
    roots += [('10', fw / '10_Evidence' / name) for name in ('screenshots', 'pcaps', 'credentials', 'findings', 'proofs', 'logs/results', 'logs/audit')]
    for module, root in roots:
        for path, blocked in walk(root):
            if not blocked:
                if module == '01' and path.name != 'resultados.json':
                    continue
                if module == '02' and (path.suffix.lower() not in {'.txt', '.xml', '.png'} or len(path.relative_to(root).parts) < 2):
                    continue
                if module == '08' and path.name != 'run.json':
                    continue
                if module == '10' and path.name != 'evidence.json' and path.suffix != '.meta':
                    continue
            host, state, reason, usable = '', 'contexto', '', False
            try:
                if blocked:
                    raise ValueError(blocked)
                if module == '01':
                    host, state, reason, usable = _osint(path)
                elif module == '02':
                    host = guess_host(path.name) or ''
                    if not host:
                        for part in path.relative_to(root).parts[:-1]:
                            match = re.fullmatch(r'recon_(.+)_\d{8}_\d{6}', part)
                            if match:
                                host = target(match[1])
                    reason = 'Artefacto de reconocimiento heredado: solo presencia; sin veredicto ni finalización acreditados. No se leyó el cuerpo.'
                elif module == '07':
                    host = guess_host(path.name) or ''
                    state = 'no_soportada'
                    reason = 'Artefacto wireless sin parser probatorio; no se leyó el cuerpo.'
                elif module == '08':
                    data = read_object(path)
                    if (type(data.get('version')) is not int or data['version'] != 1 or data.get('module') != '08'
                            or data.get('run_id') != path.parent.name):
                        raise ValueError('manifiesto forense inválido')
                    reason = 'Referencia forense sin atribución a host. Metadata solamente; análisis e integridad NO verificados.'
                else:
                    # read_record valida schema/layout y stat de payload, sin abrirlo.
                    record = _inventory().read_record(path, fw / '10_Evidence')
                    if record.target:
                        host = target(record.target)
                    reason = 'Registro de evidencia: metadata solamente, etiqueta del operador; contenido e integridad NO verificados. No demuestra vulnerabilidad.'
            except (OSError, ValueError, TypeError, RuntimeError) as error:
                state, reason = 'no_evaluable', 'Metadata no evaluable: ' + type(error).__name__
            if host and not todos and (not objetivo or not belongs_to(host, objetivo)):
                continue
            if not host and not (todos or incluir_sin_objetivo):
                state = 'no_evaluable'
                reason = 'Sin objetivo atribuible. ' + reason
                usable = False
            coverage.append(entry(module, path, repo_root, host, state, reason))
            evaluated = evaluated or usable
    return coverage, evaluated
