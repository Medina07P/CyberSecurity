"""Entradas del gestor: misma recopilación en modo individual o coordinado."""
import argparse
import os
import sys
from pathlib import Path

from .credentials import load_credentials
from .discovery import discover_emails, discover_social
from .dns import enumerate_dns, load_wordlist, normalize_domain, resolve_discovered, validate_resolver
from .model import Evidence, Limits, Run
from .runtime import HttpClient, SourceError, exit_code, redact, run_tool, write_run
from .sources import collect, collect_certificates, collect_tool, evidence_result


FRAMEWORK = Path(__file__).resolve().parents[3]
MODULE = FRAMEWORK / '01_OSINT'


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('Argumentos inválidos; consulta la línea Uso: del script')


def _parser():
    parser = Parser(description='Recopilación OSINT con evidencia')
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('social', 'emails', 'domains', 'subdomains', 'metadata', 'all'):
        child = commands.add_parser(command)
        child.add_argument('target')
        if command == 'all':
            child.add_argument('file', nargs='?', default='')
            child.add_argument('company', nargs='?', default='')
        else:
            child.add_argument('output', nargs='?', default='')
        if command == 'social':
            child.add_argument('domain', nargs='?', default='')
        if command == 'subdomains':
            child.add_argument('wordlist', nargs='?', default='')
            child.add_argument('resolver', nargs='?', default='')
    return parser


def collect_metadata(run, file):
    def operation():
        file_path = Path(file).resolve()
        if not file_path.is_file():
            raise SourceError('failed', 'Archivo de metadatos no encontrado')
        mime = run_tool(['file', '--brief', '--mime-type', '--', str(file_path)], run.limits.tool_seconds).stdout.strip()
        if mime == 'application/pdf':
            argv = ['pdfinfo', str(file_path)]
        elif mime.startswith('image/') or any(part in mime for part in ('officedocument', 'msword', 'ms-excel', 'ms-powerpoint', 'zip')):
            argv = ['exiftool', str(file_path)]
        else:
            argv = ['strings', '-n', '8', '--', str(file_path)]
        result = run_tool(argv, run.limits.tool_seconds)
        text = result.stdout.strip()
        if argv[0] == 'strings':
            text = '\n'.join(text.splitlines()[:50])
        return evidence_result('metadata', [Evidence('metadata' if argv[0] != 'strings' else 'strings', text,
                               str(file_path), 'observado', f'Extractor {argv[0]}; MIME {mime}')] if text else [])
    return collect(run, 'metadata', operation)


def main(argv=None):
    try:
        args = _parser().parse_args(argv)
        limits = Limits()
        if args.command == 'social':
            company = args.target.strip()
            if not company or len(company) > 200 or any(ord(c) < 32 for c in company):
                raise ValueError('Nombre de empresa vacío, demasiado largo o con caracteres de control')
            domain = normalize_domain(args.domain) if args.domain else None
        elif args.command != 'metadata':
            domain = normalize_domain(args.target)
            company = getattr(args, 'company', '').strip() or domain
        file = None
        if args.command == 'metadata' or (args.command == 'all' and args.file):
            file = Path(args.target if args.command == 'metadata' else args.file).resolve()
            if not file.is_file():
                raise ValueError(f'Archivo no encontrado: {file}')
        if args.command == 'subdomains':
            args.resolver = validate_resolver(args.resolver)
            if args.wordlist:
                args.wordlist = str(Path(args.wordlist).resolve())
                load_wordlist(args.wordlist, domain, limits.dns_candidates)
                print(f'⚠️ Fuerza bruta DNS sobre {domain}: hasta 1.000 candidatos, 5 consultas/s, 120 s. Solo con autorización.', file=sys.stderr)
                print('Escribe DNS_SI para confirmar: ', end='', file=sys.stderr, flush=True)
                if sys.stdin.readline().strip() != 'DNS_SI':
                    raise ValueError('Fuerza bruta DNS cancelada; no se consultó el objetivo')
        default_dirs = {'social': 'social_media', 'emails': 'emails', 'domains': 'domains',
                        'subdomains': 'subdomains', 'metadata': 'metadata', 'all': 'domains'}
        explicit_output = getattr(args, 'output', '')
        output = Path(explicit_output).resolve() if explicit_output else MODULE / default_dirs[args.command]
        if explicit_output:
            print(f'ℹ️ Salida explícita: {output}; puede no estar ignorada por git.', file=sys.stderr)
        run = Run(company if args.command == 'social' else args.target, output, limits)
        if args.command != 'metadata':
            registry = Path(os.environ.get('KEYS_FILE', FRAMEWORK / '00_Config/credentials/api-keys.yaml'))
            dirs = os.environ.get('KEYS_HARVESTER_DIRS')
            dirs = [Path(p) for p in dirs.split(os.pathsep)] if dirs is not None else [Path.home()/'.theHarvester', Path('/etc/theHarvester'), Path('/usr/local/etc/theHarvester')]
            keys = load_credentials(registry, dirs)
            run.secrets.extend(keys.values())
            client = HttpClient(limits)
        print(f'🔍 OSINT: {run.target}')
        if args.command in ('all', 'domains'):
            collect_tool(run, 'whois', domain)
            collect_tool(run, 'whatweb', domain)
            collect_tool(run, 'theHarvester', domain)
        if args.command in ('all', 'emails', 'domains'):
            discover_emails(run, client, domain, keys)
        if args.command in ('all', 'social'):
            if args.command == 'all' and not args.company:
                print(f'ℹ️ Sin nombre de empresa: se busca el dominio completo ({domain}), no su primera etiqueta.')
            discover_social(run, client, company, domain, keys)
        if args.command in ('all', 'subdomains', 'domains'):
            if args.command == 'subdomains' and args.wordlist:
                enumerate_dns(run, domain, Path(args.wordlist), args.resolver, True)
            else:
                certificates = collect_certificates(run, client, domain)
                if certificates.status in ('ok', 'empty'):
                    resolve_discovered(run, domain, [e.value for e in certificates.evidence], getattr(args, 'resolver', None))
        if file:
            collect_metadata(run, file)
        elif args.command == 'all':
            print('ℹ️ Metadatos omitidos: no se proporcionó archivo local.')
        destination = write_run(run)
        print((destination/'resumen.txt').read_text(encoding='utf-8'), end='')
        code = exit_code(run.results)
        print('✅ OSINT completado (consulta la cobertura de fuentes).' if code == 0 else '⚠️ OSINT parcial o sin fuentes utilizables; consulta errores y cobertura.')
        print(f'Resultados: {destination}')
        print(f'Errores y omisiones: {destination / "errores.log"}')
        return code
    except (ValueError, OSError) as exc:
        print(f'❌ {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
