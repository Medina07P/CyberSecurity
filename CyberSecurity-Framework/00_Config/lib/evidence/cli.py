"""Internal CLI. Wrappers supply a root explicitly; environment never overrides it."""
import argparse
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).absolute().parent.parent))
    from evidence.model import EvidenceError, UsageError
    from evidence.storage import PUBLIC_ROOTS, add, safe_text
    from evidence.inventory import scan, verify
else:
    from .model import EvidenceError, UsageError
    from .storage import PUBLIC_ROOTS, add, safe_text
    from .inventory import scan, verify


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('allow_abbrev', False)
        super().__init__(*args, **kwargs)

    def error(self, message):
        raise UsageError(message)


def main(argv: list[str] | None = None) -> int:
    parser = Parser(prog='evidence_manager.sh', add_help=False,
                    description='Gestión privada de evidencias (importación SHA-256).')
    parser.add_argument('--root', type=Path, required=True, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest='command', required=True)
    manage = commands.add_parser('manage', add_help=False)
    manage.add_argument('--help', '-h', action='store_true', help='Mostrar ayuda')
    manage.add_argument('--add', action='append', nargs='+', metavar='TIPO ARCHIVO [DESCRIPCION]')
    manage.add_argument('--target', action='append', metavar='ETIQUETA', help='Etiqueta explícita opcional')
    manage.add_argument('--list', action='count', default=0, help='Listar sin verificar contenido')
    manage.add_argument('--verify', action='count', default=0, help='Verificar integridad')
    args_list = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parser.parse_args(args_list)
        if args.help:
            if args.add is not None or args.target is not None or args.list or args.verify:
                raise UsageError('--help no admite una operación')
            manage.print_help()
            return 0
        if bool(args.add) + args.list + args.verify != 1:
            manage.print_help(file=sys.stderr)
            raise UsageError('Seleccione una operación: --add, --list o --verify')
        if args.list or args.verify:
            if args.target is not None:
                raise UsageError('--target requiere --add')
            result = scan(args.root) if args.list else verify(args.root)
            records = result.records if args.list else [entry.record for entry in result.entries]
            for record in records:
                state = ('HISTÓRICA MD5 — NO VERIFICADA' if record.format == 'legacy-md5'
                         else 'NUEVA — NO VERIFICADA') if args.list else (
                             'HISTÓRICA — MD5 COINCIDE' if record.format == 'legacy-md5'
                             else 'SHA-256 COINCIDE')
                print(safe_text(f'{state}: {record.id} {record.kind} {record.payload.name}'
                                f' target={record.target if record.target is not None else "—"}'))
            for issue in result.issues:
                state = 'SIN METADATOS' if issue.code == 'MISSING_METADATA' else 'INVÁLIDA'
                print(safe_text(f'{state} [{issue.code}]: {issue.path}: {issue.message}'))
            if not records and not result.issues:
                print('SIN EVIDENCIAS')
            if args.verify:
                if any(record.format == 'legacy-md5' for record in records):
                    print('ADVERTENCIA: MD5 heredado; no prueba autenticidad ni confianza moderna.')
                print(f'VERIFICACIÓN {"CORRECTA" if result.ok else "FALLIDA"}: '
                      f'{len(records)} verificadas; {len(result.issues)} problemas')
                return 0 if result.ok else 1
            return 0
        if len(args.add) != 1 or len(args.add[0]) not in (2, 3):
            raise UsageError('Uso: --add TIPO ARCHIVO [DESCRIPCION] [--target ETIQUETA]')
        if args.target is not None and len(args.target) != 1:
            raise UsageError('--target solo puede aparecer una vez')
        kind, source, *description = args.add[0]
        if kind not in PUBLIC_ROOTS:
            raise UsageError('Tipos: screenshot, pcap, credential, finding, proof')
        target = args.target[0] if args.target else None
        record = add(args.root, kind, Path(source), description[0] if description else '', target)
        print(f'AÑADIDA {record.id} {record.kind} SHA-256')
        return 0
    except UsageError as exc:
        print(f'USO INVÁLIDO: {safe_text(str(exc))}', file=sys.stderr)
        return 2
    except EvidenceError as exc:
        print(f'ERROR: {safe_text(str(exc))}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
