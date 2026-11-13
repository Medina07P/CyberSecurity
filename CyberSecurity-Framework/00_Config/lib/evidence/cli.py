"""Internal CLI. Wrappers supply a root explicitly; environment never overrides it."""
import argparse
from pathlib import Path
import signal
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).absolute().parent.parent))
    from evidence.model import EvidenceError, UsageError
    from evidence.storage import PUBLIC_ROOTS, add, safe_text
    from evidence.inventory import scan, verify
    from evidence.package import create
    from evidence.capture import CapturePlan, validate_plan, capture
    from evidence.process import CaptureInterrupted
else:
    from .model import EvidenceError, UsageError
    from .storage import PUBLIC_ROOTS, add, safe_text
    from .inventory import scan, verify
    from .package import create
    from .capture import CapturePlan, validate_plan, capture
    from .process import CaptureInterrupted


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('allow_abbrev', False)
        super().__init__(*args, **kwargs)

    def error(self, message):
        raise UsageError(message)


class Once(argparse.Action):
    """Reject repeated selectors/options rather than silently using the last."""
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            raise UsageError(f'{option_string} solo puede aparecer una vez')
        setattr(namespace, self.dest, True if self.nargs == 0 else values)


def _plan(args):
    if args.traffic is None and any(getattr(args, key) is not None for key in
                                    ('interface', 'duration', 'packet_limit')):
        raise UsageError('OPCIONES DE TRÁFICO SIN ACCIÓN')
    plan = CapturePlan(web=args.web, traffic=args.traffic, interface=args.interface,
                       scan=args.scan, scan_profile=args.scan_profile, system=bool(args.system),
                       duration=args.duration if args.duration is not None else 10,
                       packet_limit=args.packet_limit if args.packet_limit is not None else 100,
                       authorize_network=bool(args.authorize_network))
    validate_plan(plan)
    return plan


def _inventory(root, checking):
    result = verify(root) if checking else scan(root)
    records = [entry.record for entry in result.entries] if checking else result.records
    for record in records:
        state = ('HISTÓRICA MD5 — NO VERIFICADA' if record.format == 'legacy-md5'
                 else 'NUEVA — NO VERIFICADA') if not checking else (
                     'HISTÓRICA — MD5 COINCIDE' if record.format == 'legacy-md5' else 'SHA-256 COINCIDE')
        print(safe_text(f'{state}: {record.id} {record.kind} {record.payload.name}'
                        f' target={record.target if record.target is not None else "—"}'))
    for issue in result.issues:
        state = 'SIN METADATOS' if issue.code == 'MISSING_METADATA' else 'INVÁLIDA'
        print(safe_text(f'{state} [{issue.code}]: {issue.path}: {issue.message}'))
    if not records and not result.issues:
        print('SIN EVIDENCIAS')
    if checking:
        if any(record.format == 'legacy-md5' for record in records):
            print('ADVERTENCIA: MD5 heredado; no prueba autenticidad ni confianza moderna.')
        print(f'VERIFICACIÓN {"CORRECTA" if result.ok else "FALLIDA"}: '
              f'{len(records)} verificadas; {len(result.issues)} problemas')
    return (0 if result.ok else 1) if checking else (1 if result.issues else 0), len(records)


def _capture(root, plan):
    rc = capture(root, plan)
    if rc in (130, 143):
        print('CAPTURA: INTERRUMPIDA')
    elif rc:
        print('CAPTURA: FALLIDA/PARCIAL; consulte diagnósticos privados en logs/runs')
    else:
        print('CAPTURA: ACCIONES FINALIZADAS; no acredita integridad ni presencia de tráfico')
    return rc


def _workflow(root, plan):
    failed, records = False, 0
    if plan is not None:
        try:
            rc = _capture(root, plan)
        except CaptureInterrupted:
            raise
        except (EvidenceError, OSError) as exc:
            print(f'ERROR CAPTURA: {safe_text(str(exc))}', file=sys.stderr)
            rc = 1
        if rc in (130, 143):
            print('RESUMEN: INTERRUMPIDO')
            return rc
        failed = rc != 0
    for checking in (False, True):
        try:
            rc, count = _inventory(root, checking)
            records = max(records, count)
            failed = failed or rc != 0
        except CaptureInterrupted:
            raise
        except (EvidenceError, OSError) as exc:
            print(f'ERROR {"VERIFICACIÓN" if checking else "LISTADO"}: {safe_text(str(exc))}', file=sys.stderr)
            failed = True
    state = ('PARCIAL' if records else 'FALLIDO / SIN EVIDENCIA') if failed else 'COMPLETO'
    print(f'RESUMEN: {state}')
    return 1 if failed else 0


def _main(argv: list[str] | None = None) -> int:
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
    manage.add_argument('--package', action='append', nargs='?', const=None, metavar='NOMBRE',
                        help='Exportar evidencia confidencial sin cifrar; requiere custodia privada')
    capture_parsers = {}
    for command in ('capture', 'run'):
        sub = commands.add_parser(command, add_help=False,
                                  description='Selección explícita de acciones; nunca captura por defecto.')
        capture_parsers[command] = sub
        sub.add_argument('--help', '-h', action=Once, nargs=0, help='Mostrar ayuda sin efectos')
        for option, label, help_text in (
                ('web', 'URL', 'Captura web HTTP/HTTPS explícita'),
                ('traffic', 'HOST', 'Tráfico de un host único; requiere --interface'),
                ('interface', 'IFACE', 'Interfaz explícita para --traffic'),
                ('scan', 'HOST', 'Escaneo de un host único; requiere --scan-profile'),
                ('scan-profile', 'PERFIL', 'Perfil explícito: basic o full')):
            sub.add_argument('--' + option, action=Once, metavar=label, help=help_text)
        for option, help_text in (
                ('duration', 'Segundos de tráfico: 1–300 (por defecto 10; solo --traffic)'),
                ('packet-limit', 'Paquetes: 1–10000 (por defecto 100; solo --traffic)')):
            sub.add_argument('--' + option, action=Once, type=int, metavar='N', help=help_text)
        sub.add_argument('--system', action=Once, nargs=0, help='Contexto local del operador; sin red')
        sub.add_argument('--authorize-network', action=Once, nargs=0,
                         help='Autorización explícita para las acciones de red seleccionadas')
        if command == 'run':
            sub.add_argument('--offline', action=Once, nargs=0, help='Solo listar y verificar')
            sub.add_argument('--capture', dest='capture_selected', action=Once, nargs=0,
                             help='Capturar acciones seleccionadas, listar y verificar')
    args_list = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parser.parse_args(args_list)
        if args.command != 'manage':
            selections = ('web', 'traffic', 'interface', 'scan', 'scan_profile', 'system',
                          'duration', 'packet_limit', 'authorize_network')
            supplied = any(getattr(args, key) is not None for key in selections)
            if args.help:
                if supplied or (args.command == 'run' and (args.offline or args.capture_selected)):
                    raise UsageError('--help no admite una operación')
                capture_parsers[args.command].print_help()
                return 0
            if args.command == 'run':
                if bool(args.offline) + bool(args.capture_selected) != 1:
                    raise UsageError('Seleccione explícitamente --offline o --capture')
                if args.offline:
                    if supplied:
                        raise UsageError('--offline no admite opciones de captura/red')
                    return _workflow(args.root, None)
            plan = _plan(args)
            return _workflow(args.root, plan) if args.command == 'run' else _capture(args.root, plan)
        if args.help:
            if args.add is not None or args.target is not None or args.list or args.verify or args.package:
                raise UsageError('--help no admite una operación')
            manage.print_help()
            return 0
        if bool(args.add) + args.list + args.verify + (len(args.package) if args.package else 0) != 1:
            manage.print_help(file=sys.stderr)
            raise UsageError('Seleccione una operación: --add, --list, --verify o --package')
        if args.package:
            if args.target is not None:
                raise UsageError('--target requiere --add')
            archive = create(args.root, args.package[0])
            print(safe_text(f'PAQUETE CREADO (confidencial, sin cifrar): {archive}'))
            return 0
        if args.list or args.verify:
            if args.target is not None:
                raise UsageError('--target requiere --add')
            return _inventory(args.root, bool(args.verify))[0]
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
        print(f'USO INVÁLIDO: {safe_text(str(exc))}. Selección explícita requerida; '
              'consulte --help.', file=sys.stderr)
        return 2
    except CaptureInterrupted as exc:
        return 128 + exc.signum
    except (EvidenceError, OSError) as exc:
        print(f'ERROR: {safe_text(str(exc))}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def main(argv: list[str] | None = None) -> int:
    handlers = {}

    def interrupted(signum, frame):
        raise CaptureInterrupted(signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            handlers[signum] = signal.signal(signum, interrupted)
        return _main(argv)
    except CaptureInterrupted as exc:
        return 128 + exc.signum
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    sys.exit(main())
