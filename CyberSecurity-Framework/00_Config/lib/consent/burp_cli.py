"""Public parser: opening a GUI never grants traffic or process-stop consent."""
import argparse
from pathlib import Path
import subprocess
import sys

if __name__ == '__main__' and not __package__:
    sys.path.insert(0, str(Path(__file__).absolute().parent.parent))

from consent.burp import (BurpOps, INSTANCE, observe_burp, start_burp, stop_burp,
                          validate_port, validate_url, verify_proxy)


def main(argv=None, *, framework: Path | None = None, ops: BurpOps | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, add_help=False,
        description='Burp Community: abrir GUI no autoriza GET ni parada; no usa sesión.')
    parser.add_argument('puerto', nargs='?')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--help', '-h', action='store_true')
    mode.add_argument('--estado', action='store_true')
    mode.add_argument('--verificar', metavar='URL')
    mode.add_argument('--parar', action='store_true')
    parser.add_argument('--proxy-port')
    parser.add_argument('--instance')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--confirm-network', action='store_true')
    # Do not echo invalid tokens: argparse diagnostics could leak URL query data.
    class InvalidArguments(Exception):
        pass
    def reject(_message):
        raise InvalidArguments
    parser.error = reject
    try:
        args = parser.parse_args(argv)
        special = args.help or args.estado or args.verificar is not None or args.parar
        if args.puerto is not None and special:
            raise InvalidArguments
        if args.instance is not None and (not (args.estado or args.parar) or
                                          not INSTANCE.fullmatch(args.instance)):
            raise InvalidArguments
        if args.help or args.estado:
            if args.proxy_port is not None or args.execute or args.confirm_network or (args.help and args.instance):
                raise InvalidArguments
        elif args.verificar is not None:
            if args.proxy_port is None or not args.execute or args.instance:
                raise InvalidArguments
            validate_url(args.verificar)
            port = validate_port(int(args.proxy_port))
        elif args.parar:
            if not args.execute or args.confirm_network or args.proxy_port is not None:
                raise InvalidArguments
        elif args.execute or args.confirm_network or args.proxy_port is not None or args.instance:
            raise InvalidArguments
        else:
            port = None if args.puerto is None else validate_port(int(args.puerto))
    except (InvalidArguments, ValueError):
        print('Argumentos/consentimiento inválidos; consulte --help. Sin operaciones.', file=sys.stderr)
        return 2
    if args.help:
        parser.print_help()
        print('Verificar: --verificar URL --proxy-port N --execute --confirm-network')
        print('Parar instancia propia: --parar --instance burp-<32hex> --execute')
        return 0
    framework = Path(__file__).absolute().parents[3] if framework is None else framework
    root = framework.parent / 'scans/burp'
    ops = BurpOps() if ops is None else ops
    try:
        if args.estado:
            observation = observe_burp(root, args.instance, ops)
            print(f'Instancia: {observation.instance_id or "NO_DETERMINADO"}')
            print(f'Puerto: {observation.port if observation.port else "NO_DETERMINADO"}')
            print('Listener local: ' + {None: 'NO_DETERMINADO', True: 'OCUPADO', False: 'NO_OBSERVADO'}[observation.listening])
            print('Propietario: NO_DETERMINADO\nCaptura: NO_VERIFICADA')
            return 0
        if args.verificar is not None:
            # Method, proxy and destination origin shown without path/query secrets.
            from urllib.parse import urlsplit
            parsed = urlsplit(args.verificar)
            print(f'GET explícito a {parsed.scheme}://{parsed.netloc} vía 127.0.0.1:{port}; ruta/query omitidas.')
            if not args.confirm_network:
                if not (sys.stdin.isatty() and sys.stderr.isatty()):
                    return 2
                print('Escriba ENVIAR GET para ESTA solicitud (no certifica captura):', file=sys.stderr)
                if sys.stdin.readline().rstrip('\n') != 'ENVIAR GET':
                    return 2
            return verify_proxy(args.verificar, port, True, ops)
        if args.parar:
            rc = stop_burp(root, args.instance, ops)
            print('Señalización de instancia propia completada; recibo conservado.' if rc == 0 else
                  'Parada bloqueada: identidad/recibo/pidfd no acreditados; sin adopción legacy.')
            return rc
        instance = start_burp(framework, port, ops)
        print(f'GUI Community solicitada: {instance.instance_id}\nConfig/log privados: {instance.directory}')
        print('Recibo administrativo: ' + ('creado' if instance.managed else 'NO_DETERMINADO; parada no acreditada'))
        ops.await_listener(instance.port)
        observation = observe_burp(root, instance.instance_id, ops)
        if observation.listening is not True:
            ops.assist_gui()
        print(f'Puerto solicitado: {instance.port}; propietario NO_DETERMINADO; captura NO_VERIFICADA.')
        print('GUI no autoriza tráfico al objetivo. Burp puede realizar su propio tráfico.')
        print(f'1. Configure manualmente navegador y proxy 127.0.0.1:{instance.port}.')
        print('2. Para HTTPS, instale/acepte explícitamente el CA de Burp (http://burp).')
        print('3. Navegue con su sesión y envíe la petición interesante a Repeater.')
        print(f'4. Guarde manualmente la petición en {instance.directory}/peticion.txt (no se crea aquí).')
        print('5. Use ./05_Exploitation/web/http_inject.sh con esa petición y objetivo explícitos.')
        print('Community no tiene Scanner/API ni guarda el historial/proyecto al cerrar.')
        print('Verificación separada: --verificar URL --proxy-port N --execute --confirm-network')
        print(f'Parar solo esta instancia propia: --parar --instance {instance.instance_id} --execute')
        print('No se controlan procesos que daemonizan/escapan; nunca se adoptan por nombre/PIDlegacy.')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        # Exceptions from subprocess may carry argv/URLs; never echo raw transport errors.
        if isinstance(exc, ValueError) and args.verificar is None:
            print(str(exc), file=sys.stderr)
        else:
            print('Operación Burp no determinada/fallida; no se certifica captura.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
