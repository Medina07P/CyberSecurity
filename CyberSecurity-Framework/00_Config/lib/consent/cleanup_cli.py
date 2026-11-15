"""Stable cleaner CLI: all parsing/consent precedes any operational effects."""
import argparse
import os
from pathlib import Path
import sys

if __name__ == '__main__' and not __package__:
    # Explicit sibling package only; -I excludes cwd/PYTHONPATH/user site.
    sys.path.insert(0, str(Path(__file__).absolute().parent.parent))

from consent.cleanup import apply_cleanup, plan_cleanup


def main(argv=None, *, framework: Path | None = None, ops=None) -> int:
    parser = argparse.ArgumentParser(
        description='Cleanup LOCAL: preview por defecto; no usa el objetivo de sesión.',
        allow_abbrev=False, add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Mostrar ayuda sin efectos')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--preview', action='store_true', help='Solo presentar el plan LOCAL')
    mode.add_argument('--execute', action='store_true', help='Solicitar aplicación LOCAL')
    parser.add_argument('--confirm-local-cleanup', action='store_true',
                        help='Consentimiento explícito para ESTA aplicación LOCAL')
    args = parser.parse_args(argv)
    if args.confirm_local_cleanup and not args.execute:
        parser.error('--confirm-local-cleanup requiere --execute')
    if args.help:
        if args.execute or args.confirm_local_cleanup or args.preview:
            parser.error('--help no se combina con modos de operación')
        parser.print_help()
        return 0
    if args.execute and not args.confirm_local_cleanup:
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            parser.error('--execute requiere --confirm-local-cleanup sin TTY')
        print(f'LOCAL uid={os.getuid()}: truncar cuatro logs y ~/.bash_history; '
              'history -c solo en un hijo, NO en el shell padre. '
              'Escriba LIMPIAR LOCAL para esta ejecución:', file=sys.stderr)
        if sys.stdin.readline().rstrip('\n') != 'LIMPIAR LOCAL':
            print('Consentimiento LOCAL rechazado; sin operaciones.', file=sys.stderr)
            return 2
    # Pure planning: no stat/read/mkdir, shell, backend or session lookup.
    plan = plan_cleanup(Path.home())
    if not args.execute:
        print('PREVIEW LOCAL — sin cambios; requiere --execute y consentimiento LOCAL.')
        for operation in plan:
            print(f'  {operation.kind}: {operation.path if operation.path else "(hijo/snapshot)"}')
        print('history -c solo afecta a un Bash hijo, nunca a la memoria del shell padre.')
        print('Sin escalada automática: permisos insuficientes se reportan como fallo parcial.')
        return 0
    framework = Path(__file__).absolute().parents[3] if framework is None else framework
    try:
        result = apply_cleanup(plan, framework.parent / 'scans/cleanup', ops)
    except (OSError, ValueError) as exc:
        print(f'No se pudo preparar el informe LOCAL: {exc}', file=sys.stderr)
        return 1
    for row in result.operations:
        label = f'{row.operation.kind}: {row.operation.path or "hijo/snapshot"}'
        if row.success:
            print(f'OK LOCAL {label}')
        else:
            print(f'FALLO LOCAL {label}: {row.error}', file=sys.stderr)
    print('history -c: solo Bash hijo; memoria del shell padre intacta.')
    print(f'Informe privado LOCAL: {result.report_dir}')
    print('Resultado parcial: hay fallos.' if result.rc else 'Operaciones LOCAL completadas.')
    return result.rc


if __name__ == '__main__':
    raise SystemExit(main())
