"""Explicit preview-first CLI and menu; no session/configuration defaults."""
import argparse
import os
from pathlib import Path
import sys
from typing import Sequence

from .adapters import execute_plan
from .catalog import availability, get_action
from .model import Permissions, PlanError, PreflightError, RunResult, RuntimeContext
from .planner import build_plan, render_plan
from .validation import validate
from .workflows import load_workflow


INPUTS = ('target', 'url', 'domain', 'ports', 'port', 'request_file', 'scheme',
          'account', 'wordlist', 'max_attempts', 'max_seconds', 'product',
          'database', 'table', 'report_input')
ORIGINAL = ('bash/auto_recon.sh', 'bash/auto_enum.sh', 'bash/auto_exploit.sh',
            'python/orchestrator.py', 'python/auto_audit.py', 'python/report_generator.py',
            'powershell/auto_enum.ps1', 'workflows/quick_scan.yaml',
            'workflows/full_audit.yaml', 'docker/Dockerfile', 'docker/docker-compose.yml',
            'run_all_automation.sh', 'README.md')


def runtime_context():
    framework = Path(__file__).resolve().parents[3]
    return RuntimeContext(framework, framework.parent, Path(sys.executable), os.defpath)


def parser():
    result = argparse.ArgumentParser(description='09: planes explícitos; preview por defecto',
                                     allow_abbrev=False)
    selectors = result.add_mutually_exclusive_group()
    selectors.add_argument('--phase', choices=('recon', 'scan', 'enum', 'web', 'exploit', 'post', 'report'))
    selectors.add_argument('--full', action='store_true')
    selectors.add_argument('--workflow')
    selectors.add_argument('--action')
    for key in INPUTS:
        result.add_argument('--' + key.replace('_', '-'))
    for key in ('menu', 'list', 'check', 'execute', 'include-config'):
        result.add_argument('--' + key, action='store_true')
    result.add_argument('--authorized-target', action='append', default=[])
    result.add_argument('--allow', action='append', default=[])
    return result


def gates(step):
    if step.action != 'sqlmap_request':
        return get_action(step.action).gates
    return ('sqlmap_probe', 'sqlmap_replay') + (('sqlmap_enum',) if 'database' in step.inputs else ()) + (
        ('sqlmap_dump',) if 'table' in step.inputs else ())


def permissions_for(plan, targets, grants):
    destinations = {step.inputs.get('target', step.inputs.get('domain')) for step in plan.steps
                    if get_action(step.action).network}
    authorized = frozenset(validate('target', value) for value in targets)
    if authorized - destinations:
        raise PlanError('Autorización de destino huérfana')
    allowed = {(step.id, gate) for step in plan.steps for gate in gates(step)}
    # An explicit enum grant without database preserves the leaf's --dbs mode.
    allowed.update((step.id, 'sqlmap_enum') for step in plan.steps if step.action == 'sqlmap_request')
    parsed = set()
    for value in grants:
        pair = tuple(value.split(':'))
        if pair not in allowed:
            raise PlanError('Permiso desconocido o huérfano')
        parsed.add(pair)
    return Permissions(authorized, frozenset(parsed))


def show_catalog(ctx):
    for action in availability(ctx):
        spec = get_action(action)
        print(f'{action}: entradas {", ".join(spec.input_types) or "ninguna"}; '
              f'obligatorias {", ".join(spec.required) or "ninguna"}. '
              f'{spec.effects} Límites: {spec.limitations}')


def prepare(args, ctx):
    inputs = {key: getattr(args, key) for key in INPUTS if getattr(args, key) is not None}
    if args.include_config:
        inputs['include_config'] = True
    if args.workflow:
        path = validate('path', args.workflow)
        path = path if path.is_absolute() else ctx.framework / path
        plan = load_workflow(path, inputs)
        admitted = {key for step in plan.steps for key in get_action(step.action).input_types}
        if set(inputs) - admitted:
            raise PlanError('Flags no aplicables al workflow')
        return plan
    selector = args.action or ('full' if args.full else args.phase or 'quick')
    if args.action:
        get_action(args.action)
    if selector == 'exploit':
        raise PlanError('Exploit exige --action explícita; consultar --list')
    return build_plan(selector, inputs)


def main(argv: Sequence[str] | None = None, *, ctx: RuntimeContext | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cli = parser()
    try:
        args = cli.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    ctx = ctx or runtime_context()
    try:
        if not argv:
            cli.print_help()
            return 0
        modes = [name for name in ('menu', 'list', 'check') if getattr(args, name)]
        if modes:
            if len(argv) != 1:
                raise PlanError('--menu/--list/--check son modos exclusivos')
            if args.menu:
                return menu(ctx)
            if args.list:
                show_catalog(ctx)
            else:
                for action, found in availability(ctx).items():
                    print(f'{action}: {"presente (no probado)" if found else "ausente"}')
            return 0
        plan = prepare(args, ctx)
        permissions = permissions_for(plan, args.authorized_target, args.allow)
        print(render_plan(plan, ctx))
        if not args.execute:
            return 0
        if not plan.steps:
            raise PlanError('Guía post no ejecutable; consultar 06')
        # No stdin prompts here: neither --execute nor piped yes is authority.
        return execute_plan(plan, ctx, permissions).rc
    except PlanError as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    except (PreflightError, OSError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


def ask(prompt):
    value = input(prompt)
    if value == '':
        raise EOFError
    return value.strip()


def interactive_plan(plan, ctx):
    print(render_plan(plan, ctx))
    if not plan.steps or ask('Escriba EJECUTAR para continuar (otra respuesta cancela): ') != 'EJECUTAR':
        return 0
    targets, grants = [], []
    for host in sorted({step.inputs.get('target', step.inputs.get('domain')) for step in plan.steps
                        if get_action(step.action).network}):
        if ask(f'Autorizar destino escribiendo {host}: ') != host:
            return 0
        targets.append(host)
    for step in plan.steps:
        for gate in gates(step):
            token = f'{step.id}:{gate}'
            if ask(f'Permiso {token}; escriba el texto exacto (replay SQLmap conservador): ') != token:
                return 0
            grants.append(token)
        if step.action == 'sqlmap_request' and 'database' not in step.inputs:
            token = f'{step.id}:sqlmap_enum'
            answer = ask(f'Enumerar bases (--dbs) opcional: escriba {token} o NO para omitir: ')
            if answer == token:
                grants.append(token)
            elif answer != 'NO':
                return 0
    return execute_plan(plan, ctx, permissions_for(plan, targets, grants)).rc


def menu(ctx: RuntimeContext) -> int:
    while True:
        print('\n09 Automatización — sin objetivo de sesión; no ejecutar al entrar')
        print('1 Disponibilidad: sin entradas; comprueba PATH, no ejecuta herramientas.')
        print('2 Guía: sin entradas; explica planes, permisos y límites; sin lectura de datos.')
        print('3 Quick: pide target; preview de ping y 100 puertos TCP, ejecución opt-in.')
        print('4 Full: pide target; quick + versiones BD, no credenciales/NSE; ejecución opt-in.')
        print('5 Avanzadas: catálogo de acciones; pide sus entradas explícitas; efectos en cada acción.')
        print('6 Workflow: pide ruta YAML y target por defecto; valida/preview; ejecución opt-in.')
        print('11 Original: lista todo el árbol original, sin ejecución por extensión ni bypass.')
        print('0 Volver: sin entradas ni efectos.')
        try:
            choice = ask('Opción: ')
            if choice == '0':
                return 0
            if choice == '1':
                for action, found in availability(ctx).items():
                    print(f'{action}: {"presente (no probado)" if found else "ausente"}')
            elif choice == '2':
                print('Preview no lee config/evidencias/credenciales ni crea runs. '
                      'Ejecución: confirmar destino y cada gate de nuevo; primer fallo detiene. '
                      'CLI: --target HOST [--full|--phase F|--action A|--workflow YAML]. '
                      '--execute requiere --authorized-target HOST y --allow paso:gate. '
                      'Post es guía a 06; informes exigen report_input y report_read. '
                      'No certifica autorización, cobertura ni compatibilidad operacional.')
            elif choice == '11':
                print('\n'.join(ORIGINAL))
            elif choice in ('3', '4', '5', '6'):
                if choice == '5':
                    show_catalog(ctx)
                    action = ask('Acción exacta (0 cancela): ')
                    if action == '0':
                        continue
                    spec = get_action(action)
                    values = {}
                    for key in spec.input_types:
                        if key in spec.required:
                            values[key] = ask(f'{key} ({spec.input_types[key]}): ')
                        else:
                            value = input(f'{key} opcional ({spec.input_types[key]}; '
                                          'vacío omite, SSH port por defecto 22): ').strip()
                            if value:
                                values[key] = value
                    plan = build_plan(action, values)
                elif choice == '6':
                    path = validate('path', ask('Ruta YAML explícita: '))
                    path = path if path.is_absolute() else ctx.framework / path
                    target = ask('Target por defecto explícito: ')
                    plan = load_workflow(path, {'target': target})
                else:
                    plan = build_plan('quick' if choice == '3' else 'full',
                                      {'target': ask('Target IPv4/dominio explícito: ')})
                rc = interactive_plan(plan, ctx)
                print(f'Resultado: rc={rc}; no se conservan permisos.')
            else:
                print('Opción no válida.')
        except (EOFError, KeyboardInterrupt):
            return 0
        except (PlanError, PreflightError, OSError) as exc:
            print(f'Error: {exc}', file=sys.stderr)
